import os
import numpy as np
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

import psutil
import gmpy2
from gmpy2 import mpz

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from pyasn1.type import univ, namedtype
from pyasn1.codec.der import encoder as der_encoder, decoder as der_decoder

from app.crypto.utils import generate_unique_random_images
from app.crypto.core.prime import generate_prime,KEY_BIT_LENGTH
from app.crypto.core.math_utils import modinv

# ASN.1 контейнер для хранения шифротекста вместе с метаданными
class RSAContainer(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('ciphertext', univ.OctetString()),
        namedtype.NamedType('timestamp',   univ.OctetString()),
        namedtype.NamedType('entropy',     univ.OctetString()),
        namedtype.NamedType('n',           univ.Integer()),
        namedtype.NamedType('e',           univ.Integer())
    )

def generate_enhanced_rsa_keys_from_image(encoder, used_images=None):
    """
    Генерация RSA-ключей на основе латентного представления случайного изображения.
    Возвращает (private_key, public_key, system_entropy_bytes, timestamp_bytes).
    """
    if used_images is None:
        used_images = set()

    # 1) Получаем случайное уникальное изображение и его латентное представление
    image = generate_unique_random_images(1, shape=(28, 28, 1), used_images=used_images)[0]
    latent = encoder.predict(image[np.newaxis, ...], verbose=0)

    # 2) Собираем энтропию из системы и латента
    system_entropy = os.urandom(32)
    timestamp = datetime.utcnow().isoformat().encode('utf-8')
    cpu_usage = str(psutil.cpu_percent(interval=0.01)).encode('utf-8')
    combined = latent.tobytes() + system_entropy + timestamp + cpu_usage

    # 3) Производный ключ через PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=64,
        salt=system_entropy[:16],
        iterations=5000,
        backend=default_backend()
    )
    derived = kdf.derive(combined)

    # 4) Получаем два «семени» для p и q
    hash_p = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hash_p.update(derived[:32] + b"p")
    seed_p = hash_p.finalize()

    hash_q = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hash_q.update(derived[32:] + b"q")
    seed_q = hash_q.finalize()

    # 5) Параллельно генерируем простые по seed_p и seed_q
    with ThreadPoolExecutor(max_workers=2) as executor:
        future_p = executor.submit(generate_prime, seed_p)
        future_q = executor.submit(generate_prime, seed_q)
        p = int(future_p.result())
        q = int(future_q.result())

    # если вдруг совпали
    if p == q:
        q = int(gmpy2.next_prime(mpz(q + 2)))

    # 6) Собираем n, phi и вычисляем обратный к e
    n = p * q
    e = 65537
    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)

    # 7) Формируем объекты ключей из cryptography
    private_numbers = rsa.RSAPrivateNumbers(
        p, q, d,
        d % (p - 1),
        d % (q - 1),
        modinv(q, p),
        rsa.RSAPublicNumbers(e, n)
    )
    private_key = private_numbers.private_key(default_backend())
    public_key = private_key.public_key()
    return private_key, public_key, system_entropy, timestamp

def rsa_encrypt_with_metadata(public_key, private_key, entropy, timestamp, key_id, plaintext: bytes) -> bytes:
    """
    Шифрование plaintext и упаковка в ASN.1 структуру вместе с метаданными.
    Возвращает DER-кодированный контейнер.
    """
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA512()),
            algorithm=hashes.SHA512(),
            label=None
        )
    )
    container = RSAContainer()
    container.setComponentByName('ciphertext', ciphertext)
    container.setComponentByName('timestamp',   timestamp)
    container.setComponentByName('entropy',     entropy)
    nums = public_key.public_numbers()
    container.setComponentByName('n', nums.n)
    container.setComponentByName('e', nums.e)
    return der_encoder.encode(container)

def rsa_decrypt_with_metadata(container_bytes: bytes, private_key) -> (bytes, bytes, bytes):
    """
    Распаковывает ASN.1 контейнер, расшифровывает и возвращает
    (plaintext, entropy, timestamp).
    """
    container, _ = der_decoder.decode(container_bytes, asn1Spec=RSAContainer())
    ct      = bytes(container.getComponentByName('ciphertext'))
    ts      = bytes(container.getComponentByName('timestamp'))
    ent     = bytes(container.getComponentByName('entropy'))
    plaintext = private_key.decrypt(
        ct,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA512()),
            algorithm=hashes.SHA512(),
            label=None
        )
    )
    return plaintext, ent, ts
