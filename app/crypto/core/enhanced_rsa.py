import os
import numpy as np
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

import psutil
import gmpy2
from gmpy2 import mpz

import hmac
import hashlib

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from pyasn1.type import univ, namedtype
from pyasn1.codec.der import encoder as der_encoder, decoder as der_decoder

from app.crypto.utils import generate_unique_random_images
from app.crypto.core.prime import generate_prime, KEY_BIT_LENGTH
from app.crypto.core.math_utils import modinv

# -----------------------------------------------------------------------------
# ASN.1-контейнер с полем HMAC для целостности
# -----------------------------------------------------------------------------
class RSAContainer(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('ciphertext', univ.OctetString()),
        namedtype.NamedType('timestamp',   univ.OctetString()),
        namedtype.NamedType('entropy',     univ.OctetString()),
        namedtype.NamedType('n',           univ.Integer()),
        namedtype.NamedType('e',           univ.Integer()),
        namedtype.NamedType('hmac',        univ.OctetString()),
    )

# -----------------------------------------------------------------------------
# Генерация RSA-ключей на основе латента автоэнкодера + системной энтропии
# -----------------------------------------------------------------------------
def generate_enhanced_rsa_keys_from_image(encoder, used_images=None):
    if used_images is None:
        used_images = set()

    # 1) случайное уникальное изображение → латент
    image = generate_unique_random_images(
        1, shape=(28, 28, 1), used_images=used_images
    )[0]
    latent = encoder.predict(image[np.newaxis, ...], verbose=0)

    # 2) собираем энтропию
    system_entropy = os.urandom(32)
    timestamp      = datetime.utcnow().isoformat().encode('utf-8')
    cpu_usage      = str(psutil.cpu_percent(interval=0.01)).encode('utf-8')
    combined       = latent.tobytes() + system_entropy + timestamp + cpu_usage

    # 3) KDF → 64 байта
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=64,
        salt=system_entropy[:16],
        iterations=5000,
        backend=default_backend()
    )
    derived = kdf.derive(combined)

    # 4) семена для p и q via SHA256
    h_p = hashes.Hash(hashes.SHA256(), backend=default_backend())
    h_p.update(derived[:32] + b"p")
    seed_p = h_p.finalize()

    h_q = hashes.Hash(hashes.SHA256(), backend=default_backend())
    h_q.update(derived[32:] + b"q")
    seed_q = h_q.finalize()

    # 5) параллельная генерация p, q
    with ThreadPoolExecutor(max_workers=2) as ex:
        p = int(ex.submit(generate_prime, seed_p).result())
        q = int(ex.submit(generate_prime, seed_q).result())
    if p == q:
        q = int(gmpy2.next_prime(mpz(q + 2)))

    # 6) считаем n, phi и обратный к e
    n   = p * q
    e   = 65537
    phi = (p - 1) * (q - 1)
    d   = modinv(e, phi)

    # 7) строим объекты из cryptography
    priv_nums   = rsa.RSAPrivateNumbers(
        p, q, d,
        d % (p - 1),
        d % (q - 1),
        modinv(q, p),
        rsa.RSAPublicNumbers(e, n)
    )
    private_key = priv_nums.private_key(default_backend())
    public_key  = private_key.public_key()

    return private_key, public_key, system_entropy, timestamp

# -----------------------------------------------------------------------------
# Шифрование → ASN.1 + HMAC
# -----------------------------------------------------------------------------
def rsa_encrypt_with_metadata(
    public_key,
    private_key,      # private_key пока не используется, но может пригодиться
    entropy: bytes,
    timestamp: bytes,
    plaintext: bytes
) -> bytes:
    # 1) RSA-OAEP
    ct = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA512()),
            algorithm=hashes.SHA512(),
            label=None
        )
    )

    # 2) заполняем ASN.1-контейнер
    container = RSAContainer()
    container.setComponentByName('ciphertext', ct)
    container.setComponentByName('timestamp',   timestamp)
    container.setComponentByName('entropy',     entropy)
    nums = public_key.public_numbers()
    container.setComponentByName('n', nums.n)
    container.setComponentByName('e', nums.e)

    # 3) HMAC-SHA256 по ciphertext, ключ = system_entropy
    mac = hmac.new(entropy, ct, hashlib.sha256).digest()
    container.setComponentByName('hmac', mac)

    # 4) DER-кодируем
    return der_encoder.encode(container)

# -----------------------------------------------------------------------------
# Расшифровка + проверка HMAC
# -----------------------------------------------------------------------------
def rsa_decrypt_with_metadata(
    container_bytes: bytes,
    private_key
) -> bytes:
    # 1) извлекаем поля из ASN.1
    container, _ = der_decoder.decode(container_bytes, asn1Spec=RSAContainer())
    ct       = bytes(container.getComponentByName('ciphertext'))
    ent      = bytes(container.getComponentByName('entropy'))
    recv_mac = bytes(container.getComponentByName('hmac'))

    # 2) проверяем HMAC
    calc_mac = hmac.new(ent, ct, hashlib.sha256).digest()
    if not hmac.compare_digest(calc_mac, recv_mac):
        raise ValueError("HMAC check failed")

    # 3) RSA-дешифрование
    pt = private_key.decrypt(
        ct,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA512()),
            algorithm=hashes.SHA512(),
            label=None
        )
    )
    return pt
