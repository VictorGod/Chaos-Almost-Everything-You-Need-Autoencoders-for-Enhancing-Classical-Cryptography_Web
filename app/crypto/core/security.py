import time
import random
from cryptography.hazmat.primitives import hashes, hmac
from pyasn1.codec.der.decoder import decode as der_decode
from .enhanced_rsa import RSAContainer
from cryptography.hazmat.backends import default_backend

TARGET_TIME = 0.1  # сек

def secure_decrypt(container: bytes, private_key=None) -> bytes:
    start = time.time()

    asn1, _ = der_decode(container, asn1Spec=RSAContainer())
    ct = bytes(asn1.getComponentByName('ciphertext'))
    tag = bytes(asn1.getComponentByName('hmac'))

    key = bytes(asn1.getComponentByName('timestamp'))[:16]
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(ct)
    h.verify(tag)

    # Если private_key не передан, то подразумевается, что его берут из контекста
    priv = private_key
    if priv is None:
        raise ValueError("Private key is required for RSA decryption")

    nums = priv.private_numbers()
    n, e, d = nums.public_numbers.n, nums.public_numbers.e, nums.d

    r = random.randrange(2, n-1)
    r_e = pow(r, e, n)
    c_int = int.from_bytes(ct, 'big')
    blinded = (r_e * c_int) % n

    m1 = pow(blinded, d, n)
    r_inv = pow(r, -1, n)
    m_int = (m1 * r_inv) % n
    m_len = (m_int.bit_length() + 7)//8
    plaintext = m_int.to_bytes(m_len, 'big')

    elapsed = time.time() - start
    if elapsed < TARGET_TIME:
        time.sleep(TARGET_TIME - elapsed)

    return plaintext
