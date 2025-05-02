import pytest
from app.services.key_manager import KeyManager
from app.services.crypto_service import CryptoService
from app.services.ml_service import MLService

km = KeyManager("system")
ms = MLService(retrain=False)
cs = CryptoService("python", km, ms, "system")

def test_encrypt_decrypt():
    kid = km.create_key()
    data = b"hello world"
    ct, _ = cs.encrypt(kid, data)
    pt, _ = cs.decrypt(kid, ct)
    assert pt == data
