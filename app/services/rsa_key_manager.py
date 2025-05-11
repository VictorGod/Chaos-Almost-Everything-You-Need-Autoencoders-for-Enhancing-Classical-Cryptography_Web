from uuid import uuid4
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import rsa

class RSAKeyManager:
    def __init__(self):
        self._store: dict[str, Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey, bytes, bytes]] = {}

    def create(self, priv, pub, entropy, ts) -> str:
        key_id = str(uuid4())
        self._store[key_id] = (priv, pub, entropy, ts)
        return key_id

    def get(self, key_id):
        if key_id not in self._store:
            raise KeyError(f"RSA key_id `{key_id}` not found")
        return self._store[key_id]
