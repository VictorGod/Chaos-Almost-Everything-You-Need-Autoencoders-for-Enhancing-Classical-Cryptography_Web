import os
import base64
from typing import Tuple, Dict
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend

class PythonEncryption:
    def __init__(self, key: bytes):
        # Ожидаем ключ ровно 32 байта для AES-256
        self.key = key

    def encrypt(self, plaintext: bytes) -> Tuple[bytes, Dict[str, str]]:
        """
        Шифрует AES-256-CBC:
        - plaintext: сырые байты
        Возвращает:
        - ciphertext: сырые байты шифротекста
        - metadata: словарь с base64-строкой IV
        """
        iv = os.urandom(16)
        padder = sym_padding.PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()

        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()

        return ciphertext, {"iv": base64.b64encode(iv).decode("utf-8")}

    def decrypt(self, ciphertext: bytes, metadata: Dict[str, str]) -> Tuple[bytes, Dict[str, str]]:
        """
        Дешифрует AES-256-CBC:
        - ciphertext: сырые байты шифротекста
        - metadata: словарь, где metadata["iv"] = base64-строка IV
        Возвращает:
        - plaintext: сырые байты без паддинга
        - metadata обратно (можно переиспользовать)
        """
        iv = base64.b64decode(metadata["iv"])
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = sym_padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded) + unpadder.finalize()

        return plaintext, metadata
