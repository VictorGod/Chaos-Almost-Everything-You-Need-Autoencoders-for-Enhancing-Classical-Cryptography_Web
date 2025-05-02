import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from app.crypto.core.math_utils import shannon_entropy


class PythonEncryption:
    """
    Реализация AES-CBC шифрования/дешифрования с замером времени и
    энтропии результата.
    """

    def __init__(self, key: bytes):
        self.key = key

    def encrypt(self, data: bytes) -> (bytes, float, float):
        """
        Шифрует data, возвращает:
         - ciphertext (iv + ct)
         - время выполнения в миллисекундах
         - энтропию ciphertext
        """
        # В prod-окружении iv лучше os.urandom(AES.block_size)
        iv = AES.block_size * b'\x00'
        cipher = AES.new(self.key, AES.MODE_CBC, iv)

        start = time.perf_counter()
        ct = cipher.encrypt(pad(data, AES.block_size))
        elapsed_ms = (time.perf_counter() - start) * 1000

        ent = shannon_entropy(iv + ct)
        return iv + ct, elapsed_ms, ent

    def decrypt(self, ciphertext: bytes) -> (bytes, float):
        """
        Дешифрует ciphertext, возвращает:
         - расшифрованные данные
         - время выполнения в миллисекундах
        """
        iv = ciphertext[:AES.block_size]
        ct = ciphertext[AES.block_size:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)

        start = time.perf_counter()
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        elapsed_ms = (time.perf_counter() - start) * 1000

        return pt, elapsed_ms
