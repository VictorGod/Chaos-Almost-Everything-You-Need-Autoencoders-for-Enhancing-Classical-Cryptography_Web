from typing import Dict
from app.crypto.core.entropy import generate_symmetric_key
from app.crypto.core.key_generation import new_key_id


class KeyManager:
    def __init__(self, entropy_source: str):
        self.entropy_source = entropy_source
        self._store: Dict[str, bytes] = {}

    def create_key(self, length: int = 32) -> str:
        """
        Генерирует симметричный ключ указанной длины
        и возвращает его UUID.
        """
        key = generate_symmetric_key(length, self.entropy_source)
        kid = new_key_id()
        self._store[kid] = key
        return kid

    def get_key(self, key_id: str) -> bytes:
        """
        Возвращает raw-ключ по его идентификатору
        или None, если такого нет.
        """
        return self._store.get(key_id)
