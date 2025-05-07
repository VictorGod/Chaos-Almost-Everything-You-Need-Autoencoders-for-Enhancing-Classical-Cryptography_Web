from typing import Dict, List
from app.crypto.core.entropy import generate_symmetric_key
from app.crypto.core.key_generation import new_key_id

class KeyManager:
    """
    In‐memory хранилище симметричных ключей.
    Ключи генерируются через указанный источник энтропии.
    """

    def __init__(self, entropy_source: str):
        self.entropy_source = entropy_source
        self._store: Dict[str, bytes] = {}

    def create_key(self, length: int = 32) -> str:
        """
        Генерирует симметричный ключ длиной length байт
        и возвращает его UUID.
        """
        key = generate_symmetric_key(length, self.entropy_source)
        key_id = new_key_id()
        self._store[key_id] = key
        return key_id

    def store_key(self, key_id: str, key: bytes) -> None:
        """
        Сохраняет уже сгенерированный ключ под заданным key_id.
        Если ключ с таким key_id уже есть — перезаписывает.
        """
        self._store[key_id] = key

    def get_key(self, key_id: str) -> bytes:
        """
        Возвращает raw‐ключ по его идентификатору.
        Если ключ не найден — бросает KeyError.
        """
        if key_id not in self._store:
            raise KeyError(f"Key '{key_id}' not found")
        return self._store[key_id]

    def delete_key(self, key_id: str) -> None:
        """
        Удаляет ключ по его идентификатору.
        Если ключ не найден — бросает KeyError.
        """
        if key_id not in self._store:
            raise KeyError(f"Key '{key_id}' not found")
        del self._store[key_id]

    def list_keys(self) -> List[str]:
        """
        Возвращает список всех сохранённых идентификаторов ключей.
        """
        return list(self._store.keys())
