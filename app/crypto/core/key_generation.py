import uuid

def new_key_id() -> str:
    """
    Генерация UUID для идентификатора ключа.
    """
    return str(uuid.uuid4())
