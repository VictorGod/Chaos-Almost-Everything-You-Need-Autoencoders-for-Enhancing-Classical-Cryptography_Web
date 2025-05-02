import os
from ..chaos.logistic_map import generate_logistic_map_image

def get_entropy(length: int, source: str = "system") -> bytes:
    """
    Источник энтропии: 'system', 'logistic', 'arnold'
    """
    if source == "logistic":
        # Берём одно хаотическое значение, масштабируем и повторяем
        img = generate_logistic_map_image(image_size=1, initial_value=0.5, r=3.99)
        b = int(img.flat[0] * 255) & 0xFF
        return bytes([b] * length)
    elif source == "arnold":
        # пока просто системный + можно потом трансформировать картинку
        return os.urandom(length)
    else:
        return os.urandom(length)

def generate_symmetric_key(length: int = 32, source: str = "system") -> bytes:
    return get_entropy(length, source)
