import numpy as np

def logistic_map(x: float, r: float = 3.99) -> float:
    return r * x * (1 - x)

def generate_logistic_map_image(
    image_size: int = 28,
    initial_value: float = 0.4,
    r: float = 3.99
) -> np.ndarray:
    iterations = image_size * image_size
    x = initial_value
    seq = []
    for _ in range(iterations):
        x = logistic_map(x, r)
        seq.append(x)
    img = np.array(seq).reshape((image_size, image_size))
    return img
