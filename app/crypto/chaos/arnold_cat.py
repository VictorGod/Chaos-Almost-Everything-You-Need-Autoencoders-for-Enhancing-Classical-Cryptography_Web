import numpy as np

def arnold_cat_map(img: np.ndarray, iterations: int = 1) -> np.ndarray:
    h, w = img.shape
    result = img.copy()
    for _ in range(iterations):
        tmp = np.zeros_like(result)
        for y in range(h):
            for x in range(w):
                nx = (2 * x + y) % h
                ny = (x + y) % w
                tmp[ny, nx] = result[y, x]
        result = tmp
    return result
