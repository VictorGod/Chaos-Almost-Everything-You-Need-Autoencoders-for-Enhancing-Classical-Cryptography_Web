import os
import numpy as np
from math import log2
import gmpy2
from gmpy2 import mpz

KEY_BIT_LENGTH = 2048
used_images = set()

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception('Multiplicative inverse does not exist')
    return x % m

def logistic_map(x, r=3.99):
    return r * x * (1 - x)

def generate_unique_random_images(num_images, shape=(28,28,1), used_images=used_images):
    new = []
    while len(new) < num_images:
        b = os.urandom(np.prod(shape))
        img = np.frombuffer(b, dtype=np.uint8).reshape(shape)/255.0
        h = hash(img.tobytes())
        if h not in used_images:
            used_images.add(h)
            new.append(img)
    return np.array(new)

def shannon_entropy(data: bytes):
    if not data:
        return 0
    freq = {b: data.count(b) for b in set(data)}
    entropy = -sum((c/len(data))*log2(c/len(data)) for c in freq.values())
    return entropy
