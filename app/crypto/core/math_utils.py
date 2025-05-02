from math import log2
from typing import Tuple

def egcd(a: int, b: int) -> Tuple[int, int, int]:
    if a == 0:
        return b, 0, 1
    g, y, x = egcd(b % a, a)
    return g, x - (b // a) * y, y

def modinv(a: int, m: int) -> int:
    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception('Multiplicative inverse does not exist')
    return x % m

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {b: data.count(b) for b in set(data)}
    return -sum((cnt/len(data)) * log2(cnt/len(data)) for cnt in freq.values())
