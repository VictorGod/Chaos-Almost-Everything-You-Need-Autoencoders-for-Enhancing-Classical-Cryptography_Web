import gmpy2
from gmpy2 import mpz

# Размер простого в битах
KEY_BIT_LENGTH = 2048

def generate_prime(seed: bytes) -> int:
    """
    Превращает seed в 2048-битное число и берёт следующее простое.
    """
    si = int.from_bytes(seed, "big") | (1 << (KEY_BIT_LENGTH - 1))
    return int(gmpy2.next_prime(mpz(si)))
