def validate_key_length(length: int):
    if length not in (16, 24, 32):
        raise ValueError("Unsupported key length, use 16, 24 or 32 bytes")
