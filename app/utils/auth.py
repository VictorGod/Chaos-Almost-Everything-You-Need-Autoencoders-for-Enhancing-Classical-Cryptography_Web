from passlib.context import CryptContext
from datetime import datetime, timedelta
import jwt
import os

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_access_token(
    subject: str,
    expires_delta: timedelta,
    secret_key: str,
    algorithm: str
) -> str:
    to_encode = {"sub": subject, "exp": datetime.utcnow() + expires_delta}
    return jwt.encode(to_encode, secret_key, algorithm=algorithm)

def decode_access_token(token: str, secret_key: str, algorithms: list[str]) -> dict:
    return jwt.decode(token, secret_key, algorithms=algorithms)
