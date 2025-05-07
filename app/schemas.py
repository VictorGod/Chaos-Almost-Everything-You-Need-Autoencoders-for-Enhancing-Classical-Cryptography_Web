from pydantic import BaseModel
from typing import Any, Dict, Optional
from datetime import datetime

# --- Ключи и криптография ---

class KeyOut(BaseModel):
    key_id: str
    algorithm: str
    length: int

class EncryptRequest(BaseModel):
    key_id: str
    data: str
    retrain_autoencoder: Optional[bool] = None

class EncryptResponse(BaseModel):
    ciphertext: str
    metrics: Dict[str, Any]

class DecryptRequest(BaseModel):
    key_id: str
    ciphertext: str
    metadata: Dict[str, str]  

class DecryptResponse(BaseModel):
    plaintext: str
    metrics: Dict[str, Any]
    metadata: Dict[str, Any]

class TestResult(BaseModel):
    python_ms: float
    ml_ms: float

# --- Конфигуратор ---

class ConfigOptions(BaseModel):
    core_type: str
    entropy_source: str
    retrain_autoencoder: bool

class ConfigUpdate(BaseModel):
    core_type: Optional[str] = None
    entropy_source: Optional[str] = None
    retrain_autoencoder: Optional[bool] = None

# --- RSA / Chaos-RSA ---

class RSAKeyOut(BaseModel):
    private_key_pem: str
    public_key_pem: str
    entropy: bytes
    timestamp: datetime

class RSADecryptRequest(BaseModel):
    ciphertext_asn1_hex: str

class RSADecryptResponse(BaseModel):
    plaintext: str

class RetrainingResult(BaseModel):
    training_time: float
    mse: float
    key_generation_time: Optional[float] = None

# --- Аутентификация ---

class RegisterRequest(BaseModel):
    username: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

# --- Вариант ответа по RSA без ASN.1, если нужен простой формат ---

class RSAKeyResponse(BaseModel):
    private_key: str   # PEM в виде строки
    public_key:  str   # PEM в виде строки
    entropy:     str   # system_entropy.hex()
    timestamp:   str   # timestamp.decode('utf-8')
