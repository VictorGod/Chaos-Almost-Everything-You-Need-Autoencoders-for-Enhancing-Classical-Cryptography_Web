from dotenv import load_dotenv
load_dotenv()  

from pydantic.v1 import BaseSettings


class Config(BaseSettings):
    CORE_TYPE: str = "python"
    ENTROPY_SOURCE: str = "system"
    RETRAIN_AUTOENCODER: bool = True

    # Настройки JWT
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
