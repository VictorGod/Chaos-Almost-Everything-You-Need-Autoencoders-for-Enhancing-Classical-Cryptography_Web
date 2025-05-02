import binascii
from fastapi import APIRouter, Depends, HTTPException
from app.api.routes.auth import get_current_user
from app.services.deps import encoder, autoencoder
from app.crypto.core.enhanced_rsa import (
    generate_enhanced_rsa_keys_from_image,
    rsa_encrypt_with_metadata
)
from app.crypto.core.security import secure_decrypt
from app.crypto.autoencoder.retraining import (
    dynamic_retraining_test,
    dynamic_retraining_with_chaos_maps
)
from app.schemas import (
    RSAKeyOut,
    RSADecryptRequest,
    RSADecryptResponse,
    RetrainingResult
)
from cryptography.hazmat.primitives import serialization

router = APIRouter()

@router.post("/generate", response_model=RSAKeyOut)
async def rsa_generate(_=Depends(get_current_user)):
    # 1) Сгенерировать ключи
    priv_key, pub_key, system_entropy, timestamp = generate_enhanced_rsa_keys_from_image(encoder)

    # 2) PEM → UTF-8 строки
    private_pem = priv_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ).decode("utf-8")
    public_pem = pub_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    # 3) Энтропию и timestamp тоже приводим к строкам
    entropy_hex = binascii.hexlify(system_entropy).decode("utf-8")
    ts_str = timestamp.decode("utf-8") if isinstance(timestamp, (bytes, bytearray)) else str(timestamp)

    return RSAKeyOut(
        private_key_pem=private_pem,
        public_key_pem=public_pem,
        entropy=entropy_hex,
        timestamp=ts_str
    )

@router.post("/encrypt")
async def rsa_encrypt(
    plaintext: str,
    key_id: str,
    _=Depends(get_current_user),
):
    # Получаем свежие ключи (либо можно брать по key_id из key_manager)
    priv_key, pub_key, system_entropy, timestamp = generate_enhanced_rsa_keys_from_image(encoder)

    # Упаковать в ASN.1 контейнер
    container = rsa_encrypt_with_metadata(
        pub_key, priv_key, system_entropy, timestamp, key_id, plaintext.encode("utf-8")
    )
    # Байты → hex-строка
    ciphertext_hex = binascii.hexlify(container).decode("utf-8")
    return {"ciphertext_asn1_hex": ciphertext_hex}

@router.post("/decrypt", response_model=RSADecryptResponse)
async def rsa_decrypt(
    req: RSADecryptRequest,
    _=Depends(get_current_user),
):
    try:
        # hex → байты
        container = binascii.unhexlify(req.ciphertext_asn1_hex)
        # Распаковать
        plaintext_bytes = secure_decrypt(None, container)  # <-- здесь None замените на реальный приватный ключ из key_manager
        plaintext = plaintext_bytes.decode("utf-8")
        return RSADecryptResponse(plaintext=plaintext)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/test/random", response_model=RetrainingResult)
async def rsa_test_random(_=Depends(get_current_user)):
    # тест динамического дообучения на случайных изображениях
    training_time, mse, key_gen_time = dynamic_retraining_test(autoencoder, encoder)
    return RetrainingResult(
        training_time=training_time,
        mse=mse,
        key_generation_time=key_gen_time
    )

@router.post("/test/chaos", response_model=RetrainingResult)
async def rsa_test_chaos(_=Depends(get_current_user)):
    # тест дообучения на хаос-картах
    training_time, mse = dynamic_retraining_with_chaos_maps(autoencoder, encoder)
    return RetrainingResult(
        training_time=training_time,
        mse=mse
    )
