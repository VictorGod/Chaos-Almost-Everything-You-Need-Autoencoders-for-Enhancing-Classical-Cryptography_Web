import binascii

from fastapi import APIRouter, Depends, HTTPException
from cryptography.hazmat.primitives import serialization
import time
from concurrent.futures import ThreadPoolExecutor

from app.api.routes.auth import get_current_user
from app.schemas import (
    RSAKeyOut,
    RSAEncryptRequest,
    RSAEncryptResponse,
    RSADecryptRequest,
    RSADecryptResponse,
    RetrainingResult,
)
from app.crypto.core.enhanced_rsa import (
    generate_enhanced_rsa_keys_from_image,
    rsa_encrypt_with_metadata,
    rsa_decrypt_with_metadata,
)
from app.crypto.autoencoder.retraining import (
    dynamic_retraining_test,
    dynamic_retraining_with_chaos_maps,
)
from app.services.rsa_key_manager import RSAKeyManager
from app.services.deps import encoder, autoencoder

router = APIRouter()
rsa_km = RSAKeyManager()


@router.post("/generate", response_model=RSAKeyOut)
async def rsa_generate(_=Depends(get_current_user)):
    priv, pub, entropy, ts = generate_enhanced_rsa_keys_from_image(encoder)
    key_id = rsa_km.create(priv, pub, entropy, ts)

    return RSAKeyOut(
        key_id=key_id,
        private_key_pem=priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("utf-8"),
        public_key_pem=pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8"),
        entropy=entropy.hex(),
        timestamp=ts.decode("utf-8"),
    )


@router.post("/encrypt", response_model=RSAEncryptResponse)
async def rsa_encrypt(
    req: RSAEncryptRequest,
    _=Depends(get_current_user),
):
    """
    POST /rsa/encrypt
    {
      "key_id": "...",
      "data":   "Hello, RSA!"
    }
    """
    try:
        priv, pub, entropy, ts = rsa_km.get(req.key_id)
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))

    container = rsa_encrypt_with_metadata(
        pub, priv, entropy, ts, req.data.encode("utf-8")
    )
    return RSAEncryptResponse(
        ciphertext_asn1_hex=binascii.hexlify(container).decode("utf-8")
    )


@router.post("/decrypt", response_model=RSADecryptResponse)
async def rsa_decrypt(
    req: RSADecryptRequest,
    _=Depends(get_current_user),
):
    """
    POST /rsa/decrypt
    {
      "key_id": "...",
      "ciphertext_asn1_hex": "..."
    }
    """
    try:
        priv, _, _, _ = rsa_km.get(req.key_id)
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))

    # hex → bytes
    try:
        container = binascii.unhexlify(req.ciphertext_asn1_hex)
    except binascii.Error:
        raise HTTPException(status_code=400, detail="Invalid hex in ciphertext_asn1_hex")

    # Расшифровка (теперь возвращает только plaintext)
    try:
        plaintext_bytes = rsa_decrypt_with_metadata(container, priv)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Попробуем декодировать UTF-8, иначе base64
    try:
        text = plaintext_bytes.decode("utf-8")
    except UnicodeDecodeError:
        import base64
        text = base64.b64encode(plaintext_bytes).decode("ascii")

    return RSADecryptResponse(plaintext=text)


@router.post("/test/random", response_model=RetrainingResult)
async def rsa_test_random(_=Depends(get_current_user)):
    t, mse, kt = dynamic_retraining_test(autoencoder, encoder)
    return RetrainingResult(training_time=t, mse=mse, key_generation_time=kt)


@router.post("/test/chaos", response_model=RetrainingResult)
async def rsa_test_chaos(_=Depends(get_current_user)):
    t, mse = dynamic_retraining_with_chaos_maps(autoencoder, encoder)
    return RetrainingResult(training_time=t, mse=mse)

@router.post("/test/concurrency", response_model=RetrainingResult)
async def rsa_test_concurrency(
    threads: int = 5,
    _=Depends(get_current_user),
):
    """
    Многопоточный тест генерации RSA-ключей:
    спавним `threads` параллельных вызовов `generate_enhanced_rsa_keys_from_image`.
    Возвращаем общее время.
    """
    start = time.time()
    with ThreadPoolExecutor(max_workers=threads) as exe:
        futures = [exe.submit(generate_enhanced_rsa_keys_from_image, encoder) for _ in range(threads)]
        # ждём завершения всех
        for f in futures:
            f.result()
    elapsed = time.time() - start
    return RetrainingResult(training_time=elapsed, mse=0.0, key_generation_time=None)


@router.post("/test/concurrency-chaos", response_model=RetrainingResult)
async def rsa_test_concurrency_chaos(
    threads: int = 5,
    _=Depends(get_current_user),
):
    """
    Многопоточный тест дообучения на хаос-картах:
    запускаем `threads` вызовов `dynamic_retraining_with_chaos_maps` параллельно.
    Возвращаем средние время и средний MSE.
    """
    results = []
    start = time.time()
    with ThreadPoolExecutor(max_workers=threads) as exe:
        futures = [
            exe.submit(dynamic_retraining_with_chaos_maps, autoencoder, encoder)
            for _ in range(threads)
        ]
        for f in futures:
            t, mse = f.result()
            results.append((t, mse))
    total = time.time() - start
    avg_t = sum(r[0] for r in results) / len(results)
    avg_mse = sum(r[1] for r in results) / len(results)
    return RetrainingResult(training_time=avg_t, mse=avg_mse, key_generation_time=None)

