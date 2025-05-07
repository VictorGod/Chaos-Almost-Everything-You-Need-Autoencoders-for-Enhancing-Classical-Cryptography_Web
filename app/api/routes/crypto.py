import base64
from fastapi import APIRouter, Depends, HTTPException
from app.schemas import EncryptRequest, EncryptResponse, DecryptRequest, DecryptResponse
from app.services.deps import crypto_service
from app.api.routes.auth import get_current_user

router = APIRouter()

@router.post("/encrypt", response_model=EncryptResponse)
async def encrypt_endpoint(
    req: EncryptRequest,
    _ = Depends(get_current_user),
):
    data_bytes = req.data.encode("utf-8")
    try:
        ct_bytes, metrics = crypto_service.encrypt(
            key_id=req.key_id,
            data=data_bytes,
            retrain=req.retrain_autoencoder,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return EncryptResponse(
        ciphertext=base64.b64encode(ct_bytes).decode("utf-8"),
        metrics=metrics,
    )

@router.post("/decrypt", response_model=DecryptResponse)
async def decrypt_endpoint(
    req: DecryptRequest,
    _=Depends(get_current_user),
):
    try:
        # 1) раскодируем base64-текст
        ct = base64.b64decode(req.ciphertext)
        # 2) передадим вместе с ним metadata (сюда входит IV)
        pt_bytes, metrics = crypto_service.decrypt(
            key_id=req.key_id,
            payload=ct,
            metadata=req.metadata,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    # 3) вернем клиенту расшифрованный текст и ту же metadata (IV) на всякий случай
    return DecryptResponse(
        plaintext=pt_bytes.decode("utf-8"),
        metrics=metrics,
        metadata=req.metadata,
    )