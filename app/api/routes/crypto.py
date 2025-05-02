from fastapi import APIRouter, HTTPException
from app.schemas import EncryptRequest, EncryptResponse, DecryptRequest, DecryptResponse, TestResult
from app.services.deps import crypto_service

router = APIRouter()

@router.post("/encrypt", response_model=EncryptResponse)
async def encrypt(req: EncryptRequest):
    try:
        data = req.data.encode()
        ct, metrics = crypto_service.encrypt(req.key_id, data, req.retrain_autoencoder)
        return EncryptResponse(ciphertext=ct.hex(), metrics=metrics)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/decrypt", response_model=DecryptResponse)
async def decrypt(req: DecryptRequest):
    try:
        ct = bytes.fromhex(req.ciphertext)
        pt, metrics = crypto_service.decrypt(req.key_id, ct)
        return DecryptResponse(plaintext=pt.decode(), metrics=metrics)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/compare", response_model=TestResult)
async def compare(req: EncryptRequest):
    try:
        data = req.data.encode()
        res = crypto_service.compare(req.key_id, data)
        return TestResult(**res)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
