from fastapi import APIRouter, HTTPException
from app.schemas import KeyOut
from app.services.deps import key_manager

router = APIRouter()

@router.post("/", response_model=KeyOut)
async def create_key():
    kid = key_manager.create_key()
    return KeyOut(key_id=kid, algorithm="AES-256-CBC", length=32)

@router.get("/{key_id}", response_model=KeyOut)
async def get_key(key_id: str):
    key = key_manager.get_key(key_id)
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    return KeyOut(key_id=key_id, algorithm="AES-256-CBC", length=len(key))
