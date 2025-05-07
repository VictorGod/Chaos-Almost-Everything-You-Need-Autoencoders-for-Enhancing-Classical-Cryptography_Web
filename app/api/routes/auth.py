from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import timedelta
from fastapi.security import OAuth2PasswordRequestForm
from app.db import SessionLocal, engine
from app.models import User
from app.utils.auth import hash_password, verify_password, create_access_token, decode_access_token
from app.config import Config
from app.schemas import RegisterRequest, LoginRequest, Token
import jwt
from jwt import ExpiredSignatureError, InvalidTokenError

# При старте создаём таблицы
User.metadata.create_all(bind=engine)

cfg = Config()
router = APIRouter(tags=["auth"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.post("/register", status_code=201)
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == req.username).first()
    if user:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed = hash_password(req.password)
    new_user = User(username=req.username, hashed_password=hashed)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"msg": "User created"}


@router.post("/login", response_model=Token)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),  # fastapi подставит username&password
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    expires = timedelta(minutes=cfg.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        subject=user.username,
        expires_delta=expires,
        secret_key=cfg.JWT_SECRET_KEY,
        algorithm=cfg.JWT_ALGORITHM
    )
    return {"access_token": access_token, "token_type": "bearer"}


from fastapi import Header

async def get_current_user(
    authorization: str = Header(...),
    db: Session = Depends(get_db)
):
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="Invalid authentication scheme")
    try:
        payload = decode_access_token(token, cfg.JWT_SECRET_KEY, [cfg.JWT_ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token payload")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user  # либо возвращайте user.username, user.id, по надобности
