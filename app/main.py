from fastapi import FastAPI, Depends
from app.api.routes import auth, keys, crypto, config, rsa  # config и rsa пока оставим
from app.api.routes.auth import get_current_user

app = FastAPI(title="Extended Cryptographic Service")

# регистрация и логин без защиты
app.include_router(auth.router, prefix="/auth")

# все остальные роуты требуют авторизацию
app.include_router(keys.router,   prefix="/keys",   dependencies=[Depends(get_current_user)])
app.include_router(crypto.router, prefix="/crypto", dependencies=[Depends(get_current_user)])
app.include_router(config.router, prefix="/config", dependencies=[Depends(get_current_user)])
app.include_router(rsa.router,    prefix="/rsa",    dependencies=[Depends(get_current_user)])

@app.get("/")
async def root():
    return {"message": "Сервис запущен"}
