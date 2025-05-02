import threading
from fastapi import FastAPI, Depends
from app.crypto.chaos.dataset import generate_logistic_map_dataset
from app.crypto.utils        import used_images
from app.crypto.autoencoder.retraining import build_autoencoder
from app.crypto.core.enhanced_rsa     import generate_enhanced_rsa_keys_from_image
from app.api.routes import auth, keys, crypto, config, rsa
from app.api.routes.auth import get_current_user

app = FastAPI(title="Extended Cryptographic Service")

# глобальные объекты модели и ключей
model_autoencoder = None
encoder_model      = None
current_private_key = None
current_public_key  = None

@app.on_event("startup")
def startup_event():
    global model_autoencoder, encoder_model, current_private_key, current_public_key

    # 1. Строим автоэнкодер и энкодер
    model_autoencoder, encoder_model = build_autoencoder((28, 28))

    # 2. Немедленно генерируем первую пару ключей,
    # чтобы сервис был готов к шифрованию
    current_private_key, current_public_key, _, _ = \
        generate_enhanced_rsa_keys_from_image(encoder_model, used_images)

    # 3. Запускаем предобучение автоэнкодера в фоне на картах хаоса
    def _pretrain_loop():
        chaos_data = generate_logistic_map_dataset(
            num_images=1000,
            image_size=28,
            r=3.99,
            fixed_initial=False
        )
        model_autoencoder.fit(
            chaos_data, chaos_data,
            epochs=5,
            batch_size=64,
            validation_split=0.1,
            verbose=1
        )
        # По желанию: после предобучения можно обновить current_private_key и т.д.

    threading.Thread(target=_pretrain_loop, daemon=True).start()

# --- Роуты без авторизации ---
app.include_router(auth.router, prefix="/auth")

# --- Все остальные роуты — под JWT ---
app.include_router(keys.router,   prefix="/keys",   dependencies=[Depends(get_current_user)])
app.include_router(crypto.router, prefix="/crypto", dependencies=[Depends(get_current_user)])
app.include_router(config.router, prefix="/config", dependencies=[Depends(get_current_user)])
app.include_router(rsa.router,    prefix="/rsa",    dependencies=[Depends(get_current_user)])

@app.get("/")
async def root():
    return {"message": "Сервис запущен и готов к работе"}
