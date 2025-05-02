from fastapi import APIRouter, Depends
from app.services.deps import configurator, settings, key_manager, ml_service, crypto_service
from app.schemas import ConfigOptions, ConfigUpdate
from app.api.routes.auth import get_current_user

router = APIRouter()

@router.get("/", response_model=ConfigOptions)
async def get_config(_=Depends(get_current_user)):
    return settings

@router.post("/", response_model=ConfigOptions)
async def update_config(upd: ConfigUpdate, _=Depends(get_current_user)):
    if upd.core_type    is not None: configurator.set_core(upd.core_type)
    if upd.entropy_source is not None: configurator.set_entropy_source(upd.entropy_source)
    if upd.retrain_autoencoder is not None: configurator.set_retrain(upd.retrain_autoencoder)

    new_settings = configurator.build()

    # Monkey-patch сервисов в deps
    import app.services.deps as deps
    deps.settings        = new_settings
    deps.key_manager     = deps.KeyManager(new_settings.entropy_source)
    deps.ml_service      = deps.MLService(new_settings.retrain_autoencoder)
    deps.crypto_service  = deps.CryptoService(
        core_type=new_settings.core_type,
        key_manager=deps.key_manager,
        ml_service=deps.ml_service,
        entropy_source=new_settings.entropy_source
    )
    return new_settings
