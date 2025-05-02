from app.config import Config
from app.services.configurator import CryptoConfigurator
from app.services.key_manager import KeyManager
from app.services.ml_service import MLService
from app.services.crypto_service import CryptoService

from app.crypto.autoencoder.retraining import build_autoencoder
from app.crypto.chaos.dataset import generate_logistic_map_dataset

# 1) Предобучение autoencoder на логистических картах хаоса
autoencoder, encoder = build_autoencoder((28, 28))
chaos_data = generate_logistic_map_dataset(
    num_images=1000,
    image_size=28,
    r=3.99,
    fixed_initial=False
)
autoencoder.fit(chaos_data, chaos_data, epochs=3, batch_size=64, verbose=0)

# 2) Загружаем настройки из .env
cfg = Config()

# 3) Строим «конструктор» и получаем готовые settings
configurator = (
    CryptoConfigurator()
    .set_core(cfg.CORE_TYPE)
    .set_entropy_source(cfg.ENTROPY_SOURCE)
    .set_retrain(cfg.RETRAIN_AUTOENCODER)
)
settings = configurator.build()

# 4) Инстанцируем вспомогательные сервисы
key_manager = KeyManager(settings.entropy_source)
ml_service = MLService(settings.retrain_autoencoder)

# 5) Инжектируем все в CryptoService
crypto_service = CryptoService(
    settings=settings,
    key_manager=key_manager,
    ml_service=ml_service,
    encoder=encoder
)

__all__ = [
    "cfg",
    "settings",
    "key_manager",
    "ml_service",
    "crypto_service",
    "autoencoder",
    "encoder",
    "configurator",
]
