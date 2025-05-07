from typing import Optional, Tuple, Dict, Any
from app.crypto.core.enhanced_rsa import (
    generate_enhanced_rsa_keys_from_image,
    rsa_encrypt_with_metadata,
)
from app.crypto.core.security import secure_decrypt
from app.crypto.encryption import PythonEncryption
from app.services.key_manager import KeyManager
from app.services.ml_service import MLService


class CryptoService:
    def __init__(
        self,
        settings,
        key_manager: KeyManager,
        ml_service: MLService,
        encoder,
    ):
        self.settings = settings
        self.km       = key_manager
        self.ml       = ml_service
        self.encoder  = encoder

    def encrypt(
        self,
        key_id: str,
        data: bytes,
        retrain: Optional[bool] = None
    ) -> Tuple[bytes, Dict[str, Any]]:
        # --- Ассиметричный путь (Chaos + RSA) ---
        if self.settings.core_type == "rsa":
            priv, pub, sys_ent, ts = generate_enhanced_rsa_keys_from_image(self.encoder)
            container = rsa_encrypt_with_metadata(pub, priv, sys_ent, ts, key_id, data)
            return container, {"algorithm": "rsa_chaos"}

        # --- Симметричный путь (AES-256-CBC + ML-кодирование ключа) ---
        do_retrain = retrain if retrain is not None else self.settings.retrain_autoencoder
        if do_retrain:
            self.ml.retrain_model()

        # создаём 32-байтный ключ через MLService
        key_bytes = self.ml.generate_symmetric_key()

        # сохраняем его в KeyManager под данным key_id
        if hasattr(self.km, "store_key"):
            # если вы добавили store_key в KeyManager
            self.km.store_key(key_id, key_bytes)
        else:
            # fallback — прямое обновление внутреннего словаря
            self.km._store[key_id] = key_bytes

        # шифруем и возвращаем шифротекст + IV
        cipher = PythonEncryption(key_bytes)
        ciphertext, metadata = cipher.encrypt(data)
        return ciphertext, metadata

    def decrypt(
        self,
        key_id: str,
        payload: bytes,
        metadata: Dict[str, Any]
    ) -> Tuple[bytes, Dict[str, Any]]:
        # --- Ассиметричный путь ---
        if self.settings.core_type == "rsa":
            plaintext = secure_decrypt(payload)
            return plaintext, {}

        # --- Симметричный путь ---
        key_bytes = self.km.get_key(key_id)
        cipher = PythonEncryption(key_bytes)
        plaintext, _ = cipher.decrypt(payload, metadata)
        return plaintext, {}
