from typing import Optional, Tuple, Dict, Any

from app.crypto.core.enhanced_rsa import (
    generate_enhanced_rsa_keys_from_image,
    rsa_encrypt_with_metadata,
)
from app.crypto.core.security import secure_decrypt
from app.crypto.encryption import PythonEncryption


class CryptoService:
    def __init__(
        self,
        settings,
        key_manager,
        ml_service,
        encoder,
    ):
        self.settings = settings
        self.km = key_manager
        self.ml = ml_service
        self.encoder = encoder

    def encrypt(
        self,
        key_id: str,
        data: bytes,
        retrain: Optional[bool] = None
    ) -> Tuple[bytes, Dict[str, Any]]:
        # Ассиметричный путь: Chaos-Autoencoder + RSA
        if self.settings.core_type == "rsa":
            priv, pub, sys_ent, ts = generate_enhanced_rsa_keys_from_image(self.encoder)
            container = rsa_encrypt_with_metadata(pub, priv, sys_ent, ts, key_id, data)
            return container, {"algorithm": "rsa_chaos"}

        # Симметричный путь: PythonEncryption (AES-256-CBC) + ML-кодирование
        key = self.km.get_key(key_id)
        do_retrain = retrain if retrain is not None else self.settings.retrain_autoencoder
        if do_retrain:
            self.ml.retrain_model()

        ml_payload = self.ml.encode(data)
        cipher = PythonEncryption(key)
        ciphertext, python_ms = cipher.encrypt(ml_payload)
        entropy = self.ml.entropy(ml_payload)
        return ciphertext, {
            "python_ms": python_ms,
            "ml_entropy": entropy
        }

    def decrypt(
        self,
        key_id: str,
        payload: bytes
    ) -> Tuple[bytes, Dict[str, Any]]:
        # Ассиметричный путь
        if self.settings.core_type == "rsa":
            plaintext = secure_decrypt(payload)
            return plaintext, {}

        # Симметричный путь
        key = self.km.get_key(key_id)
        cipher = PythonEncryption(key)
        ml_plain, python_ms = cipher.decrypt(payload)
        plaintext = self.ml.decode(ml_plain)
        return plaintext, {"python_ms": python_ms}
