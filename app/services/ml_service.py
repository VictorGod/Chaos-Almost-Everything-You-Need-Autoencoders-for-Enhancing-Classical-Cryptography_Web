import hashlib
import numpy as np
from typing import Optional

from app.crypto.chaos.dataset import (
    generate_logistic_map_dataset,
)
from app.crypto.utils import generate_unique_random_images
from app.crypto.autoencoder.retraining import build_autoencoder


class MLService:
    """
    Сервис ML-операций: предобучение/дообучение автоэнкодера
    и генерация 32-байтного ключа AES из латентного вектора.
    """
    def __init__(self, retrain: bool = False, image_size: int = 28):
        self.retrain = retrain
        self.image_size = image_size

        # 1) Строим автоэнкодер и энкодер
        self.autoencoder, self.encoder = build_autoencoder((image_size, image_size))

        # 2) Первичное обучение на хаотических картах
        initial_data = generate_logistic_map_dataset(
            num_images=1000,
            image_size=image_size,
            r=3.99,
            fixed_initial=False
        )
        self.autoencoder.fit(
            initial_data,
            initial_data,
            epochs=5,
            batch_size=64,
            validation_split=0.1,
            verbose=1
        )

    def retrain_model(self, num_images: int = 500, epochs: int = 2) -> None:
        """
        Динамическое дообучение автоэнкодера на новых хаотических картах.
        Если self.retrain=False, метод бездействует.
        """
        if not self.retrain:
            return

        new_data = generate_logistic_map_dataset(
            num_images=num_images,
            image_size=self.image_size,
            r=3.99,
            fixed_initial=False
        )
        # Замораживаем нижние слои, чтобы fine-tune только верхние
        for layer in self.autoencoder.layers[:-3]:
            layer.trainable = False

        self.autoencoder.compile(optimizer='adam', loss='mse')
        self.autoencoder.fit(
            new_data,
            new_data,
            epochs=epochs,
            batch_size=32,
            verbose=1
        )

    def generate_symmetric_key(self) -> bytes:
        """
        Генерация 32-байтного ключа AES-256 из латентного вектора:
        1) Получаем уникальное случайное изображение
        2) Прогоняем его через энкодер
        3) Хэшируем выходной латент вектор в 32-байтный ключ
        """
        img = generate_unique_random_images(
            num_images=1,
            shape=(self.image_size, self.image_size, 1)
        )[0]
        latent = self.encoder.predict(img[np.newaxis, ...], verbose=0)[0]
        # sha256(latent_bytes) → 32 байта
        return hashlib.sha256(latent.tobytes()).digest()
