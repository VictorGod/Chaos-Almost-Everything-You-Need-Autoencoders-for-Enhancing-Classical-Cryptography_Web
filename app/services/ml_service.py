from typing import Optional
from app.crypto.autoencoder.training import train_autoencoder
from app.crypto.autoencoder.utils import preprocess, postprocess


class MLService:
    def __init__(self, retrain: bool = False):
        self.retrain = retrain
        self.model = None

    def encode(self, data: bytes) -> bytes:
        if self.retrain or self.model is None:
            self.model = train_autoencoder(data)
        # прямой проход
        tensor = preprocess(data)
        with __import__("torch").no_grad():
            code = self.model.encoder(tensor)
            return postprocess(self.model.decoder(code))
