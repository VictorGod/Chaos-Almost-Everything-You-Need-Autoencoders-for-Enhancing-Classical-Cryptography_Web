import torch
from .training import train_autoencoder
from .utils import preprocess, postprocess
from .models import Autoencoder

def encode_data(
    data: bytes,
    retrain: bool = False,
    model: Autoencoder = None
) -> (bytes, Autoencoder):
    """
    Кодирует и тут же декодирует data через автоэнкодер.
    Если retrain=True или model=None — сначала перетренирует модель.
    Возвращает (decoded_bytes, model).
    """
    if retrain or model is None:
        model = train_autoencoder(data)
    with torch.no_grad():
        tensor = preprocess(data)
        recon = model(tensor)
    return postprocess(recon), model
