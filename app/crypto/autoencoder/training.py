import torch
from torch import optim
from torch.utils.data import DataLoader, TensorDataset
from .models import Autoencoder
from .utils import preprocess

def train_autoencoder(data: bytes, epochs: int = 5, lr: float = 1e-3) -> Autoencoder:
    model = Autoencoder(input_dim=len(data))
    tensor = preprocess(data)
    dataset = TensorDataset(tensor, tensor)
    loader = DataLoader(dataset, batch_size=1, shuffle=True)
    optimizer = optim.Adam(model.parameters(), lr=lr)
    criterion = torch.nn.MSELoss()
    model.train()
    for _ in range(epochs):
        for x, _ in loader:
            optimizer.zero_grad()
            recon = model(x)
            loss = criterion(recon, x)
            loss.backward()
            optimizer.step()
    return model
