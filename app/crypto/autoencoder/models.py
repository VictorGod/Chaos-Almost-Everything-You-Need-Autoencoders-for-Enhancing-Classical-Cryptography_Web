import torch
from torch import nn

class Autoencoder(nn.Module):
    def __init__(self, input_dim: int = 256, hidden_dim: int = 128, code_dim: int = 32):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, code_dim),
        )
        self.decoder = nn.Sequential(
            nn.Linear(code_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, input_dim),
            nn.Sigmoid(),
        )

    def forward(self, x):
        code = self.encoder(x)
        return self.decoder(code)
