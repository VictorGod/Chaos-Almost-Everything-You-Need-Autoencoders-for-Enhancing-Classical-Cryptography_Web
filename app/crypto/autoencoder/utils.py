import numpy as np
import torch

def preprocess(data: bytes) -> torch.Tensor:
    arr = np.frombuffer(data, dtype=np.uint8).astype(np.float32) / 255.0
    return torch.from_numpy(arr).unsqueeze(0)

def postprocess(tensor: torch.Tensor) -> bytes:
    arr = (tensor.squeeze(0).detach().numpy() * 255).astype(np.uint8)
    return arr.tobytes()
