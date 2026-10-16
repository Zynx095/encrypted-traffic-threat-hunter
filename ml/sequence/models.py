"""
Compact sequence models (CPU-friendly).

Stage B  CNN1D  : two 1-D convolutions, masked mean+max pooling, small MLP head.
Stage C  GRUNet : single-layer GRU over packed (unpadded) sequences, last hidden state.
Stage D  Transformer encoder: NOT implemented. Justification (PHASE_10_SEQUENCE_MODELS.md):
         it is only warranted if B/C show a reproducible gain over the information-matched
         tabular baseline; attention would also not be an explanation by itself.
"""
from __future__ import annotations

import torch
from torch import nn
from torch.nn.utils.rnn import pack_padded_sequence


class CNN1D(nn.Module):
    def __init__(self, in_channels: int, hidden: int = 32, dropout: float = 0.1):
        super().__init__()
        self.conv = nn.Sequential(
            nn.Conv1d(in_channels, hidden, kernel_size=5, padding=2), nn.ReLU(),
            nn.Conv1d(hidden, hidden * 2, kernel_size=5, padding=2), nn.ReLU(),
        )
        self.head = nn.Sequential(nn.Dropout(dropout), nn.Linear(hidden * 4, 32), nn.ReLU(), nn.Linear(32, 1))

    def forward(self, x: torch.Tensor, mask: torch.Tensor, lengths: torch.Tensor) -> torch.Tensor:
        h = self.conv(x.transpose(1, 2)).transpose(1, 2)          # (n, L, H)
        m = mask.unsqueeze(-1).float()
        mean = (h * m).sum(1) / m.sum(1).clamp(min=1.0)
        mx = h.masked_fill(m == 0, float("-inf")).max(1).values
        mx = torch.where(torch.isfinite(mx), mx, torch.zeros_like(mx))
        return self.head(torch.cat([mean, mx], dim=1)).squeeze(-1)


class GRUNet(nn.Module):
    def __init__(self, in_channels: int, hidden: int = 48, dropout: float = 0.1):
        super().__init__()
        self.gru = nn.GRU(in_channels, hidden, num_layers=1, batch_first=True)
        self.head = nn.Sequential(nn.Dropout(dropout), nn.Linear(hidden, 1))

    def forward(self, x: torch.Tensor, mask: torch.Tensor, lengths: torch.Tensor) -> torch.Tensor:
        packed = pack_padded_sequence(x, lengths.clamp(min=1).cpu(), batch_first=True, enforce_sorted=False)
        _, h = self.gru(packed)
        return self.head(h[-1]).squeeze(-1)


ARCHITECTURES = {"cnn": CNN1D, "gru": GRUNet}


def parameter_count(model: nn.Module) -> int:
    return int(sum(p.numel() for p in model.parameters() if p.requires_grad))
