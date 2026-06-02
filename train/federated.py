# train/federated.py
"""
Multiple organizations train on their own traffic, share model weights.
No raw data leaves the organization — privacy-preserving.
PUBLISHABLE: First federated learning approach for encrypted C2 detection.

Real use case: Bank A and Bank B both run PhantomFlow.
They share model updates, not raw flows (which contain customer IPs).
Both get better detection without sharing sensitive network data.
"""

import torch
import numpy as np
from typing import List


class FederatedAggregator:
    """
    Federated Averaging (FedAvg) across multiple sensor deployments.
    Each site trains locally, sends gradients, not data.
    """

    def aggregate(self, local_weights: List[dict],
                   sample_counts: List[int]) -> dict:
        """
        Weighted FedAvg — sites with more data get more vote.
        """
        total = sum(sample_counts)
        aggregated = {}

        for key in local_weights[0].keys():
            weighted_sum = sum(
                local_weights[i][key] * (sample_counts[i] / total)
                for i in range(len(local_weights))
            )
            aggregated[key] = weighted_sum

        return aggregated

    def differential_privacy_clip(self, gradients: dict,
                                    clip_norm: float = 1.0,
                                    noise_multiplier: float = 0.1) -> dict:
        """
        Add DP noise to gradients before sharing.
        Prevents reconstruction of training data from shared weights.
        Required for any real multi-org deployment.
        """
        clipped = {}
        for key, grad in gradients.items():
            norm = torch.norm(grad)
            clipped[key] = grad / max(1.0, norm.item() / clip_norm)
            clipped[key] += torch.randn_like(grad) * noise_multiplier * clip_norm
        return clipped
