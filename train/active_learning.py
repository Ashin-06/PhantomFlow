# train/active_learning.py
"""
Instead of randomly sampling for analyst review,
actively select the flows the model is MOST UNCERTAIN about.
This maximizes analyst value — they label the most informative samples.
Reduces labeling cost by 5-10x to reach same model performance.
PUBLISHABLE: Active learning for network threat detection.
"""

import numpy as np
from typing import List


class UncertaintySampler:
    """
    Query strategy: entropy-based uncertainty sampling.
    Select flows where the ensemble is most uncertain (entropy near max).
    These are the flows where analyst labels add most information.
    """

    def select_for_labeling(self, probabilities: np.ndarray,
                             n_samples: int = 100) -> List[int]:
        """
        probabilities: (n_flows, n_classes) array of class probabilities.
        Returns indices of n_samples most uncertain flows.
        """
        # Shannon entropy of prediction distribution
        entropy = -np.sum(
            probabilities * np.log2(probabilities + 1e-9),
            axis=1
        )
        # Highest entropy = most uncertain
        return np.argsort(entropy)[::-1][:n_samples].tolist()

    def select_diverse_uncertain(self, probabilities: np.ndarray,
                                  features: np.ndarray,
                                  n_samples: int = 100) -> List[int]:
        """
        Diversity sampling: pick uncertain AND diverse samples.
        Prevents all selected samples being from the same flow cluster.
        """
        from sklearn.cluster import KMeans
        entropy = -np.sum(probabilities * np.log2(probabilities + 1e-9), axis=1)

        # Take top 500 uncertain, then cluster them, pick one per cluster
        top_uncertain = np.argsort(entropy)[::-1][:500]
        X_uncertain = features[top_uncertain]

        kmeans = KMeans(n_clusters=n_samples, random_state=42, n_init=10)
        kmeans.fit(X_uncertain)

        # Pick the sample closest to each cluster center
        selected = []
        for center in kmeans.cluster_centers_:
            dists = np.linalg.norm(X_uncertain - center, axis=1)
            selected.append(top_uncertain[np.argmin(dists)])

        return selected
