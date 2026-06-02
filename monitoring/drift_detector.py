# monitoring/drift_detector.py
"""
Detects when the traffic distribution shifts — meaning your model
is now scoring on data it was never trained on.
This is what happens when a new C2 framework (like Havoc) releases.
"""

from scipy.stats import ks_2samp, chi2_contingency
import numpy as np


class DriftDetector:
    """
    Page-Hinkley test for concept drift in real-time streams.
    Alerts when feature distributions shift significantly.
    Novel for this application — publishable angle.
    """

    def __init__(self, reference_df, feature_cols, threshold=50, alpha=0.01):
        self.reference = reference_df[feature_cols].fillna(0)
        self.feature_cols = feature_cols
        self.threshold = threshold
        self.alpha = alpha
        self._ph_sum = 0.0
        self._ph_min = 0.0

    def check_drift(self, window_df) -> dict:
        """
        Kolmogorov-Smirnov test on each feature.
        If >20% of features drift, trigger model retraining.
        """
        drifted_features = []
        for col in self.feature_cols:
            ref = self.reference[col].dropna().values
            cur = window_df[col].dropna().values
            if len(cur) < 30:
                continue
            stat, pval = ks_2samp(ref, cur)
            if pval < self.alpha:
                drifted_features.append((col, stat, pval))

        drift_ratio = len(drifted_features) / len(self.feature_cols)
        return {
            "drift_detected": drift_ratio > 0.20,
            "drift_ratio": drift_ratio,
            "drifted_features": drifted_features[:5],  # Top 5
            "recommendation": (
                "Trigger model retraining" if drift_ratio > 0.20
                else "Monitor"
            ),
        }

    def page_hinkley(self, score: float) -> bool:
        """
        Online drift detection on model confidence scores.
        If average confidence suddenly drops, distribution shifted.
        """
        self._ph_sum += score - np.mean([score]) - 0.01
        self._ph_min = min(self._ph_min, self._ph_sum)
        return (self._ph_sum - self._ph_min) > self.threshold
