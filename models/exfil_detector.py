# models/exfil_detector.py
"""
Detects data exfiltration by modeling upload burst patterns.
Uses a combination of:
  - Statistical thresholding on byte ratios
  - Isolation Forest for anomalous upload sessions
  - Gradient boosting for sustained exfil classification
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, GradientBoostingClassifier
from sklearn.preprocessing import RobustScaler
from sklearn.metrics import classification_report
import joblib
from typing import Dict, List, Optional, Tuple


class ExfilDetector:
    """
    Two-stage exfiltration detector:
    Stage 1: Isolation Forest flags statistically anomalous upload patterns
    Stage 2: GBM classifies confirmed anomalies as exfil vs. legitimate transfer
    
    Catches:
    - DNS exfiltration (large DNS query volume, high entropy)
    - HTTPS exfiltration (high bytes_ratio, abnormal upload bursts)
    - ICMP/ping tunneling
    - Slow-and-low exfiltration (extended low-bandwidth uploads)
    """

    EXFIL_FEATURES = [
        # Volume features
        "bytes_ratio",              # > 5 is suspicious
        "orig_bytes",
        "resp_bytes",
        "total_bytes",
        "bytes_per_sec",
        "pkts_per_sec",
        # Timing
        "duration_s",
        "iat_mean_ms",
        "iat_cv",
        # Size
        "large_pkt_ratio",          # Large packets = bulk data transfer
        "pkt_size_entropy",
        # Context
        "connection_count_1m",
        "connection_count_5m",
        # DNS (if applicable)
        "dns_shannon_entropy",
        "dns_query_len",
    ]

    def __init__(self):
        # Stage 1: Unsupervised anomaly detection
        self.iso_forest = IsolationForest(
            n_estimators=200,
            contamination=0.01,     # 1% expected anomaly rate
            random_state=42,
            n_jobs=-1,
        )
        
        # Stage 2: Supervised classification
        self.classifier = GradientBoostingClassifier(
            n_estimators=300,
            max_depth=5,
            learning_rate=0.05,
            subsample=0.8,
            random_state=42,
        )
        
        self.scaler = RobustScaler()  # Robust to outliers in network data
        self.trained_supervised = False

    def fit_unsupervised(self, df_benign: pd.DataFrame):
        """
        Train Isolation Forest on benign traffic only.
        No labels required — models normal upload behavior.
        """
        X = self.scaler.fit_transform(
            df_benign[self.EXFIL_FEATURES].fillna(0)
        )
        self.iso_forest.fit(X)
        print(f"[Exfil] Isolation Forest trained on {len(df_benign)} benign flows")

    def fit_supervised(self, df_labeled: pd.DataFrame):
        """
        Train GBM classifier on labeled data (requires both benign + exfil).
        Call after fit_unsupervised.
        """
        X = self.scaler.transform(
            df_labeled[self.EXFIL_FEATURES].fillna(0)
        )
        y = df_labeled["label"].values  # 0=benign, 1=exfil
        
        self.classifier.fit(X, y)
        self.trained_supervised = True
        
        y_pred = self.classifier.predict(X)
        print("\n=== Exfil Classifier (training) ===")
        print(classification_report(y, y_pred,
              target_names=["benign", "exfil"]))

    def predict(self, features: Dict) -> Dict:
        """
        Two-stage prediction for a single flow.
        Returns detailed result including anomaly score and confidence.
        """
        raw_values = []
        for k in self.EXFIL_FEATURES:
            val = features.get(k, 0.0)
            if val is None or (isinstance(val, float) and np.isnan(val)):
                raw_values.append(0.0)
            else:
                raw_values.append(float(val))
        row = np.array([raw_values], dtype=np.float32)
        X = self.scaler.transform(row)
        
        # Stage 1: Anomaly score (-1=anomaly, +1=normal)
        iso_score = self.iso_forest.decision_function(X)[0]
        iso_pred = self.iso_forest.predict(X)[0]
        # Normalize to [0, 1] (higher = more anomalous)
        anomaly_score = max(0.0, min(1.0, (-iso_score + 0.5) / 1.0))
        
        result = {
            "anomaly_score": float(anomaly_score),
            "iso_pred": int(iso_pred),
            "exfil_probability": 0.0,
            "prediction": "benign",
        }
        
        # Stage 2: Only classify if anomalous
        if iso_pred == -1 and self.trained_supervised:
            exfil_prob = self.classifier.predict_proba(X)[0, 1]
            result["exfil_probability"] = float(exfil_prob)
            result["prediction"] = "exfil" if exfil_prob > 0.6 else "anomaly"
        elif iso_pred == -1:
            result["prediction"] = "anomaly"
            result["exfil_probability"] = float(anomaly_score)
        
        # Heuristic: extreme byte ratio is a very strong signal
        if features.get("bytes_ratio", 0) > 20:
            result["exfil_probability"] = max(result["exfil_probability"], 0.85)
            result["prediction"] = "exfil"
            result["trigger"] = "extreme_bytes_ratio"
        
        return result

    MIN_UPLOAD_SESSIONS = 2
    
    def predict_with_context(self, flow: dict, dst_history: list) -> dict:
        """
        dst_history: previous flows to the same destination IP
        
        Single large upload = backup job, Windows Update, video call
        Multiple large uploads to same unusual dst = exfil
        """
        base_result = self.predict(flow)
        
        if base_result["prediction"] != "exfil":
            return base_result
        
        # Confirm with context
        large_uploads_to_dst = sum(
            1 for h in dst_history
            if h.get("orig_bytes", 0) > 100_000  # > 100KB
        )
        
        if large_uploads_to_dst < self.MIN_UPLOAD_SESSIONS:
            if flow.get("orig_bytes", 0) > 10_000_000 or base_result.get("trigger") == "extreme_bytes_ratio":
                # High confidence single-session exfiltration — do not downgrade
                base_result["note"] = "High-volume single session exfiltration detected"
            else:
                # Downgrade — single upload, probably legitimate
                base_result["prediction"] = "suspicious_upload"
                base_result["exfil_probability"] *= 0.4
                base_result["note"] = "Single session — awaiting pattern confirmation"
        else:
            # Upgrade — sustained pattern
            base_result["exfil_probability"] = min(
                0.99, base_result["exfil_probability"] * 1.3
            )
            base_result["note"] = f"Sustained: {large_uploads_to_dst} sessions"
        
        return base_result

    def save(self, path: str = "models/exfil_detector.pkl"):
        joblib.dump({
            "iso_forest": self.iso_forest,
            "classifier": self.classifier,
            "scaler": self.scaler,
            "trained_supervised": self.trained_supervised,
        }, path)

    @classmethod
    def load(cls, path: str = "models/exfil_detector.pkl"):
        data = joblib.load(path)
        inst = cls()
        inst.iso_forest = data["iso_forest"]
        inst.classifier = data["classifier"]
        inst.scaler = data["scaler"]
        inst.trained_supervised = data.get("trained_supervised", False)
        return inst


### 3.4 Ensemble with SHAP

