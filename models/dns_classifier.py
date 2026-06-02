# models/dns_classifier.py
"""
XGBoost classifier for DNS tunneling detection.
Uses entropy + character distribution features.
Handles both iodine-style IP-in-DNS and dnscat2-style data tunneling.
"""

import json
import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import classification_report, roc_auc_score
import shap
import joblib
from typing import Dict, Tuple
from features.extractor import FeatureExtractor


class DNSTunnelingClassifier:
    """
    Binary classifier: tunneling (1) vs. benign DNS (0).
    
    Key features ranked by importance:
    1. dns_shannon_entropy       — most powerful single feature
    2. dns_bigram_entropy        — captures encoding patterns
    3. dns_max_label_len         — tunneling uses very long subdomains
    4. dns_digit_ratio           — encoded data has high digit density
    5. dns_vowel_ratio           — base64 has ~zero vowels
    6. dns_query_len             — tunneling queries are abnormally long
    7. connection_count_1m       — repeated queries to same domain
    """

    DNS_FEATURES = [
        "dns_shannon_entropy",
        "dns_bigram_entropy",
        "dns_query_len",
        "dns_label_count",
        "dns_max_label_len",
        "dns_unique_chars",
        "dns_vowel_ratio",
        "dns_digit_ratio",
        "dns_hyphen_ratio",
        "dns_is_ip_encoded",
        "dns_consecutive_digits",
        "dns_longest_run",
        "connection_count_1m",
        "connection_count_5m",
    ]

    def __init__(self):
        self.model = xgb.XGBClassifier(
            n_estimators=500,
            max_depth=7,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.8,
            scale_pos_weight=10,     # Class imbalance: 10:1 benign:tunnel
            use_label_encoder=False,
            eval_metric="auc",
            early_stopping_rounds=50,
            tree_method="hist",
            random_state=42,
        )
        self.scaler = StandardScaler()
        self.explainer = None

    def prepare_features(self, df: pd.DataFrame) -> np.ndarray:
        """Extract and scale DNS features from DataFrame."""
        X = df[self.DNS_FEATURES].fillna(0).values
        return self.scaler.transform(X)

    def train(self, df_train: pd.DataFrame, df_val: pd.DataFrame):
        X_train = self.scaler.fit_transform(
            df_train[self.DNS_FEATURES].fillna(0)
        )
        y_train = df_train["label"].values
        X_val = self.scaler.transform(
            df_val[self.DNS_FEATURES].fillna(0)
        )
        y_val = df_val["label"].values
        
        self.model.fit(
            X_train, y_train,
            eval_set=[(X_val, y_val)],
            verbose=50,
        )
        
        # Build SHAP explainer
        self.explainer = shap.TreeExplainer(self.model)
        
        # Evaluation
        y_pred = self.model.predict(X_val)
        y_prob = self.model.predict_proba(X_val)[:, 1]
        
        print("\n=== DNS Classifier Evaluation ===")
        print(classification_report(y_val, y_pred,
              target_names=["benign", "tunneling"]))
        print(f"AUC-ROC: {roc_auc_score(y_val, y_prob):.4f}")
        
        # Feature importance
        importance = dict(zip(self.DNS_FEATURES,
                              self.model.feature_importances_))
        print("\nTop 5 features:")
        for feat, imp in sorted(importance.items(),
                                key=lambda x: -x[1])[:5]:
            print(f"  {feat}: {imp:.4f}")

    def predict_with_explanation(self, dns_query: str,
                                  context_features: Dict) -> Dict:
        """
        Predict and explain why a DNS query is flagged.
        Returns structured result with SHAP values.
        """
        extractor = FeatureExtractor(redis_client=None)
        dns_feat = extractor.extract_dns_features(dns_query)
        dns_feat.update(context_features)
        
        # Build feature vector
        row = {k: dns_feat.get(k, 0.0) for k in self.DNS_FEATURES}
        X = self.scaler.transform([list(row.values())])
        
        prob = self.model.predict_proba(X)[0, 1]
        pred = int(prob > 0.5)
        
        # ── Heuristic override for high-entropy tunneling that ML misses ──
        # Shannon entropy > 4.0 + max label length > 30 = strong tunneling signal
        # (benign domains average ~2.5 entropy and rarely exceed 20 char labels)
        shannon = row["dns_shannon_entropy"]
        max_lbl = row["dns_max_label_len"]
        digit_r = row["dns_digit_ratio"]
        if shannon > 4.0 and max_lbl > 30:
            override_prob = min(0.97, 0.60 + (shannon - 4.0) * 0.15 + digit_r * 0.20)
            if override_prob > prob:
                prob = override_prob
                pred = 1
        
        # SHAP explanation
        shap_values = None
        if self.explainer:
            shap_vals = self.explainer.shap_values(X)[0]
            shap_values = {feat: float(val)
                          for feat, val in zip(self.DNS_FEATURES, shap_vals)}
            # Sort by absolute contribution
            shap_values = dict(sorted(shap_values.items(),
                                      key=lambda x: -abs(x[1])))
        
        return {
            "query": dns_query,
            "probability": prob,
            "prediction": "tunneling" if pred else "benign",
            "top_features": {
                "shannon_entropy": row["dns_shannon_entropy"],
                "max_label_len": row["dns_max_label_len"],
                "vowel_ratio": row["dns_vowel_ratio"],
            },
            "shap_values": shap_values,
        }

    def save(self, path: str = "models/dns_classifier.pkl"):
        joblib.dump({
            "model": self.model,
            "scaler": self.scaler,
            "explainer": self.explainer,
        }, path)
        print(f"[DNS] Saved to {path}")

    @classmethod
    def load(cls, path: str = "models/dns_classifier.pkl"):
        obj = cls()
        data = joblib.load(path)
        obj.model = data["model"]
        obj.scaler = data["scaler"]
        obj.explainer = data["explainer"]
        return obj
