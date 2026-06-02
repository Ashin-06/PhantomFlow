# train/online_evaluator.py
"""
Evaluate trained models on a held-out dataset stream.
Never seen during training — true generalization test.
"""

import numpy as np
import pandas as pd
import json
from sklearn.metrics import (
    classification_report, confusion_matrix,
    roc_auc_score, average_precision_score,
)
from sklearn.preprocessing import label_binarize
import joblib
import xgboost as xgb
import matplotlib.pyplot as plt


class OnlineEvaluator:
    """
    Evaluates all three models on fresh data streams.
    Produces the numbers for your research paper's Table 1.
    """

    CLASS_NAMES = ["benign", "c2_beacon", "dns_tunnel", "exfil"]

    def __init__(self, model_dir: str = "models/"):
        self.river_model = joblib.load(f"{model_dir}/river_model.pkl")
        self.sgd_model   = joblib.load(f"{model_dir}/sgd_model_47.pkl")
        self.imputer     = joblib.load(f"{model_dir}/imputer_47.pkl")
        self.scaler      = joblib.load(f"{model_dir}/scaler_47.pkl")
        self.xgb_model   = xgb.XGBClassifier()
        self.xgb_model.load_model(f"{model_dir}/xgb_model.json")

        from lab.stream_reader import DatasetStreamer
        from lab.feature_adapter import UniversalAdapter, PHANTOMFLOW_FEATURES
        self.streamer = DatasetStreamer()
        self.adapter  = UniversalAdapter()
        self.features = PHANTOMFLOW_FEATURES

    def evaluate_on_stream(self, dataset_key: str,
                            max_rows: int = 50000) -> dict:
        """
        Stream a held-out dataset and evaluate all models.
        Implements the strict Three-Stage Generalization Test Protocol:
        - Stage 2: Cross-dataset holdout metrics.
        - Stage 3: Adversarial test by injecting Gaussian noise (σ=0.1) and checking degradation < 5%.
        """
        all_y_true  = []
        all_X_scaled = []

        print(f"\n[Eval] Evaluating on {dataset_key}...")

        for chunk in self.streamer.stream(dataset_key, max_rows):
            adapted = self.adapter.adapt(chunk, dataset_key)
            if len(adapted) == 0:
                continue

            X_raw = adapted[self.features].values.astype(np.float32)
            y = adapted["label"].values.astype(int)

            X = np.where(np.isinf(X_raw), np.nan, X_raw)
            X = self.imputer.transform(X)
            X = self.scaler.transform(X)

            all_X_scaled.append(X)
            all_y_true.extend(y.tolist())

        if not all_y_true:
            print("  [Eval] No valid rows found in stream for evaluation.")
            return {"dataset": dataset_key, "n_samples": 0, "xgb_auc": {}}

        X_scaled = np.vstack(all_X_scaled)
        y_true   = np.array(all_y_true)

        # ==========================================
        # STAGE 2: CROSS-DATASET HOLDOUT EVALUATION
        # ==========================================
        sgd_pred_s2 = self.sgd_model.predict(X_scaled)
        xgb_pred_s2 = self.xgb_model.predict(X_scaled)
        xgb_prob_s2 = self.xgb_model.predict_proba(X_scaled)

        # ==========================================
        # STAGE 3: ADVERSARIAL / NOISY TEST (Gaussian noise σ=0.1)
        # ==========================================
        noise = np.random.normal(loc=0.0, scale=0.1, size=X_scaled.shape)
        X_noisy = X_scaled + noise

        sgd_pred_s3 = self.sgd_model.predict(X_noisy)
        xgb_pred_s3 = self.xgb_model.predict(X_noisy)
        xgb_prob_s3 = self.xgb_model.predict_proba(X_noisy)

        # Calculate metrics
        from sklearn.metrics import f1_score
        f1_s2_sgd = f1_score(y_true, sgd_pred_s2, average="macro", zero_division=0)
        f1_s2_xgb = f1_score(y_true, xgb_pred_s2, average="macro", zero_division=0)

        f1_s3_sgd = f1_score(y_true, sgd_pred_s3, average="macro", zero_division=0)
        f1_s3_xgb = f1_score(y_true, xgb_pred_s3, average="macro", zero_division=0)

        degrad_sgd = (f1_s2_sgd - f1_s3_sgd) / (f1_s2_sgd + 1e-9) * 100.0
        degrad_xgb = (f1_s2_xgb - f1_s3_xgb) / (f1_s2_xgb + 1e-9) * 100.0

        print(f"\n{'='*60}")
        print(f"THREE-STAGE GENERALIZATION PROTOCOL REPORT - {dataset_key}")
        print(f"{'='*60}")

        print("\n[STAGE 2] Cross-Dataset Holdout Metrics (No Noise):")
        print("\nSGD CLASSIFIER:")
        print(classification_report(y_true, sgd_pred_s2,
              labels=[0, 1, 2, 3], target_names=self.CLASS_NAMES, zero_division=0))
        print("\nXGBOOST:")
        print(classification_report(y_true, xgb_pred_s2,
              labels=[0, 1, 2, 3], target_names=self.CLASS_NAMES, zero_division=0))

        # AUC per class (XGBoost)
        y_bin = label_binarize(y_true, classes=[0, 1, 2, 3])
        auc_scores = {}
        for i, cls in enumerate(self.CLASS_NAMES):
            if y_bin[:, i].sum() > 0:
                auc_scores[f"auc_{cls}"] = float(roc_auc_score(
                    y_bin[:, i], xgb_prob_s2[:, i]
                ))

        print("\nAUC-ROC per class (XGBoost):")
        for k, v in auc_scores.items():
            print(f"  {k}: {v:.4f}")

        print("\n[STAGE 3] Adversarial Noisy Metrics (Gaussian Noise sigma=0.1):")
        print(f"  SGD Macro F1: {f1_s2_sgd:.4f} -> {f1_s3_sgd:.4f} (Degradation: {degrad_sgd:.2f}%)")
        print(f"  XGB Macro F1: {f1_s2_xgb:.4f} -> {f1_s3_xgb:.4f} (Degradation: {degrad_xgb:.2f}%)")

        # Verify degradation threshold (< 5%)
        if degrad_sgd < 5.0:
            print("  [PASS] SGD Classifier adversarial robustness check (< 5% degradation).")
        else:
            print("  [FAIL] SGD Classifier overfitted to exact feature magnitudes (> 5% degradation).")

        if degrad_xgb < 5.0:
            print("  [PASS] XGBoost Classifier adversarial robustness check (< 5% degradation).")
        else:
            print("  [FAIL] XGBoost Classifier overfitted to exact feature magnitudes (> 5% degradation).")

        # Save results
        results = {
            "dataset": dataset_key,
            "n_samples": len(y_true),
            "xgb_auc": auc_scores,
            "stage_2": {
                "sgd_macro_f1": float(f1_s2_sgd),
                "xgb_macro_f1": float(f1_s2_xgb),
            },
            "stage_3": {
                "sgd_macro_f1": float(f1_s3_sgd),
                "xgb_macro_f1": float(f1_s3_xgb),
                "sgd_degradation_pct": float(degrad_sgd),
                "xgb_degradation_pct": float(degrad_xgb),
            }
        }
        import os
        os.makedirs("eval", exist_ok=True)
        with open(f"eval/eval_{dataset_key}.json", "w") as f:
            json.dump(results, f, indent=2)

        return results
