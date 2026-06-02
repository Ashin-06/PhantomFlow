# train/validation_pipeline.py
"""
Complete ML validation methodology.
Every check here catches a different type of failure.
"""

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.model_selection import StratifiedKFold, learning_curve
from sklearn.calibration import calibration_curve
from sklearn.metrics import (
    classification_report, roc_auc_score,
    brier_score_loss, average_precision_score,
)
from scipy import stats
import warnings


class RobustValidator:
    """
    Runs 8 different validation checks before allowing a model to train.
    Each catches a different ML failure mode.
    """

    def __init__(self, df: pd.DataFrame, feature_cols: list, label_col: str = "label"):
        self.df = df
        self.features = feature_cols
        self.label = label_col
        self.issues = []

    # ===== CHECK 1: Data Leakage Detection =====
    def check_leakage(self):
        """
        Adversarial validation: train a classifier to distinguish
        train set from test set. If it succeeds (AUC > 0.6),
        your distributions are different — temporal leakage or
        dataset mixing issue.
        """
        from sklearn.ensemble import RandomForestClassifier

        print("\n[Check 1] Adversarial validation (leakage detection)...")

        # Time-based split
        df_sorted = self.df.sort_values("timestamp") if "timestamp" in self.df else self.df
        n = len(df_sorted)
        train = df_sorted.iloc[:int(n*0.8)].copy()
        test = df_sorted.iloc[int(n*0.8):].copy()

        train["is_test"] = 0
        test["is_test"] = 1
        combined = pd.concat([train, test])

        X = combined[self.features].fillna(0)
        y = combined["is_test"]

        clf = RandomForestClassifier(n_estimators=100, random_state=42)
        from sklearn.model_selection import cross_val_score
        scores = cross_val_score(clf, X, y, cv=5, scoring="roc_auc")
        auc = scores.mean()

        if auc > 0.6:
            msg = (f"LEAKAGE DETECTED: Adversarial AUC={auc:.3f} > 0.6. "
                   f"Train/test distributions are distinguishable. "
                   f"Check for temporal leakage or dataset mixing.")
            self.issues.append(msg)
            print(f"  ⚠️  {msg}")
        else:
            print(f"  ✓ No leakage detected (adversarial AUC={auc:.3f})")

        return auc

    # ===== CHECK 2: Feature Distribution Analysis =====
    def check_feature_distributions(self):
        """
        Check for:
        1. Features with near-zero variance (useless)
        2. Features that are 90%+ zeros (likely from wrong dataset)
        3. Extreme outliers (data pipeline bugs)
        4. Features perfectly correlated with label (target leakage)
        """
        print("\n[Check 2] Feature distribution analysis...")

        X = self.df[self.features].fillna(0)
        y = self.df[self.label]
        issues = []

        for col in self.features:
            series = X[col]

            # Zero variance
            if series.std() < 1e-6:
                issues.append(f"  ⚠️  {col}: near-zero variance ({series.std():.2e}) — useless feature")

            # High zero fraction
            zero_frac = (series == 0).mean()
            if zero_frac > 0.9:
                issues.append(f"  ⚠️  {col}: {zero_frac:.1%} zeros — likely wrong dataset")

            # Target correlation (leakage)
            try:
                corr, pval = stats.pointbiserialr(series, y)
                if abs(corr) > 0.95 and pval < 0.001:
                    issues.append(f"  🚨 {col}: correlation with label = {corr:.3f} — TARGET LEAKAGE")
            except Exception:
                pass

        if issues:
            for issue in issues:
                print(issue)
                self.issues.append(issue)
        else:
            print("  ✓ All features have reasonable distributions")

    # ===== CHECK 3: Class Imbalance Assessment =====
    def check_class_balance(self):
        """
        Extreme imbalance (>100:1) requires special handling beyond GAN.
        Report exact ratios and recommend strategies.
        """
        print("\n[Check 3] Class balance check...")
        counts = self.df[self.label].value_counts().sort_index()
        total = len(self.df)

        print(f"  Label distribution:")
        for label, count in counts.items():
            pct = count / total * 100
            print(f"    Class {label}: {count:,} ({pct:.1f}%)")

        majority = counts.max()
        for label, count in counts.items():
            ratio = majority / count
            if ratio > 100:
                msg = (f"Class {label}: {ratio:.0f}:1 imbalance. "
                       f"GAN augmentation alone is insufficient at this ratio. "
                       f"Need: focal loss + class-weighted sampling + SMOTE combo.")
                self.issues.append(msg)
                print(f"  ⚠️  {msg}")

    # ===== CHECK 4: Learning Curves =====
    def plot_learning_curves(self, model, output_path: str = "eval_learning_curves.png"):
        """
        Learning curves diagnose overfitting vs underfitting.

        Overfitting:  train score >> val score (gap closes slowly with more data)
        Underfitting: both scores low (model too simple)
        Good fit:     both scores high and close
        """
        print("\n[Check 4] Computing learning curves...")
        X = self.df[self.features].fillna(0).values
        y = self.df[self.label].values

        train_sizes, train_scores, val_scores = learning_curve(
            model, X, y,
            train_sizes=np.linspace(0.1, 1.0, 10),
            cv=5,
            scoring="f1_macro",
            n_jobs=-1,
            shuffle=False,  # NEVER shuffle for temporal data
        )

        fig, ax = plt.subplots(figsize=(10, 6))
        ax.fill_between(train_sizes, train_scores.mean(1) - train_scores.std(1),
                        train_scores.mean(1) + train_scores.std(1), alpha=0.1, color="blue")
        ax.fill_between(train_sizes, val_scores.mean(1) - val_scores.std(1),
                        val_scores.mean(1) + val_scores.std(1), alpha=0.1, color="green")
        ax.plot(train_sizes, train_scores.mean(1), "b-o", label="Training score")
        ax.plot(train_sizes, val_scores.mean(1), "g-o", label="Validation score")

        # Annotate the gap
        final_gap = train_scores.mean(1)[-1] - val_scores.mean(1)[-1]
        ax.set_title(f"Learning Curves (final gap: {final_gap:.3f})")
        ax.set_xlabel("Training set size")
        ax.set_ylabel("F1 Macro")
        ax.legend()
        ax.grid(alpha=0.3)

        plt.tight_layout()
        plt.savefig(output_path, dpi=150)
        plt.close()
        print(f"  Saved to {output_path}")

        if final_gap > 0.10:
            msg = f"OVERFITTING: train-val gap = {final_gap:.3f} > 0.10"
            self.issues.append(msg)
            print(f"  ⚠️  {msg}")
        elif val_scores.mean(1)[-1] < 0.7:
            msg = f"UNDERFITTING: val F1 = {val_scores.mean(1)[-1]:.3f} < 0.70"
            self.issues.append(msg)
            print(f"  ⚠️  {msg}")
        else:
            print(f"  ✓ Learning curve looks healthy (gap={final_gap:.3f})")

    # ===== CHECK 5: Calibration Check =====
    def check_calibration(self, model, X_val, y_val):
        """
        Are confidence scores meaningful?
        If model says 90% confidence, it should be right ~90% of the time.
        Miscalibrated models cause analysts to distrust the system.

        Fix: Platt scaling or isotonic regression after training.
        """
        print("\n[Check 5] Calibration check...")
        if not hasattr(model, "predict_proba"):
            print("  SKIP: Model has no predict_proba method")
            return 0.0
            
        y_prob = model.predict_proba(X_val)[:, 1]

        # Binary: threat vs clean
        y_binary = (y_val > 0).astype(int)

        fraction_of_positives, mean_predicted_value = calibration_curve(
            y_binary, y_prob, n_bins=10
        )

        brier = brier_score_loss(y_binary, y_prob)

        fig, ax = plt.subplots(figsize=(8, 6))
        ax.plot([0, 1], [0, 1], "k--", label="Perfect calibration")
        ax.plot(mean_predicted_value, fraction_of_positives, "s-",
                label=f"Model (Brier={brier:.3f})")
        ax.set_xlabel("Mean predicted probability")
        ax.set_ylabel("Fraction of positives")
        ax.set_title("Calibration Curve")
        ax.legend()
        ax.grid(alpha=0.3)
        plt.savefig("eval_calibration_curve.png", dpi=150)
        plt.close()

        if brier > 0.15:
            msg = (f"POOR CALIBRATION: Brier score={brier:.3f}. "
                   f"Apply isotonic regression or temperature scaling.")
            self.issues.append(msg)
            print(f"  ⚠️  {msg}")
        else:
            print(f"  ✓ Calibration acceptable (Brier={brier:.3f})")

        return brier

    # ===== CHECK 6: Temporal Consistency =====
    def check_temporal_consistency(self, model, feature_cols: list):
        """
        Model should perform consistently across time, not just on average.
        If performance degrades in the last month, the model is drifting.
        """
        print("\n[Check 6] Temporal consistency check...")
        if "timestamp" not in self.df.columns:
            print("  SKIP: No timestamp column")
            return

        df_sorted = self.df.sort_values("timestamp")
        n = len(df_sorted)
        chunk_size = n // 10

        scores = []
        for i in range(10):
            chunk = df_sorted.iloc[i*chunk_size:(i+1)*chunk_size]
            if chunk[self.label].nunique() < 2:
                continue
            X_chunk = chunk[feature_cols].fillna(0).values
            y_chunk = chunk[self.label].values
            from sklearn.metrics import f1_score
            preds = model.predict(X_chunk)
            score = f1_score(y_chunk, preds, average="macro", zero_division=0)
            scores.append(score)

        if len(scores) > 2:
            trend = np.polyfit(range(len(scores)), scores, 1)[0]
            if trend < -0.02:
                msg = (f"TEMPORAL DRIFT: F1 declining at {trend:.4f}/chunk. "
                       f"Model performance degrades over time — needs retraining schedule.")
                self.issues.append(msg)
                print(f"  ⚠️  {msg}")
            else:
                print(f"  ✓ Temporal consistency OK (trend={trend:.4f}/chunk)")

    # ===== CHECK 7: Cross-Dataset Generalization =====
    def check_cross_dataset_generalization(self, model,
                                            train_df: pd.DataFrame,
                                            test_df: pd.DataFrame,
                                            feature_cols: list):
        """
        Train on CICIDS, test on CTU-13.
        If performance collapses, the model memorized dataset-specific artifacts,
        not real threat patterns.
        This is the most important check for a research paper.
        """
        print("\n[Check 7] Cross-dataset generalization check...")

        X_train = train_df[feature_cols].fillna(0).values
        y_train = train_df[self.label].values
        X_test = test_df[feature_cols].fillna(0).values
        y_test = test_df[self.label].values

        from sklearn.metrics import f1_score
        model.fit(X_train, y_train)

        same_dataset_score = f1_score(
            y_train, model.predict(X_train), average="macro", zero_division=0
        )
        cross_dataset_score = f1_score(
            y_test, model.predict(X_test), average="macro", zero_division=0
        )

        drop = same_dataset_score - cross_dataset_score
        print(f"  Same-dataset F1:  {same_dataset_score:.3f}")
        print(f"  Cross-dataset F1: {cross_dataset_score:.3f}")
        print(f"  Generalization drop: {drop:.3f}")

        if drop > 0.20:
            msg = (f"POOR GENERALIZATION: Cross-dataset F1 drop = {drop:.3f}. "
                   f"Model memorized dataset artifacts, not real threat patterns. "
                   f"Increase training dataset diversity.")
            self.issues.append(msg)
            print(f"  ⚠️  {msg}")
        else:
            print(f"  ✓ Model generalizes across datasets")

    # ===== CHECK 8: Feature Importance Sanity =====
    def check_feature_importance_sanity(self, model, feature_cols: list):
        """
        Top features should make domain sense.
        If "cert_validity_days" is the #1 feature for C2 detection,
        something is wrong — that's not how C2 works.
        """
        print("\n[Check 8] Feature importance sanity check...")
        
        EXPECTED_TOP_FOR_THREAT = {
            "dns_shannon_entropy":  ["dns_tunnel"],
            "periodicity_score":    ["c2_beacon"],
            "bytes_ratio":          ["exfiltration"],
            "ja3_malware_score":    ["c2_beacon"],
            "iat_cv":               ["c2_beacon"],
        }

        if hasattr(model, "feature_importances_"):
            importance = dict(zip(feature_cols, model.feature_importances_))
            top5 = sorted(importance.items(), key=lambda x: -x[1])[:5]
            print("  Top 5 features:")
            for feat, imp in top5:
                print(f"    {feat}: {imp:.4f}")

            # Check if top feature is a known-good signal
            if not top5:
                return
            top_feat = top5[0][0]
            if top_feat in ["flow_id", "timestamp", "dataset_source"]:
                msg = f"DATA LEAKAGE: Top feature is '{top_feat}' — identifier column"
                self.issues.append(msg)
                print(f"  🚨 {msg}")
            elif top_feat not in EXPECTED_TOP_FOR_THREAT:
                print(f"  ⚠️  Top feature '{top_feat}' unexpected — verify domain logic")
            else:
                print(f"  ✓ Top feature '{top_feat}' is domain-appropriate")

    def summary(self):
        print(f"\n{'='*60}")
        print(f"VALIDATION SUMMARY: {len(self.issues)} issues found")
        if self.issues:
            for i, issue in enumerate(self.issues, 1):
                print(f"  {i}. {issue}")
            print("\nDo NOT proceed to production until issues are resolved.")
        else:
            print("  ✓ All checks passed. Safe to train.")
        print("="*60)
