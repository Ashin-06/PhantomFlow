# lab/triangulation_testing.py
"""
PhantomFlow Triangulation & Stress Testing Suite
Evaluates trained models against timing jitter, connection truncation, and feature ablation.
"""

import numpy as np
import pandas as pd
import joblib
import xgboost as xgb
from sklearn.metrics import classification_report, accuracy_score, f1_score


class TriangulationTester:
    def __init__(self, model_dir: str = "models/"):
        print("[Triangulation] Loading trained model checkpoints...")
        self.imputer = joblib.load(f"{model_dir}/imputer_47.pkl")
        self.scaler = joblib.load(f"{model_dir}/scaler_47.pkl")
        self.sgd_model = joblib.load(f"{model_dir}/sgd_model_47.pkl")
        
        self.xgb_model = xgb.XGBClassifier()
        self.xgb_model.load_model(f"{model_dir}/xgb_model.json")
        
        from lab.feature_adapter import PHANTOMFLOW_FEATURES
        self.features = PHANTOMFLOW_FEATURES

    def generate_stress_data(self, scenario: str, n_samples: int = 1000) -> tuple:
        """
        Generates test data under different adversarial scenarios.
        Classes: 0=Benign, 1=C2 Beacon, 2=DNS Tunnel, 3=Exfil
        """
        np.random.seed(42)
        classes = [0, 1, 2, 3]
        labels = np.random.choice(classes, n_samples)
        
        data = []
        for cls in labels:
            row = {feat: 0.0 for feat in self.features}
            
            # 1. Baseline Benign (Class 0)
            if cls == 0:
                row["duration_s"] = np.random.uniform(0.1, 5.0)
                row["iat_mean_ms"] = np.random.uniform(10.0, 100.0)
                row["iat_std_ms"] = np.random.uniform(10.0, 200.0)
                row["iat_cv"] = row["iat_std_ms"] / (row["iat_mean_ms"] + 1e-9)
                row["pkt_size_mean"] = np.random.uniform(500.0, 1000.0)
                row["orig_bytes"] = np.random.uniform(1000.0, 50000.0)
                row["resp_bytes"] = np.random.uniform(5000.0, 500000.0)
                row["bytes_ratio"] = row["orig_bytes"] / (row["resp_bytes"] + 1.0)
                row["periodicity_score"] = np.random.uniform(0.0, 0.1)
                row["ja3_malware_score"] = np.random.uniform(0.0, 0.2)
                row["dns_shannon_entropy"] = np.random.uniform(2.0, 3.2)
                row["failed_connection_ratio"] = np.random.uniform(0.0, 0.05)

            # 2. C2 Beacon (Class 1)
            elif cls == 1:
                row["duration_s"] = np.random.uniform(10.0, 60.0)
                row["iat_mean_ms"] = np.random.uniform(10000.0, 30000.0)
                row["pkt_size_mean"] = np.random.uniform(100.0, 250.0)
                row["orig_bytes"] = np.random.uniform(500.0, 2000.0)
                row["resp_bytes"] = np.random.uniform(500.0, 2000.0)
                row["bytes_ratio"] = np.random.uniform(0.8, 1.2)
                row["periodicity_score"] = np.random.uniform(0.9, 0.99)
                row["ja3_malware_score"] = np.random.uniform(0.8, 0.98)
                row["dns_shannon_entropy"] = np.random.uniform(2.0, 3.0)
                row["failed_connection_ratio"] = np.random.uniform(0.0, 0.02)
                
                # Apply Timing Jitter Scenario
                if scenario == "jitter":
                    # Adversarial Jitter: high timing variance (iat_cv between 0.8 and 1.5)
                    row["iat_std_ms"] = row["iat_mean_ms"] * np.random.uniform(0.8, 1.5)
                    row["iat_cv"] = row["iat_std_ms"] / (row["iat_mean_ms"] + 1e-9)
                    row["periodicity_score"] = np.random.uniform(0.0, 0.3)  # Breaks timing periodicity
                else:
                    # Normal clean training behavior (no jitter)
                    row["iat_std_ms"] = np.random.uniform(10.0, 100.0)
                    row["iat_cv"] = row["iat_std_ms"] / (row["iat_mean_ms"] + 1e-9)

            # 3. DNS Tunnel (Class 2)
            elif cls == 2:
                row["duration_s"] = np.random.uniform(0.5, 10.0)
                row["iat_mean_ms"] = np.random.uniform(50.0, 500.0)
                row["pkt_size_mean"] = np.random.uniform(150.0, 300.0)
                row["orig_bytes"] = np.random.uniform(1000.0, 10000.0)
                row["resp_bytes"] = np.random.uniform(1000.0, 10000.0)
                row["bytes_ratio"] = np.random.uniform(0.5, 2.0)
                row["dns_query_len"] = np.random.uniform(80.0, 200.0)
                row["dns_shannon_entropy"] = np.random.uniform(4.5, 5.5)
                row["failed_connection_ratio"] = np.random.uniform(0.1, 0.4)

            # 4. Exfiltration (Class 3)
            elif cls == 3:
                row["iat_mean_ms"] = np.random.uniform(1.0, 10.0)
                row["pkt_size_mean"] = np.random.uniform(1000.0, 1450.0)
                row["orig_bytes"] = np.random.uniform(1e6, 5e7)
                row["resp_bytes"] = np.random.uniform(1e4, 5e4)
                row["bytes_ratio"] = row["orig_bytes"] / (row["resp_bytes"] + 1.0)
                row["periodicity_score"] = np.random.uniform(0.0, 0.2)
                row["ja3_malware_score"] = np.random.uniform(0.0, 0.3)
                row["dns_shannon_entropy"] = np.random.uniform(2.0, 3.2)
                row["failed_connection_ratio"] = np.random.uniform(0.0, 0.05)
                
                # Apply Truncated Duration Scenario
                if scenario == "truncated":
                    # Adversarial Truncation: force exfiltration to stop in under 5 seconds
                    row["duration_s"] = np.random.uniform(0.5, 5.0)
                else:
                    row["duration_s"] = np.random.uniform(60.0, 600.0)

            data.append(row)

        df = pd.DataFrame(data)
        
        # Apply Feature Ablation Scenario
        if scenario == "ablation":
            # Force duration_s and iat_cv completely to 0.0 to test reliance on deep behavior features
            df["duration_s"] = 0.0
            df["iat_cv"] = 0.0
            
        return df[self.features].values.astype(np.float32), labels

    def run_evaluation(self, X_raw: np.ndarray, y_true: np.ndarray) -> dict:
        """Helper to transform and evaluate both models."""
        X = np.where(np.isinf(X_raw), np.nan, X_raw)
        X = self.imputer.transform(X)
        X = self.scaler.transform(X)
        
        sgd_preds = self.sgd_model.predict(X)
        xgb_preds = self.xgb_model.predict(X)
        
        return {
            "sgd_acc": accuracy_score(y_true, sgd_preds),
            "sgd_f1": f1_score(y_true, sgd_preds, average="macro"),
            "xgb_acc": accuracy_score(y_true, xgb_preds),
            "xgb_f1": f1_score(y_true, xgb_preds, average="macro"),
            "xgb_report": classification_report(y_true, xgb_preds, target_names=["benign", "beacon", "dns_tunnel", "exfil"], output_dict=True)
        }

    def run_all_tests(self):
        scenarios = ["control", "jitter", "truncated", "ablation"]
        results = {}
        
        print("\n" + "="*70)
        print("PHANTOMFLOW ADVERSARIAL STRESS & TRIANGULATION RESULTS")
        print("="*70)
        
        for sc in scenarios:
            X, y = self.generate_stress_data(sc)
            res = self.run_evaluation(X, y)
            results[sc] = res
            
            print(f"\n[Scenario: {sc.upper()}]")
            print(f"  SGD Accuracy: {res['sgd_acc']:.4f} | SGD F1 Macro: {res['sgd_f1']:.4f}")
            print(f"  XGB Accuracy: {res['xgb_acc']:.4f} | XGB F1 Macro: {res['xgb_f1']:.4f}")
            
            # Print class-specific F1 for XGBoost to see what broke
            rep = res["xgb_report"]
            print("  XGBoost Class F1-scores:")
            print(f"    - Benign:     {rep['benign']['f1-score']:.4f}")
            print(f"    - C2 Beacon:  {rep['beacon']['f1-score']:.4f}")
            print(f"    - DNS Tunnel: {rep['dns_tunnel']['f1-score']:.4f}")
            print(f"    - Exfil:      {rep['exfil']['f1-score']:.4f}")
            
        print("\n" + "="*70)
        print("ANALYSIS SUMMARY:")
        print("="*70)
        
        # 1. Analyze Jitter Sensitivity
        jitter_f1 = results["jitter"]["xgb_report"]["beacon"]["f1-score"]
        control_f1 = results["control"]["xgb_report"]["beacon"]["f1-score"]
        print(f"1. Timing Jitter Sensitivity (Class 1 Beacon F1):")
        print(f"   Control (Periodic): {control_f1:.4f} -> Jitter (Noisy): {jitter_f1:.4f}")
        if jitter_f1 < 0.70:
            print("   [CRITICAL] High Timing Sensitivity detected! Attacker jitter effectively bypasses timing rules.")
        else:
            print("   [ROBUST] Timing Jitter resisted successfully! Model leverages secondary features (JA3, sizes).")

        # 2. Analyze Truncation Sensitivity
        trunc_f1 = results["truncated"]["xgb_report"]["exfil"]["f1-score"]
        ctrl_exfil_f1 = results["control"]["xgb_report"]["exfil"]["f1-score"]
        print(f"\n2. Duration Truncation Sensitivity (Class 3 Exfil F1):")
        print(f"   Control (Long): {ctrl_exfil_f1:.4f} -> Truncated (Short): {trunc_f1:.4f}")

        # 3. Analyze Ablation (No Timing & Length)
        ablation_acc = results["ablation"]["xgb_acc"]
        control_acc = results["control"]["xgb_acc"]
        print(f"\n3. Feature Ablation (Duration & IAT_CV removed entirely):")
        print(f"   Control Accuracy: {control_acc:.4f} -> Ablated Accuracy: {ablation_acc:.4f}")
        print(f"   Ablated XGBoost Class F1-scores:")
        print(f"     - Benign:     {results['ablation']['xgb_report']['benign']['f1-score']:.4f}")
        print(f"     - C2 Beacon:  {results['ablation']['xgb_report']['beacon']['f1-score']:.4f}")
        print(f"     - DNS Tunnel: {results['ablation']['xgb_report']['dns_tunnel']['f1-score']:.4f}")
        print(f"     - Exfil:      {results['ablation']['xgb_report']['exfil']['f1-score']:.4f}")
        
        
if __name__ == "__main__":
    tester = TriangulationTester()
    tester.run_all_tests()
