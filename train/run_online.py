# train/run_online.py
"""
Unified entry point — runs full streaming training, cross-dataset stream evaluation,
and honest Group-based Flow ID evaluation on organic real-world captures.
"""

import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import argparse
import numpy as np
import pandas as pd
import joblib
import xgboost as xgb
from train.online_trainer import OnlineTrainer
from train.online_evaluator import OnlineEvaluator
from sklearn.metrics import classification_report

def run_honest_group_evaluation(model_dir="models/"):
    print("\n" + "=" * 60)
    print("HONEST OOD GROUP SESSION EVALUATION (NO LEAKAGE)")
    print("=" * 60)

    # Load preprocessors and models
    try:
        imputer = joblib.load(f"{model_dir}/imputer_47.pkl")
        scaler = joblib.load(f"{model_dir}/scaler_47.pkl")
        sgd_model = joblib.load(f"{model_dir}/sgd_model_47.pkl")
        
        xgb_model = xgb.XGBClassifier()
        xgb_model.load_model(f"{model_dir}/xgb_model.json")
    except Exception as e:
        print(f"[Error] Failed to load models for honest evaluation: {e}")
        return

    # Load organic datasets
    datasets = {
        "Real KDD Capture": "lab/real_kdd_dataset.csv",
        "Ground Truth Capture": "lab/ground_truth_dataset.csv"
    }

    from lab.feature_adapter import PHANTOMFLOW_FEATURES
    CLASS_NAMES = ["benign", "c2_beacon", "dns_tunnel", "exfil"]

    for name, path in datasets.items():
        if not os.path.exists(path):
            print(f"  [WARN] Dataset path {path} not found.")
            continue

        df = pd.read_csv(path)
        print(f"\nEvaluating on {name} ({len(df):,} rows)...")

        # Split on unique Flow ID to completely avoid membership leakage
        unique_flows = df["flow_id"].unique()
        np.random.seed(42)
        np.random.shuffle(unique_flows)

        # 75% training split, 25% held-out test split
        split_idx = int(len(unique_flows) * 0.75)
        test_flows = set(unique_flows[split_idx:])
        test_df = df[df["flow_id"].isin(test_flows)].copy()

        print(f"  Held-out test split: {len(test_df):,} rows ({len(test_flows):,} unique flows)")

        # Feature isolation
        X_raw = test_df[PHANTOMFLOW_FEATURES].values.astype(np.float32)
        y_true = test_df["label"].values.astype(int)

        X_clean = np.where(np.isinf(X_raw), np.nan, X_raw)
        X_proc = imputer.transform(X_clean)
        X_proc = scaler.transform(X_proc)

        present_labels = sorted(list(set(y_true)))
        target_names = [CLASS_NAMES[l] for l in present_labels]

        # SGD Evaluation
        print(f"\n  SGD Classifier ({name}):")
        sgd_preds = sgd_model.predict(X_proc)
        print(classification_report(y_true, sgd_preds, labels=present_labels, target_names=target_names, zero_division=0))

        # XGBoost Evaluation
        print(f"  XGBoost Classifier ({name}):")
        xgb_preds = xgb_model.predict(X_proc)
        print(classification_report(y_true, xgb_preds, labels=present_labels, target_names=target_names, zero_division=0))


def main(args):
    os.makedirs("models", exist_ok=True)
    os.makedirs("eval", exist_ok=True)

    # Training datasets (ordered: easiest → hardest domain)
    TRAIN_DATASETS = [
        "cicids2017_monday",       # Pure benign baseline
        "cicids2017_friday",       # Botnet C2 + PortScan
        "cicids2017_wednesday",    # DoS anomalies
        "cicids2017_thursday",     # Infiltration/exfil
        "ctu13_scenario1",         # Real botnet C2 (Neris IRC botnet)
        "unsw_nb15_train",         # Backdoors + Shellcode
        "dns_exfil_github",        # DNS tunneling queries
    ]

    # Held-out for evaluation ONLY — never trained on
    EVAL_DATASETS = [
        "cicids2018_s3",           # Different year — true generalization
        "ctu13_scenario9",         # Neris HTTP botnet out-of-sample C2
    ]

    # ===== TRAINING =====
    print("=" * 60)
    print("PHANTOMFLOW ONLINE STREAM TRAINING (ALL 5 MILLION+ ROWS)")
    print("=" * 60)
    print(f"Training on {len(TRAIN_DATASETS)} datasets")
    print(f"Max rows per dataset: {args.max_rows or 'unlimited'}")
    print("=" * 60)

    trainer = OnlineTrainer(output_dir="models/")
    trainer.train_on_datasets(TRAIN_DATASETS, max_rows_per_dataset=args.max_rows)

    # ===== EVALUATION =====
    print("\n" + "=" * 60)
    print("STREAM HELD-OUT EVALUATION (TEMPORAL/CROSS-DATASET)")
    print("=" * 60)

    evaluator = OnlineEvaluator(model_dir="models/")
    for ds in EVAL_DATASETS:
        try:
            evaluator.evaluate_on_stream(ds, max_rows=args.eval_rows)
        except Exception as e:
            print(f"  Eval failed for {ds}: {e}")

    # ===== HONEST GROUP EVALUATION =====
    run_honest_group_evaluation(model_dir="models/")

    print("\n[SUCCESS] Complete. Models saved in models/  |  Results in eval/")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument(
        "--max_rows", type=int, default=800000,
        help="Max rows per training dataset (default 800K for 5.6M total rows)."
    )
    p.add_argument(
        "--eval_rows", type=int, default=100000,
        help="Rows to use for evaluation (default 100K)."
    )
    main(p.parse_args())

