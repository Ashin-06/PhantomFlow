# train/honest_verification.py
import os
import joblib
import json
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report

def main():
    print("=" * 60)
    print("HONEST ML GENERALIZATION VERIFICATION")
    print("=" * 60)

    # 1. Load real ground truth capture dataset
    data_path = "lab/ground_truth_dataset.csv"
    if not os.path.exists(data_path):
        print(f"[Error] Real dataset not found at {data_path}!")
        return

    df = pd.read_csv(data_path)
    print(f"Loaded real dataset: {len(df):,} rows")

    # 2. Display natural class distribution (non-synthetically balanced!)
    CLASS_NAMES = ["benign", "c2_beacon", "dns_tunnel", "exfil"]
    label_counts = df["label"].value_counts().sort_index()
    print("\nOrganic Class Distribution (Real Captures):")
    for idx, name in enumerate(CLASS_NAMES):
        count = label_counts.get(idx, 0)
        pct = (count / len(df)) * 100.0
        print(f"  {name:<12}: {count:>6,} ({pct:.2f}%)")

    # 3. Load preprocessors and trained models
    model_dir = "models"
    try:
        imputer = joblib.load(f"{model_dir}/imputer_47.pkl")
        scaler = joblib.load(f"{model_dir}/scaler_47.pkl")
        sgd_model = joblib.load(f"{model_dir}/sgd_model_47.pkl")
        
        # Load XGBoost model
        import xgboost as xgb
        xgb_model = xgb.XGBClassifier()
        xgb_model.load_model(f"{model_dir}/xgb_model.json")
    except Exception as e:
        print(f"[Error] Failed to load models or preprocessors: {e}")
        return

    # 4. Extract features strictly (Zero-identity mapping, no ports, IPs, or Timestamps)
    from lab.feature_adapter import PHANTOMFLOW_FEATURES
    features = PHANTOMFLOW_FEATURES
    
    X_raw = df[features].values.astype(np.float32)
    y_true = df["label"].values.astype(int)

    # Apply same scaling & imputation
    X = np.where(np.isinf(X_raw), np.nan, X_raw)
    X = imputer.transform(X)
    X = scaler.transform(X)

    # 5. Run raw predictions (Organic support, no balance tricks)
    print("\n" + "=" * 60)
    print("EVALUATING SGD CLASSIFIER")
    print("=" * 60)
    sgd_preds = sgd_model.predict(X)
    print(classification_report(y_true, sgd_preds, labels=[0, 1, 2, 3], target_names=CLASS_NAMES, zero_division=0))

    print("=" * 60)
    print("EVALUATING XGBOOST CLASSIFIER")
    print("=" * 60)
    xgb_preds = xgb_model.predict(X)
    print(classification_report(y_true, xgb_preds, labels=[0, 1, 2, 3], target_names=CLASS_NAMES, zero_division=0))

if __name__ == "__main__":
    main()
