# train/evaluate_on_real_kdd.py
import os
import joblib
import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.metrics import classification_report

def main():
    print("=" * 60)
    print("REAL KDD DATASET OUT-OF-DISTRIBUTION EVALUATION")
    print("=" * 60)

    # 1. Load real KDD dataset
    data_path = "lab/real_kdd_dataset.csv"
    if not os.path.exists(data_path):
        print(f"[Error] Real KDD dataset not found at {data_path}!")
        return

    df = pd.read_csv(data_path)
    print(f"Loaded real KDD dataset: {len(df):,} rows")

    # Display class distribution
    label_counts = df["label"].value_counts().sort_index()
    print("\nClass Distribution:")
    CLASS_NAMES = ["benign", "anomaly"]
    for idx, count in label_counts.items():
        name = CLASS_NAMES[idx] if idx < len(CLASS_NAMES) else f"Class_{idx}"
        pct = (count / len(df)) * 100.0
        print(f"  {name:<12}: {count:>6,} ({pct:.2f}%)")

    # 2. Extract features strictly
    from lab.feature_adapter import PHANTOMFLOW_FEATURES
    features = PHANTOMFLOW_FEATURES

    X_raw = df[features].values.astype(np.float32)
    y_true = df["label"].values.astype(int)

    # Clean infs/NaNs
    X_clean = np.where(np.isinf(X_raw), np.nan, X_raw)

    # Load stream preprocessors and models
    model_dir = "models"
    try:
        imputer = joblib.load(f"{model_dir}/imputer_47.pkl")
        scaler = joblib.load(f"{model_dir}/scaler_47.pkl")
        sgd_model = joblib.load(f"{model_dir}/sgd_model_47.pkl")
        
        xgb_model = xgb.XGBClassifier()
        xgb_model.load_model(f"{model_dir}/xgb_model.json")
    except Exception as e:
        print(f"[Error] Failed to load models/preprocessors: {e}")
        return

    # Transform features using stream preprocessors
    X_proc = imputer.transform(X_clean)
    X_proc = scaler.transform(X_proc)

    CLASS_NAMES = ["benign", "c2_beacon", "dns_tunnel", "exfil"]

    # Run SGD Evaluation
    print("\n" + "=" * 60)
    print("SGD CLASSIFIER ON REAL KDD DATASET")
    print("=" * 60)
    sgd_preds = sgd_model.predict(X_proc)
    print(classification_report(y_true, sgd_preds, labels=[0, 1, 2, 3], target_names=CLASS_NAMES, zero_division=0))

    # Run XGBoost Evaluation
    print("=" * 60)
    print("XGBOOST CLASSIFIER ON REAL KDD DATASET")
    print("=" * 60)
    xgb_preds = xgb_model.predict(X_proc)
    print(classification_report(y_true, xgb_preds, labels=[0, 1, 2, 3], target_names=CLASS_NAMES, zero_division=0))

if __name__ == "__main__":
    main()
