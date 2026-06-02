# train/train_on_kdd_grouped.py
import os
import joblib
import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import RobustScaler
from sklearn.linear_model import SGDClassifier
import xgboost as xgb
from sklearn.metrics import classification_report

def main():
    print("=" * 60)
    print("TRAINING ON REAL KDD CAPTURES WITH GROUP-BASED FLOW ID SPLIT")
    print("=" * 60)

    # 1. Load real KDD dataset
    data_path = "lab/real_kdd_dataset.csv"
    if not os.path.exists(data_path):
        print(f"[Error] Real KDD dataset not found at {data_path}!")
        return

    df = pd.read_csv(data_path)
    print(f"Loaded real KDD dataset: {len(df):,} rows")

    # 2. Prevent Group Session Leakage by splitting on unique flow_id
    unique_flows = df["flow_id"].unique()
    print(f"Unique Flow Sessions: {len(unique_flows):,}")

    # Set up random split of Flows (75% train flows, 25% test flows)
    np.random.seed(42)
    np.random.shuffle(unique_flows)
    
    split_idx = int(len(unique_flows) * 0.75)
    train_flows = set(unique_flows[:split_idx])
    test_flows = set(unique_flows[split_idx:])

    train_df = df[df["flow_id"].isin(train_flows)].copy()
    test_df = df[df["flow_id"].isin(test_flows)].copy()

    print(f"Train set: {len(train_df):,} rows ({len(train_flows):,} unique flows)")
    print(f"Test set:  {len(test_df):,} rows ({len(test_flows):,} unique flows)")

    # 3. Extract features strictly (Zero-identity mapping)
    from lab.feature_adapter import PHANTOMFLOW_FEATURES
    features = PHANTOMFLOW_FEATURES
    
    X_train_raw = train_df[features].values.astype(np.float32)
    y_train = train_df["label"].values.astype(int)

    X_test_raw = test_df[features].values.astype(np.float32)
    y_test = test_df["label"].values.astype(int)

    # Imputation & Scaling
    X_train_clean = np.where(np.isinf(X_train_raw), np.nan, X_train_raw)
    X_test_clean = np.where(np.isinf(X_test_raw), np.nan, X_test_raw)

    imputer = SimpleImputer(strategy="median")
    scaler = RobustScaler()

    X_train_proc = imputer.fit_transform(X_train_clean)
    X_train_proc = scaler.fit_transform(X_train_proc)

    X_test_proc = imputer.transform(X_test_clean)
    X_test_proc = scaler.transform(X_test_proc)

    # 4. Train classifiers on non-overlapping flow sessions
    sgd_model = SGDClassifier(loss="log_loss", penalty="l2", class_weight="balanced", random_state=42)
    sgd_model.fit(X_train_proc, y_train)

    xgb_model = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        eval_metric="mlogloss",
        random_state=42
    )
    xgb_model.fit(X_train_proc, y_train)

    # 5. Evaluate on real out-of-distribution holdout!
    CLASS_NAMES = ["benign", "c2_beacon", "dns_tunnel", "exfil"]
    
    # Filter targets actually present in the splits to avoid reporting error
    present_labels = sorted(list(set(y_test)))
    target_names = [CLASS_NAMES[l] for l in present_labels]

    print("\n" + "=" * 60)
    print("SGD CLASSIFIER (NO FLOW SESSION LEAKAGE)")
    print("=" * 60)
    sgd_preds = sgd_model.predict(X_test_proc)
    print(classification_report(y_test, sgd_preds, labels=present_labels, target_names=target_names, zero_division=0))

    print("=" * 60)
    print("XGBOOST CLASSIFIER (NO FLOW SESSION LEAKAGE)")
    print("=" * 60)
    xgb_preds = xgb_model.predict(X_test_proc)
    print(classification_report(y_test, xgb_preds, labels=present_labels, target_names=target_names, zero_division=0))

if __name__ == "__main__":
    main()
