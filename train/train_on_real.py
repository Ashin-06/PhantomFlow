# train/train_on_real.py
import os
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import RobustScaler
from sklearn.linear_model import SGDClassifier
import xgboost as xgb
from sklearn.metrics import classification_report

def main():
    print("=" * 60)
    print("TRAINING ON REAL GROUND-TRUTH CAPTURE DATA")
    print("=" * 60)

    # 1. Load real ground-truth capture dataset
    data_path = "lab/ground_truth_dataset.csv"
    if not os.path.exists(data_path):
        print(f"[Error] Ground-truth dataset not found at {data_path}!")
        return

    df = pd.read_csv(data_path)
    print(f"Loaded real dataset: {len(df):,} rows")

    # 2. Extract features strictly (Zero-identity mapping)
    from lab.feature_adapter import PHANTOMFLOW_FEATURES
    features = PHANTOMFLOW_FEATURES
    
    X_raw = df[features].values.astype(np.float32)
    y = df["label"].values.astype(int)

    # Median imputation and robust scaling
    X_clean = np.where(np.isinf(X_raw), np.nan, X_raw)
    
    # 3. Train-test split (75% train, 25% test) preserving class ratio
    X_train, X_test, y_train, y_test = train_test_split(
        X_clean, y, test_size=0.25, random_state=42, stratify=y
    )

    imputer = SimpleImputer(strategy="median")
    scaler = RobustScaler()

    X_train_proc = imputer.fit_transform(X_train)
    X_train_proc = scaler.fit_transform(X_train_proc)

    X_test_proc = imputer.transform(X_test)
    X_test_proc = scaler.transform(X_test_proc)

    # 4. Initialize classifiers
    # Apply class weights to SGD to handle imbalance naturally!
    sgd_model = SGDClassifier(loss="log_loss", penalty="l2", class_weight="balanced", random_state=42)
    sgd_model.fit(X_train_proc, y_train)

    # Train XGBoost with class weights or scale_pos_weight mapping
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
    
    print("\n" + "=" * 60)
    print("SGD CLASSIFIER ON REAL HOLDOUT TEST")
    print("=" * 60)
    sgd_preds = sgd_model.predict(X_test_proc)
    print(classification_report(y_test, sgd_preds, labels=[0, 1, 2, 3], target_names=CLASS_NAMES, zero_division=0))

    print("=" * 60)
    print("XGBOOST CLASSIFIER ON REAL HOLDOUT TEST")
    print("=" * 60)
    xgb_preds = xgb_model.predict(X_test_proc)
    print(classification_report(y_test, xgb_preds, labels=[0, 1, 2, 3], target_names=CLASS_NAMES, zero_division=0))

    # Save real-trained estimators
    os.makedirs("models_real", exist_ok=True)
    joblib.dump(imputer, "models_real/imputer.pkl")
    joblib.dump(scaler, "models_real/scaler.pkl")
    joblib.dump(sgd_model, "models_real/sgd_model.pkl")
    xgb_model.save_model("models_real/xgb_model.json")
    print("\n[SUCCESS] Real estimators saved inside models_real/")

if __name__ == "__main__":
    main()
