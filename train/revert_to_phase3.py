# train/revert_to_phase3.py
"""
Stage 1: Revert Stage 1 to Phase 3 State (Organic CTU-13 Only)
No NTP/telemetry benign injection: Remove all synthetic data generation.
Stream ONLY organic datasets.
Inspect decision score distributions and sweep threshold z dynamically.
"""

import os
import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import SGDClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.metrics import precision_score, recall_score, f1_score

from lab.stream_reader import DatasetStreamer
from lab.feature_adapter import UniversalAdapter

INVARIANT_FEATURES = [
    "duration_s", "total_bytes", "orig_bytes",
    "orig_pkts", "resp_bytes", "bytes_ratio"
]

STAGE1_TRAIN_DATASETS = [
    ("ctu13_scenario9",  150000),
    ("ctu13_scenario3",  100000),
    ("ctu13_scenario4",  100000),
    ("ctu13_scenario13", 100000),
    ("cicids2017_botnet", 50000), 
]

def main():
    print("="*70)
    print("REVERTING STAGE 1 TO PHASE 3 STATE (ORGANIC ONLY)")
    print("="*70)
    
    streamer = DatasetStreamer()
    adapter = UniversalAdapter()
    
    X_train_list, y_train_list = [], []
    
    # 1. Stream training datasets
    for ds_key, max_rows in STAGE1_TRAIN_DATASETS:
        print(f"\nStreaming training dataset: {ds_key}...")
        try:
            for chunk in streamer.stream(ds_key, max_rows):
                adapted = adapter.adapt(chunk, ds_key)
                if len(adapted) == 0:
                    continue
                X_chunk = adapted[INVARIANT_FEATURES].fillna(0).values
                y_chunk = (adapted["label"] == 1).astype(int).values
                X_train_list.append(X_chunk)
                y_train_list.append(y_chunk)
        except Exception as e:
            print(f"  WARNING: {ds_key} streaming failed: {e}")
            continue
            
    X_train = np.vstack(X_train_list)
    y_train = np.concatenate(y_train_list)
    n_c2_train = (y_train == 1).sum()
    n_benign_train = (y_train == 0).sum()
    print(f"\nOrganic Train Data: {len(y_train):,} flows | Benign: {n_benign_train:,} | C2: {n_c2_train:,}")
    
    # 2. Fit Imputer and Scaler
    imputer = SimpleImputer(strategy="median")
    X_train_clean = np.where(np.isinf(X_train), np.nan, X_train)
    X_train_imp = imputer.fit_transform(X_train_clean)
    
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train_imp)
    
    # 3. Train SGDClassifier (loss="modified_huber" for decision_function probability support)
    # Use balanced class weights
    clf = SGDClassifier(
        loss="modified_huber",
        alpha=1e-4,
        max_iter=2000,
        class_weight="balanced",
        random_state=42,
    )
    clf.fit(X_train_scaled, y_train)
    print("SGDClassifier trained on organic data.")
    
    # Get training decision scores
    train_scores = clf.decision_function(X_train_scaled)
    train_benign_scores = train_scores[y_train == 0]
    train_c2_scores = train_scores[y_train == 1]
    
    print("\nTraining Decision Scores Distribution:")
    print(f"  Benign: Mean = {train_benign_scores.mean():.4f}, Std = {train_benign_scores.std():.4f}")
    print(f"  C2:     Mean = {train_c2_scores.mean():.4f}, Std = {train_c2_scores.std():.4f}")
    
    # 4. Stream Murlo validation set (Scenario 8)
    print("\nStreaming Validation dataset: ctu13_scenario8 (Murlo)...")
    X_val_list, y_val_list = [], []
    for chunk in streamer.stream("ctu13_scenario8", max_rows=30000):
        adapted = adapter.adapt(chunk, "ctu13_scenario8")
        if len(adapted) == 0:
            continue
        X_val_list.append(adapted[INVARIANT_FEATURES].fillna(0).values)
        y_val_list.append((adapted["label"] == 1).astype(int).values)
        
    X_val = np.vstack(X_val_list)
    y_val = np.concatenate(y_val_list)
    
    X_val_clean = np.where(np.isinf(X_val), np.nan, X_val)
    X_val_imp = imputer.transform(X_val_clean)
    X_val_scaled = scaler.transform(X_val_imp)
    
    val_scores = clf.decision_function(X_val_scaled)
    val_benign_scores = val_scores[y_val == 0]
    val_c2_scores = val_scores[y_val == 1]
    
    print("\nValidation (Murlo) Decision Scores Distribution:")
    print(f"  Benign: Mean = {val_benign_scores.mean():.4f}, Std = {val_benign_scores.std():.4f}")
    print(f"  C2:     Mean = {val_c2_scores.mean():.4f}, Std = {val_c2_scores.std():.4f}")
    
    val_benign_mean = val_benign_scores.mean()

    # 5. Dynamic Threshold Sweep
    print("\nSweeping threshold z from -10.0 to 0.0...")
    best_z = -7.0
    best_recall = 0.0
    best_precision = 0.0
    
    # Sweep with step of 0.1
    for z in np.arange(-10.0, 0.1, 0.1):
        if z >= val_benign_mean:
            continue
        preds = (val_scores >= z).astype(int)
        rec = recall_score(y_val, preds, zero_division=0)
        prec = precision_score(y_val, preds, zero_division=0)
        f1 = f1_score(y_val, preds, zero_division=0)
        
        # We need recall >= 75% while maximizing precision
        if rec >= 0.75:
            if prec > best_precision or (best_recall < 0.75):
                best_z = z
                best_recall = rec
                best_precision = prec
                
    print(f"\nSelected Threshold z = {best_z:.2f}")
    print(f"  Murlo Recall    = {best_recall*100:.2f}%")
    print(f"  Murlo Precision = {best_precision*100:.2f}%")
    
    print("\nDetailed Threshold Sweep Table:")
    print(f"{'z':>6} {'Recall':>10} {'Precision':>10}")
    print("-" * 30)
    for test_z in [-10.0, -8.0, -7.0, -6.0, -5.0, -4.0, -3.0, -2.0, -1.0, 0.0, 1.0, 2.0]:
        preds = (val_scores >= test_z).astype(int)
        rec = recall_score(y_val, preds, zero_division=0)
        prec = precision_score(y_val, preds, zero_division=0)
        print(f"{test_z:6.1f} {rec*100:9.2f}% {prec*100:9.2f}%")
    
    # 6. Verify boundary condition
    val_benign_mean = val_benign_scores.mean()
    print(f"\nBoundary Condition Check:")
    print(f"  Benign Mean Score = {val_benign_mean:.4f}")
    print(f"  Selected Threshold z = {best_z:.4f}")
    if val_benign_mean > best_z:
        print("  [PASS] Benign mean decision score is higher than the selected threshold.")
    else:
        print("  [FAIL] Benign mean decision score is lower than or equal to the selected threshold.")
        
    # Save the models
    os.makedirs("models", exist_ok=True)
    joblib.dump({"model": clf, "scaler": scaler, "imputer": imputer}, "models/stage1_invariant.pkl")
    joblib.dump(clf, "models/sgd_model.pkl")
    joblib.dump(imputer, "models/imputer.pkl")
    joblib.dump(scaler, "models/scaler.pkl")
    print("\nSaved Stage 1 model assets successfully.")

if __name__ == "__main__":
    main()
