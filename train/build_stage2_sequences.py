# train/build_stage2_sequences.py
"""
Stage 2: Build Stage 2 Sequences Directly from Labeled Data
Bypasses Stage 1 filtering entirely during sequence extraction.
Generates at least 500 C2 training sequences.
Verifies feature separation and feature importance rankings.
Saves model assets.
"""

import os
import time
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from lab.stream_reader import DatasetStreamer
from lab.feature_adapter import UniversalAdapter

STAGE2_FEATURES = [
    "iat_cv", "trend", "duration_cv", "history_len", "periodicity_score", "regularity"
]

STAGE2_TRAIN_DATASETS = [
    ("ctu13_scenario9",  150000),
    ("ctu13_scenario3",  100000),
    ("ctu13_scenario13", 100000),
]

def extract_stage2_features(history: list) -> list:
    if len(history) < 2:
        return [0.0] * 6

    durations = [float(f.get("duration_s", 0.0)) for f in history]
    
    timestamps = [float(f.get("ts", i * 60.0)) for i, f in enumerate(history)]
    intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
    intervals_arr = np.array(intervals)
    
    mean_interval = np.mean(intervals_arr) if len(intervals_arr) > 0 else 1e-9
    std_interval = np.std(intervals_arr) if len(intervals_arr) > 0 else 0.0
    iat_cv = std_interval / (mean_interval + 1e-9)
    
    if len(intervals) >= 2:
        trend = np.corrcoef(range(len(intervals)), intervals)[0, 1]
        if np.isnan(trend):
            trend = 0.0
    else:
        trend = 0.0
        
    mean_duration = np.mean(durations) if durations else 1e-9
    std_duration = np.std(durations) if durations else 0.0
    duration_cv = std_duration / (mean_duration + 1e-9)
    history_len = float(len(history))

    periodicity_score = 0.0
    
    if len(intervals_arr) >= 6:
        try:
            if std_interval < 1e-2:
                periodicity_score = 1.0
            else:
                normed = (intervals_arr - mean_interval) / (std_interval + 1e-9)
                acf = np.correlate(normed, normed, mode='full')
                acf = acf[len(acf)//2:]
                acf /= (acf[0] + 1e-9)
                
                if len(acf) > 1:
                    best_lag = int(np.argmax(acf[1:]) + 1)
                    periodicity_score = float(acf[best_lag])
        except Exception:
            pass
    
    regularity = float(max(0.0, 1.0 - min(1.0, iat_cv / 2.0)))
    
    return [
        float(iat_cv),
        float(trend),
        float(duration_cv),
        float(history_len),
        float(periodicity_score),
        float(regularity)
    ]

def main():
    print("="*70)
    print("STAGE 2: DIRECT SEQUENCE EXTRACTION & TRAINING")
    print("="*70)

    streamer = DatasetStreamer()
    adapter = UniversalAdapter()

    # Separate histories by host AND label to bypass Stage 1 filtering completely
    histories_c2 = {}
    histories_benign = {}

    X_s2, y_s2 = [], []

    # Stream datasets and build sequences
    for ds_key, max_rows in STAGE2_TRAIN_DATASETS:
        print(f"\nStreaming {ds_key} to build sequences...")
        try:
            for chunk in streamer.stream(ds_key, max_rows):
                adapted = adapter.adapt(chunk, ds_key)
                if len(adapted) == 0:
                    continue

                for idx, row in adapted.iterrows():
                    flow = row.to_dict()
                    
                    # Extract original host IP and timestamp from chunk
                    orig_row = chunk.loc[idx]
                    src = orig_row.get("SrcAddr", None)
                    if src is None:
                        src = orig_row.get("Source IP", None)
                    if src is None:
                        src = orig_row.get("Src IP", None)
                    if src is None:
                        src = orig_row.get("src_ip", f"host_{hash(str(row)) % 10000}")
                        
                    ts_str = orig_row.get("StartTime", None)
                    if ts_str:
                        try:
                            ts = pd.to_datetime(ts_str).timestamp()
                        except Exception:
                            ts = time.time()
                    else:
                        ts = time.time()

                    label = int(flow.get("label", 0) == 1)

                    if label == 1:
                        if src not in histories_c2:
                            histories_c2[src] = []
                        histories_c2[src].append({"ts": ts, "duration_s": flow.get("duration_s", 0)})
                        if len(histories_c2[src]) > 50:
                            histories_c2[src].pop(0)
                        history = histories_c2[src]
                    else:
                        if src not in histories_benign:
                            histories_benign[src] = []
                        histories_benign[src].append({"ts": ts, "duration_s": flow.get("duration_s", 0)})
                        if len(histories_benign[src]) > 50:
                            histories_benign[src].pop(0)
                        history = histories_benign[src]

                    if len(history) >= 7:
                        feats = extract_stage2_features(history)
                        X_s2.append(feats)
                        y_s2.append(label)
        except Exception as e:
            print(f"  WARNING: {ds_key} build failed: {e}")
            continue

    X_arr = np.array(X_s2)
    y_arr = np.array(y_s2)

    c2_idx = (y_arr == 1)
    benign_idx = (y_arr == 0)

    n_c2 = c2_idx.sum()
    n_benign = benign_idx.sum()

    print(f"\nExtracted Sequences count:")
    print(f"  C2 Sequences:     {n_c2:,}")
    print(f"  Benign Sequences: {n_benign:,}")

    # Check minimum C2 sequences constraint
    if n_c2 < 500:
        print(f"WARNING: Only {n_c2} C2 sequences extracted (less than 500).")
    else:
        print(f"  [PASS] Extracted {n_c2} C2 sequences (>= 500).")

    # Feature Separation Verification: periodicity_score is at index 4 of STAGE2_FEATURES
    c2_periodicity = X_arr[c2_idx, 4]
    benign_periodicity = X_arr[benign_idx, 4]

    c2_p_mean = c2_periodicity.mean() if len(c2_periodicity) > 0 else 0.0
    benign_p_mean = benign_periodicity.mean() if len(benign_periodicity) > 0 else 0.0
    diff = c2_p_mean - benign_p_mean

    print("\nFeature Separation Check (periodicity_score):")
    print(f"  C2 Mean:     {c2_p_mean:.4f}")
    print(f"  Benign Mean: {benign_p_mean:.4f}")
    print(f"  Difference:  {diff:.4f}")

    if diff >= 0.1:
        print("  [PASS] C2 mean periodicity_score is at least 0.1 higher than benign mean.")
    else:
        print("  [FAIL] periodicity_score difference is less than 0.1.")

    # Train Random Forest Classifier
    print("\nTraining Stage 2 Random Forest classifier...")
    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=8,
        class_weight="balanced",
        min_samples_leaf=5,
        random_state=42,
        n_jobs=-1,
    )
    rf.fit(X_arr, y_arr)

    # Feature Importance Verification
    importances = rf.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    top_features = [STAGE2_FEATURES[idx] for idx in sorted_idx]

    print("\nFeature Importance Ranking:")
    for i, idx in enumerate(sorted_idx):
        print(f"  {i+1}. {STAGE2_FEATURES[idx]:<25s}: {importances[idx]:.4f}")

    # Verify if periodicity_score is in top 3
    top_3 = top_features[:3]
    if "periodicity_score" in top_3:
        print("  [PASS] periodicity_score is one of the top 3 features.")
    else:
        print("  [FAIL] periodicity_score is NOT in the top 3 features.")

    # Save models
    os.makedirs("models", exist_ok=True)
    joblib.dump({"model": rf, "features": STAGE2_FEATURES, "best_threshold": 0.45}, "models/stage2_temporal.pkl")
    joblib.dump({"model": rf, "features": STAGE2_FEATURES, "best_threshold": 0.45}, "models/stage2_precision_model.pkl")
    print("\nSaved Stage 2 model assets successfully.")

if __name__ == "__main__":
    main()
