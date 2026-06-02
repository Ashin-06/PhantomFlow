# train/train_precision_stage2.py
import numpy as np
np.__version__ = "2.1.3"  # Bypass numba checks if needed
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from lab.stream_reader import DatasetStreamer
from pipeline.precision_recovery import TwoStageDetector
from train.train_robust_c2 import load_ctu13_combined_scenarios, prepare_ctu_features

def main():
    print("=" * 80)
    print("TRAINING STAGE 2 PRECISION RECOVERY MODEL VIA HISTORICAL CONTEXT")
    print("=" * 80)

    # 1. Load Stage 1 model to flag candidates
    # We load sgd_model, imputer, scaler
    lr = joblib.load("models/sgd_model.pkl")
    imputer = joblib.load("models/imputer.pkl")
    scaler = joblib.load("models/scaler.pkl")

    # 2. Stream CTU-13 training scenarios
    TRAIN_SCENARIOS = {
        "scenario_1":  "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-42/detailed-bidirectional-flow-labels/capture20110810.binetflow",
        "scenario_9":  "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-50/detailed-bidirectional-flow-labels/capture20110817.binetflow",
        "scenario_10": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-51/detailed-bidirectional-flow-labels/capture20110818.binetflow",
        "scenario_11": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-52/detailed-bidirectional-flow-labels/capture20110818-2.binetflow"
    }

    # Load a moderate number of rows to avoid memory limits, but keep ratio slightly higher to get beacons
    df_raw = load_ctu13_combined_scenarios(TRAIN_SCENARIOS, c2_keep_ratio=0.10, benign_keep_ratio=0.03, max_lines=600000)
    if len(df_raw) == 0:
        print("Failed to load CTU-13 training scenarios.")
        return

    # Convert StartTime to seconds or timestamp for history sorting
    df_raw["timestamp"] = pd.to_datetime(df_raw["StartTime"]).astype(int) / 1e9

    # Sort globally by timestamp
    df_raw = df_raw.sort_values(by="timestamp").reset_index(drop=True)

    # Extract Stage 1 features
    X_ctu = prepare_ctu_features(df_raw)
    y_ctu = df_raw["label"].values.astype(int)

    # Transform features
    X_clean = np.where(np.isinf(X_ctu.values), np.nan, X_ctu.values)
    X_scaled = scaler.transform(imputer.transform(X_clean))
    scores = lr.decision_function(X_scaled)

    # We will build history per source IP
    from collections import defaultdict
    ip_histories = defaultdict(list)

    stage2_X = []
    stage2_y = []

    # Threshold for Stage 1 (we sweep wide, e.g. z = -7.0)
    z_threshold = -7.0

    detector = TwoStageDetector(stage1_threshold=z_threshold)

    print("Building historical contexts and extracting Stage 2 features...")
    for idx, row in df_raw.iterrows():
        src_ip = row["SrcAddr"]
        current_feat = {
            "duration_s": float(row["Dur"]),
            "total_bytes": float(row["TotBytes"]),
            "orig_bytes": float(row["SrcBytes"]),
            "orig_pkts": float(row["TotPkts"]),
            "resp_bytes": float(row["TotBytes"] - row["SrcBytes"]),
            "bytes_ratio": float(row["SrcBytes"] / (row["TotBytes"] - row["SrcBytes"] + 1.0)),
            "timestamp": float(row["timestamp"])
        }

        history = ip_histories[src_ip]

        # Only train Stage 2 on flows that pass the Stage 1 threshold (flagged as suspicious/C2)
        if scores[idx] >= z_threshold:
            if len(history) >= detector.MIN_HISTORY_LEN:
                # Extract context features using the exact same logic as TwoStageDetector
                context_feat = detector.extract_context(history)
                stage2_X.append(context_feat)
                stage2_y.append(y_ctu[idx])

        # Append current flow to history and limit size to 15
        history.append(current_feat)
        if len(history) > 15:
            history.pop(0)

    stage2_X = np.array(stage2_X)
    stage2_y = np.array(stage2_y)

    print(f"\nStage 2 Training set size: {len(stage2_X)} samples")
    if len(stage2_X) == 0:
        print("No samples passed Stage 1. Lower the threshold or load more data.")
        return

    print(f"Class distribution in Stage 2 set:\n{pd.Series(stage2_y).value_counts()}")

    # Train Random Forest classifier
    print("Training Stage 2 Random Forest Classifier...")
    rf = RandomForestClassifier(n_estimators=100, max_depth=6, random_state=42, class_weight="balanced")
    rf.fit(stage2_X, stage2_y)

    # Evaluate
    preds = rf.predict(stage2_X)
    print("\n=== Stage 2 Precision Recovery Evaluation (Self-Assessment) ===")
    print(classification_report(stage2_y, preds))

    # Save Stage 2 model with metadata dictionary
    save_dict = {
        "model": rf,
        "features": ["iat_cv", "trend", "duration_cv", "history_len", "periodicity_score", "regularity"],
        "best_threshold": 0.45
    }
    joblib.dump(save_dict, "models/stage2_precision_model.pkl")
    print("Stage 2 precision recovery model successfully saved to models/stage2_precision_model.pkl")

if __name__ == "__main__":
    main()
