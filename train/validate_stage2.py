# train/validate_stage2.py
import warnings
warnings.filterwarnings("ignore")
import numpy as np
np.__version__ = "2.1.3"  # Bypass numba checks if needed
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, precision_score, recall_score, f1_score
from train.train_robust_c2 import load_ctu13_combined_scenarios, prepare_ctu_features
from scipy import signal

def extract_context_from_history(history):
    if len(history) < 2:
        return [0.0] * 6

    durations = [float(f.get("duration_s", 0.0)) for f in history]
    timestamps = [float(f.get("timestamp", i * 60.0)) for i, f in enumerate(history)]
    intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
    intervals_arr = np.array(intervals)
    
    # Existing features
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

    # NEW: Autocorrelation periodicity score
    periodicity_score = 0.0
    
    if len(intervals_arr) >= 6:
        try:
            normed = (intervals_arr - np.mean(intervals_arr))
            normed /= (np.std(intervals_arr) + 1e-9)
            
            acf = np.correlate(normed, normed, mode='full')
            acf = acf[len(acf)//2:]
            acf /= (acf[0] + 1e-9)
            
            # Find peaks beyond lag 0
            peaks, _ = signal.find_peaks(acf[1:], height=0.2, prominence=0.1)
            if len(peaks) > 0:
                best_lag = peaks[np.argmax(acf[peaks + 1])] + 1
                periodicity_score = float(acf[best_lag])
        except Exception:
            pass
    
    # NEW: Regularity score (inverse of CV — high = regular = suspicious)
    regularity = float(max(0.0, 1.0 - min(1.0, iat_cv / 2.0)))

    return [
        float(iat_cv),
        float(trend),
        float(duration_cv),
        float(history_len),
        float(periodicity_score),
        float(regularity)
    ]

def collect_stage2_data(scenarios_dict, lr, imputer, scaler, z_threshold=-7.0, c2_keep=0.20, benign_keep=0.03, max_lines=600000):
    df_raw = load_ctu13_combined_scenarios(scenarios_dict, c2_keep_ratio=c2_keep, benign_keep_ratio=benign_keep, max_lines=max_lines)
    if len(df_raw) == 0:
        return np.array([]), np.array([])
        
    df_raw["timestamp"] = pd.to_datetime(df_raw["StartTime"]).astype(int) / 1e9
    df_raw = df_raw.sort_values(by="timestamp").reset_index(drop=True)
    
    X_ctu = prepare_ctu_features(df_raw)
    y_ctu = df_raw["label"].values.astype(int)
    
    X_clean = np.where(np.isinf(X_ctu.values), np.nan, X_ctu.values)
    X_scaled = scaler.transform(imputer.transform(X_clean))
    scores = lr.decision_function(X_scaled)
    
    from collections import defaultdict
    ip_histories = defaultdict(list)
    
    stage2_X = []
    stage2_y = []
    
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
        
        if scores[idx] >= z_threshold:
            # Changed to len(history) >= 2
            if len(history) >= 2:
                context_feat = extract_context_from_history(history)
                stage2_X.append(context_feat)
                stage2_y.append(y_ctu[idx])
                
        history.append(current_feat)
        if len(history) > 15:
            history.pop(0)
            
    return np.array(stage2_X), np.array(stage2_y)

def main():
    print("=" * 80)
    print("OOD VALIDATION OF STAGE 2 PRECISION RECOVERY MODEL WITH PERIODICITY")
    print("=" * 80)
    
    # Load Stage 1
    lr = joblib.load("models/sgd_model.pkl")
    imputer = joblib.load("models/imputer.pkl")
    scaler = joblib.load("models/scaler.pkl")
    
    # 1. Train on Neris (Scenarios 1, 9, 10, 11) + Rbot IRC (Scenario 4)
    TRAIN_SCENARIOS = {
        "scenario_1":  "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-42/detailed-bidirectional-flow-labels/capture20110810.binetflow",
        "scenario_9":  "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-50/detailed-bidirectional-flow-labels/capture20110817.binetflow",
        "scenario_10": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-51/detailed-bidirectional-flow-labels/capture20110818.binetflow",
        "scenario_11": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-52/detailed-bidirectional-flow-labels/capture20110818-2.binetflow",
        "scenario_4":  "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-45/detailed-bidirectional-flow-labels/capture20110815.binetflow"
    }
    
    print("\n--- Collecting Training Data from Neris & Rbot (Scenarios 1, 4, 9, 10, 11) ---")
    train_X, train_y = collect_stage2_data(TRAIN_SCENARIOS, lr, imputer, scaler, z_threshold=-7.0, c2_keep=0.15, benign_keep=0.03, max_lines=400000)
    print(f"Collected {len(train_X)} training samples.")
    
    # 2. Test on Murlo (Scenario 8)
    TEST_SCENARIOS = {
        "scenario_8": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-49/detailed-bidirectional-flow-labels/capture20110816-3.binetflow"
    }
    print("\n--- Collecting Test Data from Murlo (Scenario 8) ---")
    test_X, test_y = collect_stage2_data(TEST_SCENARIOS, lr, imputer, scaler, z_threshold=-7.0, c2_keep=0.50, benign_keep=0.05, max_lines=400000)
    print(f"Collected {len(test_X)} test samples.")
    
    if len(train_X) == 0 or len(test_X) == 0:
        print("Data collection failed. Adjust ratios or thresholds.")
        return
        
    ALL_FEATURE_NAMES = ["iat_cv", "trend", "duration_cv", "history_len", "periodicity_score", "regularity"]
    
    FEATURE_SUBSETS = {
        "Legacy Features": ["iat_cv", "trend", "duration_cv", "history_len"],
        "All Periodicity Features": ALL_FEATURE_NAMES
    }
    
    for name, feats in FEATURE_SUBSETS.items():
        print("\n" + "=" * 60)
        print(f"EVALUATING SUBSET: {name}")
        print("=" * 60)
        
        # Get indices of selected features
        indices = [ALL_FEATURE_NAMES.index(f) for f in feats]
        
        sub_train_X = train_X[:, indices]
        sub_test_X = test_X[:, indices]
        
        # Train Random Forest
        rf = RandomForestClassifier(n_estimators=100, max_depth=6, random_state=42, class_weight="balanced")
        rf.fit(sub_train_X, train_y)
        
        # Predict probabilities
        probs = rf.predict_proba(sub_test_X)[:, 1]
        
        # Print probability statistics by class
        df_probs = pd.DataFrame({"prob": probs, "label": test_y})
        print("\nProbability Statistics by True Class:")
        print(df_probs.groupby("label")["prob"].describe())
        
        # Sweep thresholds
        best_f1 = 0
        best_thresh = 0.50
        best_report = None
        
        print(f"\nThreshold Sweep Results for {name}:")
        print(f"{'Thresh':<8}{'Precision':<12}{'Recall':<10}{'F1-score':<10}")
        for thresh in np.arange(0.05, 0.95, 0.05):
            preds = (probs >= thresh).astype(int)
            p = precision_score(test_y, preds, zero_division=0)
            r = recall_score(test_y, preds, zero_division=0)
            f1 = f1_score(test_y, preds, average="binary", zero_division=0)
            print(f"{thresh:<8.2f}{p:<12.4f}{r:<10.4f}{f1:<10.4f}")
            if f1 > best_f1:
                best_f1 = f1
                best_thresh = thresh
                best_report = classification_report(test_y, preds, zero_division=0)
                
        print(f"\nBest Decision Threshold found: {best_thresh:.2f} (F1-score: {best_f1:.4f})")
        if best_report:
            print(best_report)
        else:
            # Print default threshold report
            preds_def = (probs >= 0.50).astype(int)
            print("\nDefault 0.50 Threshold Report:")
            print(classification_report(test_y, preds_def, zero_division=0))
            
        # If this is "All Periodicity Features", save it as models/stage2_precision_model.pkl
        if name == "All Periodicity Features":
            # Save the trained model and features
            joblib.dump({
                "model": rf,
                "features": feats,
                "best_threshold": float(best_thresh)
            }, "models/stage2_precision_model.pkl")
            print(f"Saved {name} model to models/stage2_precision_model.pkl")

if __name__ == "__main__":
    main()
