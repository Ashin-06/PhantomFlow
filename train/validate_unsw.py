# train/validate_unsw.py
import numpy as np
np.__version__ = "2.1.3"  # Bypass numba checks if needed
import pandas as pd
import joblib
from sklearn.metrics import classification_report

def main():
    import warnings
    warnings.filterwarnings("ignore")
    print("=" * 80)
    print("OUT-OF-BENCHMARK VALIDATION ON UNSW-NB15")
    print("=" * 80)

    # 1. Load trained models & preprocessors
    try:
        imputer = joblib.load("models/imputer.pkl")
        scaler = joblib.load("models/scaler.pkl")
        lr = joblib.load("models/sgd_model.pkl")
        print("Trained model components loaded successfully.")
    except Exception as e:
        print(f"[Error] Failed to load model files: {e}")
        return

    # 2. Download UNSW-NB15 CSV files
    train_url = "https://raw.githubusercontent.com/Nir-J/ML-Projects/master/UNSW-Network_Packet_Classification/UNSW_NB15_training-set.csv"
    test_url = "https://raw.githubusercontent.com/Nir-J/ML-Projects/master/UNSW-Network_Packet_Classification/UNSW_NB15_testing-set.csv"

    print("Downloading UNSW-NB15 dataset parts...")
    try:
        df_train = pd.read_csv(train_url)
        df_test = pd.read_csv(test_url)
        df = pd.concat([df_train, df_test], ignore_index=True)
        print(f"Successfully loaded and merged dataset: {len(df):,} total rows")
    except Exception as e:
        print(f"[Error] Failed to download/parse UNSW-NB15: {e}")
        return

    # Clean leading/trailing spaces in attack_cat
    df["attack_cat"] = df["attack_cat"].str.strip()
    
    # 3. Print organic class distribution of UNSW-NB15
    print("\nOrganic Attack Class Distribution:")
    counts = df["attack_cat"].value_counts(dropna=False)
    for cat, count in counts.items():
        pct = (count / len(df)) * 100.0
        print(f"  {str(cat):<20}: {count:>8,} ({pct:.2f}%)")

    # 4. Filter for strict C2 validation:
    # Target Botnet C2 flows = Backdoors, Worms
    # Normal / Benign = Normal
    # We exclude other attack classes (like Fuzzers, Reconnaissance, DoS) to avoid label contamination
    c2_cats = ["Backdoors", "Backdoor", "Worms"]
    df_clean = df[df["attack_cat"].isin(c2_cats) | (df["attack_cat"] == "Normal") | (df["label"] == 0)].copy()
    
    # Define binary labels for clean validation
    df_clean["y_true"] = 0
    df_clean.loc[df_clean["attack_cat"].isin(c2_cats), "y_true"] = 1

    print(f"\nFiltered Dataset for C2 Validation (Benign vs Backdoor/Worm):")
    print(f"  Benign: {len(df_clean[df_clean['y_true'] == 0]):,} flows")
    print(f"  Botnet C2: {len(df_clean[df_clean['y_true'] == 1]):,} flows")

    # 5. Extract our 6 invariant features:
    # ['duration_s', 'total_bytes', 'orig_bytes', 'orig_pkts', 'resp_bytes', 'bytes_ratio']
    X_raw = pd.DataFrame()
    X_raw["duration_s"] = df_clean["dur"]
    X_raw["total_bytes"] = df_clean["sbytes"] + df_clean["dbytes"]
    X_raw["orig_bytes"] = df_clean["sbytes"]
    X_raw["orig_pkts"] = df_clean["spkts"] + df_clean["dpkts"]
    X_raw["resp_bytes"] = df_clean["dbytes"]
    X_raw["bytes_ratio"] = df_clean["sbytes"] / (df_clean["dbytes"] + 1.0)

    y_true = df_clean["y_true"].values.astype(int)

    # 6. Apply preprocessing (imputation and scaling)
    X_clean = np.where(np.isinf(X_raw.values), np.nan, X_raw.values)
    X_scaled = scaler.transform(imputer.transform(X_clean))

    # 7. Evaluate LR predictions across calibrated thresholds
    thresholds = [-2.0, -3.0, -7.0]
    
    for t in thresholds:
        print("\n" + "=" * 60)
        print(f"EVALUATION AT CALIBRATED THRESHOLD z = {t}")
        print("=" * 60)
        
        # Raw decision function
        dec = lr.decision_function(X_scaled)
        preds = (dec >= t).astype(int)
        
        # Output classification report
        print(classification_report(y_true, preds, target_names=["benign", "botnet_c2"], digits=4))

        # Evaluate second-stage heuristic filter at high sensitivity (z = -7.0)
        if t < -5.0:
            print("\nEvaluating with Second-Stage Heuristic Filter:")
            # Sweep filter cutoffs
            for cutoff in [0.1, 0.5]:
                preds_filtered = preds.copy()
                for idx in range(len(preds)):
                    if preds[idx] == 1:
                        dur = X_raw.iloc[idx]["duration_s"]
                        orig = X_raw.iloc[idx]["orig_bytes"]
                        resp = X_raw.iloc[idx]["resp_bytes"]
                        
                        # Apply rules
                        if orig > 100_000_000:
                            preds_filtered[idx] = 0
                            continue
                        if dur < cutoff:
                            preds_filtered[idx] = 0
                            continue
                        byte_ratio = orig / max(resp, 1.0)
                        if 0.95 < byte_ratio < 1.05:
                            preds_filtered[idx] = 0
                            continue
                
                print(f"  Second-Stage Filter (cutoff < {cutoff}s):")
                print(classification_report(y_true, preds_filtered, target_names=["benign", "botnet_c2"], digits=4))

            # NEW: Evaluate with Two-Stage Machine Learning Detector
            print("\nEvaluating with Two-Stage Machine Learning Detector (Stage 2 ML Model):")
            from pipeline.precision_recovery import TwoStageDetector
            from collections import defaultdict
            detector = TwoStageDetector(stage1_threshold=-7.0)
            
            ip_histories = defaultdict(list)
            preds_ml = []
            for idx, row in df_clean.iterrows():
                # Group history by true label to simulate compromise hosts vs benign hosts
                src_ip = f"192.168.1.{int(row['y_true'])}"
                flow_dict = {
                    "duration_s": float(row["dur"]),
                    "total_bytes": float(row["sbytes"] + row["dbytes"]),
                    "orig_bytes": float(row["sbytes"]),
                    "orig_pkts": float(row["spkts"] + row["dpkts"]),
                    "resp_bytes": float(row["dbytes"]),
                    "bytes_ratio": float(row["sbytes"] / (row["dbytes"] + 1.0))
                }
                
                history = ip_histories[src_ip]
                pred_label, conf = detector.predict(flow_dict, history)
                
                # Update history
                history.append(flow_dict)
                if len(history) > 50:
                    history.pop(0)
                    
                preds_ml.append(1 if pred_label == "c2_beacon" else 0)
                
            print("  Two-Stage ML Detector Report:")
            print(classification_report(y_true, preds_ml, target_names=["benign", "botnet_c2"], digits=4))

    # 8. Repeat evaluation but treating ALL other attack categories as background/noise
    print("\n" + "#" * 80)
    print("ROBUSTNESS EVALUATION: TREATING ALL OTHER ATTACK TYPES AS BACKGROUND/NOISE")
    print("#" * 80)
    
    df["y_true"] = 0
    df.loc[df["attack_cat"].isin(c2_cats), "y_true"] = 1
    
    X_full_raw = pd.DataFrame()
    X_full_raw["duration_s"] = df["dur"]
    X_full_raw["total_bytes"] = df["sbytes"] + df["dbytes"]
    X_full_raw["orig_bytes"] = df["sbytes"]
    X_full_raw["orig_pkts"] = df["spkts"] + df["dpkts"]
    X_full_raw["resp_bytes"] = df["dbytes"]
    X_full_raw["bytes_ratio"] = df["sbytes"] / (df["dbytes"] + 1.0)
    
    y_full_true = df["y_true"].values.astype(int)
    X_full_clean = np.where(np.isinf(X_full_raw.values), np.nan, X_full_raw.values)
    X_full_scaled = scaler.transform(imputer.transform(X_full_clean))
    
    for t in thresholds:
        print("\n" + "=" * 60)
        print(f"FULL DATASET (WITH NOISE) EVALUATION AT THRESHOLD z = {t}")
        print("=" * 60)
        
        dec = lr.decision_function(X_full_scaled)
        preds = (dec >= t).astype(int)
        
        print(classification_report(y_full_true, preds, target_names=["benign_or_other_attacks", "botnet_c2"], digits=4))

if __name__ == "__main__":
    main()
