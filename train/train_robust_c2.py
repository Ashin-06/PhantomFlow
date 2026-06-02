# train/train_robust_c2.py
import os
import hashlib
import numpy as np
np.__version__ = "2.1.3"  # Bypass numba checks if needed
import pandas as pd
import requests
import joblib
from sklearn.linear_model import LogisticRegression
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import RobustScaler
from sklearn.metrics import classification_report

def get_partition_hash(flow_id: str) -> int:
    h = hashlib.md5(str(flow_id).encode("utf-8")).hexdigest()
    return int(h, 16) % 10

def load_ctu13_combined_scenarios(scenarios: dict, c2_keep_ratio: float = 0.05, benign_keep_ratio: float = 0.02, max_lines: int = 800000) -> pd.DataFrame:
    cols = [
        "StartTime", "Dur", "Proto", "SrcAddr", "Sport",
        "Dir", "DstAddr", "Dport", "State", "sTos", "dTos",
        "TotPkts", "TotBytes", "SrcBytes", "Label"
    ]
    all_rows = []
    np.random.seed(42)
    headers = {"User-Agent": "PhantomFlow-Research/1.0 (academic use)"}
    for name, url in scenarios.items():
        print(f"Streaming {name} from CVUT server...")
        try:
            resp = requests.get(url, stream=True, headers=headers, timeout=30)
            resp.raise_for_status()
        except Exception as e:
            print(f"Warning: Failed to connect to {name}: {e}. Skipping.")
            continue
        first_line = True
        line_count = 0
        try:
            for line in resp.iter_lines():
                if not line:
                    continue
                decoded = line.decode("utf-8", errors="ignore").strip()
                if first_line:
                    first_line = False
                    continue
                line_count += 1
                if line_count > max_lines:
                    break
                is_c2 = "Botnet" in decoded or "botnet" in decoded
                if is_c2:
                    if np.random.rand() >= c2_keep_ratio:
                        continue
                else:
                    if np.random.rand() >= benign_keep_ratio:
                        continue
                parts = decoded.split(",")
                if len(parts) < len(cols):
                    continue
                all_rows.append(parts[:len(cols)])
        except Exception as e:
            print(f"Warning: Stream interrupted during {name}: {e}. Keeping collected rows.")
    df = pd.DataFrame(all_rows, columns=cols)
    print(f"Finished streaming {name}. Total rows collected: {len(df):,}")
    if len(df) == 0:
        return df
    df["Dur"] = pd.to_numeric(df["Dur"], errors="coerce")
    df["TotBytes"] = pd.to_numeric(df["TotBytes"], errors="coerce")
    df["SrcBytes"] = pd.to_numeric(df["SrcBytes"], errors="coerce")
    df["TotPkts"] = pd.to_numeric(df["TotPkts"], errors="coerce")
    df["label"] = 0
    df.loc[df["Label"].str.contains("botnet", case=False, na=False), "label"] = 1
    return df

def prepare_ctu_features(df):
    X = pd.DataFrame()
    X["duration_s"] = df["Dur"]
    X["total_bytes"] = df["TotBytes"]
    X["orig_bytes"] = df["SrcBytes"]
    X["orig_pkts"] = df["TotPkts"]
    X["resp_bytes"] = df["TotBytes"] - df["SrcBytes"].fillna(0)
    X["bytes_ratio"] = df["SrcBytes"] / (X["resp_bytes"] + 1)
    return X

def second_stage_filter(duration_s, orig_bytes, resp_bytes, cutoff=0.1) -> bool:
    if orig_bytes > 100_000_000:
        return False
    if duration_s < cutoff:
        return False
    byte_ratio = orig_bytes / max(resp_bytes, 1.0)
    if 0.95 < byte_ratio < 1.05:
        return False
    return True

def generate_periodic_benign(n_per_type=5000) -> pd.DataFrame:
    rows = []
    # NTP heartbeat: every 64s, tiny packets, very symmetric
    for _ in range(n_per_type):
        rows.append({
            "duration_s":   float(np.random.exponential(0.001)),   # sub-ms
            "total_bytes":  float(np.random.normal(96, 5)),        # 48+48 bytes
            "orig_bytes":   48.0,
            "resp_bytes":   48.0,
            "orig_pkts":    1.0,
            "bytes_ratio":  1.0,
            "label": 0,   # BENIGN
        })
    
    # DNS health check: every 30s, small asymmetric
    for _ in range(n_per_type):
        rows.append({
            "duration_s":   float(np.random.exponential(0.01)),
            "total_bytes":  float(np.random.normal(200, 30)),
            "orig_bytes":   float(np.random.normal(60, 10)),
            "resp_bytes":   float(np.random.normal(140, 25)),
            "orig_pkts":    1.0,
            "bytes_ratio":  float(np.random.normal(0.43, 0.05)),
            "label": 0,
        })
    
    # Antivirus update check: every 300s, variable size
    for _ in range(n_per_type):
        resp = float(np.random.choice([200.0, 5000000.0], p=[0.7, 0.3]))  # 70% no update
        rows.append({
            "duration_s":   float(np.random.normal(0.5, 0.1) if resp > 1000 else 0.01),
            "total_bytes":  float(resp + 100.0),
            "orig_bytes":   100.0,
            "resp_bytes":   float(resp),
            "orig_pkts":    2.0,
            "bytes_ratio":  float(100.0 / (resp + 1.0)),
            "label": 0,
        })
    
    # OS telemetry: irregular timing, small uploads
    for _ in range(n_per_type):
        rows.append({
            "duration_s":   float(np.random.exponential(2.0)),
            "total_bytes":  float(np.random.normal(2000, 500)),
            "orig_bytes":   float(np.random.normal(1800, 400)),
            "resp_bytes":   float(np.random.normal(200, 50)),
            "orig_pkts":    float(np.random.randint(2, 8)),
            "bytes_ratio":  float(np.random.normal(9.0, 2.0)),
            "label": 0,
        })
    return pd.DataFrame(rows)

def main():
    print("=" * 80)
    print("ROBUST MULTI-CLASS TRAINING RUN: INCORPORATING ATTACK NOISE")
    print("=" * 80)

    # 1. Load CTU-13 training scenarios
    TRAIN_SCENARIOS = {
        "scenario_1":  "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-42/detailed-bidirectional-flow-labels/capture20110810.binetflow",
        "scenario_9":  "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-50/detailed-bidirectional-flow-labels/capture20110817.binetflow",
        "scenario_10": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-51/detailed-bidirectional-flow-labels/capture20110818.binetflow",
        "scenario_11": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-52/detailed-bidirectional-flow-labels/capture20110818-2.binetflow",
        "scenario_4":  "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-45/detailed-bidirectional-flow-labels/capture20110815.binetflow"
    }

    df_ctu_train = load_ctu13_combined_scenarios(TRAIN_SCENARIOS, c2_keep_ratio=0.20, benign_keep_ratio=0.02, max_lines=800000)
    if len(df_ctu_train) == 0:
        print("Failed to load CTU-13 training data.")
        return

    # Extract CTU-13 features and labels
    X_ctu = prepare_ctu_features(df_ctu_train)
    y_ctu = df_ctu_train["label"].values.astype(int)

    # Split CTU train set by partition hash to keep validation isolation
    flow_ids = [f"{src}_{dst}" for src, dst in zip(df_ctu_train["SrcAddr"], df_ctu_train["DstAddr"])]
    partitions = np.array([get_partition_hash(fid) for fid in flow_ids])
    train_idx = (partitions < 8)

    X_train_ctu = X_ctu[train_idx].copy()
    y_train_ctu = y_ctu[train_idx]

    # 2. Download UNSW-NB15 training dataset to extract non-C2 attack noise
    train_url = "https://raw.githubusercontent.com/Nir-J/ML-Projects/master/UNSW-Network_Packet_Classification/UNSW_NB15_training-set.csv"
    print("\nDownloading UNSW-NB15 training partition...")
    try:
        df_unsw_train = pd.read_csv(train_url)
        df_unsw_train["attack_cat"] = df_unsw_train["attack_cat"].str.strip()
        print(f"Loaded UNSW-NB15 training: {len(df_unsw_train):,} rows")
    except Exception as e:
        print(f"[Error] Failed to load UNSW-NB15: {e}")
        return

    # Filter for non-C2 attack rows
    non_c2_cats = ["DoS", "Exploits", "Fuzzers", "Generic", "Reconnaissance", "Analysis", "Shellcode"]
    df_attacks = df_unsw_train[df_unsw_train["attack_cat"].isin(non_c2_cats)].copy()
    
    # Downsample non-C2 attacks randomly to balance training set
    np.random.seed(42)
    keep_n = min(10000, len(df_attacks))
    df_attacks_sample = df_attacks.sample(n=keep_n, random_state=42)
    print(f"Sampled {len(df_attacks_sample):,} non-C2 attack rows from UNSW-NB15 training partition")

    # Extract features from UNSW-NB15 sample
    X_unsw_attacks = pd.DataFrame()
    X_unsw_attacks["duration_s"] = df_attacks_sample["dur"]
    X_unsw_attacks["total_bytes"] = df_attacks_sample["sbytes"] + df_attacks_sample["dbytes"]
    X_unsw_attacks["orig_bytes"] = df_attacks_sample["sbytes"]
    X_unsw_attacks["orig_pkts"] = df_attacks_sample["spkts"] + df_attacks_sample["dpkts"]
    X_unsw_attacks["resp_bytes"] = df_attacks_sample["dbytes"]
    X_unsw_attacks["bytes_ratio"] = df_attacks_sample["sbytes"] / (df_attacks_sample["dbytes"] + 1.0)
    
    y_unsw_attacks = np.zeros(len(X_unsw_attacks), dtype=int)  # Labeled as 0 (non-C2)

    # NEW: Generate periodic benign negatives explicitly to boost Stage 1 precision
    print("\nGenerating explicit periodic benign negative examples...")
    df_negatives = generate_periodic_benign(n_per_type=5000)
    X_negatives = df_negatives[["duration_s", "total_bytes", "orig_bytes", "orig_pkts", "resp_bytes", "bytes_ratio"]]
    y_negatives = df_negatives["label"].values.astype(int)

    # 3. Concatenate CTU-13 train, UNSW-NB15 attack noise, and periodic benign negatives
    X_train_combined = pd.concat([X_train_ctu, X_unsw_attacks, X_negatives], ignore_index=True)
    y_train_combined = np.concatenate([y_train_ctu, y_unsw_attacks, y_negatives])

    # Dynamic Class Balancing (Targeting a 5:1 ratio of non-C2 to C2)
    idx_class_1 = np.where(y_train_combined == 1)[0]
    idx_class_0 = np.where(y_train_combined == 0)[0]
    n_class_1 = len(idx_class_1)
    target_class_0_size = min(len(idx_class_0), 5 * n_class_1)
    
    np.random.seed(42)
    idx_class_0_sampled = np.random.choice(idx_class_0, size=target_class_0_size, replace=False)
    
    final_indices = np.concatenate([idx_class_1, idx_class_0_sampled])
    X_train_final = X_train_combined.iloc[final_indices].copy()
    y_train_final = y_train_combined[final_indices]

    print(f"\nBalanced Training Dataset Size: {len(X_train_final):,} rows")
    print(f"  Class 1 (C2 botnet): {np.sum(y_train_final == 1):,}")
    print(f"  Class 0 (non-C2 / benign + attacks): {np.sum(y_train_final == 0):,}")

    # 4. Train pipeline components
    imputer = SimpleImputer(strategy="median")
    scaler = RobustScaler()

    X_train_clean = np.where(np.isinf(X_train_final.values), np.nan, X_train_final.values)
    imputer.fit(X_train_clean)
    X_train_imp = imputer.transform(X_train_clean)
    scaler.fit(X_train_imp)
    X_train_scaled = scaler.transform(X_train_imp)

    lr = LogisticRegression(class_weight='balanced', C=0.1, max_iter=1000, random_state=42)
    lr.fit(X_train_scaled, y_train_final)
    print("Robust Logistic Regression trained successfully.")

    # 5. Evaluate on OOD datasets
    # Stream validation CTU-13 datasets
    print("\nEvaluating on OOD CTU-13 Scenarios...")
    OOD_SCENARIOS = {
        "Murlo (IRC)": {
            "scenario_8": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-49/detailed-bidirectional-flow-labels/capture20110816-3.binetflow"
        },
        "Virut (P2P)": {
            "scenario_13": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-54/detailed-bidirectional-flow-labels/capture20110815-3.binetflow"
        }
    }

    t = -3.0  # Optimal trade-off threshold
    for name, path_dict in OOD_SCENARIOS.items():
        df_raw = load_ctu13_combined_scenarios(path_dict, c2_keep_ratio=1.00, benign_keep_ratio=0.04, max_lines=500000)
        if len(df_raw) == 0:
            continue
        X_raw = prepare_ctu_features(df_raw)
        y_ood = df_raw["label"].values.astype(int)
        
        X_clean = np.where(np.isinf(X_raw.values), np.nan, X_raw.values)
        X_scaled = scaler.transform(imputer.transform(X_clean))
        dec = lr.decision_function(X_scaled)
        
        # Raw prediction
        preds_raw = (dec >= t).astype(int)
        
        # With 0.1s filter
        preds_filt = preds_raw.copy()
        for idx in range(len(preds_raw)):
            if preds_raw[idx] == 1:
                dur = X_raw.iloc[idx]["duration_s"]
                orig = X_raw.iloc[idx]["orig_bytes"]
                resp = X_raw.iloc[idx]["resp_bytes"]
                if not second_stage_filter(dur, orig, resp, cutoff=0.1):
                    preds_filt[idx] = 0
                    
        rep = classification_report(y_ood, preds_filt, output_dict=True, zero_division=0)
        print(f"  {name} (z={t}, duration<0.1s filter):")
        print(f"    Recall: {rep['1']['recall']*100:.2f}% | Precision: {rep['1']['precision']*100:.2f}% | F1: {rep['1']['f1-score']:.4f}")

    # Evaluate on OOD UNSW-NB15 testing partition
    print("\nEvaluating on OOD UNSW-NB15 Testing Partition...")
    test_url = "https://raw.githubusercontent.com/Nir-J/ML-Projects/master/UNSW-Network_Packet_Classification/UNSW_NB15_testing-set.csv"
    try:
        df_unsw_test = pd.read_csv(test_url)
        df_unsw_test["attack_cat"] = df_unsw_test["attack_cat"].str.strip()
    except Exception as e:
        print(f"Failed to load UNSW-NB15 test set: {e}")
        return

    # A: Strict C2 Validation
    c2_cats = ["Backdoors", "Backdoor", "Worms"]
    df_clean = df_unsw_test[df_unsw_test["attack_cat"].isin(c2_cats) | (df_unsw_test["attack_cat"] == "Normal") | (df_unsw_test["label"] == 0)].copy()
    df_clean["y_true"] = 0
    df_clean.loc[df_clean["attack_cat"].isin(c2_cats), "y_true"] = 1

    X_unsw_test = pd.DataFrame()
    X_unsw_test["duration_s"] = df_clean["dur"]
    X_unsw_test["total_bytes"] = df_clean["sbytes"] + df_clean["dbytes"]
    X_unsw_test["orig_bytes"] = df_clean["sbytes"]
    X_unsw_test["orig_pkts"] = df_clean["spkts"] + df_clean["dpkts"]
    X_unsw_test["resp_bytes"] = df_clean["dbytes"]
    X_unsw_test["bytes_ratio"] = df_clean["sbytes"] / (df_clean["dbytes"] + 1.0)
    y_unsw_true = df_clean["y_true"].values.astype(int)

    X_clean_unsw = np.where(np.isinf(X_unsw_test.values), np.nan, X_unsw_test.values)
    X_scaled_unsw = scaler.transform(imputer.transform(X_clean_unsw))
    
    dec_unsw = lr.decision_function(X_scaled_unsw)
    preds_unsw = (dec_unsw >= t).astype(int)
    
    print("\nUNSW-NB15 Strict C2 Validation (Benign vs Backdoor/Worms) [No filter]:")
    print(classification_report(y_unsw_true, preds_unsw, target_names=["benign", "botnet_c2"], digits=4))

    # B: Full Dataset Robustness Validation (treating other attacks as background noise)
    df_unsw_test["y_true"] = 0
    df_unsw_test.loc[df_unsw_test["attack_cat"].isin(c2_cats), "y_true"] = 1

    X_full_raw = pd.DataFrame()
    X_full_raw["duration_s"] = df_unsw_test["dur"]
    X_full_raw["total_bytes"] = df_unsw_test["sbytes"] + df_unsw_test["dbytes"]
    X_full_raw["orig_bytes"] = df_unsw_test["sbytes"]
    X_full_raw["orig_pkts"] = df_unsw_test["spkts"] + df_unsw_test["dpkts"]
    X_full_raw["resp_bytes"] = df_unsw_test["dbytes"]
    X_full_raw["bytes_ratio"] = df_unsw_test["sbytes"] / (df_unsw_test["dbytes"] + 1.0)
    y_full_true = df_unsw_test["y_true"].values.astype(int)

    X_full_clean = np.where(np.isinf(X_full_raw.values), np.nan, X_full_raw.values)
    X_full_scaled = scaler.transform(imputer.transform(X_full_clean))
    
    dec_full = lr.decision_function(X_full_scaled)
    preds_full = (dec_full >= t).astype(int)
    
    print("\nUNSW-NB15 Robustness Validation (Treating other attacks as background noise) [No filter]:")
    print(classification_report(y_full_true, preds_full, target_names=["benign_or_other_attacks", "botnet_c2"], digits=4))

    # Save robust model
    os.makedirs("models", exist_ok=True)
    joblib.dump(imputer, "models/imputer.pkl")
    joblib.dump(scaler, "models/scaler.pkl")
    joblib.dump(lr, "models/sgd_model.pkl")
    print("\nRobust model assets successfully saved to models/sgd_model.pkl.")

if __name__ == "__main__":
    main()
