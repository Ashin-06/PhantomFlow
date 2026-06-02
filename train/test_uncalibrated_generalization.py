# train/test_uncalibrated_generalization.py
import hashlib
import numpy as np
import pandas as pd
import requests
from sklearn.linear_model import SGDClassifier, LogisticRegression
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

def main():
    print("=" * 80)
    print("DIAGNOSTIC: UNCALIBRATED LINEAR MODEL OOD GENERALIZATION")
    print("=" * 80)

    # Invariant features
    INVARIANT_FEATURES = ["duration_s", "total_bytes", "orig_bytes", "orig_pkts", "resp_bytes", "bytes_ratio"]

    TRAIN_SCENARIOS = {
        "scenario_1":  "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-42/detailed-bidirectional-flow-labels/capture20110810.binetflow",
        "scenario_9":  "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-50/detailed-bidirectional-flow-labels/capture20110817.binetflow",
        "scenario_10": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-51/detailed-bidirectional-flow-labels/capture20110818.binetflow",
        "scenario_11": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-52/detailed-bidirectional-flow-labels/capture20110818-2.binetflow"
    }

    df_train_raw = load_ctu13_combined_scenarios(TRAIN_SCENARIOS, c2_keep_ratio=0.005, benign_keep_ratio=0.04, max_lines=800000)
    if len(df_train_raw) == 0:
        return

    def prepare_features(df):
        X = pd.DataFrame()
        X["duration_s"] = df["Dur"]
        X["total_bytes"] = df["TotBytes"]
        X["orig_bytes"] = df["SrcBytes"]
        X["orig_pkts"] = df["TotPkts"]
        X["resp_bytes"] = df["TotBytes"] - df["SrcBytes"].fillna(0)
        X["bytes_ratio"] = df["SrcBytes"] / (X["resp_bytes"] + 1)
        return X

    X_train_raw = prepare_features(df_train_raw)
    y_train_full = df_train_raw["label"].values.astype(int)

    flow_ids = [f"{src}_{dst}" for src, dst in zip(df_train_raw["SrcAddr"], df_train_raw["DstAddr"])]
    partitions = np.array([get_partition_hash(fid) for fid in flow_ids])
    train_idx = (partitions < 8)

    imputer = SimpleImputer(strategy="median")
    scaler = RobustScaler()

    X_train_clean = np.where(np.isinf(X_train_raw), np.nan, X_train_raw)
    X_train_split = X_train_clean[train_idx]
    y_train = y_train_full[train_idx]

    imputer.fit(X_train_split)
    scaler.fit(imputer.transform(X_train_split))

    X_train_scaled = scaler.transform(imputer.transform(X_train_split))

    # Train raw models
    print("\nTraining raw (uncalibrated) models...")
    sgd = SGDClassifier(loss="log_loss", penalty="l2", class_weight="balanced", random_state=42)
    sgd.fit(X_train_scaled, y_train)

    lr = LogisticRegression(class_weight='balanced', C=0.1, max_iter=1000, random_state=42)
    lr.fit(X_train_scaled, y_train)

    # Load OOD
    OOD_SCENARIOS = {
        "Murlo (IRC)": {
            "scenario_8": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-49/detailed-bidirectional-flow-labels/capture20110816-3.binetflow"
        },
        "Virut (P2P)": {
            "scenario_13": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-54/detailed-bidirectional-flow-labels/capture20110815-3.binetflow"
        },
        "Rbot (IRC)": {
            "scenario_4": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-45/detailed-bidirectional-flow-labels/capture20110815.binetflow"
        }
    }

    for name, path_dict in OOD_SCENARIOS.items():
        df_raw = load_ctu13_combined_scenarios(path_dict, c2_keep_ratio=1.00, benign_keep_ratio=0.04, max_lines=500000)
        if len(df_raw) == 0:
            continue
        X_raw = prepare_features(df_raw)
        y_ood = df_raw["label"].values.astype(int)
        X_clean = np.where(np.isinf(X_raw), np.nan, X_raw)
        X_scaled = scaler.transform(imputer.transform(X_clean))

        print(f"\n--- Evaluating OOD {name} ---")
        for clf, label in [(sgd, "SGD"), (lr, "Logistic Regression")]:
            # Raw predict uses default decision boundary (f(x) > 0 for LR/SGD, or proba > 0.5)
            preds = clf.predict(X_scaled)
            print(f"[{label}] Raw Default Threshold Prediction Report:")
            print(classification_report(y_ood, preds, zero_division=0))
            
            # Print decision function statistics for C2 class to see distribution
            dec = clf.decision_function(X_scaled)
            print(f"[{label}] Decision Values for actual C2 flows:")
            c2_dec = dec[y_ood == 1]
            print(f"  Mean: {c2_dec.mean():.4f} | Median: {np.median(c2_dec):.4f} | Min: {c2_dec.min():.4f} | Max: {c2_dec.max():.4f}")

if __name__ == "__main__":
    main()
