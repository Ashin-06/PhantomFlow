# train/ablation_experiment.py
import os
import hashlib
import numpy as np
import pandas as pd
import requests
from sklearn.linear_model import SGDClassifier
import xgboost as xgb
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import RobustScaler
from sklearn.metrics import classification_report

def get_partition_hash(flow_id: str) -> int:
    """Deterministically assign a Flow ID to a partition (0-9)."""
    h = hashlib.md5(str(flow_id).encode("utf-8")).hexdigest()
    return int(h, 16) % 10

def map_proto(proto_str: str) -> float:
    """Map protocol string to a distinct numerical code."""
    p = str(proto_str).lower().strip()
    if "tcp" in p:
        return 1.0
    elif "udp" in p:
        return 2.0
    elif "icmp" in p:
        return 3.0
    return 0.0

def map_state(state_str: str) -> float:
    """Map common TCP/UDP connection states to distinct numerical codes."""
    s = str(state_str).upper().strip()
    states = {
        "CON": 1.0, "INT": 2.0, "REQ": 3.0, "RST": 4.0,
        "SF": 5.0, "S0": 6.0, "REJ": 7.0, "RSTO": 8.0,
        "FIN": 9.0, "URP": 10.0
    }
    return states.get(s, 0.0)

def load_ctu13_combined_scenarios(scenarios: dict, c2_keep_ratio: float = 0.05, benign_keep_ratio: float = 0.02, max_lines: int = 800000) -> pd.DataFrame:
    """
    Stream and merge multiple CTU-13 scenarios directly from Czech Technical University.
    """
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
                continue  # Skip binetflow header

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

    # Parse physical numeric columns
    df["Dur"] = pd.to_numeric(df["Dur"], errors="coerce")
    df["TotBytes"] = pd.to_numeric(df["TotBytes"], errors="coerce")
    df["SrcBytes"] = pd.to_numeric(df["SrcBytes"], errors="coerce")
    df["TotPkts"] = pd.to_numeric(df["TotPkts"], errors="coerce")

    # Map labels to binary threat class
    df["label"] = 0
    df.loc[df["Label"].str.contains("botnet", case=False, na=False), "label"] = 1

    return df

def main():
    print("=" * 80)
    print("OPTION C: DIAGNOSTIC FEATURE ABLATION EXPERIMENT")
    print("=" * 80)

    # Ingest training corpus (Neris HTTP and IRC)
    TRAIN_SCENARIOS = {
        "scenario_1":  "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-42/detailed-bidirectional-flow-labels/capture20110810.binetflow",
        "scenario_9":  "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-50/detailed-bidirectional-flow-labels/capture20110817.binetflow",
        "scenario_10": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-51/detailed-bidirectional-flow-labels/capture20110818.binetflow",
        "scenario_11": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-52/detailed-bidirectional-flow-labels/capture20110818-2.binetflow"
    }

    df_train_raw = load_ctu13_combined_scenarios(TRAIN_SCENARIOS, c2_keep_ratio=0.005, benign_keep_ratio=0.04, max_lines=800000)
    
    if len(df_train_raw) == 0:
        print("Error: No training data loaded.")
        return

    # Feature space assembly
    def prepare_features(df):
        X = pd.DataFrame()
        X["duration_s"] = df["Dur"]
        X["total_bytes"] = df["TotBytes"]
        X["orig_bytes"] = df["SrcBytes"]
        X["orig_pkts"] = df["TotPkts"]
        X["resp_bytes"] = df["TotBytes"] - df["SrcBytes"].fillna(0)
        X["bytes_ratio"] = df["SrcBytes"] / (X["resp_bytes"] + 1)
        X["proto_encoded"] = df["Proto"].apply(map_proto)
        X["state_encoded"] = df["State"].apply(map_state)
        return X

    X_train_raw = prepare_features(df_train_raw)
    y_train_full = df_train_raw["label"].values.astype(int)

    # Deterministic zero-leakage flow splitting for validation
    flow_ids = [f"{src}_{dst}" for src, dst in zip(df_train_raw["SrcAddr"], df_train_raw["DstAddr"])]
    partitions = np.array([get_partition_hash(fid) for fid in flow_ids])
    train_idx = (partitions < 8)

    X_train_split = X_train_raw[train_idx]
    y_train = y_train_full[train_idx]

    # Preprocessors
    imputer = SimpleImputer(strategy="median")
    scaler = RobustScaler()

    X_train_clean = np.where(np.isinf(X_train_split), np.nan, X_train_split)
    imputer.fit(X_train_clean)
    X_train_imp = imputer.transform(X_train_clean)
    scaler.fit(X_train_imp)
    X_train_scaled = pd.DataFrame(scaler.transform(X_train_imp), columns=X_train_raw.columns)

    print(f"\n[Train Set] Loaded {len(X_train_scaled):,} rows.")
    train_classes = pd.Series(y_train).value_counts().to_dict()
    print("Class Balance:", train_classes)
    n_benign = train_classes.get(0, 1)
    n_c2 = train_classes.get(1, 1)
    scale_pos_weight = n_benign / n_c2

    # Ingest Murlo IRC OOD scenario
    MURLO_SCENARIO = {
        "scenario_8": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-49/detailed-bidirectional-flow-labels/capture20110816-3.binetflow"
    }
    df_murlo_raw = load_ctu13_combined_scenarios(MURLO_SCENARIO, c2_keep_ratio=1.00, benign_keep_ratio=0.04, max_lines=500000)
    
    X_murlo_raw = prepare_features(df_murlo_raw)
    y_murlo = df_murlo_raw["label"].values.astype(int)

    X_murlo_clean = np.where(np.isinf(X_murlo_raw), np.nan, X_murlo_raw)
    X_murlo_scaled = pd.DataFrame(scaler.transform(imputer.transform(X_murlo_clean)), columns=X_murlo_raw.columns)
    print(f"[Murlo Set] Loaded {len(X_murlo_scaled):,} rows.")

    FULL_FEATURES = ['duration_s', 'total_bytes', 'orig_bytes', 'orig_pkts', 'resp_bytes', 'bytes_ratio', 'proto_encoded', 'state_encoded']
    INVARIANT_FEATURES = ['duration_s', 'total_bytes', 'orig_bytes', 'orig_pkts', 'resp_bytes', 'bytes_ratio']

    results = {}

    for feature_set, name in [(FULL_FEATURES, 'full'), (INVARIANT_FEATURES, 'invariant')]:
        print(f"\nTraining on {name} feature set...")
        
        # Train SGD
        sgd = SGDClassifier(loss="log_loss", penalty="l2", class_weight="balanced", random_state=42)
        sgd.fit(X_train_scaled[feature_set], y_train)
        
        # Train XGBoost
        xgb_clf = xgb.XGBClassifier(
            n_estimators=100,
            max_depth=4,
            min_child_weight=1,
            subsample=0.7,
            colsample_bytree=0.7,
            learning_rate=0.05,
            scale_pos_weight=scale_pos_weight,
            eval_metric="aucpr",
            random_state=42
        )
        xgb_clf.fit(X_train_scaled[feature_set], y_train)

        # Evaluate on Murlo OOD
        for clf, label in [(sgd, 'SGD'), (xgb_clf, 'XGB')]:
            preds = clf.predict(X_murlo_scaled[feature_set])
            report = classification_report(y_murlo, preds, output_dict=True, zero_division=0)
            
            # Record recall, precision, F1-score for threat class '1'
            results[f'{label}_{name}_recall'] = report['1']['recall']
            results[f'{label}_{name}_precision'] = report['1']['precision']
            results[f'{label}_{name}_f1'] = report['1']['f1-score']

    print("\n" + "=" * 80)
    print("OPTION C: 2x2 FEATURE ABLATION COMPARISON ON OOD MURLO IRC")
    print("=" * 80)
    df_res = pd.DataFrame({
        "Murlo C2 Recall": [results['SGD_full_recall'], results['SGD_invariant_recall'], results['XGB_full_recall'], results['XGB_invariant_recall']],
        "Murlo C2 Precision": [results['SGD_full_precision'], results['SGD_invariant_precision'], results['XGB_full_precision'], results['XGB_invariant_precision']],
        "Murlo C2 F1-Score": [results['SGD_full_f1'], results['SGD_invariant_f1'], results['XGB_full_f1'], results['XGB_invariant_f1']]
    }, index=["SGD (Full)", "SGD (Invariant)", "XGBoost (Full)", "XGBoost (Invariant)"])
    print(df_res)
    print("=" * 80)

if __name__ == "__main__":
    main()
