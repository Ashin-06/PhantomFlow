# train/calibrate_model.py
import os
import hashlib
import numpy as np
import pandas as pd
import requests
from sklearn.linear_model import SGDClassifier, LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import RobustScaler
from sklearn.metrics import precision_recall_curve, classification_report

def get_partition_hash(flow_id: str) -> int:
    """Deterministically assign a Flow ID to a partition (0-9)."""
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
    print("OPTION B: PROBABILITY CALIBRATION & THRESHOLD OPTIMIZATION")
    print("=" * 80)

    TRAIN_SCENARIOS = {
        "scenario_1":  "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-42/detailed-bidirectional-flow-labels/capture20110810.binetflow",
        "scenario_9":  "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-50/detailed-bidirectional-flow-labels/capture20110817.binetflow",
        "scenario_10": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-51/detailed-bidirectional-flow-labels/capture20110818.binetflow",
        "scenario_11": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-52/detailed-bidirectional-flow-labels/capture20110818-2.binetflow"
    }

    df_train_raw = load_ctu13_combined_scenarios(TRAIN_SCENARIOS, c2_keep_ratio=0.005, benign_keep_ratio=0.04, max_lines=800000)
    if len(df_train_raw) == 0:
        return

    # Invariant features only
    X_train_raw = pd.DataFrame()
    X_train_raw["duration_s"] = df_train_raw["Dur"]
    X_train_raw["total_bytes"] = df_train_raw["TotBytes"]
    X_train_raw["orig_bytes"] = df_train_raw["SrcBytes"]
    X_train_raw["orig_pkts"] = df_train_raw["TotPkts"]
    X_train_raw["resp_bytes"] = df_train_raw["TotBytes"] - df_train_raw["SrcBytes"].fillna(0)
    X_train_raw["bytes_ratio"] = df_train_raw["SrcBytes"] / (X_train_raw["resp_bytes"] + 1)
    
    y_train_full = df_train_raw["label"].values.astype(int)

    flow_ids = [f"{src}_{dst}" for src, dst in zip(df_train_raw["SrcAddr"], df_train_raw["DstAddr"])]
    partitions = np.array([get_partition_hash(fid) for fid in flow_ids])
    
    train_idx = (partitions < 8)
    val_idx = (partitions >= 8)

    imputer = SimpleImputer(strategy="median")
    scaler = RobustScaler()

    X_train_clean = np.where(np.isinf(X_train_raw), np.nan, X_train_raw)
    
    # Fit preprocessors on training partition only to avoid leakage
    X_train_split = X_train_clean[train_idx]
    y_train = y_train_full[train_idx]
    X_val_split = X_train_clean[val_idx]
    y_val = y_train_full[val_idx]

    imputer.fit(X_train_split)
    scaler.fit(imputer.transform(X_train_split))

    X_train_scaled = scaler.transform(imputer.transform(X_train_split))
    X_val_scaled = scaler.transform(imputer.transform(X_val_split))

    print(f"\n[Splits] Train size: {len(X_train_scaled):,}, Validation size: {len(X_val_scaled):,}")
    print("Class Balance Train:", pd.Series(y_train).value_counts().to_dict())
    print("Class Balance Validation:", pd.Series(y_val).value_counts().to_dict())

    # Option B-1: Calibrated SGD
    print("\nFitting Option B-1: Calibrated SGD...")
    base_sgd = SGDClassifier(loss="log_loss", penalty="l2", class_weight="balanced", random_state=42)
    calibrated_sgd = CalibratedClassifierCV(base_sgd, method='isotonic', cv=5)
    calibrated_sgd.fit(X_train_scaled, y_train)

    # Option B-2: Calibrated Logistic Regression
    print("Fitting Option B-2: Calibrated Logistic Regression...")
    base_lr = LogisticRegression(class_weight='balanced', C=0.1, max_iter=1000, random_state=42)
    calibrated_lr = CalibratedClassifierCV(base_lr, method='sigmoid', cv=5)
    calibrated_lr.fit(X_train_scaled, y_train)

    # Find operational threshold on Validation set (target: precision >= 0.60)
    CLASS_NAMES = ["benign", "c2_beacon"]
    
    for model, label in [(calibrated_sgd, 'Calibrated SGD'), (calibrated_lr, 'Calibrated LR')]:
        probs = model.predict_proba(X_val_scaled)[:, 1]
        precision, recall, thresholds = precision_recall_curve(y_val, probs)
        
        viable_idx = np.where(precision >= 0.60)[0]
        if len(viable_idx) > 0:
            best_idx = viable_idx[0]
            # Ensure index doesn't overshoot thresholds array size
            best_thresh = thresholds[min(best_idx, len(thresholds)-1)]
            best_recall = recall[best_idx]
            best_prec = precision[best_idx]
            print(f"\n[{label}] Optimal Operating Point found:")
            print(f"  Threshold (P>=0.60): {best_thresh:.4f}")
            print(f"  Precision: {best_prec:.4f} | Recall: {best_recall:.4f}")
            
            # Predict on Validation at calibrated threshold
            preds = (probs >= best_thresh).astype(int)
        else:
            best_prec_idx = np.argmax(precision)
            best_thresh = thresholds[min(best_prec_idx, len(thresholds)-1)]
            print(f"\n[{label}] WARNING: Target precision >= 0.60 not met on validation split.")
            print(f"  Failsafe Threshold (Max Precision): {best_thresh:.4f} (Precision: {precision[best_prec_idx]:.4f} | Recall: {recall[best_prec_idx]:.4f})")
            preds = (probs >= best_thresh).astype(int)

        print(f"Validation Report for {label} at Calibrated Threshold:")
        print(classification_report(y_val, preds, target_names=CLASS_NAMES, zero_division=0))

        # Evaluate on OOD Murlo IRC
        MURLO_SCENARIO = {
            "scenario_8": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-49/detailed-bidirectional-flow-labels/capture20110816-3.binetflow"
        }
        df_murlo = load_ctu13_combined_scenarios(MURLO_SCENARIO, c2_keep_ratio=1.00, benign_keep_ratio=0.04, max_lines=500000)
        X_murlo_raw = pd.DataFrame()
        X_murlo_raw["duration_s"] = df_murlo["Dur"]
        X_murlo_raw["total_bytes"] = df_murlo["TotBytes"]
        X_murlo_raw["orig_bytes"] = df_murlo["SrcBytes"]
        X_murlo_raw["orig_pkts"] = df_murlo["TotPkts"]
        X_murlo_raw["resp_bytes"] = df_murlo["TotBytes"] - df_murlo["SrcBytes"].fillna(0)
        X_murlo_raw["bytes_ratio"] = df_murlo["SrcBytes"] / (X_murlo_raw["resp_bytes"] + 1)
        y_murlo = df_murlo["label"].values.astype(int)
        
        X_murlo_clean = np.where(np.isinf(X_murlo_raw), np.nan, X_murlo_raw)
        X_murlo_scaled = scaler.transform(imputer.transform(X_murlo_clean))

        murlo_probs = model.predict_proba(X_murlo_scaled)[:, 1]
        murlo_preds = (murlo_probs >= best_thresh).astype(int)
        print(f"OOD Murlo Report for {label} at Calibrated Threshold:")
        print(classification_report(y_murlo, murlo_preds, target_names=CLASS_NAMES, zero_division=0))

if __name__ == "__main__":
    main()
