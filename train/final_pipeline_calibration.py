# train/final_pipeline_calibration.py
import os
import hashlib
import numpy as np
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

def prepare_features(df):
    X = pd.DataFrame()
    X["duration_s"] = df["Dur"]
    X["total_bytes"] = df["TotBytes"]
    X["orig_bytes"] = df["SrcBytes"]
    X["orig_pkts"] = df["TotPkts"]
    X["resp_bytes"] = df["TotBytes"] - df["SrcBytes"].fillna(0)
    X["bytes_ratio"] = df["SrcBytes"] / (X["resp_bytes"] + 1)
    return X

def second_stage_filter(row_df_or_dict: dict, z_score: float) -> bool:
    """
    Apply heuristic rules to suppress obvious false positives
    when operating in high-sensitivity mode (z < -5).
    Returns True if flow should be escalated as an alert.
    """
    if z_score >= -5.0:
        # Second stage filter only applies to high-sensitivity modes (z < -5)
        return True

    orig_bytes = row_df_or_dict.get("orig_bytes", 0.0)
    resp_bytes = row_df_or_dict.get("resp_bytes", 0.0)
    duration_s = row_df_or_dict.get("duration_s", 0.0)

    # Rule 1: C2 sessions rarely transfer >100MB outbound in a single session
    if orig_bytes > 100_000_000:
        return False

    # Rule 2: C2 sessions are persistent — very short sessions are likely scanners/one-offs
    if duration_s < 2.0:
        return False

    # Rule 3: Symmetric byte ratios are typical of file sync/speedtest/bulk transfers, not C2 beaconing
    byte_ratio = orig_bytes / max(resp_bytes, 1.0)
    if 0.95 < byte_ratio < 1.05:
        return False

    return True

def main():
    print("=" * 80)
    print("FINAL CALIBRATION: EXPANDED TRAINING + THRESHOLD SWEEP + SECOND-STAGE FILTER")
    print("=" * 80)

    # Expanded training: Now includes Rbot IRC (Scenario 4) to break Neris-only quirks
    TRAIN_SCENARIOS = {
        "scenario_1":  "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-42/detailed-bidirectional-flow-labels/capture20110810.binetflow",
        "scenario_9":  "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-50/detailed-bidirectional-flow-labels/capture20110817.binetflow",
        "scenario_10": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-51/detailed-bidirectional-flow-labels/capture20110818.binetflow",
        "scenario_11": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-52/detailed-bidirectional-flow-labels/capture20110818-2.binetflow",
        "scenario_4":  "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-45/detailed-bidirectional-flow-labels/capture20110815.binetflow"
    }

    df_train_raw = load_ctu13_combined_scenarios(TRAIN_SCENARIOS, c2_keep_ratio=0.005, benign_keep_ratio=0.04, max_lines=800000)
    if len(df_train_raw) == 0:
        print("Failed to load training data.")
        return

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

    # Fit Logistic Regression (balanced)
    lr = LogisticRegression(class_weight='balanced', C=0.1, max_iter=1000, random_state=42)
    lr.fit(X_train_scaled, y_train)

    # Load OOD Scenarios (Note: Rbot scenario_4 is now part of training, so OOD test is Murlo and Virut)
    OOD_SCENARIOS = {
        "Murlo (IRC)": {
            "scenario_8": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-49/detailed-bidirectional-flow-labels/capture20110816-3.binetflow"
        },
        "Virut (P2P)": {
            "scenario_13": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-54/detailed-bidirectional-flow-labels/capture20110815-3.binetflow"
        }
    }

    ood_datasets = {}
    for name, path_dict in OOD_SCENARIOS.items():
        df_raw = load_ctu13_combined_scenarios(path_dict, c2_keep_ratio=1.00, benign_keep_ratio=0.04, max_lines=500000)
        if len(df_raw) == 0:
            continue
        X_raw = prepare_features(df_raw)
        y_ood = df_raw["label"].values.astype(int)
        
        # We need raw features in the dict format to apply the second stage filter
        # So we keep X_raw alongside X_scaled
        X_clean = np.where(np.isinf(X_raw), np.nan, X_raw)
        X_scaled = scaler.transform(imputer.transform(X_clean))
        ood_datasets[name] = (X_scaled, y_ood, X_raw)

    decision_thresholds = [-10.0, -7.0, -6.0, -5.0, -4.0, -3.0, -2.0, -1.0, 0.0, 1.0, 2.0]
    
    rows = []
    for t in decision_thresholds:
        for name, (X_scaled, y_ood, X_raw) in ood_datasets.items():
            dec = lr.decision_function(X_scaled)
            
            # --- Scenario A: Raw predictions ---
            preds_raw = (dec >= t).astype(int)
            rep_raw = classification_report(y_ood, preds_raw, output_dict=True, zero_division=0)
            
            # --- Scenario B: Predictions with Second-Stage Filter ---
            # Apply second stage filter for samples that are predicted positive
            preds_filtered = preds_raw.copy()
            for idx in range(len(preds_raw)):
                if preds_raw[idx] == 1:
                    row_dict = {
                        "duration_s": X_raw.iloc[idx]["duration_s"],
                        "orig_bytes": X_raw.iloc[idx]["orig_bytes"],
                        "resp_bytes": X_raw.iloc[idx]["resp_bytes"],
                    }
                    if not second_stage_filter(row_dict, z_score=t):
                        preds_filtered[idx] = 0
            
            rep_filt = classification_report(y_ood, preds_filtered, output_dict=True, zero_division=0)
            
            rows.append({
                "Threshold (z)": t,
                "OOD Family": name,
                "Raw Recall": rep_raw['1']['recall'],
                "Raw Precision": rep_raw['1']['precision'],
                "Raw F1": rep_raw['1']['f1-score'],
                "Filt Recall": rep_filt['1']['recall'],
                "Filt Precision": rep_filt['1']['precision'],
                "Filt F1": rep_filt['1']['f1-score'],
            })

    df_res = pd.DataFrame(rows)
    pd.set_option('display.max_columns', None)
    pd.set_option('display.width', 1000)
    print("\n" + "=" * 80)
    print("COMPARATIVE CALIBRATION MATRIX (RAW VS SECOND-STAGE FILTERED)")
    print("=" * 80)
    print(df_res.to_string(index=False))
    print("=" * 80)

    # Save the calibrated assets
    os.makedirs("models", exist_ok=True)
    os.makedirs("models_real", exist_ok=True)
    
    # We save these calibrated assets
    joblib.dump(imputer, "models/imputer.pkl")
    joblib.dump(scaler, "models/scaler.pkl")
    joblib.dump(lr, "models/sgd_model.pkl") # We save our LogisticRegression model to sgd_model.pkl so it seamlessly drops into the pipeline
    
    joblib.dump(imputer, "models_real/imputer.pkl")
    joblib.dump(scaler, "models_real/scaler.pkl")
    joblib.dump(lr, "models_real/sgd_model.pkl")
    
    print("Calibrated model assets successfully saved to models/ and models_real/.")

if __name__ == "__main__":
    main()
