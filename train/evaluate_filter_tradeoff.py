# train/evaluate_filter_tradeoff.py
import numpy as np
import pandas as pd
import requests
import joblib
from sklearn.metrics import classification_report

np.__version__ = "2.1.3"  # Bypass numba checks if needed

def load_ctu13_virut(c2_keep_ratio: float = 1.00, benign_keep_ratio: float = 0.04) -> pd.DataFrame:
    cols = [
        "StartTime", "Dur", "Proto", "SrcAddr", "Sport",
        "Dir", "DstAddr", "Dport", "State", "sTos", "dTos",
        "TotPkts", "TotBytes", "SrcBytes", "Label"
    ]
    url = "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-54/detailed-bidirectional-flow-labels/capture20110815-3.binetflow"
    print("Streaming Scenario 13 (Virut)...")
    headers = {"User-Agent": "PhantomFlow-Research/1.0 (academic use)"}
    try:
        resp = requests.get(url, stream=True, headers=headers, timeout=30)
        resp.raise_for_status()
    except Exception as e:
        print(f"Failed to connect to Virut: {e}")
        return pd.DataFrame()
        
    all_rows = []
    np.random.seed(42)
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
        if line_count > 500000:
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

def run_filter(df_features, preds_raw, duration_cutoff):
    preds_filtered = preds_raw.copy()
    for idx in range(len(preds_raw)):
        if preds_raw[idx] == 1:
            row = df_features.iloc[idx]
            orig_bytes = row["orig_bytes"]
            resp_bytes = row["resp_bytes"]
            duration_s = row["duration_s"]
            
            # Rule 1: orig_bytes > 100MB -> block
            if orig_bytes > 100_000_000:
                preds_filtered[idx] = 0
                continue
            # Rule 2: duration < cutoff -> block
            if duration_s < duration_cutoff:
                preds_filtered[idx] = 0
                continue
            # Rule 3: symmetric ratio -> block
            byte_ratio = orig_bytes / max(resp_bytes, 1.0)
            if 0.95 < byte_ratio < 1.05:
                preds_filtered[idx] = 0
                continue
    return preds_filtered

def main():
    imputer = joblib.load("models/imputer.pkl")
    scaler = joblib.load("models/scaler.pkl")
    lr = joblib.load("models/sgd_model.pkl")

    df = load_ctu13_virut()
    if len(df) == 0:
        return
        
    X_raw = prepare_features(df)
    y_true = df["label"].values.astype(int)
    X_clean = np.where(np.isinf(X_raw), np.nan, X_raw)
    X_scaled = scaler.transform(imputer.transform(X_clean))

    dec = lr.decision_function(X_scaled)
    t = -7.0
    preds_raw = (dec >= t).astype(int)

    raw_report = classification_report(y_true, preds_raw, output_dict=True, zero_division=0)
    print(f"\nBaseline Raw model at z = {t}:")
    print(f"  Recall: {raw_report['1']['recall']*100:.2f}% | Precision: {raw_report['1']['precision']*100:.2f}% | F1: {raw_report['1']['f1-score']:.4f}")

    print("\nSweeping Duration Cutoffs for Second-Stage Filter:")
    print("=" * 80)
    print(f"{'Duration Cutoff':<18} | {'Recall':<10} | {'Precision':<10} | {'F1-Score':<10}")
    print("-" * 80)
    
    for cutoff in [0.0, 0.1, 0.3, 0.5, 1.0, 2.0]:
        preds_filtered = run_filter(X_raw, preds_raw, duration_cutoff=cutoff)
        rep = classification_report(y_true, preds_filtered, output_dict=True, zero_division=0)
        print(f"duration < {cutoff:<4}s     | {rep['1']['recall']*100:>8.2f}% | {rep['1']['precision']*100:>8.2f}% | {rep['1']['f1-score']:>8.4f}")
    print("=" * 80)

if __name__ == "__main__":
    main()
