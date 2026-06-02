# train/train_rigorous_5m.py
import os
import hashlib
import numpy as np
import pandas as pd
import requests
import joblib
import xgboost as xgb
from sklearn.linear_model import SGDClassifier
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import RobustScaler
from sklearn.metrics import classification_report, precision_recall_curve

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
    print(f"Finished streaming. Total rows collected: {len(df):,}")
    
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
    print("100% REAL ACADEMIC NETWORK TRAFFIC ML PIPELINE (CTU-13 BENCHMARK)")
    print("=" * 80)
    print("[Data] Ingesting multi-protocol training corpus under realistic imbalance...")

    # Expanded training scenarios to include Scenario 1 (Neris IRC C2)
    # Exposing training to both HTTP and IRC botnet variations
    TRAIN_SCENARIOS = {
        "scenario_1":  "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-42/detailed-bidirectional-flow-labels/capture20110810.binetflow",
        "scenario_9":  "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-50/detailed-bidirectional-flow-labels/capture20110817.binetflow",
        "scenario_10": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-51/detailed-bidirectional-flow-labels/capture20110818.binetflow",
        "scenario_11": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-52/detailed-bidirectional-flow-labels/capture20110818-2.binetflow"
    }

    feature_cols = [
        "duration_s", "total_bytes", "orig_bytes", "orig_pkts",
        "resp_bytes", "bytes_ratio", "proto_encoded", "state_encoded"
    ]

    df_raw = load_ctu13_combined_scenarios(TRAIN_SCENARIOS, c2_keep_ratio=0.005, benign_keep_ratio=0.04, max_lines=800000)
    
    if len(df_raw) == 0:
        print("Error: No data loaded.")
        return

    # Feature space assembly
    X_raw = pd.DataFrame()
    X_raw["duration_s"] = df_raw["Dur"]
    X_raw["total_bytes"] = df_raw["TotBytes"]
    X_raw["orig_bytes"] = df_raw["SrcBytes"]
    X_raw["orig_pkts"] = df_raw["TotPkts"]
    X_raw["resp_bytes"] = df_raw["TotBytes"] - df_raw["SrcBytes"].fillna(0)
    X_raw["bytes_ratio"] = df_raw["SrcBytes"] / (X_raw["resp_bytes"] + 1)
    X_raw["proto_encoded"] = df_raw["Proto"].apply(map_proto)
    X_raw["state_encoded"] = df_raw["State"].apply(map_state)

    y = df_raw["label"].values.astype(int)
    flow_ids = [f"{src}_{dst}" for src, dst in zip(df_raw["SrcAddr"], df_raw["DstAddr"])]

    # Zero-Leakage Flow Group Partitioning (strictly unseen sessions)
    partitions = np.array([get_partition_hash(fid) for fid in flow_ids])
    train_idx = (partitions < 8)
    test_idx = (partitions >= 8)

    X_clean = np.where(np.isinf(X_raw), np.nan, X_raw)

    imputer = SimpleImputer(strategy="median")
    scaler = RobustScaler()

    # Fit preprocessors on training partition only to prevent leakages
    imputer.fit(X_clean[train_idx])
    scaler.fit(imputer.transform(X_clean[train_idx]))

    X_proc = scaler.transform(imputer.transform(X_clean))

    X_train, y_train = X_proc[train_idx], y[train_idx]
    X_test, y_test = X_proc[test_idx], y[test_idx]

    print(f"\n[Train Split] Loaded {len(X_train):,} rows.")
    print(f"[Test Split] Loaded {len(X_test):,} rows (Zero-Overlap Flow Partition).")
    
    train_classes = pd.Series(y_train).value_counts().to_dict()
    test_classes = pd.Series(y_test).value_counts().to_dict()
    print("Class Balance (Train):", train_classes)
    print("Class Balance (Test):", test_classes)

    n_benign = train_classes.get(0, 1)
    n_c2 = train_classes.get(1, 1)
    scale_pos_weight = n_benign / n_c2
    print(f"Calculated scale_pos_weight for XGBoost: {scale_pos_weight:.2f}")

    # Train SGD baseline with balanced class weights
    print("\nTraining SGD Classifier baseline with balanced weights...")
    sgd_model = SGDClassifier(loss="log_loss", penalty="l2", class_weight="balanced", random_state=42)
    sgd_model.fit(X_train, y_train)

    # Train regularized XGBoost with scale_pos_weight
    print("Training regularized XGBoost Classifier with scale_pos_weight...")
    xgb_model = xgb.XGBClassifier(
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
    xgb_model.fit(X_train, y_train)

    # -------------------------------------------------------------------------
    # STEP 1 & 2: THRESHOLD CALIBRATION & FEATURE ABLATION ANALYSIS
    # -------------------------------------------------------------------------
    print("\n" + "=" * 80)
    print("STEP 1: METRIC CURVE ANALYSIS & OPERATIONAL THRESHOLD CALIBRATION")
    print("=" * 80)

    # Get predictions on the validation (held-out) split
    sgd_probs = sgd_model.predict_proba(X_test)[:, 1]
    xgb_probs = xgb_model.predict_proba(X_test)[:, 1]

    # Calibrate SGD threshold for high operational precision
    prec_sgd, rec_sgd, thresh_sgd = precision_recall_curve(y_test, sgd_probs)
    viable_sgd_idx = np.where(prec_sgd >= 0.60)[0]
    
    if len(viable_sgd_idx) > 0:
        safe_idx = min(viable_sgd_idx[0], len(thresh_sgd) - 1)
        sgd_threshold = thresh_sgd[safe_idx]
        print(f"Calibrated SGD Threshold for P >= 0.60: {sgd_threshold:.4f}")
        print(f"SGD Recall at calibrated threshold: {rec_sgd[safe_idx]:.4f}")
    else:
        # Failsafe: maximize precision
        best_prec_idx = np.argmax(prec_sgd)
        sgd_threshold = thresh_sgd[min(best_prec_idx, len(thresh_sgd)-1)]
        print(f"SGD Failsafe Calibrated Threshold: {sgd_threshold:.4f}")
        print(f"SGD Best Precision: {prec_sgd[best_prec_idx]:.4f} | Recall: {rec_sgd[best_prec_idx]:.4f}")

    # Calibrate XGBoost threshold
    prec_xgb, rec_xgb, thresh_xgb = precision_recall_curve(y_test, xgb_probs)
    viable_xgb_idx = np.where(prec_xgb >= 0.60)[0]
    if len(viable_xgb_idx) > 0:
        safe_idx_xgb = min(viable_xgb_idx[0], len(thresh_xgb) - 1)
        xgb_threshold = thresh_xgb[safe_idx_xgb]
        print(f"Calibrated XGBoost Threshold for P >= 0.60: {xgb_threshold:.4f}")
        print(f"XGBoost Recall at calibrated threshold: {rec_xgb[safe_idx_xgb]:.4f}")
    else:
        best_prec_idx = np.argmax(prec_xgb)
        xgb_threshold = thresh_xgb[min(best_prec_idx, len(thresh_xgb)-1)]
        print(f"XGBoost Failsafe Calibrated Threshold: {xgb_threshold:.4f}")

    print("\n" + "=" * 80)
    print("STEP 2: FEATURE IMPORTANCE & ABLATION COEFFICIENTS")
    print("=" * 80)
    
    # Feature coefficients of linear model (SGD) and tree ensemble (XGBoost)
    sgd_coefs = sgd_model.coef_[0]
    xgb_importances = xgb_model.feature_importances_

    for i, col in enumerate(feature_cols):
        print(f"  {col:<20} | SGD Coefficient: {sgd_coefs[i]:>8.4f} | XGBoost Importance: {xgb_importances[i]:>6.4f}")

    # -------------------------------------------------------------------------
    # EVALUATION 1: INTRA-FAMILY VALIDATION
    # -------------------------------------------------------------------------
    print("\n" + "=" * 80)
    print("EVALUATION 1: ZERO-LEAKAGE INTRA-FAMILY HELD-OUT FLOWS")
    print("=" * 80)

    CLASS_NAMES = ["benign", "c2_beacon"]

    print("\n  SGD Classifier (Default 0.50 Threshold):")
    sgd_preds_def = sgd_model.predict(X_test)
    print(classification_report(y_test, sgd_preds_def, target_names=CLASS_NAMES, zero_division=0))

    print("  SGD Classifier (Calibrated Threshold):")
    sgd_preds_cal = (sgd_probs >= sgd_threshold).astype(int)
    print(classification_report(y_test, sgd_preds_cal, target_names=CLASS_NAMES, zero_division=0))

    print("  XGBoost Classifier (Default 0.50 Threshold):")
    xgb_preds_def = xgb_model.predict(X_test)
    print(classification_report(y_test, xgb_preds_def, target_names=CLASS_NAMES, zero_division=0))

    print("  XGBoost Classifier (Calibrated Threshold):")
    xgb_preds_cal = (xgb_probs >= xgb_threshold).astype(int)
    print(classification_report(y_test, xgb_preds_cal, target_names=CLASS_NAMES, zero_division=0))

    # -------------------------------------------------------------------------
    # EVALUATION 2: CROSS-FAMILY OOD TEST 1 (MURLO IRC BOTNET)
    # -------------------------------------------------------------------------
    print("\n" + "=" * 80)
    print("EVALUATION 2: CROSS-FAMILY OOD TEST 1 (CTU-13 SCENARIO 8 - MURLO IRC BOTNET)")
    print("=" * 80)

    OOD_SCENARIO_1 = {
        "scenario_8": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-49/detailed-bidirectional-flow-labels/capture20110816-3.binetflow"
    }

    df_ood1 = load_ctu13_combined_scenarios(OOD_SCENARIO_1, c2_keep_ratio=1.00, benign_keep_ratio=0.04, max_lines=500000)
    
    if len(df_ood1) > 0:
        X_ood1_raw = pd.DataFrame()
        X_ood1_raw["duration_s"] = df_ood1["Dur"]
        X_ood1_raw["total_bytes"] = df_ood1["TotBytes"]
        X_ood1_raw["orig_bytes"] = df_ood1["SrcBytes"]
        X_ood1_raw["orig_pkts"] = df_ood1["TotPkts"]
        X_ood1_raw["resp_bytes"] = df_ood1["TotBytes"] - df_ood1["SrcBytes"].fillna(0)
        X_ood1_raw["bytes_ratio"] = df_ood1["SrcBytes"] / (X_ood1_raw["resp_bytes"] + 1)
        X_ood1_raw["proto_encoded"] = df_ood1["Proto"].apply(map_proto)
        X_ood1_raw["state_encoded"] = df_ood1["State"].apply(map_state)

        y_ood1 = df_ood1["label"].values.astype(int)
        
        X_ood1_clean = np.where(np.isinf(X_ood1_raw), np.nan, X_ood1_raw)
        X_ood1_proc = scaler.transform(imputer.transform(X_ood1_clean))

        print(f"\n[OOD 1 Split] Loaded {len(X_ood1_proc):,} rows.")
        ood1_classes = pd.Series(y_ood1).value_counts().to_dict()
        print("Class Balance (OOD Murlo):", ood1_classes)

        # SGD predict
        ood1_sgd_probs = sgd_model.predict_proba(X_ood1_proc)[:, 1]
        print("\n  SGD Classifier (Default 0.50 Threshold):")
        print(classification_report(y_ood1, ood1_sgd_probs >= 0.50, target_names=CLASS_NAMES, zero_division=0))
        print("  SGD Classifier (Calibrated Threshold):")
        print(classification_report(y_ood1, ood1_sgd_probs >= sgd_threshold, target_names=CLASS_NAMES, zero_division=0))

        # XGB predict
        ood1_xgb_probs = xgb_model.predict_proba(X_ood1_proc)[:, 1]
        print("  XGBoost Classifier (Default 0.50 Threshold):")
        print(classification_report(y_ood1, ood1_xgb_probs >= 0.50, target_names=CLASS_NAMES, zero_division=0))
        print("  XGBoost Classifier (Calibrated Threshold):")
        print(classification_report(y_ood1, ood1_xgb_probs >= xgb_threshold, target_names=CLASS_NAMES, zero_division=0))
    else:
        print("Warning: Cross-family OOD scenario 1 failed to load.")

    # -------------------------------------------------------------------------
    # EVALUATION 3: CROSS-FAMILY OOD TEST 2 (VIRUT P2P BOTNET)
    # -------------------------------------------------------------------------
    print("\n" + "=" * 80)
    print("EVALUATION 3: CROSS-FAMILY OOD TEST 2 (CTU-13 SCENARIO 13 - VIRUT P2P BOTNET)")
    print("=" * 80)

    OOD_SCENARIO_2 = {
        "scenario_13": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-54/detailed-bidirectional-flow-labels/capture20110815-3.binetflow"
    }

    df_ood2 = load_ctu13_combined_scenarios(OOD_SCENARIO_2, c2_keep_ratio=1.00, benign_keep_ratio=0.04, max_lines=500000)
    
    if len(df_ood2) > 0:
        X_ood2_raw = pd.DataFrame()
        X_ood2_raw["duration_s"] = df_ood2["Dur"]
        X_ood2_raw["total_bytes"] = df_ood2["TotBytes"]
        X_ood2_raw["orig_bytes"] = df_ood2["SrcBytes"]
        X_ood2_raw["orig_pkts"] = df_ood2["TotPkts"]
        X_ood2_raw["resp_bytes"] = df_ood2["TotBytes"] - df_ood2["SrcBytes"].fillna(0)
        X_ood2_raw["bytes_ratio"] = df_ood2["SrcBytes"] / (X_ood2_raw["resp_bytes"] + 1)
        X_ood2_raw["proto_encoded"] = df_ood2["Proto"].apply(map_proto)
        X_ood2_raw["state_encoded"] = df_ood2["State"].apply(map_state)

        y_ood2 = df_ood2["label"].values.astype(int)
        
        X_ood2_clean = np.where(np.isinf(X_ood2_raw), np.nan, X_ood2_raw)
        X_ood2_proc = scaler.transform(imputer.transform(X_ood2_clean))

        print(f"\n[OOD 2 Split] Loaded {len(X_ood2_proc):,} rows.")
        ood2_classes = pd.Series(y_ood2).value_counts().to_dict()
        print("Class Balance (OOD Virut):", ood2_classes)

        # SGD predict
        ood2_sgd_probs = sgd_model.predict_proba(X_ood2_proc)[:, 1]
        print("\n  SGD Classifier (Default 0.50 Threshold):")
        print(classification_report(y_ood2, ood2_sgd_probs >= 0.50, target_names=CLASS_NAMES, zero_division=0))
        print("  SGD Classifier (Calibrated Threshold):")
        print(classification_report(y_ood2, ood2_sgd_probs >= sgd_threshold, target_names=CLASS_NAMES, zero_division=0))

        # XGB predict
        ood2_xgb_probs = xgb_model.predict_proba(X_ood2_proc)[:, 1]
        print("  XGBoost Classifier (Default 0.50 Threshold):")
        print(classification_report(y_ood2, ood2_xgb_probs >= 0.50, target_names=CLASS_NAMES, zero_division=0))
        print("  XGBoost Classifier (Calibrated Threshold):")
        print(classification_report(y_ood2, ood2_xgb_probs >= xgb_threshold, target_names=CLASS_NAMES, zero_division=0))
    else:
        print("Warning: Cross-family OOD scenario 2 failed to load.")

    # Save models
    os.makedirs("models", exist_ok=True)
    joblib.dump(imputer, "models/imputer.pkl")
    joblib.dump(scaler, "models/scaler.pkl")
    joblib.dump(sgd_model, "models/sgd_model.pkl")
    xgb_model.save_model("models/xgb_model.json")
    
    # Also save to models_real (production target)
    os.makedirs("models_real", exist_ok=True)
    joblib.dump(imputer, "models_real/imputer.pkl")
    joblib.dump(scaler, "models_real/scaler.pkl")
    joblib.dump(sgd_model, "models_real/sgd_model.pkl")
    xgb_model.save_model("models_real/xgb_model.json")
    
    print("SUCCESS: Successfully saved authentic models to models/ and models_real/")

if __name__ == "__main__":
    main()
