"""Reproduce and diagnose the legacy CTU-13 scenario 9 result (AUC 0.317).

    python -m evaluation.legacy_repro

Loads the shipped models/xgb_model.json + imputer_47/scaler_47 and replays what
train/online_evaluator.py did: all of scenario 9 (time order) through
lab.feature_adapter, with the old label map (Background counted as benign).
Prints one JSON object; numbers are quoted in docs/AUDIT.md.
"""
import json
import tomllib
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.metrics import roc_auc_score

from evaluation.download import CONFIG, CTU13_SCENARIOS, ctu13_class, fetch
from lab.feature_adapter import PHANTOMFLOW_FEATURES, UniversalAdapter


def scenario9() -> pd.DataFrame:
    cfg = tomllib.loads(CONFIG.read_text())
    src = cfg["sources"]["ctu13"]
    raw = Path(cfg["data_dir"]) / "raw" / "ctu13"
    parts = []
    for name, sha in src["files"]:
        df = pd.read_parquet(fetch(src["base_url"] + name, raw / name, sha),
                             columns=["Duration", "TotPkts", "TotBytes", "SrcBytes", "Label",
                                      "source_file", "dataset", "__index_level_0__"])
        df = df[(df["dataset"] == "merged_binetflow") & (df["source_file"].map(CTU13_SCENARIOS) == 9)]
        parts.append(df)
    df = pd.concat(parts).sort_values("__index_level_0__")
    return df.rename(columns={"Duration": "Dur"}).reset_index(drop=True)


def main() -> None:
    df = scenario9()
    cls = ctu13_class(df["Label"])
    head = cls.iloc[:100_000].value_counts().to_dict()
    X = UniversalAdapter()._adapt_ctu13(df)[PHANTOMFLOW_FEATURES].to_numpy(np.float32)
    X = np.where(np.isinf(X), np.nan, X)
    populated = int((~np.isnan(X)).any(axis=0).sum())
    m = Path("models")
    Xs = joblib.load(m / "scaler_47.pkl").transform(joblib.load(m / "imputer_47.pkl").transform(X))
    model = xgb.XGBClassifier()
    model.load_model(m / "xgb_model.json")
    p = model.predict_proba(Xs)

    y_old = (cls == "botnet").to_numpy()            # old map: background + normal = benign
    keep = (cls != "background").to_numpy()          # corrected: background excluded
    out = {
        "first_100k_class_counts": head,
        "rows": len(df),
        "class_counts": cls.value_counts().to_dict(),
        "features_populated_of_47": populated,
        "auc_c2_old_labels": roc_auc_score(y_old, p[:, 1]),
        "auc_c2_normal_only": roc_auc_score(y_old[keep], p[keep, 1]) if keep.any() else None,
        "auc_attack_any_old_labels": roc_auc_score(y_old, 1 - p[:, 0]),
        "predicted_class_share": np.bincount(p.argmax(1), minlength=4).tolist(),
        # Single raw features: >0.5 means larger values for botnet flows.
        "single_feature_auc_old_labels": {
            c: roc_auc_score(y_old, df[c].fillna(0)) for c in ["Dur", "TotPkts", "TotBytes", "SrcBytes"]
        },
    }
    print(json.dumps(out, indent=2, default=float))


if __name__ == "__main__":
    main()
