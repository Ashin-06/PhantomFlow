"""Flow features shared by CICIDS2017 (CICFlowMeter) and CTU-13 (Argus binetflow).

Only fields both tools export are used, so within- and cross-dataset numbers
are computed on the same inputs. Known mismatch: CICFlowMeter byte counts are
payload bytes, Argus counts include headers.
"""
import numpy as np
import pandas as pd

FEATURES = ["duration_s", "tot_pkts", "tot_bytes", "src_bytes",
            "bytes_per_pkt", "src_byte_frac", "dst_port"]

# Corrected-CICIDS2017 label -> evaluation class. Labels not listed are dropped:
# "... - Attempted" flows (attack attempts that carried no attack payload,
# Engelen et al.) and classes too small to split by time (Infiltration: 36
# flows, Heartbleed: 11).
CICIDS_CLASSES = {
    "BENIGN": "benign",
    "Botnet": "botnet",
    "Portscan": "portscan", "Infiltration - Portscan": "portscan",
    "DDoS": "ddos",
    "DoS Hulk": "dos", "DoS GoldenEye": "dos", "DoS Slowloris": "dos", "DoS Slowhttptest": "dos",
    "FTP-Patator": "bruteforce", "SSH-Patator": "bruteforce",
    "Web Attack - Brute Force": "webattack", "Web Attack - XSS": "webattack",
    "Web Attack - SQL Injection": "webattack",
}


def _derived(out: pd.DataFrame) -> pd.DataFrame:
    out["bytes_per_pkt"] = out["tot_bytes"] / out["tot_pkts"].replace(0, np.nan)
    out["src_byte_frac"] = out["src_bytes"] / out["tot_bytes"].replace(0, np.nan)
    return out


def cicids_reference(raw: pd.DataFrame) -> pd.DataFrame:
    """Every flow of each CICIDS2017 day, labels ignored: normalisation reference."""
    out = _cicids_features(raw)
    out["capture"] = "cicids2017-" + raw["day"]
    return out


def ctu13_reference(bg: pd.DataFrame) -> pd.DataFrame:
    """Background sample of each CTU-13 scenario: normalisation reference."""
    out = _derived(bg[["duration_s", "tot_pkts", "tot_bytes", "src_bytes", "dst_port"]].astype(float))
    out["capture"] = "ctu13-s" + bg["scenario"].astype(str)
    return out


def capture_normalise(df: pd.DataFrame, ref: pd.DataFrame, feats: list) -> pd.DataFrame:
    """log1p, then centre and scale each capture by its own median and IQR.

    The statistics come from `ref`, the unlabelled traffic of the same capture,
    so no labels are used and the test captures need no labels either. This
    removes per-capture scale differences (tool byte-counting conventions,
    network speed), not differences in behaviour.
    """
    cols = [f for f in feats if f != "dst_port"]
    out = df.copy()
    for cap, idx in out.groupby("capture").groups.items():
        r = np.log1p(ref.loc[ref["capture"] == cap, cols].clip(lower=0))
        if r.empty:
            raise ValueError(f"no reference traffic for capture {cap}")
        iqr = (r.quantile(0.75) - r.quantile(0.25)).replace(0, 1.0)
        out.loc[idx, cols] = (np.log1p(out.loc[idx, cols].clip(lower=0)) - r.median()) / iqr
    return out


def _cicids_features(raw: pd.DataFrame) -> pd.DataFrame:
    out = pd.DataFrame({
        "duration_s": raw["duration_us"] / 1e6,
        "tot_pkts": raw["fwd_pkts"] + raw["bwd_pkts"],
        "tot_bytes": raw["fwd_bytes"] + raw["bwd_bytes"],
        "src_bytes": raw["fwd_bytes"],
        "dst_port": raw["dst_port"],
    }).astype(float)
    return _derived(out)


def cicids_frame(raw: pd.DataFrame) -> pd.DataFrame:
    """Raw cicids2017.parquet rows -> FEATURES + label, capture, order."""
    raw = raw[raw["label_raw"].isin(CICIDS_CLASSES)]
    out = _cicids_features(raw)
    out["label"] = raw["label_raw"].map(CICIDS_CLASSES)
    out["capture"] = "cicids2017-" + raw["day"]
    out["order"] = raw["ts"].rank(method="first").to_numpy()
    return out.reset_index(drop=True)


def ctu13_frame(raw: pd.DataFrame) -> pd.DataFrame:
    """Raw ctu13.parquet rows (background already removed) -> same schema."""
    out = raw[["duration_s", "tot_pkts", "tot_bytes", "src_bytes", "dst_port"]].astype(float)
    out = _derived(out)
    out["label"] = raw["cls"].map({"normal": "benign", "botnet": "botnet"})
    out["capture"] = "ctu13-s" + raw["scenario"].astype(str)
    out["scenario"] = raw["scenario"]
    out["order"] = raw["order"]
    return out.reset_index(drop=True)


def time_split(df: pd.DataFrame, fracs=(0.6, 0.2, 0.2)) -> pd.Series:
    """Chronological train/val/test inside each class.

    Each attack ran in one window, so a single global cut would leave whole
    classes out of training. Splitting each class by time keeps every class
    in every split while the test flows are always later than the training
    flows of the same class.
    """
    q = df.groupby("label")["order"].rank(method="first", pct=True)
    a, b = fracs[0], fracs[0] + fracs[1]
    return pd.Series(np.select([q <= a, q <= b], ["train", "val"], "test"), index=df.index)
