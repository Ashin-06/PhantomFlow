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


def cicids_frame(raw: pd.DataFrame) -> pd.DataFrame:
    """Raw cicids2017.parquet rows -> FEATURES + label, capture, order."""
    raw = raw[raw["label_raw"].isin(CICIDS_CLASSES)]
    out = pd.DataFrame({
        "duration_s": raw["duration_us"] / 1e6,
        "tot_pkts": raw["fwd_pkts"] + raw["bwd_pkts"],
        "tot_bytes": raw["fwd_bytes"] + raw["bwd_bytes"],
        "src_bytes": raw["fwd_bytes"],
        "dst_port": raw["dst_port"],
    })
    out = _derived(out)
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
