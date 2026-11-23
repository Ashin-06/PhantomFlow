import pytest

# ML stack is optional for the API-only CI job; requirements-eval.txt installs it.
for _mod in ("numpy", "pandas", "sklearn", "scipy", "xgboost"):
    pytest.importorskip(_mod)

import numpy as np
import pandas as pd

from evaluation.download import ctu13_class
from evaluation.features import FEATURES, capture_normalise, cicids_frame, time_split


def test_ctu13_labels_use_substrings_and_keep_background_apart():
    labels = pd.Series([
        "flow=From-Botnet-V50-1-TCP-CC73-Not-Encrypted",
        "flow=To-Normal-V50-UDP-NTP-server",
        "flow=From-Normal-V50-Grill",
        "flow=Background-TCP-Established",
        "flow=To-Background-UDP-CVUT-DNS-Server",
    ])
    assert ctu13_class(labels).tolist() == ["botnet", "normal", "normal", "background", "background"]


def _cicids_raw():
    return pd.DataFrame({
        "ts": pd.to_datetime(["2017-07-03 09:00", "2017-07-07 10:00", "2017-07-07 10:01", "2017-07-07 10:02"]),
        "src_ip": "a", "dst_ip": "b", "dst_port": [443, 8080, 8080, 80], "proto": 6,
        "duration_us": [2e6, 1e6, 0, 5e5], "fwd_pkts": [3, 2, 1, 4], "bwd_pkts": [1, 2, 0, 0],
        "fwd_bytes": [300, 100, 0, 0], "bwd_bytes": [100, 100, 0, 0],
        "label_raw": ["BENIGN", "Botnet", "Botnet - Attempted", "Portscan"],
        "day": ["monday", "friday", "friday", "friday"],
    })


def test_cicids_frame_drops_attempted_and_derives_features():
    df = cicids_frame(_cicids_raw())
    assert df["label"].tolist() == ["benign", "botnet", "portscan"]
    assert set(FEATURES) <= set(df.columns)
    first = df.iloc[0]
    assert first["duration_s"] == 2.0 and first["tot_pkts"] == 4 and first["tot_bytes"] == 400
    assert first["bytes_per_pkt"] == 100 and first["src_byte_frac"] == 0.75
    assert np.isnan(df.iloc[2]["src_byte_frac"])  # 0 / 0 bytes is missing, not 0 or inf


def test_time_split_keeps_each_class_in_time_order():
    df = pd.DataFrame({"label": ["x"] * 10 + ["y"] * 5, "order": list(range(10)) + list(range(100, 105))})
    split = time_split(df)
    for _, g in df.assign(split=split).groupby("label"):
        tr, va, te = (g.loc[g["split"] == s, "order"] for s in ("train", "val", "test"))
        assert len(tr) and len(te)
        assert tr.max() < te.min()
        assert va.empty or tr.max() < va.min() <= va.max() < te.min()
    assert (split[:10] == "train").sum() == 6


def test_capture_normalise_uses_each_captures_own_reference():
    feats = ["tot_bytes", "dst_port"]
    df = pd.DataFrame({"capture": ["a", "a", "b", "b"], "tot_bytes": [10.0, 1000.0, 10.0, 1000.0],
                       "dst_port": [80.0, 80.0, 80.0, 80.0]})
    ref = pd.DataFrame({"capture": ["a"] * 3 + ["b"] * 3,
                        "tot_bytes": [5.0, 10.0, 20.0, 500.0, 1000.0, 2000.0], "dst_port": 0.0})
    out = capture_normalise(df, ref, feats)
    assert out.loc[0, "tot_bytes"] == pytest.approx(0.0)   # median of capture a
    assert out.loc[3, "tot_bytes"] == pytest.approx(0.0)   # median of capture b
    assert (out["dst_port"] == 80).all()                   # ports are categorical, left as is
    with pytest.raises(ValueError):
        capture_normalise(df, ref[ref["capture"] == "a"], feats)
