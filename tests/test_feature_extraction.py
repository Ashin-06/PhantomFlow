import pytest

# ML stack is optional for the API-only CI job; requirements-eval.txt installs it.
for _mod in ("numpy", "pandas", "sklearn", "scipy", "xgboost"):
    pytest.importorskip(_mod)

import math

import numpy as np
import pandas as pd

from features.dns_features import DNSAnalyzer
from features.timing_features import BeaconTimingAnalyzer
from lab.feature_adapter import PHANTOMFLOW_FEATURES, UniversalAdapter


def test_periodic_beacon_has_low_iat_variation():
    regular = BeaconTimingAnalyzer().analyze([60.0 * i for i in range(30)])
    rng = np.random.default_rng(0)
    jittered = BeaconTimingAnalyzer().analyze(list(np.cumsum(rng.exponential(60, 30))))
    assert regular["iat_mean_ms"] == pytest.approx(60_000)
    assert regular["iat_cv"] < 0.01 < jittered["iat_cv"]


def test_dns_entropy_separates_encoded_subdomain():
    a = DNSAnalyzer()
    query = "aGVsbG8gd29ybGQgdGhpcyBpcyBleGZpbA.evil.example"
    benign = a.analyze("www.google.com", "10.0.0.1")
    tunnel = a.analyze(query, "10.0.0.1")
    assert tunnel["dns_shannon_entropy"] > benign["dns_shannon_entropy"]
    assert tunnel["dns_query_len"] == len(query)
    assert math.isfinite(tunnel["dns_vowel_ratio"])


def test_adapters_return_schema_and_consistent_semantics():
    ad = UniversalAdapter()
    cic = ad.adapt(pd.DataFrame({" Flow Duration": [2e6], " Total Fwd Packets": [3],
                                 " Total Backward Packets": [5], "Total Length of Fwd Packets": [300],
                                 " Total Length of Bwd Packets": [100], "label": [1]}), "cicids2017_friday")
    ctu = ad.adapt(pd.DataFrame({"Dur": [2.0], "TotPkts": [8], "TotBytes": [400], "SrcBytes": [300],
                                 "label": [1]}), "ctu13_scenario9")
    for out in (cic, ctu):
        assert list(out.columns) == PHANTOMFLOW_FEATURES + ["label"]
        assert out["duration_s"].iloc[0] == 2.0
        assert out["orig_bytes"].iloc[0] == 300 and out["resp_bytes"].iloc[0] == 100
    assert cic["orig_pkts"].iloc[0] == 3            # originator packets, not fwd + bwd
    assert np.isnan(ctu["orig_pkts"].iloc[0])       # Argus has no per-side packet count
    assert np.isnan(cic["failed_connection_ratio"].iloc[0])
