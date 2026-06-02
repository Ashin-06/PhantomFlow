# lab/feature_adapter.py
"""
Each dataset has different column names.
This maps every dataset to PhantomFlow's unified feature schema.
Missing features stay NaN — handled downstream by imputer.
"""

import numpy as np
import pandas as pd
from typing import Dict, Optional


PHANTOMFLOW_FEATURES = [
    "duration_s", "iat_mean_ms", "iat_std_ms", "iat_cv",
    "iat_min_ms", "iat_max_ms", "iat_median_ms",
    "pkt_size_mean", "pkt_size_std", "pkt_size_min",
    "pkt_size_max", "pkt_size_entropy", "small_pkt_ratio", "large_pkt_ratio",
    "total_bytes", "orig_bytes", "resp_bytes", "bytes_ratio",
    "orig_pkts", "resp_pkts", "pkt_ratio",
    "periodicity_score", "dominant_period_ms", "iat_skewness", "iat_kurtosis",
    "sni_entropy", "sni_len", "tls_resumed",
    "ja3_malware_score", "ja4_malware_score",
    "cert_validity_days", "cert_self_signed",
    "dns_query_len", "dns_label_count", "dns_max_label_len",
    "dns_unique_chars", "dns_shannon_entropy", "dns_bigram_entropy",
    "dns_vowel_ratio", "dns_digit_ratio", "dns_hyphen_ratio",
    "dns_is_ip_encoded", "dns_consecutive_digits", "dns_longest_run",
    "connection_count_1m", "connection_count_5m", "failed_connection_ratio",
]


class UniversalAdapter:
    """
    Adapts any dataset chunk to PhantomFlow's feature schema.
    Fills missing features with NaN — imputer handles them later.
    Derives computable features from available columns.
    """

    def adapt(self, df: pd.DataFrame, dataset_key: str) -> pd.DataFrame:
        """Route to correct adapter based on dataset."""
        # Strict Anti-Leakage: Purge identity artifacts and secondary label columns
        PURGE_COLS = [
            'Flow ID', 'Source IP', 'Destination IP',
            'Src IP', 'Dst IP', 'src_ip', 'dst_ip',
            'Source Port', 'Destination Port',
            'Timestamp', 'StartTime', 'Src Port', 'Dst Port',
            'Label', 'Flow Bytes/s', 'Flow Packets/s'
        ]
        df = df.drop(columns=[col for col in PURGE_COLS if col in df.columns], errors="ignore")

        # If the input DataFrame is already fully adapted (e.g. from our mock generator),
        # preserve it directly to avoid wiping out the high-fidelity features.
        if all(col in df.columns for col in PHANTOMFLOW_FEATURES):
            out = df[PHANTOMFLOW_FEATURES].copy()
            out["label"] = df.get("label", 0)
            return out

        if "cicids" in dataset_key:
            return self._adapt_cicids(df)
        elif "ctu13" in dataset_key:
            return self._adapt_ctu13(df)
        elif "unsw" in dataset_key:
            return self._adapt_unsw(df)
        elif "dns" in dataset_key:
            return self._adapt_dns_only(df)
        elif "kdd" in dataset_key:
            return self._adapt_kdd(df)
        else:
            return self._adapt_generic(df)

    def _adapt_cicids(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        CICIDS 2017/2018 feature mapping.
        Best overlap with PhantomFlow — has IAT stats and packet length stats.
        """
        out = pd.DataFrame(np.nan, index=df.index, columns=PHANTOMFLOW_FEATURES)

        # Strip spaces from column names (CICIDS has leading spaces)
        df.columns = df.columns.str.strip()

        def safe(col, divisor=1.0):
            if col in df.columns:
                return pd.to_numeric(df[col], errors="coerce") / divisor
            return np.nan

        # Direct mappings (with unit conversions)
        out["duration_s"]       = safe("Flow Duration", 1e6)     # μs → s
        out["iat_mean_ms"]      = safe("Fwd IAT Mean", 1000)     # μs → ms
        out["iat_std_ms"]       = safe("Fwd IAT Std", 1000)
        out["iat_min_ms"]       = safe("Fwd IAT Min", 1000)
        out["iat_max_ms"]       = safe("Fwd IAT Max", 1000)
        out["pkt_size_mean"]    = safe("Fwd Packet Length Mean")
        out["pkt_size_std"]     = safe("Fwd Packet Length Std")
        out["pkt_size_min"]     = safe("Fwd Packet Length Min")
        out["pkt_size_max"]     = safe("Fwd Packet Length Max")
        out["orig_bytes"]       = safe("Total Length of Fwd Packets")
        out["resp_bytes"]       = safe("Total Length of Bwd Packets")
        out["orig_pkts"]        = pd.Series(safe("Total Fwd Packets"), index=df.index).fillna(0) + pd.Series(safe("Total Backward Packets"), index=df.index).fillna(0)
        out["resp_pkts"]        = safe("Total Backward Packets")
        out["failed_connection_ratio"] = safe("RST Flag Count")  # approximate

        # Derived (always compute if source columns exist)
        out["total_bytes"] = out["orig_bytes"].fillna(0) + out["resp_bytes"].fillna(0)
        out["bytes_ratio"] = out["orig_bytes"] / (out["resp_bytes"] + 1)
        out["pkt_ratio"]   = out["orig_pkts"] / (out["resp_pkts"] + 1)
        out["iat_cv"]      = out["iat_std_ms"] / (out["iat_mean_ms"].abs() + 1e-9)

        # Approximate small/large packet ratios from min/max
        out["small_pkt_ratio"] = (out["pkt_size_min"] < 100).astype(float)
        out["large_pkt_ratio"] = (out["pkt_size_max"] > 1400).astype(float)

        out["label"] = df.get("label", 0)
        return out

    def _adapt_ctu13(self, df: pd.DataFrame) -> pd.DataFrame:
        """CTU-13 binetflow — fewer features available."""
        out = pd.DataFrame(np.nan, index=df.index, columns=PHANTOMFLOW_FEATURES)

        out["duration_s"]   = pd.to_numeric(df.get("Dur", np.nan), errors="coerce")
        out["total_bytes"]  = pd.to_numeric(df.get("TotBytes", np.nan), errors="coerce")
        out["orig_bytes"]   = pd.to_numeric(df.get("SrcBytes", np.nan), errors="coerce")
        out["orig_pkts"]    = pd.to_numeric(df.get("TotPkts", np.nan), errors="coerce")
        out["resp_bytes"]   = out["total_bytes"] - out["orig_bytes"].fillna(0)
        out["bytes_ratio"]  = out["orig_bytes"] / (out["resp_bytes"] + 1)
        out["label"] = df.get("label", 0)
        return out

    def _adapt_unsw(self, df: pd.DataFrame) -> pd.DataFrame:
        """UNSW-NB15 feature mapping — 49 features with good overlap."""
        out = pd.DataFrame(np.nan, index=df.index, columns=PHANTOMFLOW_FEATURES)

        def safe(col):
            return pd.to_numeric(df[col], errors="coerce") if col in df.columns else np.nan

        out["duration_s"]    = safe("dur")
        out["orig_bytes"]    = safe("sbytes")
        out["resp_bytes"]    = safe("dbytes")
        out["orig_pkts"]     = pd.Series(safe("spkts"), index=df.index).fillna(0) + pd.Series(safe("dpkts"), index=df.index).fillna(0)
        out["resp_pkts"]     = safe("dpkts")
        out["total_bytes"]   = safe("sbytes") + safe("dbytes")
        out["bytes_ratio"]   = safe("sbytes") / (safe("dbytes") + 1)
        out["pkt_size_mean"] = safe("smeansz")
        out["failed_connection_ratio"] = safe("synack")  # approximate

        out["label"] = df.get("label", 0)
        return out

    def _adapt_dns_only(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        DNS-only datasets — compute all DNS features from raw query string.
        This is the only dataset that populates dns_* features properly.
        """
        from features.dns_features import DNSAnalyzer
        analyzer = DNSAnalyzer()

        out = pd.DataFrame(np.nan, index=df.index, columns=PHANTOMFLOW_FEATURES)

        for idx, row in df.iterrows():
            query = str(row.get("dns_query", ""))
            if not query:
                continue
            dns_feat = analyzer.analyze(query, "0.0.0.0")
            for feat_name, feat_val in dns_feat.items():
                if feat_name in PHANTOMFLOW_FEATURES:
                    out.at[idx, feat_name] = float(feat_val)

        out["label"] = df.get("label", 0)
        return out

    def _adapt_kdd(self, df: pd.DataFrame) -> pd.DataFrame:
        """KDD99 — minimal mapping, testing only."""
        out = pd.DataFrame(np.nan, index=df.index, columns=PHANTOMFLOW_FEATURES)
        out["duration_s"]            = pd.to_numeric(df.get("duration", 0), errors="coerce")
        out["orig_bytes"]            = pd.to_numeric(df.get("src_bytes", 0), errors="coerce")
        out["resp_bytes"]            = pd.to_numeric(df.get("dst_bytes", 0), errors="coerce")
        out["total_bytes"]           = out["orig_bytes"].fillna(0) + out["resp_bytes"].fillna(0)
        out["bytes_ratio"]           = out["orig_bytes"] / (out["resp_bytes"] + 1)
        out["connection_count_1m"]   = pd.to_numeric(df.get("count", 0), errors="coerce")
        out["failed_connection_ratio"]= pd.to_numeric(df.get("serror_rate", 0), errors="coerce")
        out["label"] = df.get("label", 0)
        return out

    def _adapt_generic(self, df: pd.DataFrame) -> pd.DataFrame:
        """Best-effort for unknown dataset — map by column name similarity."""
        out = pd.DataFrame(np.nan, index=df.index, columns=PHANTOMFLOW_FEATURES)
        out["label"] = df.get("label", 0)
        return out
