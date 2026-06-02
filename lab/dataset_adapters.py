# lab/dataset_adapters.py
"""
Each dataset has different column names.
These adapters normalize everything to PhantomFlow's feature schema.
NEVER zero out features — use only datasets that have the feature,
or clearly document which features are dataset-specific.
"""

import pandas as pd
import numpy as np
from typing import Optional


class CICIDSAdapter:
    """
    Adapter for CICIDS 2017/2018.
    These datasets have IAT stats, packet length stats —
    the closest public dataset to PhantomFlow's actual features.
    """

    # CICIDS column → PhantomFlow column
    COLUMN_MAP = {
        "Flow Duration":           "duration_s",          # microseconds → divide by 1e6
        "Fwd IAT Mean":            "iat_mean_ms",         # microseconds → divide by 1000
        "Fwd IAT Std":             "iat_std_ms",
        "Fwd IAT Min":             "iat_min_ms",
        "Fwd IAT Max":             "iat_max_ms",
        "Fwd Packet Length Mean":  "pkt_size_mean",
        "Fwd Packet Length Std":   "pkt_size_std",
        "Fwd Packet Length Min":   "pkt_size_min",
        "Fwd Packet Length Max":   "pkt_size_max",
        "Total Length of Fwd Packets": "orig_bytes",
        "Total Length of Bwd Packets": "resp_bytes",
        "Total Fwd Packets":       "orig_pkts",
        "Total Backward Packets":  "resp_pkts",
        "Flow Bytes/s":            "bytes_per_sec",
        "Flow Packets/s":          "pkts_per_sec",
    }

    LABEL_MAP = {
        "BENIGN":       0,
        "Bot":          1,
        "Infiltration": 3,
        "PortScan":     2,
    }

    def adapt(self, df: pd.DataFrame) -> pd.DataFrame:
        out = pd.DataFrame()

        for cicids_col, pf_col in self.COLUMN_MAP.items():
            if cicids_col in df.columns:
                out[pf_col] = pd.to_numeric(df[cicids_col], errors='coerce')
            else:
                # Do NOT fill with 0 — mark as missing
                out[pf_col] = np.nan

        # Unit conversions
        if "duration_s" in out:
            out["duration_s"] = out["duration_s"] / 1e6  # μs → s
        if "iat_mean_ms" in out:
            out["iat_mean_ms"] = out["iat_mean_ms"] / 1000  # μs → ms
        if "iat_std_ms" in out:
            out["iat_std_ms"] = out["iat_std_ms"] / 1000

        # Derived features (computable from available data)
        out["total_bytes"] = out.get("orig_bytes", 0) + out.get("resp_bytes", 0)
        out["bytes_ratio"] = out.get("orig_bytes", 0) / (out.get("resp_bytes", 0) + 1)
        out["pkt_ratio"] = out.get("orig_pkts", 0) / (out.get("resp_pkts", 0) + 1)

        # IAT CV (derivable)
        if "iat_std_ms" in out and "iat_mean_ms" in out:
            out["iat_cv"] = out["iat_std_ms"] / (out["iat_mean_ms"] + 1e-9)

        # Labels
        label_col = "Label" if "Label" in df.columns else " Label"
        if label_col in df.columns:
            out["label"] = df[label_col].map(self.LABEL_MAP)
            out = out[out["label"].notna()]  # Drop unmapped labels
            out["label"] = out["label"].astype(int)

        # Track which features are REAL vs MISSING for this dataset
        out["dataset_source"] = "CICIDS"
        out["has_tls_features"] = False   # CICIDS has no JA3
        out["has_dns_features"] = False   # CICIDS has no DNS entropy
        out["has_timing_features"] = True  # CICIDS has IAT stats

        return out


class CTU13Adapter:
    """
    CTU-13 comes as NetFlow or Zeek conn.log format.
    Has real botnet C2 — most valuable dataset for C2 detection.
    """

    # Zeek conn.log columns
    ZEEK_MAP = {
        "duration":   "duration_s",
        "orig_bytes": "orig_bytes",
        "resp_bytes": "resp_bytes",
        "orig_pkts":  "orig_pkts",
        "resp_pkts":  "resp_pkts",
        "id.resp_p":  "dport",
    }

    def adapt_zeek(self, df: pd.DataFrame) -> pd.DataFrame:
        """Adapt Zeek conn.log output."""
        out = pd.DataFrame()
        for zeek_col, pf_col in self.ZEEK_MAP.items():
            if zeek_col in df.columns:
                out[pf_col] = pd.to_numeric(df[zeek_col], errors='coerce')

        out["total_bytes"] = out.get("orig_bytes", 0) + out.get("resp_bytes", 0)
        out["bytes_ratio"] = out.get("orig_bytes", 0) / (out.get("resp_bytes", 0) + 1)

        # CTU-13 labels from Zeek notices or manual annotation file
        if "label" in df.columns:
            out["label"] = df["label"].map({"Botnet": 1, "Normal": 0, "Background": 0})
        out["dataset_source"] = "CTU13"
        out["has_timing_features"] = False  # Zeek conn.log has no per-packet IAT
        out["has_tls_features"] = False     # Partial — no JA3 without ssl.log join
        out["has_dns_features"] = False

        return out


class DNSExfilAdapter:
    """
    Adapter for DNS exfiltration datasets.
    These have the DNS-specific features that CICIDS doesn't have.
    """

    def adapt(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        DNS exfil datasets typically have query string + label.
        We recompute all DNS features from the raw query.
        """
        from features.dns_features import DNSAnalyzer
        analyzer = DNSAnalyzer()

        rows = []
        for _, row in df.iterrows():
            query = row.get("query", "")
            src = row.get("src_ip", "0.0.0.0")
            label = 2 if row.get("label") == "tunnel" else 0

            dns_feat = analyzer.analyze(query, src)
            dns_feat["label"] = label
            dns_feat["dataset_source"] = "dns_exfil"
            dns_feat["has_dns_features"] = True
            dns_feat["has_tls_features"] = False
            dns_feat["has_timing_features"] = False
            rows.append(dns_feat)

        return pd.DataFrame(rows)
