# lab/download_kdd99.py
import pandas as pd
import numpy as np
from sklearn.datasets import fetch_kddcup99
import sys

print("Downloading KDD Cup 99 dataset (this is built into sklearn)...")
kdd = fetch_kddcup99(as_frame=True, percent10=True)
df = kdd.frame

print(f"Loaded {len(df)} rows. Processing features to match PhantomFlow...")

# Create an empty dataframe with all PhantomFlow columns set to 0.0
FEATURE_NAMES = [
    "duration_s", "iat_mean_ms", "iat_std_ms", "iat_cv",
    "iat_min_ms", "iat_max_ms", "iat_median_ms", "iat_skewness",
    "iat_kurtosis", "periodicity_score", "dominant_period_ms",
    "pkt_size_mean", "pkt_size_std", "pkt_size_min", "pkt_size_max",
    "pkt_size_median", "pkt_size_entropy", "small_pkt_ratio", "large_pkt_ratio",
    "total_bytes", "orig_bytes", "resp_bytes", "bytes_ratio",
    "bytes_per_sec", "pkts_per_sec", "orig_pkts", "resp_pkts", "pkt_ratio",
    "sni_entropy", "sni_len", "tls_resumed",
    "ja3_malware_score", "ja4_malware_score",
    "cert_validity_days", "cert_self_signed",
    "dns_query_len", "dns_label_count", "dns_max_label_len",
    "dns_unique_chars", "dns_shannon_entropy", "dns_bigram_entropy",
    "dns_vowel_ratio", "dns_digit_ratio", "dns_hyphen_ratio",
    "dns_is_ip_encoded", "dns_consecutive_digits", "dns_longest_run",
    "connection_count_1m", "connection_count_5m",
    "failed_connection_ratio",
]

out_df = pd.DataFrame(0.0, index=np.arange(len(df)), columns=FEATURE_NAMES)
out_df["flow_id"] = [f"flow_{i}" for i in range(len(df))]

# Map KDD features to PhantomFlow features where possible
out_df["duration_s"] = df["duration"].astype(float)
out_df["orig_bytes"] = df["src_bytes"].astype(float)
out_df["resp_bytes"] = df["dst_bytes"].astype(float)
out_df["total_bytes"] = out_df["orig_bytes"] + out_df["resp_bytes"]

# Avoid division by zero
out_df["bytes_ratio"] = out_df["orig_bytes"] / (out_df["resp_bytes"] + 1)

# Connection counts (approximated from KDD count features)
out_df["connection_count_1m"] = df["count"].astype(float)

# Error rates
out_df["failed_connection_ratio"] = df["serror_rate"].astype(float)

# Map labels
# KDD Labels: b'normal.', b'smurf.', b'neptune.', etc.
# We map them to PhantomFlow labels: 0=benign, 1=C2, 2=DNS, 3=Exfil
def map_label(kdd_label):
    lbl = kdd_label.decode('utf-8') if isinstance(kdd_label, bytes) else str(kdd_label)
    lbl = lbl.strip('.')
    
    if lbl == 'normal':
        return 0
    # Map DoS attacks to C2 (for testing ML pipeline on real anomalies)
    elif lbl in ['smurf', 'neptune', 'back', 'teardrop', 'pod', 'land']:
        return 1
    # Map Probing to DNS tunnel (since they involve scanning/scanning-like anomalies)
    elif lbl in ['portsweep', 'ipsweep', 'satan', 'nmap']:
        return 2
    # Map R2L / U2R to Exfil
    else:
        return 3

out_df["label"] = df["labels"].apply(map_label)

# Filter down to a manageable size to prevent the 30 minute training time
# Let's take 20,000 samples while keeping distribution
out_df = out_df.sample(20000, random_state=42)

out_df.to_csv("lab/real_kdd_dataset.csv", index=False)
print("Saved mapped real dataset to lab/real_kdd_dataset.csv!")
print(out_df["label"].value_counts())
