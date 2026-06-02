# lab/mock_dataset_gen.py
import pandas as pd
import numpy as np
import os
import uuid

def generate_mock_dataset(num_flows=2000):
    np.random.seed(42)
    rows = []
    
    # feature names from extractor
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

    for _ in range(num_flows):
        flow_id = str(uuid.uuid4())
        # Labels: 0=benign (80%), 1=C2 (5%), 2=DNS (5%), 3=Exfil (10%)
        label = np.random.choice([0, 1, 2, 3], p=[0.8, 0.05, 0.05, 0.10])
        
        # Base flow features
        flow_features = {feat: np.random.rand() for feat in FEATURE_NAMES}
        
        # Override specific features to make models learn properly
        if label == 1:  # C2 Beacon
            flow_features["periodicity_score"] = np.random.uniform(0.7, 0.99)
            flow_features["dominant_period_ms"] = np.random.choice([10000, 30000, 60000])
            flow_features["ja3_malware_score"] = np.random.uniform(0.8, 1.0)
            flow_features["iat_cv"] = np.random.uniform(0.01, 0.1) # low jitter
        elif label == 2:  # DNS Tunnel
            flow_features["dns_shannon_entropy"] = np.random.uniform(4.5, 6.0)
            flow_features["dns_max_label_len"] = np.random.randint(50, 63)
            flow_features["dns_vowel_ratio"] = np.random.uniform(0.0, 0.1)
            flow_features["bytes_ratio"] = np.random.uniform(1.0, 2.0)
        elif label == 3:  # Exfil
            flow_features["bytes_ratio"] = np.random.uniform(5.0, 50.0) # High upload
            flow_features["orig_bytes"] = np.random.uniform(1e6, 1e8)
            flow_features["large_pkt_ratio"] = np.random.uniform(0.8, 1.0)
        else: # Benign
            flow_features["periodicity_score"] = np.random.uniform(0.0, 0.2)
            flow_features["dns_shannon_entropy"] = np.random.uniform(1.5, 3.0)
            flow_features["bytes_ratio"] = np.random.uniform(0.1, 0.5) # Mostly download
            flow_features["ja3_malware_score"] = 0.0

        num_packets = np.random.randint(5, 20)
        
        for p in range(num_packets):
            row = {
                "flow_id": flow_id,
                "label": label,
                "iat_ms": np.random.uniform(10, 1000) if label != 1 else flow_features["dominant_period_ms"] + np.random.normal(0, 50),
                "pkt_size": np.random.randint(40, 1500),
                "direction": np.random.choice([0, 1]),
                "tcp_flags_norm": np.random.rand(),
            }
            row.update(flow_features)
            rows.append(row)
            
    df = pd.DataFrame(rows)
    os.makedirs("lab", exist_ok=True)
    df.to_csv("lab/ground_truth_dataset.csv", index=False)
    print(f"Generated mock dataset at lab/ground_truth_dataset.csv with {len(df)} rows.")

if __name__ == "__main__":
    generate_mock_dataset()
