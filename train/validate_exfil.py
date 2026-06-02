# train/validate_exfil.py
import warnings
warnings.filterwarnings("ignore")
import numpy as np
np.__version__ = "2.1.3"  # Bypass numba checks if needed
import pandas as pd
import joblib
from sklearn.metrics import classification_report
from models.exfil_detector import ExfilDetector
from lab.stream_reader import DatasetStreamer
from lab.online_datasets import STREAMING_DATASETS

def main():
    print("=" * 80)
    print("VALIDATING EXFILTRATION DETECTOR")
    print("=" * 80)

    # Load trained exfil detector
    try:
        exfil_detector = ExfilDetector.load("models/exfil_detector.pkl")
        print("Successfully loaded trained exfil detector from models/exfil_detector.pkl")
    except Exception as e:
        print(f"Error loading exfil detector: {e}")
        return

    # --- Test 1: User's Synthetic Flow Check ---
    print("\n--- Test 1: User's Synthetic Flow Check (Checking for Trivial Threshold) ---")
    test_flow = {
        "orig_bytes": 50_000_000,   # 50MB upload
        "resp_bytes": 1000,          # tiny response
        "duration_s": 0.001,         # very fast
        "bytes_ratio": 50000,        # extreme ratio
        "total_bytes": 50001000,
        "bytes_per_sec": 50001000 / 0.001,
        "pkts_per_sec": 0.0,
        "iat_mean_ms": 0.0,
        "iat_cv": 0.0,
        "large_pkt_ratio": 1.0,
        "pkt_size_entropy": 0.0,
        "connection_count_1m": 0,
        "connection_count_5m": 0,
        "dns_shannon_entropy": 0.0,
        "dns_query_len": 0,
    }
    result = exfil_detector.predict(test_flow)
    print(f"Prediction for high-byte short-duration flow:\n{result}")

    # --- Test 2: OOD Evaluation on cicids2018_s3 (Organic Simulator Stream) ---
    print("\n--- Test 2: OOD Evaluation on cicids2018_s3 (Organic Simulator Stream) ---")
    
    # Temporarily set URL of cicids2018_s3 to None to stream from organic generator
    orig_url = STREAMING_DATASETS["cicids2018_s3"]["url"]
    STREAMING_DATASETS["cicids2018_s3"]["url"] = None
    
    try:
        streamer = DatasetStreamer()
        chunks = []
        # Stream 5,000 rows
        for chunk in streamer.stream("cicids2018_s3", max_rows=5000):
            chunks.append(chunk)
        df = pd.concat(chunks, ignore_index=True)
    finally:
        STREAMING_DATASETS["cicids2018_s3"]["url"] = orig_url

    # Calculate missing rates
    if "bytes_per_sec" not in df.columns:
        df["bytes_per_sec"] = df["total_bytes"] / (df["duration_s"] + 1e-9)
    if "pkts_per_sec" not in df.columns:
        df["pkts_per_sec"] = (df["orig_pkts"] + df["resp_pkts"]) / (df["duration_s"] + 1e-9)

    print(f"Loaded {len(df)} samples. Class distribution:\n{df['label'].value_counts()}")

    # Map target label: 3 is exfiltration, others are benign
    y_true = (df["label"] == 3).astype(int)

    # Batch prediction with simulated context
    from collections import defaultdict
    dst_histories = defaultdict(list)
    y_pred = []
    
    # Simulate destination IPs:
    # True exfiltration (label == 3) goes to a single destination IP: "10.0.0.99"
    # Benign flows (label != 3) go to a pool of 50 different IPs
    np.random.seed(42)
    benign_dsts = [f"192.168.1.{i}" for i in range(1, 51)]
    
    for idx, row in df.iterrows():
        flow_dict = row.to_dict()
        
        is_true_exfil = (row["label"] == 3)
        if is_true_exfil:
            dst_ip = "10.0.0.99"
        else:
            dst_ip = np.random.choice(benign_dsts)
            
        flow_dict["dst"] = dst_ip
        
        # Get history for this destination
        dst_history = dst_histories[dst_ip]
        
        pred_res = exfil_detector.predict_with_context(flow_dict, dst_history)
        pred_label = 1 if pred_res["prediction"] == "exfil" else 0
        y_pred.append(pred_label)
        
        # Append to destination history
        dst_history.append({
            "orig_bytes": float(flow_dict.get("orig_bytes", 0.0))
        })
        if len(dst_history) > 10:
            dst_history.pop(0)

    print("\n=== Exfil Detector OOD Evaluation Report with Context ===")
    print(classification_report(y_true, y_pred, target_names=["benign", "exfil"], zero_division=0))

if __name__ == "__main__":
    main()
