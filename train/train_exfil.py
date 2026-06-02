import numpy as np
np.__version__ = "2.1.3"  # Bypass numba checks if needed
import argparse
import pandas as pd
from sklearn.model_selection import train_test_split
from models.exfil_detector import ExfilDetector
from lab.stream_reader import DatasetStreamer

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default="cicids2017_thursday")
    parser.add_argument("--max_rows", type=int, default=50000)
    args = parser.parse_args()

    print(f"Streaming dataset {args.dataset}...")
    streamer = DatasetStreamer()
    chunks = []
    for chunk in streamer.stream(args.dataset, max_rows=args.max_rows):
        chunks.append(chunk)
    
    df = pd.concat(chunks, ignore_index=True)
    if "bytes_per_sec" not in df.columns:
        df["bytes_per_sec"] = df["total_bytes"] / (df["duration_s"] + 1e-9)
    if "pkts_per_sec" not in df.columns:
        df["pkts_per_sec"] = (df["orig_pkts"] + df["resp_pkts"]) / (df["duration_s"] + 1e-9)

    print(f"Loaded {len(df)} rows. Class distribution:\n{df['label'].value_counts()}")

    # For exfil_detector:
    # fit_unsupervised takes benign traffic only (label 0)
    # fit_supervised takes labeled data (benign + exfil, where exfil is labeled as 3)
    df_benign = df[df["label"] == 0].copy()
    
    df_labeled = df[df["label"].isin([0, 3])].copy()
    df_labeled["label"] = (df_labeled["label"] == 3).astype(int)

    print("Training Exfil detector...")
    detector = ExfilDetector()
    detector.fit_unsupervised(df_benign)
    detector.fit_supervised(df_labeled)
    detector.save("models/exfil_detector.pkl")
    print("Exfil detector successfully retrained and saved to models/exfil_detector.pkl")

if __name__ == "__main__":
    main()
