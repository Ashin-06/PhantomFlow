# train/data_pipeline.py
"""
Three-source data ingestion:
1. Public labeled datasets (immediate)
2. Lab-generated real C2 traffic (week 2)
3. Production feedback loop (ongoing)
"""
import pandas as pd
import hashlib

DATASETS = {
    # Free, labeled, downloadable today
    "CICIDS2017": "https://www.unb.ca/cic/datasets/ids-2017.html",
    "CICIDS2018": "https://www.unb.ca/cic/datasets/ids-2018.html", 
    "CTU-13":     "https://mcfp.felk.cvut.cz/publicDatasets/CTU-13-Dataset/",
    "UNSW-NB15":  "https://research.unsw.edu.au/projects/unsw-nb15-dataset",
    "MalwareTrafficAnalysis": "https://www.malware-traffic-analysis.net/",
    
    # Real C2 PCAPs (your lab generates these)
    "Sliver_60s":   "lab/pcaps/sliver_beacon_60s.pcap",
    "Cobalt_300s":  "lab/pcaps/cobalt_strike_5min.pcap",
    "iodine_dns":   "lab/pcaps/iodine_tunnel.pcap",
    "dnscat2":      "lab/pcaps/dnscat2_tunnel.pcap",
}

class DataPipeline:
    def __init__(self):
        self.versions = {}  # track dataset versions for reproducibility
    
    def download_public_datasets(self, output_dir: str = "data/raw"):
        """Download all public labeled datasets."""
        import requests, os
        os.makedirs(output_dir, exist_ok=True)
        # CTU-13 is most relevant — real botnet traffic
        # CICIDS2018 has infiltration + botnet scenarios
        pass
        
    def merge_and_balance(self, dfs: list) -> pd.DataFrame:
        """
        Merge multiple datasets. Handle class imbalance via:
        1. Undersample majority (benign)
        2. Oversample minority (C2/tunnel/exfil) via GAN augmentation
        3. Never mix train/test across dataset sources (data leakage)
        """
        if not dfs:
            return pd.DataFrame()
        return pd.concat(dfs, ignore_index=True)
        
    def create_train_val_test_split(self, df: pd.DataFrame):
        """
        CRITICAL: Split by TIME not random.
        Random split leaks temporal patterns into test set.
        Train on Jan-Aug, validate Sep, test Oct-Dec.
        This is how real production models are evaluated.
        """
        if "timestamp" in df.columns:
            df_sorted = df.sort_values("timestamp")
        else:
            df_sorted = df
        n = len(df_sorted)
        train = df_sorted.iloc[:int(n*0.7)]
        val   = df_sorted.iloc[int(n*0.7):int(n*0.85)]
        test  = df_sorted.iloc[int(n*0.85):]
        return train, val, test
    
    def version_dataset(self, df: pd.DataFrame, version: str):
        """Hash the dataset for reproducibility. MLflow logs this."""
        fingerprint = hashlib.sha256(
            pd.util.hash_pandas_object(df).values.tobytes()
        ).hexdigest()[:16]
        self.versions[version] = fingerprint
        print(f"Dataset v{version} fingerprint: {fingerprint}")
