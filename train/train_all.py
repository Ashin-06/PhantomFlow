# train/train_all.py
"""
End-to-end training pipeline for all PhantomFlow models.
Run: python3 train/train_all.py --dataset lab/ground_truth_dataset.csv
"""

import argparse
import os
import json
import warnings
warnings.filterwarnings('ignore')
import numpy as np
import pandas as pd
import mlflow
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, roc_auc_score
import joblib
import shap

from models.lstm_beacon import LSTMBeaconDetector, BeaconSequenceDataset, BeaconTrainer
from models.dns_classifier import DNSTunnelingClassifier
from models.exfil_detector import ExfilDetector
from train.gan_augment import NetworkTrafficGAN
from features.extractor import FeatureExtractor


def build_lstm_sequences(df: pd.DataFrame):
    """Convert per-flow DataFrame to packet sequences for LSTM."""
    sequences, labels = [], []
    
    for uid, group in df.groupby("flow_id"):
        if len(group) < 5:
            continue
        
        seq = group[["iat_ms", "pkt_size", "direction", "tcp_flags_norm"]].values
        label = group["label"].iloc[0]
        
        # Binary: beacon vs. not-beacon (for LSTM)
        binary_label = 1 if label == 1 else 0
        sequences.append(seq.astype(np.float32))
        labels.append(binary_label)
    
    return sequences, labels


def train_all(args):
    mlflow.set_experiment("phantomflow")
    
    print(f"[Train] Loading dataset: {args.dataset}")
    df = pd.read_csv(args.dataset)
    print(f"[Train] {len(df)} samples\n{df['label'].value_counts()}")
    
    # Train/val/test split
    df_train, df_test = train_test_split(df, test_size=0.2, stratify=df["label"],
                                          random_state=42)
    df_train, df_val = train_test_split(df_train, test_size=0.15, stratify=df_train["label"],
                                         random_state=42)
    
    print(f"\n[Train] Splits: train={len(df_train)}, val={len(df_val)}, test={len(df_test)}")
    
    # === GAN Augmentation ===
    print("\n[Train] === GAN Augmentation ===")
    feature_cols = FeatureExtractor.FEATURE_NAMES
    X_real = df_train[feature_cols].fillna(0).values
    y_real = df_train["label"].values
    
    gan = NetworkTrafficGAN(feature_dim=len(feature_cols))
    gan.train(X_real, y_real, epochs=args.gan_epochs)
    df_train = gan.augment_minority_classes(df_train, target_count=5000)
    
    # === Train LSTM Beacon Detector ===
    print("\n[Train] === LSTM Beacon Detector ===")
    if "iat_ms" in df.columns:
        from torch.utils.data import DataLoader
        
        train_seqs, train_labels = build_lstm_sequences(df_train)
        val_seqs, val_labels = build_lstm_sequences(df_val)
        
        train_dataset = BeaconSequenceDataset(train_seqs, train_labels)
        val_dataset = BeaconSequenceDataset(val_seqs, val_labels)
        train_loader = DataLoader(train_dataset, batch_size=64, shuffle=True)
        val_loader = DataLoader(val_dataset, batch_size=64)
        
        lstm = LSTMBeaconDetector()
        trainer = BeaconTrainer(lstm)
        
        with mlflow.start_run(run_name="lstm_beacon"):
            trainer.train(train_loader, val_loader, epochs=args.lstm_epochs)
            mlflow.log_artifact("models/best_lstm.pt")
    
    # === Train DNS Classifier ===
    print("\n[Train] === DNS Tunneling Classifier ===")
    df_dns_train = df_train[df_train["label"].isin([0, 2])].copy()
    df_dns_train["label"] = (df_dns_train["label"] == 2).astype(int)
    df_dns_val = df_val[df_val["label"].isin([0, 2])].copy()
    df_dns_val["label"] = (df_dns_val["label"] == 2).astype(int)
    
    dns_clf = DNSTunnelingClassifier()
    with mlflow.start_run(run_name="dns_classifier"):
        dns_clf.train(df_dns_train, df_dns_val)
        dns_clf.save("models/dns_classifier.pkl")
        mlflow.log_artifact("models/dns_classifier.pkl")
    
    # === Train Exfil Detector ===
    print("\n[Train] === Exfil Detector ===")
    df_benign = df_train[df_train["label"] == 0]
    df_exfil = df_train[df_train["label"].isin([0, 3])].copy()
    df_exfil["label"] = (df_exfil["label"] == 3).astype(int)
    
    exfil = ExfilDetector()
    with mlflow.start_run(run_name="exfil_detector"):
        exfil.fit_unsupervised(df_benign)
        exfil.fit_supervised(df_exfil)
        exfil.save("models/exfil_detector.pkl")
    
    # === Train Meta-Learner (Stacking) ===
    print("\n[Train] === Meta-Learner ===")
    _train_meta_learner(df_train, df_val, df_test)
    
    print("\n✓ All models trained successfully!")


def _train_meta_learner(df_train, df_val, df_test):
    """
    Build stacking ensemble by getting predictions from each model
    and training logistic regression meta-learner.
    """
    # Load trained models
    dns_clf = DNSTunnelingClassifier.load("models/dns_classifier.pkl")
    exfil_det = ExfilDetector.load("models/exfil_detector.pkl")
    
    def get_meta_features(df):
        rows = []
        for _, row in df.iterrows():
            feat = row.to_dict()
            dns_res = dns_clf.predict_with_explanation(
                feat.get("dns_query", ""), feat
            )
            exfil_res = exfil_det.predict(feat)
            
            rows.append([
                feat.get("periodicity_score", 0),
                feat.get("iat_cv", 0),
                feat.get("bytes_ratio", 0),
                feat.get("dns_shannon_entropy", 0),
                feat.get("ja3_malware_score", 0),
                dns_res["probability"],
                exfil_res["exfil_probability"],
                exfil_res["anomaly_score"],
            ])
        return np.array(rows)
    
    print("  Building meta-features...")
    X_meta_train = get_meta_features(df_train)
    X_meta_val = get_meta_features(df_val)
    X_meta_test = get_meta_features(df_test)
    
    y_train = df_train["label"].values
    y_test = df_test["label"].values
    
    scaler = StandardScaler()
    X_tr = scaler.fit_transform(X_meta_train)
    X_te = scaler.transform(X_meta_test)
    
    meta = LogisticRegression(C=1.0, max_iter=1000, multi_class="multinomial")
    meta.fit(X_tr, y_train)
    
    y_pred = meta.predict(X_te)
    print(classification_report(y_test, y_pred,
          target_names=["clean", "c2_beacon", "dns_tunnel", "exfil"]))
    
    # SHAP for meta-learner
    explainer = shap.LinearExplainer(meta, X_tr)
    
    joblib.dump({
        "model": meta,
        "scaler": scaler,
        "explainer": explainer,
    }, "models/meta_learner.pkl")
    print("  Meta-learner saved to models/meta_learner.pkl")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--lstm_epochs", type=int, default=30)
    parser.add_argument("--gan_epochs", type=int, default=200)
    args = parser.parse_args()
    train_all(args)
