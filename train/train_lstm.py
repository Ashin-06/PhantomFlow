# train/train_lstm.py
"""
Standalone script to train the LSTM beacon detector.
Run after dataset_builder.py has produced lab/ground_truth_dataset.csv
"""

import argparse
import numpy as np
import pandas as pd
import torch
from torch.utils.data import DataLoader
from sklearn.model_selection import train_test_split
import mlflow
import os

from models.lstm_beacon import LSTMBeaconDetector, BeaconSequenceDataset, BeaconTrainer


def load_sequences_from_df(df: pd.DataFrame):
    """
    Build packet sequences from per-flow DataFrame.
    
    The DataFrame must have per-packet rows with columns:
    flow_id, iat_ms, pkt_size, direction, tcp_flags_norm, label
    
    If only flow-level features exist, we simulate sequences from
    the timing distribution parameters.
    """
    sequences, labels = [], []

    if "iat_ms" in df.columns and "pkt_size" in df.columns:
        # True per-packet data
        for uid, grp in df.groupby("flow_id"):
            if len(grp) < 5:
                continue
            seq = grp[["iat_ms", "pkt_size", "direction", "tcp_flags_norm"]].values.astype(np.float32)
            lbl = int(grp["label"].iloc[0] == 1)
            sequences.append(seq)
            labels.append(lbl)
    else:
        # Reconstruct synthetic sequences from flow-level stats
        for _, row in df.iterrows():
            mean_iat = row.get("iat_mean_ms", 100)
            std_iat = row.get("iat_std_ms", 10)
            n_pkts = max(5, int(row.get("orig_pkts", 20) + row.get("resp_pkts", 20)))
            n_pkts = min(n_pkts, 100)

            if row.get("label") == 1 and row.get("periodicity_score", 0) > 0.5:
                # Simulate periodic beacon
                period = row.get("dominant_period_ms", mean_iat)
                jitter = period * 0.2
                iats = np.abs(np.random.normal(period, jitter, n_pkts))
            else:
                # Simulate web traffic (exponential IAT)
                iats = np.random.exponential(mean_iat, n_pkts)

            sizes = np.abs(np.random.normal(
                row.get("pkt_size_mean", 500),
                row.get("pkt_size_std", 200),
                n_pkts
            ))
            directions = np.random.choice([0.0, 1.0], n_pkts)
            flags = np.zeros(n_pkts)

            seq = np.column_stack([iats, sizes, directions, flags]).astype(np.float32)
            lbl = int(row.get("label") == 1)
            sequences.append(seq)
            labels.append(lbl)

    print(f"[LSTM] {len(sequences)} sequences | "
          f"beacon={sum(labels)} benign={len(labels)-sum(labels)}")
    return sequences, labels


def main(args):
    mlflow.set_experiment("phantomflow_lstm")

    print(f"[LSTM] Loading: {args.dataset}")
    df = pd.read_csv(args.dataset)

    sequences, labels = load_sequences_from_df(df)

    # Stratified split
    from sklearn.model_selection import train_test_split
    idx = list(range(len(sequences)))
    idx_tr, idx_tmp = train_test_split(idx, test_size=0.3, stratify=labels)
    idx_val, idx_test = train_test_split(
        idx_tmp, test_size=0.5,
        stratify=[labels[i] for i in idx_tmp]
    )

    train_ds = BeaconSequenceDataset(
        [sequences[i] for i in idx_tr], [labels[i] for i in idx_tr]
    )
    val_ds = BeaconSequenceDataset(
        [sequences[i] for i in idx_val], [labels[i] for i in idx_val]
    )

    train_loader = DataLoader(train_ds, batch_size=args.batch, shuffle=True, num_workers=2)
    val_loader = DataLoader(val_ds, batch_size=args.batch)

    # Class weights for imbalanced data
    n_benign = labels.count(0)
    n_beacon = labels.count(1)
    class_weights = [1.0, n_benign / max(n_beacon, 1)]
    print(f"[LSTM] Class weights: benign=1.0, beacon={class_weights[1]:.2f}")

    model = LSTMBeaconDetector(
        input_size=4,
        hidden_size=args.hidden,
        num_layers=args.layers,
        dropout=args.dropout,
    )
    trainer = BeaconTrainer(model)

    with mlflow.start_run(run_name="lstm_beacon"):
        mlflow.log_params({
            "hidden_size": args.hidden,
            "num_layers": args.layers,
            "dropout": args.dropout,
            "epochs": args.epochs,
            "batch_size": args.batch,
        })

        trainer.train(
            train_loader, val_loader,
            epochs=args.epochs,
            lr=args.lr,
            class_weights=class_weights,
        )

        mlflow.log_artifact("models/best_lstm.pt")
    print("[LSTM] Done. Saved to models/best_lstm.pt")


if __name__ == "__main__":
    os.makedirs("models", exist_ok=True)
    p = argparse.ArgumentParser()
    p.add_argument("--dataset", required=True, help="Path to labeled CSV")
    p.add_argument("--epochs", type=int, default=30)
    p.add_argument("--batch", type=int, default=64)
    p.add_argument("--hidden", type=int, default=128)
    p.add_argument("--layers", type=int, default=2)
    p.add_argument("--dropout", type=float, default=0.3)
    p.add_argument("--lr", type=float, default=1e-3)
    main(p.parse_args())
