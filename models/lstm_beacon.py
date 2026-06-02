# models/lstm_beacon.py
"""
Bidirectional LSTM that learns the temporal signature of C2 beaconing.
Input: sequence of (IAT, packet_size, direction) tuples per flow
Detects even jittered beacons that simple threshold methods miss.
"""

import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
from torch.utils.data import Dataset, DataLoader
from typing import List, Tuple


class BeaconSequenceDataset(Dataset):
    """
    Each sample is a sequence of packet events for one flow.
    Sequences are padded/truncated to SEQ_LEN.
    """
    SEQ_LEN = 100    # 100 packet events per sequence
    FEATURES = 4     # [IAT_ms, pkt_size, direction(0/1), tcp_flags_norm]

    def __init__(self, sequences: List[np.ndarray], labels: List[int]):
        self.sequences = sequences
        self.labels = labels

    def __len__(self):
        return len(self.sequences)

    def __getitem__(self, idx):
        seq = self.sequences[idx]
        # Pad or truncate
        if len(seq) < self.SEQ_LEN:
            pad = np.zeros((self.SEQ_LEN - len(seq), self.FEATURES), dtype=np.float32)
            seq = np.vstack([seq, pad])
        else:
            seq = seq[:self.SEQ_LEN]
        
        return (
            torch.tensor(seq, dtype=torch.float32),
            torch.tensor(self.labels[idx], dtype=torch.long)
        )


class LSTMBeaconDetector(nn.Module):
    """
    Bidirectional LSTM with attention for C2 beacon detection.
    Architecture:
        Input → BiLSTM(128) → Attention → FC(64) → Dropout(0.3) → FC(2)
    
    Bidirectional: captures both forward patterns (packet → C2 check-in)
    and backward patterns (response timing after check-in).
    
    Attention: focuses on the most discriminative time steps
    (e.g., the regular check-in moments in a beacon sequence).
    """

    def __init__(self, input_size: int = 4, hidden_size: int = 128,
                 num_layers: int = 2, num_classes: int = 2,
                 dropout: float = 0.3):
        super().__init__()
        
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        
        # Bidirectional LSTM
        self.lstm = nn.LSTM(
            input_size=input_size,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
            bidirectional=True,
            dropout=dropout if num_layers > 1 else 0,
        )
        
        # Self-attention over time steps
        lstm_out_size = hidden_size * 2  # bidirectional
        self.attention = nn.Sequential(
            nn.Linear(lstm_out_size, 64),
            nn.Tanh(),
            nn.Linear(64, 1),
        )
        
        # Classification head
        self.classifier = nn.Sequential(
            nn.Linear(lstm_out_size, 64),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(64, num_classes),
        )
        
        # Batch normalization for stability
        self.bn = nn.BatchNorm1d(lstm_out_size)

    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        x: (batch, seq_len, features)
        Returns: (logits, attention_weights)
        """
        # LSTM
        lstm_out, _ = self.lstm(x)
        # lstm_out: (batch, seq_len, hidden*2)
        
        # Attention
        attn_scores = self.attention(lstm_out)       # (batch, seq_len, 1)
        attn_weights = torch.softmax(attn_scores, dim=1)  # (batch, seq_len, 1)
        
        # Weighted sum
        context = (attn_weights * lstm_out).sum(dim=1)  # (batch, hidden*2)
        
        # Normalize + classify
        context = self.bn(context)
        logits = self.classifier(context)
        
        return logits, attn_weights.squeeze(-1)


class BeaconTrainer:
    """Training loop with class-weighted loss for imbalanced data."""

    def __init__(self, model: LSTMBeaconDetector, device: str = "auto"):
        self.device = torch.device(
            "cuda" if torch.cuda.is_available() and device == "auto" else "cpu"
        )
        self.model = model.to(self.device)
        print(f"[LSTM] Training on {self.device}")

    def train(self, train_loader: DataLoader, val_loader: DataLoader,
              epochs: int = 30, lr: float = 1e-3,
              class_weights: List[float] = None):
        
        weights = torch.tensor(class_weights or [1.0, 5.0],
                               dtype=torch.float32).to(self.device)
        criterion = nn.CrossEntropyLoss(weight=weights)
        optimizer = optim.AdamW(self.model.parameters(), lr=lr, weight_decay=1e-4)
        scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)
        
        best_val_f1 = 0.0
        
        for epoch in range(epochs):
            self.model.train()
            train_loss = 0.0
            
            for sequences, labels in train_loader:
                sequences = sequences.to(self.device)
                labels = labels.to(self.device)
                
                optimizer.zero_grad()
                logits, _ = self.model(sequences)
                loss = criterion(logits, labels)
                loss.backward()
                
                # Gradient clipping
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
                optimizer.step()
                train_loss += loss.item()
            
            val_f1 = self.evaluate(val_loader)
            scheduler.step()
            
            print(f"Epoch {epoch+1:3d}/{epochs} | "
                  f"Loss: {train_loss/len(train_loader):.4f} | "
                  f"Val F1: {val_f1:.4f}")
            
            if val_f1 > best_val_f1:
                best_val_f1 = val_f1
                torch.save(self.model.state_dict(), "models/best_lstm.pt")
        
        print(f"[LSTM] Best Val F1: {best_val_f1:.4f}")

    def evaluate(self, loader: DataLoader) -> float:
        from sklearn.metrics import f1_score
        self.model.eval()
        all_preds, all_labels = [], []
        
        with torch.no_grad():
            for sequences, labels in loader:
                sequences = sequences.to(self.device)
                logits, _ = self.model(sequences)
                preds = torch.argmax(logits, dim=1).cpu().numpy()
                all_preds.extend(preds)
                all_labels.extend(labels.numpy())
        
        return f1_score(all_labels, all_preds, average="macro", zero_division=0)

    def predict_proba(self, sequence: np.ndarray) -> Tuple[float, np.ndarray]:
        """
        Returns (malicious_probability, attention_weights).
        Attention weights show WHICH time steps drove the prediction —
        useful for analyst explainability.
        """
        self.model.eval()
        
        # Preprocess
        if len(sequence) < BeaconSequenceDataset.SEQ_LEN:
            pad = np.zeros(
                (BeaconSequenceDataset.SEQ_LEN - len(sequence), BeaconSequenceDataset.FEATURES)
            )
            sequence = np.vstack([sequence, pad])
        
        tensor = torch.tensor(sequence[:BeaconSequenceDataset.SEQ_LEN],
                              dtype=torch.float32).unsqueeze(0).to(self.device)
        
        with torch.no_grad():
            logits, attn = self.model(tensor)
            prob = torch.softmax(logits, dim=1)[0, 1].item()
            attn_np = attn[0].cpu().numpy()
        
        return prob, attn_np
