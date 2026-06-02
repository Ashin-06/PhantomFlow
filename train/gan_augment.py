# train/gan_augment.py
"""
Conditional GAN for augmenting minority class (C2/tunnel/exfil) samples.
Architecture adapted from CT-GAN principles — uses a Transformer-based
generator to produce realistic tabular network feature distributions.
"""

import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
import pandas as pd
from torch.utils.data import DataLoader, TensorDataset


class CondGenerator(nn.Module):
    """
    Conditional generator: takes noise + class label → feature vector.
    Transformer-based for better inter-feature dependencies.
    """
    
    def __init__(self, noise_dim: int = 128, num_classes: int = 4,
                 output_dim: int = 50, hidden_dim: int = 256):
        super().__init__()
        self.embed = nn.Embedding(num_classes, 32)
        self.input_proj = nn.Linear(noise_dim + 32, hidden_dim)
        
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=hidden_dim, nhead=8, dim_feedforward=512,
            dropout=0.1, batch_first=True
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=3)
        self.output = nn.Sequential(
            nn.Linear(hidden_dim, output_dim),
            nn.Tanh()
        )

    def forward(self, z: torch.Tensor, labels: torch.Tensor) -> torch.Tensor:
        class_emb = self.embed(labels)
        x = torch.cat([z, class_emb], dim=1)
        x = self.input_proj(x).unsqueeze(1)  # Add sequence dim
        x = self.transformer(x).squeeze(1)
        return self.output(x)


class Discriminator(nn.Module):
    def __init__(self, input_dim: int = 50, num_classes: int = 4, hidden: int = 256):
        super().__init__()
        self.embed = nn.Embedding(num_classes, 32)
        self.net = nn.Sequential(
            nn.Linear(input_dim + 32, hidden),
            nn.LeakyReLU(0.2),
            nn.Dropout(0.3),
            nn.Linear(hidden, hidden // 2),
            nn.LeakyReLU(0.2),
            nn.Linear(hidden // 2, 1),
        )

    def forward(self, x: torch.Tensor, labels: torch.Tensor) -> torch.Tensor:
        class_emb = self.embed(labels)
        return self.net(torch.cat([x, class_emb], dim=1))


class NetworkTrafficGAN:
    """
    Wasserstein GAN with gradient penalty (WGAN-GP) for stable training
    on network traffic tabular data.
    """

    def __init__(self, feature_dim: int, num_classes: int = 4,
                 noise_dim: int = 128, device: str = "auto"):
        self.device = torch.device(
            "cuda" if torch.cuda.is_available() and device == "auto" else "cpu"
        )
        self.noise_dim = noise_dim
        self.num_classes = num_classes
        
        self.G = CondGenerator(noise_dim, num_classes, feature_dim).to(self.device)
        self.D = Discriminator(feature_dim, num_classes).to(self.device)
        
        self.G_opt = optim.Adam(self.G.parameters(), lr=1e-4, betas=(0.0, 0.9))
        self.D_opt = optim.Adam(self.D.parameters(), lr=1e-4, betas=(0.0, 0.9))

    def _gradient_penalty(self, real: torch.Tensor, fake: torch.Tensor,
                           labels: torch.Tensor) -> torch.Tensor:
        alpha = torch.rand(real.size(0), 1, device=self.device)
        interpolated = alpha * real + (1 - alpha) * fake
        interpolated.requires_grad_(True)
        
        d_interp = self.D(interpolated, labels)
        grad = torch.autograd.grad(
            outputs=d_interp, inputs=interpolated,
            grad_outputs=torch.ones_like(d_interp),
            create_graph=True, retain_graph=True
        )[0]
        gp = ((grad.norm(2, dim=1) - 1) ** 2).mean()
        return gp

    def train(self, real_data: np.ndarray, labels: np.ndarray,
              epochs: int = 200, batch_size: int = 256,
              n_critic: int = 5, lambda_gp: float = 10.0):
        
        X = torch.tensor(real_data, dtype=torch.float32)
        y = torch.tensor(labels, dtype=torch.long)
        dataset = TensorDataset(X, y)
        loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)
        
        for epoch in range(epochs):
            for real_batch, label_batch in loader:
                real_batch = real_batch.to(self.device)
                label_batch = label_batch.to(self.device)
                bs = real_batch.size(0)
                
                # Train Discriminator n_critic times
                for _ in range(n_critic):
                    z = torch.randn(bs, self.noise_dim, device=self.device)
                    fake = self.G(z, label_batch).detach()
                    
                    d_real = self.D(real_batch, label_batch).mean()
                    d_fake = self.D(fake, label_batch).mean()
                    gp = self._gradient_penalty(real_batch, fake, label_batch)
                    
                    d_loss = d_fake - d_real + lambda_gp * gp
                    self.D_opt.zero_grad()
                    d_loss.backward()
                    self.D_opt.step()
                
                # Train Generator
                z = torch.randn(bs, self.noise_dim, device=self.device)
                fake = self.G(z, label_batch)
                g_loss = -self.D(fake, label_batch).mean()
                
                self.G_opt.zero_grad()
                g_loss.backward()
                self.G_opt.step()
            
            if (epoch + 1) % 20 == 0:
                print(f"GAN Epoch {epoch+1}/{epochs} | "
                      f"D: {d_loss.item():.4f} | G: {g_loss.item():.4f}")

    def generate_samples(self, label: int, n: int = 1000) -> np.ndarray:
        """Generate n synthetic samples for a given class."""
        self.G.eval()
        with torch.no_grad():
            z = torch.randn(n, self.noise_dim, device=self.device)
            labels = torch.full((n,), label, dtype=torch.long, device=self.device)
            samples = self.G(z, labels).cpu().numpy()
        return samples

    def augment_minority_classes(self, df: pd.DataFrame,
                                  target_count: int = 5000) -> pd.DataFrame:
        """
        Augment minority classes to target_count samples each.
        Returns df with synthetic samples appended.
        """
        from features.extractor import FeatureExtractor
        feature_cols = FeatureExtractor.FEATURE_NAMES
        
        augmented = [df]
        for cls in [1, 2, 3]:  # C2, DNS tunnel, exfil
            cls_df = df[df["label"] == cls]
            deficit = target_count - len(cls_df)
            if deficit <= 0:
                continue
            
            print(f"[GAN] Generating {deficit} synthetic samples for class {cls}")
            synthetic = self.generate_samples(cls, deficit)
            syn_df = pd.DataFrame(synthetic, columns=feature_cols)
            syn_df["label"] = cls
            syn_df["synthetic"] = True
            augmented.append(syn_df)
        
        result = pd.concat(augmented, ignore_index=True)
        print(f"[GAN] Dataset: {len(df)} real + "
              f"{len(result)-len(df)} synthetic = {len(result)} total")
        return result
