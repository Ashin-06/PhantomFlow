import numpy as np
np.__version__ = "2.1.3"
import os
import joblib
import torch

def audit_model(path, name):
    print(f"\n=== Auditing {name} ({path}) ===")
    if not os.path.exists(path):
        print("  [Error] Path does not exist!")
        return

    try:
        if path.endswith(".pt"):
            weights = torch.load(path, map_location="cpu")
            print(f"  Type: PyTorch State Dict")
            print(f"  Keys in state dict: {list(weights.keys())}")
            for k, v in weights.items():
                if hasattr(v, "shape"):
                    print(f"    {k}: shape {list(v.shape)}")
        else:
            data = joblib.load(path)
            print(f"  Type: {type(data)}")
            if isinstance(data, dict):
                print(f"  Keys: {list(data.keys())}")
                for k, v in data.items():
                    print(f"    {k}: {type(v)}")
                    if hasattr(v, "feature_names_in_"):
                        print(f"      feature_names_in_: {v.feature_names_in_}")
                    elif hasattr(v, "classes_"):
                        print(f"      classes_: {v.classes_}")
                    elif hasattr(v, "n_features_in_"):
                        print(f"      n_features_in_: {v.n_features_in_}")
            else:
                if hasattr(data, "feature_names_in_"):
                    print(f"    feature_names_in_: {data.feature_names_in_}")
                if hasattr(data, "classes_"):
                    print(f"    classes_: {data.classes_}")
                if hasattr(data, "n_features_in_"):
                    print(f"    n_features_in_: {data.n_features_in_}")
    except Exception as e:
        print(f"  [Error] Failed to audit: {e}")

def main():
    audit_model("models/best_lstm.pt", "LSTM Beacon Model")
    audit_model("models/dns_classifier.pkl", "DNS Tunneling Classifier")
    audit_model("models/exfil_detector.pkl", "Exfiltration Detector")
    audit_model("models/meta_learner.pkl", "Meta Learner Stacking Model")

if __name__ == "__main__":
    main()
