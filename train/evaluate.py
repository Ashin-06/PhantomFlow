# train/evaluate.py
"""
Comprehensive model evaluation with confusion matrices and ROC curves.
Run after training to get full performance report.
"""

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    confusion_matrix, classification_report,
    roc_curve, auc, roc_auc_score,
    precision_recall_curve, average_precision_score,
)
from sklearn.preprocessing import label_binarize
import json


def full_evaluation(df_test: pd.DataFrame, predictions: np.ndarray,
                    probabilities: np.ndarray, output_dir: str = "eval/"):
    """Generate complete evaluation report."""
    
    import os
    os.makedirs(output_dir, exist_ok=True)
    
    y_true = df_test["label"].values
    CLASS_NAMES = ["clean", "c2_beacon", "dns_tunnel", "exfiltration"]
    
    # === 1. Classification Report ===
    report = classification_report(y_true, predictions,
                                   target_names=CLASS_NAMES, output_dict=True)
    
    print("=== PhantomFlow Evaluation Report ===")
    print(classification_report(y_true, predictions, target_names=CLASS_NAMES))
    
    # === 2. Confusion Matrix ===
    cm = confusion_matrix(y_true, predictions)
    fig, ax = plt.subplots(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=CLASS_NAMES, yticklabels=CLASS_NAMES, ax=ax)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title("PhantomFlow Confusion Matrix")
    plt.tight_layout()
    plt.savefig(f"{output_dir}/confusion_matrix.png", dpi=150)
    plt.close()
    print(f"Confusion matrix saved to {output_dir}/confusion_matrix.png")
    
    # === 3. ROC Curves (one-vs-rest) ===
    y_bin = label_binarize(y_true, classes=[0, 1, 2, 3])
    fig, ax = plt.subplots(figsize=(8, 6))
    colors = ["#4CAF50", "#F44336", "#2196F3", "#FF9800"]
    
    for i, (cls_name, color) in enumerate(zip(CLASS_NAMES, colors)):
        if i == 0:
            continue  # Skip "clean" ROC
        fpr, tpr, _ = roc_curve(y_bin[:, i], probabilities[:, i])
        roc_auc = auc(fpr, tpr)
        ax.plot(fpr, tpr, color=color, label=f"{cls_name} (AUC={roc_auc:.3f})")
    
    ax.plot([0, 1], [0, 1], "k--", alpha=0.5)
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("PhantomFlow ROC Curves")
    ax.legend(loc="lower right")
    ax.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(f"{output_dir}/roc_curves.png", dpi=150)
    plt.close()
    print(f"ROC curves saved to {output_dir}/roc_curves.png")
    
    # === 4. Precision-Recall Curves ===
    fig, axes = plt.subplots(1, 3, figsize=(15, 5))
    for i, (cls_name, ax) in enumerate(zip(CLASS_NAMES[1:], axes), start=1):
        prec, rec, _ = precision_recall_curve(y_bin[:, i], probabilities[:, i])
        ap = average_precision_score(y_bin[:, i], probabilities[:, i])
        ax.plot(rec, prec)
        ax.set_title(f"{cls_name}\nAP={ap:.3f}")
        ax.set_xlabel("Recall")
        ax.set_ylabel("Precision")
        ax.grid(alpha=0.3)
    
    plt.suptitle("Precision-Recall Curves")
    plt.tight_layout()
    plt.savefig(f"{output_dir}/pr_curves.png", dpi=150)
    plt.close()
    
    # === 5. Save metrics JSON ===
    metrics = {
        "macro_f1": report["macro avg"]["f1-score"],
        "macro_precision": report["macro avg"]["precision"],
        "macro_recall": report["macro avg"]["recall"],
        "per_class": {cls: report[cls] for cls in CLASS_NAMES},
    }
    with open(f"{output_dir}/metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)
    
    print(f"\nMacro F1: {metrics['macro_f1']:.4f}")
    print(f"All artifacts saved to {output_dir}/")
    return metrics
