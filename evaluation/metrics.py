"""Detection metrics. Every rate is computed from explicit confusion counts."""
import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score


def best_f1_threshold(y, score) -> float:
    """Score threshold that maximises F1. Call this on validation data only."""
    y = np.asarray(y, bool)
    order = np.argsort(-np.asarray(score))
    s, ys = np.asarray(score)[order], y[order]
    tp = np.cumsum(ys)
    fp = np.cumsum(~ys)
    f1 = 2 * tp / (tp + fp + y.sum())
    last = np.r_[s[1:] != s[:-1], True]          # only cut between distinct scores
    i = np.argmax(np.where(last, f1, -1))
    return float(s[i])


def binary_report(y, score, threshold: float) -> dict:
    """Precision/recall/F1/FPR at `threshold` (alarm if score >= threshold) plus PR-AUC and ROC-AUC."""
    y = np.asarray(y, bool)
    pred = np.asarray(score) >= threshold
    tp, fp = int((pred & y).sum()), int((pred & ~y).sum())
    fn, tn = int((~pred & y).sum()), int((~pred & ~y).sum())
    both = 0 < y.sum() < len(y)
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return {
        "n": len(y), "n_pos": int(y.sum()), "prevalence": float(y.mean()) if len(y) else 0.0,
        "threshold": float(threshold),
        "precision": p, "recall": r, "f1": 2 * p * r / (p + r) if p + r else 0.0,
        "fpr": fp / (fp + tn) if fp + tn else 0.0,
        "pr_auc": float(average_precision_score(y, score)) if both else None,
        "roc_auc": float(roc_auc_score(y, score)) if both else None,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
    }


def multiclass_report(y, proba, classes) -> dict:
    """One-vs-rest report per class from argmax predictions; PR-AUC from the class probability."""
    y = np.asarray(y)
    pred = np.asarray(classes)[np.argmax(proba, axis=1)]
    out = {}
    for i, c in enumerate(classes):
        r = binary_report(y == c, (pred == c).astype(float), 0.5)
        yc = y == c
        r["pr_auc"] = float(average_precision_score(yc, proba[:, i])) if 0 < yc.sum() < len(yc) else None
        r["roc_auc"] = float(roc_auc_score(yc, proba[:, i])) if 0 < yc.sum() < len(yc) else None
        out[c] = r
    return out
