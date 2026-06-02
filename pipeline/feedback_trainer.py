# pipeline/feedback_trainer.py
"""
Online Learning from Analyst Feedback.
When an analyst marks an alert True Positive or False Positive,
this module partially retrains the invariant LR model on that labelled sample.
This is supervised online learning (active learning) — the industry standard at
Darktrace, Vectra, CrowdStrike for adapting models to specific networks.
"""
import os
import time
import logging
import threading
import numpy as np
from typing import Optional

log = logging.getLogger(__name__)
_lock = threading.Lock()

FEEDBACK_MODEL_PATH = "models/invariant_feedback.pkl"
BASE_MODEL_PATH = "models/stage1_invariant.pkl"

# Features the invariant SGD model was trained on
INVARIANT_FEATURES = [
    "duration_s", "total_bytes", "orig_bytes",
    "orig_pkts", "resp_bytes", "bytes_ratio"
]

class FeedbackTrainer:
    def __init__(self, redis_client=None):
        self.redis = redis_client
        self._model = None
        self._scaler = None
        self._imputer = None
        self._load_model()

    def _load_model(self):
        """Load feedback model (or fall back to base model)."""
        import joblib
        for path in [FEEDBACK_MODEL_PATH, BASE_MODEL_PATH]:
            if os.path.exists(path):
                try:
                    data = joblib.load(path)
                    self._model = data.get("model")
                    self._scaler = data.get("scaler")
                    self._imputer = data.get("imputer")
                    log.info(f"[Feedback] Loaded model from {path}")
                    return
                except Exception as e:
                    log.warning(f"[Feedback] Could not load {path}: {e}")
        log.warning("[Feedback] No model found — feedback will be skipped")

    def _features_to_vector(self, features: dict) -> Optional[np.ndarray]:
        row = []
        for f in INVARIANT_FEATURES:
            val = features.get(f, 0.0)
            if val is None:
                val = 0.0
            try:
                row.append(float(val))
            except (ValueError, TypeError):
                row.append(0.0)
        return np.array([row], dtype=np.float64)

    def update(self, features: dict, label: int) -> bool:
        """
        Partially retrain the model on one labelled sample.
        label: 1 = true positive (threat), 0 = false positive (benign)
        Thread-safe — uses file lock.
        """
        if self._model is None:
            log.warning("[Feedback] No model loaded, skipping update")
            return False

        if not hasattr(self._model, 'partial_fit'):
            log.warning("[Feedback] Model does not support partial_fit")
            return False

        with _lock:
            try:
                X = self._features_to_vector(features)
                # Apply preprocessing if available
                if self._imputer is not None:
                    X = self._imputer.transform(X)
                if self._scaler is not None:
                    X = self._scaler.transform(X)

                self._model.partial_fit(X, [label], classes=[0, 1])

                # Save updated model
                import joblib
                data = {"model": self._model}
                if self._scaler:
                    data["scaler"] = self._scaler
                if self._imputer:
                    data["imputer"] = self._imputer
                joblib.dump(data, FEEDBACK_MODEL_PATH)

                # Update Redis telemetry
                if self.redis:
                    try:
                        self.redis.incr("feedback_count")
                        self.redis.set("last_feedback_ts", int(time.time()))
                        self.redis.set("last_feedback_label", label)
                    except Exception:
                        pass

                log.info(
                    f"[Feedback] Model updated: label={label} "
                    f"({'threat confirmed' if label == 1 else 'false positive corrected'})"
                )
                return True

            except Exception as e:
                log.error(f"[Feedback] partial_fit failed: {e}")
                return False

    def get_stats(self) -> dict:
        stats = {"feedback_count": 0, "last_update": None, "model_path": None}
        if self.redis:
            try:
                stats["feedback_count"] = int(self.redis.get("feedback_count") or 0)
                ts = self.redis.get("last_feedback_ts")
                if ts:
                    stats["last_update"] = int(ts)
            except Exception:
                pass
        if os.path.exists(FEEDBACK_MODEL_PATH):
            stats["model_path"] = FEEDBACK_MODEL_PATH
            stats["model_mtime"] = int(os.path.getmtime(FEEDBACK_MODEL_PATH))
        return stats
