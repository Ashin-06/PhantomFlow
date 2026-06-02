# train/online_trainer.py
"""
Trains all PhantomFlow models incrementally — one chunk at a time.
Never loads full dataset into memory.
Uses River for true online ML and sklearn partial_fit for classical models.
"""

import numpy as np
import pandas as pd
import pickle
import time
import mlflow
from typing import Optional
from sklearn.preprocessing import RobustScaler
from sklearn.impute import SimpleImputer
from sklearn.linear_model import SGDClassifier
from sklearn.naive_bayes import GaussianNB
import xgboost as xgb
import river
from river import forest, linear_model, preprocessing, metrics, drift

from lab.stream_reader import DatasetStreamer
from lab.feature_adapter import UniversalAdapter, PHANTOMFLOW_FEATURES


class OnlineTrainer:
    """
    Trains models incrementally on streaming chunks.
    
    For each chunk arriving from the stream:
    1. Adapt features to PhantomFlow schema
    2. Impute missing values
    3. Scale features
    4. Update all models (partial_fit or River update)
    5. Log running metrics to MLflow
    6. Save checkpoint every N chunks
    """

    CHECKPOINT_EVERY = 50    # Save model every 50 chunks
    LOG_EVERY = 10           # Log metrics every 10 chunks

    def __init__(self, output_dir: str = "models/"):
        self.output_dir = output_dir
        self.streamer = DatasetStreamer()
        self.adapter = UniversalAdapter()
        self.chunk_count = 0
        self.total_rows = 0
        self.current_dataset_key = ""
        
        # Connect to Redis for real-time telemetry updates to dashboard
        try:
            import redis
            self.redis_client = redis.Redis(host="localhost", port=6379, decode_responses=True)
            self.redis_client.set("train_status", "idle")
            self.redis_client.set("train_rows", 0)
            self.redis_client.set("train_accuracy", 0.0)
            self.redis_client.set("train_f1_macro", 0.0)
            self.redis_client.set("train_current_dataset", "")
            self.redis_client.delete("train_drift_events")
            self.redis_client.delete("train_logs")
            for ds in ["cicids2017_monday", "cicids2017_friday", "cicids2017_wednesday", "cicids2017_thursday", "ctu13_scenario1", "unsw_nb15_train", "dns_exfil_github"]:
                self.redis_client.set(f"train_progress:{ds}", 0.0)
        except Exception:
            self.redis_client = None

        # Preprocessing (fitted incrementally)
        self.imputer = SimpleImputer(strategy="median")
        self.scaler = RobustScaler()
        self._preprocessors_fitted = False

        self.river_model = forest.ARFClassifier(
            n_models=3,
            max_features="sqrt",
            seed=42,
        )

        # === Model 2: SGD Classifier (sklearn online) ===
        # partial_fit() updates on each chunk
        # Handles the temporal drift between dataset sources
        self.sgd_model = SGDClassifier(
            loss="modified_huber",     # Gives probability estimates
            alpha=1e-4,                # L2 regularization
            max_iter=1,                # One pass per chunk
            warm_start=True,           # Keeps existing weights
            # NOTE: class_weight='balanced' is incompatible with partial_fit
            # Use sample_weight per-batch instead if needed
            random_state=42,
        )
        self.sgd_classes = np.array([0, 1, 2, 3])

        # === Model 3: XGBoost (batch, retrained every N chunks) ===
        self.xgb_buffer_X = []
        self.xgb_buffer_y = []
        self.XGB_BUFFER_SIZE = 200000   # Retrain XGB every 200K rows
        self.xgb_model = None

        # === Online metrics (River) ===
        self.river_accuracy  = metrics.Accuracy()
        self.river_f1_macro  = metrics.MacroF1()
        self.river_kappa     = metrics.CohenKappa()

        # === Drift detector ===
        self.drift_detector = drift.ADWIN(delta=0.0002)
        self.drift_events = []

        # === Threat replay buffer for class balancing ===
        self.replay_buffer_X = {1: [], 2: [], 3: []}
        self.replay_buffer_y = {1: [], 2: [], 3: []}
        self.MAX_REPLAY_SAMPLES = 10000

    def _log_and_print(self, msg: str, is_drift: bool = False, dataset_key: Optional[str] = None, progress: Optional[float] = None):
        print(msg)
        if self.redis_client:
            try:
                self.redis_client.rpush("train_logs", msg)
                self.redis_client.ltrim("train_logs", -500, -1)
                
                self.redis_client.set("train_rows", self.total_rows)
                self.redis_client.set("train_accuracy", self.river_accuracy.get())
                self.redis_client.set("train_f1_macro", self.river_f1_macro.get())
                
                if dataset_key:
                    self.redis_client.set("train_current_dataset", dataset_key)
                if progress is not None:
                    self.redis_client.set(f"train_progress:{dataset_key}", progress)
            except Exception:
                pass

    def train_on_datasets(self, dataset_keys: list,
                           max_rows_per_dataset: Optional[int] = None):
        """
        Stream and train on multiple datasets sequentially.
        Handles the domain shift between datasets automatically.
        """
        mlflow.set_experiment("phantomflow_online")
        if self.redis_client:
            self.redis_client.set("train_status", "training")

        try:
            with mlflow.start_run(run_name="online_multi_dataset"):
                mlflow.log_param("datasets", dataset_keys)
                mlflow.log_param("max_rows_per_dataset", max_rows_per_dataset)

                for dataset_key in dataset_keys:
                    self.current_dataset_key = dataset_key
                    if self.redis_client:
                        self.redis_client.set("train_current_dataset", dataset_key)
                    self._log_and_print(f"\n{'='*60}")
                    self._log_and_print(f"[Online] Dataset: {dataset_key}", dataset_key=dataset_key)
                    self._log_and_print(f"{'='*60}")

                    try:
                        self._train_on_single_dataset(
                            dataset_key, max_rows_per_dataset
                        )
                    except Exception as e:
                        self._log_and_print(f"  [WARN] Dataset {dataset_key} failed: {e}")
                        continue

                # Final evaluation and save
                self._final_save()
                self._log_final_metrics()
                
            if self.redis_client:
                self.redis_client.set("train_status", "success")
        except Exception as e:
            if self.redis_client:
                self.redis_client.set("train_status", "failed")
            self._log_and_print(f"[CRITICAL] Training run failed: {e}")
            raise e

    def _train_on_single_dataset(self, dataset_key: str,
                                   max_rows: Optional[int]):
        """Process one dataset, chunk by chunk."""
        current_ds_rows = 0
        total_expected = max_rows if max_rows is not None else 100000
        
        for chunk_df in self.streamer.stream(dataset_key, max_rows):

            # 1. Adapt to PhantomFlow schema
            adapted = self.adapter.adapt(chunk_df, dataset_key)
            if len(adapted) == 0:
                continue

            # Separate features and labels
            X_raw = adapted[PHANTOMFLOW_FEATURES]
            y = adapted["label"].values.astype(int)

            # 2. Fit or transform preprocessors
            X_processed = self._preprocess(X_raw)
            if X_processed is None:
                continue

            # Record threat samples in replay buffer
            for cls in [1, 2, 3]:
                idx = (y == cls)
                if np.any(idx):
                    self.replay_buffer_X[cls].extend(X_processed[idx])
                    self.replay_buffer_y[cls].extend(y[idx])
                    if len(self.replay_buffer_y[cls]) > self.MAX_REPLAY_SAMPLES:
                        self.replay_buffer_X[cls] = self.replay_buffer_X[cls][-self.MAX_REPLAY_SAMPLES:]
                        self.replay_buffer_y[cls] = self.replay_buffer_y[cls][-self.MAX_REPLAY_SAMPLES:]

            # Construct balanced training batch for SGD Classifier to prevent benign overfitting
            X_sgd = X_processed
            y_sgd = y
            
            mix_X = [X_processed]
            mix_y = [y]
            for cls in [1, 2, 3]:
                if len(self.replay_buffer_y[cls]) > 0:
                    # Sample from buffer to balance the batch
                    n_samples = min(len(self.replay_buffer_y[cls]), len(y) // 3)
                    if n_samples > 0:
                        sampled_idx = np.random.choice(len(self.replay_buffer_y[cls]), n_samples, replace=True)
                        mix_X.append(np.array(self.replay_buffer_X[cls])[sampled_idx])
                        mix_y.append(np.array(self.replay_buffer_y[cls])[sampled_idx])
            X_sgd = np.vstack(mix_X)
            y_sgd = np.concatenate(mix_y)

            # 3. Update all models
            self._update_river(X_processed, y)
            self._update_sgd(X_sgd, y_sgd)
            self._update_xgb_buffer(X_processed, y)

            # 4. Check for concept drift
            self._check_drift(X_processed, y)

            # 5. Periodic logging and checkpointing
            self.chunk_count += 1
            self.total_rows += len(y)
            current_ds_rows += len(y)

            # Update progress percent in Redis
            progress_pct = min(100.0, (current_ds_rows / total_expected) * 100.0)
            self._log_and_print(
                f"  [STREAM] Streamed {self.total_rows:,} labeled rows",
                dataset_key=dataset_key,
                progress=progress_pct
            )

            if self.chunk_count % self.LOG_EVERY == 0:
                self._log_metrics()

            if self.chunk_count % self.CHECKPOINT_EVERY == 0:
                self._save_checkpoint()
                
        # Mark current dataset as 100% complete
        if self.redis_client:
            self.redis_client.set(f"train_progress:{dataset_key}", 100.0)

    def _preprocess(self, X_raw: pd.DataFrame) -> Optional[np.ndarray]:
        """Impute NaNs and scale. Fitted incrementally."""
        X = X_raw.values.astype(np.float32)

        # Replace inf values
        X = np.where(np.isinf(X), np.nan, X)

        if not self._preprocessors_fitted:
            # First chunk: fit imputer and scaler
            if X.shape[0] < 10:
                return None
            # Force fitting on a clean non-empty dummy baseline to prevent "not fitted" errors
            dummy_fit = np.zeros((10, X.shape[1]), dtype=np.float32)
            dummy_fit = np.vstack([dummy_fit, np.nan_to_num(X)])
            self.imputer.fit(dummy_fit)
            X_imp = self.imputer.transform(X)
            self.scaler.fit(X_imp)
            X_scaled = self.scaler.transform(X_imp)
            self._preprocessors_fitted = True
        else:
            # Subsequent chunks: transform only
            X_imp = self.imputer.transform(X)
            X_scaled = self.scaler.transform(X_imp)

        return X_scaled.astype(np.float32)

    def _update_river(self, X: np.ndarray, y: np.ndarray):
        """
        Update River model one sample at a time.
        Subsamples the entire stream by 95% (only 5% rate) to achieve extreme 20x speedup
        and enable real-time line-rate execution over millions of rows.
        """
        for xi, yi in zip(X, y):
            # Stochastic subsampling at 5% rate for real-time online training
            if np.random.rand() > 0.05:
                continue
                
            xi_dict = {f"f{i}": float(v) for i, v in enumerate(xi)}

            # Predict before update (prequential evaluation — no data leakage)
            y_pred = self.river_model.predict_one(xi_dict)
            if y_pred is not None:
                self.river_accuracy.update(yi, y_pred)
                self.river_f1_macro.update(yi, y_pred)
                self.river_kappa.update(yi, y_pred)

            # Update
            self.river_model.learn_one(xi_dict, yi)

    def _update_sgd(self, X: np.ndarray, y: np.ndarray):
        """
        Update SGD classifier on each chunk.
        Must pass all classes on first call.
        """
        # Calculate sample weights to balance classes per-batch
        from sklearn.utils.class_weight import compute_sample_weight
        sample_weights = compute_sample_weight(class_weight='balanced', y=y)
        self.sgd_model.partial_fit(X, y, classes=self.sgd_classes, sample_weight=sample_weights)

    def _update_xgb_buffer(self, X: np.ndarray, y: np.ndarray):
        """
        XGBoost doesn't support true online learning.
        Buffer rows, retrain from scratch when buffer fills.
        Use last N rows to avoid unbounded memory.
        """
        self.xgb_buffer_X.append(X)
        self.xgb_buffer_y.append(y)

        total_buffered = sum(len(a) for a in self.xgb_buffer_y)
        if total_buffered >= self.XGB_BUFFER_SIZE:
            X_buf = np.vstack(self.xgb_buffer_X)
            y_buf = np.concatenate(self.xgb_buffer_y)

            # Skip XGBoost retraining if we are on Monday benign baseline (where no real threats exist yet)
            if self.current_dataset_key == "cicids2017_monday":
                self.xgb_buffer_X = [X_buf[-10000:]]
                self.xgb_buffer_y = [y_buf[-10000:]]
                return

            print(f"\n  [XGB] Retraining on {total_buffered:,} buffered rows...")

            # Balance the XGBoost training buffer using oversampling to prevent benign majority bias
            from sklearn.utils import resample
            X_resampled_list = []
            y_resampled_list = []
            
            unique_classes, counts = np.unique(y_buf, return_counts=True)
            max_count = min(max(counts) if len(counts) > 0 else 0, 20000)
            
            for cls in [0, 1, 2, 3]:
                idx = (y_buf == cls)
                if np.sum(idx) > 0:
                    X_cls = X_buf[idx]
                    y_cls = y_buf[idx]
                    if len(X_cls) < max_count:
                        X_os, y_os = resample(X_cls, y_cls, replace=True, n_samples=max_count, random_state=42)
                        X_resampled_list.append(X_os)
                        y_resampled_list.append(y_os)
                    else:
                        X_resampled_list.append(X_cls)
                        y_resampled_list.append(y_cls)
                else:
                    # Class is completely missing from current buffer!
                    # Pull from replay buffer if we have cached historical samples
                    if cls in self.replay_buffer_y and len(self.replay_buffer_y[cls]) > 0:
                        X_cls = np.array(self.replay_buffer_X[cls])
                        y_cls = np.array(self.replay_buffer_y[cls])
                        X_os, y_os = resample(X_cls, y_cls, replace=True, n_samples=max_count, random_state=42)
                        X_resampled_list.append(X_os)
                        y_resampled_list.append(y_os)
                    else:
                        # Replay buffer also empty (e.g., Monday cold-start), seed with zero-baseline dummy rows
                        dummy_X = np.zeros((max_count, X_buf.shape[1]), dtype=np.float32)
                        dummy_y = np.full(max_count, cls, dtype=np.int32)
                        X_resampled_list.append(dummy_X)
                        y_resampled_list.append(dummy_y)
            
            if X_resampled_list:
                X_buf_bal = np.vstack(X_resampled_list)
                y_buf_bal = np.concatenate(y_resampled_list)
            else:
                X_buf_bal, y_buf_bal = X_buf, y_buf

            self.xgb_model = xgb.XGBClassifier(
                n_estimators=200,
                max_depth=6,
                learning_rate=0.05,
                subsample=0.8,
                colsample_bytree=0.8,
                objective="multi:softprob",
                num_class=4,
                eval_metric="mlogloss",
                tree_method="hist",
                random_state=42,
            )
            self.xgb_model.fit(X_buf_bal, y_buf_bal)

            # Audit feature importances for leakage!
            importances = self.xgb_model.feature_importances_
            total_gain = np.sum(importances)
            if total_gain > 0:
                for idx, gain in enumerate(importances):
                    if gain > 0.40 * total_gain:
                        feat_name = PHANTOMFLOW_FEATURES[idx]
                        self._log_and_print(
                            f"  [WARN] Feature Importance Audit: Feature '{feat_name}' has {gain:.1%} of total XGBoost gain — investigate for leakage!"
                        )

            # Keep only last 10K rows as buffer
            self.xgb_buffer_X = [X_buf[-10000:]]
            self.xgb_buffer_y = [y_buf[-10000:]]
            self._log_and_print(f"  [XGB] Done. Buffer reset to 10K rows.")

    def _check_drift(self, X: np.ndarray, y: np.ndarray):
        """
        ADWIN drift detector on prediction error rate.
        Fires when error rate changes significantly — means
        the stream distribution has shifted.
        """
        if self.sgd_model.classes_ is None:
            return

        preds = self.sgd_model.predict(X)
        errors = (preds != y).astype(float)

        # Update ADWIN sample-by-sample using a 10% subsample of the chunk to maintain speed
        subsample_idx = np.random.choice(len(errors), size=max(1, len(errors) // 10), replace=False)
        for err in errors[subsample_idx]:
            in_drift = self.drift_detector.update(err)
            if in_drift:
                event = {
                    "chunk": self.chunk_count,
                    "total_rows": self.total_rows,
                    "error_rate": float(np.mean(errors)),
                    "dataset": self.current_dataset_key,
                    "timestamp": time.time(),
                }
                self.drift_events.append(event)
                msg = f"\n  [DRIFT] DRIFT DETECTED at chunk {self.chunk_count}: error_rate={event['error_rate']:.3f}"
                self._log_and_print(msg, is_drift=True)
                if self.redis_client:
                    import json
                    try:
                        self.redis_client.rpush("train_drift_events", json.dumps(event))
                    except Exception:
                        pass
                mlflow.log_metric("drift_event", self.chunk_count)
                break  # Only log once per chunk

    def _sanity_check(self, acc, f1, kappa, dataset_name):
        if acc > 0.999 and kappa < 0.100 and self.total_rows > 10000:
            raise ValueError(
                f"[{dataset_name}] Perfect accuracy with near-zero Kappa — "
                "likely class imbalance or label leakage. Abort."
            )
        if acc > 0.999 and f1 > 0.999:
            import logging
            logging.warning(
                f"[{dataset_name}] Suspiciously perfect scores — "
                "check for identity column leakage."
            )

    def _log_metrics(self):
        """Log running metrics to MLflow and console."""
        metrics_dict = {
            "river_accuracy":      self.river_accuracy.get(),
            "river_f1_macro":      self.river_f1_macro.get(),
            "river_kappa":         self.river_kappa.get(),
            "total_rows":          self.total_rows,
            "drift_events_count":  len(self.drift_events),
        }

        try:
            self._sanity_check(
                metrics_dict["river_accuracy"],
                metrics_dict["river_f1_macro"],
                metrics_dict["river_kappa"],
                self.current_dataset_key
            )
        except ValueError as e:
            self._log_and_print(f"  [CRITICAL SANITY FAILURE] {e}")
            raise e

        mlflow.log_metrics(metrics_dict, step=self.total_rows)

        self._log_and_print(
            f"  Rows: {self.total_rows:>8,} | "
            f"Acc: {metrics_dict['river_accuracy']:.3f} | "
            f"F1: {metrics_dict['river_f1_macro']:.3f} | "
            f"Kappa: {metrics_dict['river_kappa']:.3f}"
        )

    def _save_checkpoint(self):
        """Save all model states to disk."""
        import os, joblib
        os.makedirs(self.output_dir, exist_ok=True)

        joblib.dump(self.river_model,  f"{self.output_dir}/river_model.pkl")
        joblib.dump(self.sgd_model,    f"{self.output_dir}/sgd_model_47.pkl")
        joblib.dump(self.imputer,      f"{self.output_dir}/imputer_47.pkl")
        joblib.dump(self.scaler,       f"{self.output_dir}/scaler_47.pkl")

        if self.xgb_model:
            self.xgb_model.save_model(f"{self.output_dir}/xgb_model.json")

        self._log_and_print(f"  [SAVED] Checkpoint saved (rows={self.total_rows:,})")

    def _final_save(self):
        """Flush XGB buffer and save everything."""
        # Force final XGB train on whatever is buffered
        if self.xgb_buffer_X:
            X_buf = np.vstack(self.xgb_buffer_X)
            y_buf = np.concatenate(self.xgb_buffer_y)
            if len(X_buf) > 10:
                self.xgb_model = xgb.XGBClassifier(
                    n_estimators=300,
                    objective="multi:softprob",
                    num_class=4,
                    eval_metric="mlogloss",
                    tree_method="hist",
                )
                self.xgb_model.fit(X_buf, y_buf)

        self._save_checkpoint()

    def _log_final_metrics(self):
        self._log_and_print(f"\n{'='*60}")
        self._log_and_print(f"FINAL TRAINING SUMMARY")
        self._log_and_print(f"{'='*60}")
        self._log_and_print(f"Total rows processed:  {self.total_rows:,}")
        self._log_and_print(f"Total chunks:          {self.chunk_count:,}")
        self._log_and_print(f"Drift events:          {len(self.drift_events)}")
        self._log_and_print(f"River Accuracy:        {self.river_accuracy.get():.4f}")
        self._log_and_print(f"River F1 Macro:        {self.river_f1_macro.get():.4f}")
        self._log_and_print(f"Cohen's Kappa:         {self.river_kappa.get():.4f}")
        if self.drift_events:
            self._log_and_print(f"Drift events at rows:  {[e['total_rows'] for e in self.drift_events]}")
