# pipeline/precision_recovery.py
"""
Two-Stage C2 Beacon Detector.
Stage 1: Catch wide using calibrated Invariant Logistic Regression at z=-7.0.
Stage 2: Filter precise using host-level connection history and temporal context.
"""

import numpy as np
import pandas as pd
import joblib
from typing import List, Dict, Tuple, Optional

class TwoStageDetector:
    MIN_HISTORY_LEN = 2
    STAGE2_THRESHOLD = 0.45

    def __init__(self, stage1_path: str = "models/sgd_model.pkl",
                 imputer_path: str = "models/imputer.pkl",
                 scaler_path: str = "models/scaler.pkl",
                 stage2_path: str = "models/stage2_precision_model.pkl",
                 stage1_threshold: float = -7.0):
        # Load Stage 1 assets
        self.lr = joblib.load(stage1_path)
        self.imputer = joblib.load(imputer_path)
        self.scaler = joblib.load(scaler_path)
        self.z = stage1_threshold
        
        # Load Stage 2 assets (fall back to heuristic rules if model doesn't exist yet)
        try:
            loaded = joblib.load(stage2_path)
            if isinstance(loaded, dict) and "model" in loaded:
                self.stage2 = loaded["model"]
                self.stage2_features = loaded.get("features", ["iat_cv", "trend", "duration_cv", "history_len", "periodicity_score", "regularity"])
                self.stage2_threshold = loaded.get("best_threshold", self.STAGE2_THRESHOLD)
            else:
                self.stage2 = loaded
                self.stage2_features = ["iat_cv", "trend", "duration_cv", "history_len", "periodicity_score", "regularity"]
                self.stage2_threshold = self.STAGE2_THRESHOLD
            # Force stage2_threshold to 0.45
            self.stage2_threshold = min(self.stage2_threshold, self.STAGE2_THRESHOLD)
            self.has_stage2_model = True
            print(f"[TwoStageDetector] Loaded Stage 2 ML model from {stage2_path} using features: {self.stage2_features} (threshold={self.stage2_threshold})")
        except Exception:
            self.stage2 = None
            self.has_stage2_model = False
            self.stage2_features = []
            self.stage2_threshold = self.STAGE2_THRESHOLD
            print("[TwoStageDetector] Stage 2 ML model not found. Falling back to heuristic context rules.")

    def predict(self, flow_features: Dict, flow_history: List[Dict]) -> Tuple[str, float]:
        """
        Predict C2 beaconing using both single-flow and historical context.
        
        flow_features: Dict of current flow features containing:
          - duration_s, total_bytes, orig_bytes, orig_pkts, resp_bytes, bytes_ratio
        flow_history: List of Dicts representing past connections from same src_ip
        """
        # 1. Prepare Stage 1 features
        feat_cols = ["duration_s", "total_bytes", "orig_bytes", "orig_pkts", "resp_bytes", "bytes_ratio"]
        row = [flow_features.get(c, 0.0) for c in feat_cols]
        
        # Transform using Stage 1 preprocessors
        X_clean = np.where(np.isinf([row]), np.nan, [row])
        X_imp = self.imputer.transform(X_clean)
        X_scaled = self.scaler.transform(X_imp)
        
        # Get Stage 1 decision function score
        score = self.lr.decision_function(X_scaled)[0]
        
        # If Stage 1 doesn't trigger, classify as benign immediately
        if score < self.z:
            return "benign", float(1.0 / (1.0 + np.exp(-score)))
            
        # 2. Stage 2 Context Validation
        # If there isn't enough history yet, classify as suspicious (pending baseline)
        if len(flow_history) < self.MIN_HISTORY_LEN:
            if score > -3.0:  # Very strong Stage 1 signal
                return "c2_suspicious_strong", 0.65
            return "suspicious", float(1.0 / (1.0 + np.exp(-score)))
            
        context_features = self.extract_context(flow_history)
        
        if self.has_stage2_model:
            # Predict using trained Stage 2 ML model
            try:
                all_feats = ["iat_cv", "trend", "duration_cv", "history_len", "periodicity_score", "regularity", "dominant_period_ms"]
                feat_dict = dict(zip(all_feats, context_features))
                
                sub_context = [feat_dict[f] for f in self.stage2_features]
                X_context = np.array([sub_context]).reshape(1, -1)
                prob = self.stage2.predict_proba(X_context)[0, 1]
                if prob >= self.stage2_threshold:
                    return "c2_beacon", float(prob)
                else:
                    return "benign", float(1.0 - prob)
            except Exception as e:
                print(f"[TwoStageDetector] Stage 2 model inference error: {e}. Falling back to heuristics.")
                
        # Heuristic Stage 2 Fallback Rules
        # Beacons reconnect regularly (low interval coefficient of variation)
        # and have consistent duration and volume characteristics.
        iat_cv = context_features[0]
        duration_cv = context_features[2]
        regularity = context_features[5]
        
        # Heuristic beacon score: lower variance in timing/volume -> higher beacon probability
        is_periodic = iat_cv < 0.25 or regularity > 0.8
        is_consistent_duration = duration_cv < 0.20
        
        if is_periodic or is_consistent_duration:
            return "c2_beacon", 0.85
            
        return "benign", 0.15

    def extract_context(self, history: List[Dict]) -> List[float]:
        """
        Extract temporal and structural context from host flow history.
        """
        if len(history) < 2:
            return [0.0] * 6

        durations = [float(f.get("duration_s", 0.0)) for f in history]
        
        # Parse or mock timestamps if they exist to compute IATs
        timestamps = [float(f.get("ts", f.get("timestamp", i * 60.0))) for i, f in enumerate(history)]
        intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
        intervals_arr = np.array(intervals)
        
        mean_interval = np.mean(intervals_arr) if len(intervals_arr) > 0 else 1e-9
        std_interval = np.std(intervals_arr) if len(intervals_arr) > 0 else 0.0
        iat_cv = std_interval / (mean_interval + 1e-9)
        
        # Calculate trend of intervals
        if len(intervals) >= 2:
            trend = np.corrcoef(range(len(intervals)), intervals)[0, 1]
            if np.isnan(trend):
                trend = 0.0
        else:
            trend = 0.0
            
        mean_duration = np.mean(durations) if durations else 1e-9
        std_duration = np.std(durations) if durations else 0.0
        duration_cv = std_duration / (mean_duration + 1e-9)
        history_len = float(len(history))

        # Autocorrelation periodicity score
        periodicity_score = 0.0
        dominant_period_ms = 0.0
        
        if len(intervals_arr) >= 6:
            try:
                # Handle constant case (zero variance) as perfect periodicity
                if std_interval < 1e-2:
                    periodicity_score = 1.0
                    dominant_period_ms = float(mean_interval * 1000.0)
                else:
                    normed = (intervals_arr - mean_interval) / (std_interval + 1e-9)
                    acf = np.correlate(normed, normed, mode='full')
                    acf = acf[len(acf)//2:]
                    acf /= (acf[0] + 1e-9)
                    
                    if len(acf) > 1:
                        best_lag = int(np.argmax(acf[1:]) + 1)
                        periodicity_score = float(acf[best_lag])
                        dominant_period_ms = float(mean_interval * best_lag * 1000.0)
            except Exception:
                pass
        
        # Regularity score (inverse of CV — high = regular = suspicious)
        regularity = float(max(0.0, 1.0 - min(1.0, iat_cv / 2.0)))
        
        return [
            float(iat_cv),
            float(trend),
            float(duration_cv),
            float(history_len),
            float(periodicity_score),
            float(regularity),
            float(dominant_period_ms)
        ]
