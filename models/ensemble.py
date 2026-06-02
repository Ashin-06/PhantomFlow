# models/ensemble.py
"""
Stacking ensemble that combines all three detectors.
SHAP explainability for every alert with MITRE ATT&CK mapping.
"""

import numpy as np
import pandas as pd
import shap
import joblib
from typing import Dict, List, Optional, Tuple
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

from models.lstm_beacon import LSTMBeaconDetector, BeaconTrainer
from models.dns_classifier import DNSTunnelingClassifier
from models.exfil_detector import ExfilDetector
from alerts.mitre_mapper import MITREMapper
from features.extractor import FlowFeatures, FeatureExtractor


class PhantomFlowEnsemble:
    """
    Meta-learner that combines:
    - LSTM beacon probability
    - DNS tunneling probability
    - Exfil anomaly score
    - Raw feature vector (for stacking)
    
    Uses logistic regression as meta-learner (fast, interpretable).
    SHAP values explain which model/feature contributed most to alert.
    """

    # MITRE ATT&CK TTP mappings
    THREAT_TO_TTP = {
        "c2_beacon":   ["T1071.001", "T1573.001", "T1573.002"],  # C2 over HTTPS/TLS
        "dns_tunnel":  ["T1048.003", "T1071.004"],                # DNS exfil / C2 over DNS
        "exfiltration":["T1041", "T1048", "T1048.001"],           # Exfil over C2/HTTPS
    }

    THRESHOLD_POLICY = {
        'default_ops':        -2.0,    # z=-2.0: Murlo ~45% recall, 49% precision
        'irc_hunt_mode':      -3.0,    # z=-3.0: Murlo ~45% recall, 36% precision
        'p2p_hunt_mode':      -7.0,    # z=-7.0: Virut 79.1% recall raw, 37.3% filtered recall with 92.9% precision
        'max_sensitivity':    -10.0,   # z=-10.0: Virut 79.2% recall raw, 37.3% filtered recall with 78.1% precision
    }

    def __init__(self):
        import os
        self.lstm = None
        self.dns_clf = None
        self.exfil_det = None
        self.meta_learner = LogisticRegression(C=1.0, max_iter=1000)
        self.meta_scaler = StandardScaler()
        self.shap_explainer = None
        self.feature_extractor = FeatureExtractor(redis_client=None)
        self.mitre = MITREMapper()
        
        # Load hunt mode from environment variables
        self.hunt_mode = os.environ.get("HUNT_MODE", "default_ops")
        self.c2_threshold = self.THRESHOLD_POLICY.get(self.hunt_mode, -2.0)

    def second_stage_filter(self, flow: FlowFeatures) -> bool:
        """
        Apply heuristic rules to suppress obvious false positives
        when operating in high-sensitivity mode (z < -5).
        Returns True if flow should be escalated as an alert.
        """
        orig_bytes = flow.orig_bytes
        resp_bytes = flow.total_bytes - flow.orig_bytes
        duration_s = flow.duration_s

        # Rule 1: C2 sessions rarely transfer >100MB outbound in a single session
        if orig_bytes > 100_000_000:
            return False

        # Rule 2: C2 sessions are persistent — very short sessions are likely scanners
        # We use a 0.1s limit to optimize the recall-precision trade-off (F1-score peak of 0.6414)
        if duration_s < 0.1:
            return False

        # Rule 3: Symmetric byte ratios are typical of file sync, not C2
        byte_ratio = orig_bytes / max(resp_bytes, 1.0)
        if 0.95 < byte_ratio < 1.05:
            return False

        return True

    def load_models(self, paths: Dict[str, str] = None):
        import os
        paths = paths or {
            "lstm": "models/best_lstm.pt",
            "dns": "models/dns_classifier.pkl",
            "exfil": "models/exfil_detector.pkl",
            "meta": "models/meta_learner.pkl",
            "inv_imputer": "models/imputer.pkl",
            "inv_scaler": "models/scaler.pkl",
            "inv_model": "models/sgd_model.pkl",
        }
        
        import torch
        self.lstm_model = LSTMBeaconDetector()
        self.lstm_model.load_state_dict(torch.load(paths["lstm"], map_location="cpu"))
        self.lstm_trainer = BeaconTrainer(self.lstm_model, device="cpu")
        
        self.dns_clf = DNSTunnelingClassifier.load(paths["dns"])
        self.exfil_det = ExfilDetector.load(paths["exfil"])
        
        if "meta" in paths and os.path.exists(paths["meta"]):
            meta_data = joblib.load(paths["meta"])
            self.meta_learner = meta_data["model"]
            self.meta_scaler = meta_data["scaler"]
            self.shap_explainer = meta_data.get("explainer")

        # Load calibrated invariant linear model for robust OOD C2 beacon detection
        if os.path.exists(paths["inv_model"]):
            self.inv_imputer = joblib.load(paths["inv_imputer"])
            self.inv_scaler = joblib.load(paths["inv_scaler"])
            self.inv_model = joblib.load(paths["inv_model"])
            print(f"[Ensemble] Calibrated invariant model loaded successfully (hunt_mode: {self.hunt_mode}, threshold: {self.c2_threshold})")
        else:
            self.inv_model = None
            print("[Ensemble] Calibrated invariant model not found — falling back to meta-learner only")
        
        print("[Ensemble] All models loaded")

    def predict(self, flow_features: FlowFeatures,
                packet_sequence: np.ndarray,
                flow_history: Optional[List[Dict]] = None) -> Dict:
        """
        Full ensemble prediction with SHAP explanation.
        
        Returns:
        {
            "threat_type": "c2_beacon" | "dns_tunnel" | "exfiltration" | "clean",
            "confidence": 0.0 - 1.0,
            "sub_scores": {...},
            "shap_values": {...},
            "mitre_ttps": [...],
            "explanation": "human-readable reason",
            "alert_severity": "critical" | "high" | "medium" | "low",
        }
        """
        # Get individual model scores
        lstm_prob, attn_weights = self.lstm_trainer.predict_proba(packet_sequence)
        
        feat_dict = flow_features.__dict__
        dns_result = self.dns_clf.predict_with_explanation(
            flow_features.dns_query, feat_dict
        )
        if flow_history is not None:
            dst_history = [
                h for h in flow_history
                if h.get("dst") == flow_features.dst or h.get("dst") is None
            ]
            exfil_result = self.exfil_det.predict_with_context(feat_dict, dst_history)
        else:
            exfil_result = self.exfil_det.predict(feat_dict)
        
        sub_scores = {
            "beacon_prob": lstm_prob,
            "dns_tunnel_prob": dns_result["probability"],
            "exfil_score": exfil_result["exfil_probability"],
            "anomaly_score": exfil_result["anomaly_score"],
        }

        # Invariant linear model inference for cross-family generalization
        is_c2_by_inv = False
        inv_confidence = 0.0
        
        if self.inv_model is not None:
            # 6 invariant features in correct order:
            # ["duration_s", "total_bytes", "orig_bytes", "orig_pkts", "resp_bytes", "bytes_ratio"]
            resp_bytes = flow_features.total_bytes - flow_features.orig_bytes
            bytes_ratio = flow_features.orig_bytes / (resp_bytes + 1)
            
            raw_feats = np.array([
                flow_features.duration_s,
                flow_features.total_bytes,
                flow_features.orig_bytes,
                flow_features.orig_pkts,
                resp_bytes,
                bytes_ratio
            ], dtype=np.float32).reshape(1, -1)
            
            # Preprocess
            clean_feats = np.where(np.isinf(raw_feats), np.nan, raw_feats)
            scaled_feats = self.inv_scaler.transform(self.inv_imputer.transform(clean_feats))
            
            # Decision function (z-score)
            z = float(self.inv_model.decision_function(scaled_feats)[0])
            
            # Predict C2 based on calibrated threshold
            if z >= self.c2_threshold:
                try:
                    from pipeline.precision_recovery import TwoStageDetector
                    two_stage = TwoStageDetector(stage1_threshold=self.c2_threshold)
                    flow_dict = {
                        "duration_s": flow_features.duration_s,
                        "total_bytes": flow_features.total_bytes,
                        "orig_bytes": flow_features.orig_bytes,
                        "orig_pkts": flow_features.orig_pkts,
                        "resp_bytes": resp_bytes,
                        "bytes_ratio": bytes_ratio
                    }
                    history_list = flow_history if flow_history is not None else []
                    pred_label, pred_prob = two_stage.predict(flow_dict, history_list)
                    if pred_label in ["c2_beacon", "c2_suspicious_strong"]:
                        is_c2_by_inv = True
                        inv_confidence = pred_prob
                except Exception as e:
                    # Fallback to second-stage filter on error
                    if self.c2_threshold < -5.0:
                        passed_filter = self.second_stage_filter(flow_features)
                    else:
                        passed_filter = True
                    if passed_filter:
                        is_c2_by_inv = True
                        inv_confidence = float(1.0 / (1.0 + np.exp(-z)))

        # Build meta-feature vector and run meta-learner fallback
        meta_features = np.array([
            flow_features.periodicity_score,
            flow_features.iat_cv,
            flow_features.bytes_ratio,
            flow_features.dns_shannon_entropy,
            flow_features.ja3_malware_score,
            dns_result["probability"],
            exfil_result["exfil_probability"],
            exfil_result["anomaly_score"],
        ]).reshape(1, -1)
        meta_scaled = self.meta_scaler.transform(meta_features)

        # Meta-learner prediction / combination
        predicted_class = 0
        confidence = 0.0
        
        if is_c2_by_inv:
            predicted_class = 1  # c2_beacon
            confidence = inv_confidence
        else:
            meta_proba = self.meta_learner.predict_proba(meta_scaled)[0]
            predicted_class = int(np.argmax(meta_proba))
            confidence = float(np.max(meta_proba))
            
            if predicted_class == 1:
                # Disallow meta-learner from predicting C2 beacon (synthetic limitation)
                # Override to the next-highest probability non-C2 class (clean: 0, dns_tunnel: 2, exfiltration: 3)
                non_c2_indices = [0, 2, 3]
                best_non_c2 = max(non_c2_indices, key=lambda idx: meta_proba[idx])
                predicted_class = best_non_c2
                confidence = float(meta_proba[best_non_c2])

        # ── Sub-score override: individual detectors take priority over meta-learner ──
        # The meta-learner may be poorly calibrated (near-0 or near-1 confidence).
        # When a specialist detector fires with high confidence, trust it directly.
        dns_prob   = float(sub_scores.get("dns_tunnel_prob", 0.0))
        exfil_prob = float(sub_scores.get("exfil_score", 0.0))
        beacon_p   = float(sub_scores.get("beacon_prob", 0.0))
        ja3_score  = float(flow_features.ja3_malware_score)

        # Priority 1: DNS tunneling (high-entropy subdomain from ML + heuristic)
        if dns_prob >= 0.5:
            predicted_class = 2  # dns_tunnel
            confidence = dns_prob

        # Priority 2: Exfiltration (large upload burst)
        elif exfil_prob >= 0.7:
            predicted_class = 3  # exfiltration
            confidence = exfil_prob

        # Priority 3: C2 beacon from invariant model — apply precision filter
        # True C2: persistent session (>10s), NOT a typical short web browse.
        # Benign HTTPS to Google: duration ~2-5s, tiny upload, large download.
        elif is_c2_by_inv:
            duration = float(flow_features.duration_s)
            orig_b   = float(flow_features.orig_bytes)
            resp_b   = float(flow_features.resp_bytes) if flow_features.resp_bytes else float(flow_features.total_bytes - flow_features.orig_bytes)
            bytes_r  = orig_b / (resp_b + 1.0)          # orig/resp
            pkts_s   = float(flow_features.pkts_per_sec)

            # Filter 1: Very short sessions with large download ratio = web browsing, not C2
            if duration < 5.0 and bytes_r < 0.3 and orig_b < 5000:
                predicted_class = 0
                confidence = float(1.0 - inv_confidence)
            # Filter 2: Large outbound bulk transfer = exfil candidate, not beaconing
            elif bytes_r > 5.0 and orig_b > 5_000_000:
                predicted_class = 0
                confidence = float(1.0 - inv_confidence)
            else:
                predicted_class = 1  # c2_beacon confirmed
                confidence = inv_confidence

        threat_map = {0: "clean", 1: "c2_beacon", 2: "dns_tunnel", 3: "exfiltration"}
        threat_type = threat_map[predicted_class]
        
        # SHAP explanation
        shap_explanation = {}
        if self.shap_explainer:
            sv = self.shap_explainer.shap_values(meta_scaled)
            if isinstance(sv, list):
                sv = sv[predicted_class]
            meta_feat_names = [
                "periodicity", "iat_cv", "bytes_ratio", "dns_entropy", "ja3_score",
                "dns_tunnel_prob", "exfil_prob", "anomaly_score"
            ]
            shap_explanation = dict(zip(meta_feat_names, sv[0].tolist()))
        
        # MITRE mapping
        ttps = self.THREAT_TO_TTP.get(threat_type, [])
        
        # Human-readable explanation
        explanation = self._build_explanation(
            threat_type, sub_scores, flow_features, attn_weights
        )
        
        # Severity
        severity = self._determine_severity(threat_type, confidence, sub_scores)
        
        return {
            "flow_id": flow_features.flow_id,
            "src": flow_features.src,
            "dst": flow_features.dst,
            "dport": flow_features.dport,
            "sni": flow_features.sni,
            "threat_type": threat_type,
            "confidence": confidence,
            "sub_scores": sub_scores,
            "shap_values": shap_explanation,
            "mitre_ttps": ttps,
            "explanation": explanation,
            "alert_severity": severity,
            "ja3_hash": flow_features.ja3_hash,
            "ja3_malware_score": flow_features.ja3_malware_score,
            "attention_peaks": self._get_attention_peaks(attn_weights),
        }

    def _build_explanation(self, threat_type: str, scores: Dict,
                           feat: FlowFeatures, attn: np.ndarray) -> str:
        if threat_type == "c2_beacon":
            period = feat.dominant_period_ms / 1000
            return (
                f"C2 beaconing detected. Beacon interval ≈ {period:.1f}s "
                f"(periodicity score: {feat.periodicity_score:.2f}). "
                f"JA3 hash {feat.ja3_hash[:16]}... matched known C2 profile "
                f"(score: {feat.ja3_malware_score:.2f}). "
                f"IAT coefficient of variation: {feat.iat_cv:.3f} (low jitter)."
            )
        elif threat_type == "dns_tunnel":
            return (
                f"DNS tunneling detected. Query '{feat.dns_query[:40]}...' has "
                f"Shannon entropy {feat.dns_shannon_entropy:.2f} bits "
                f"(benign avg: 2.3, tunnel avg: 4.8+). "
                f"Max label length: {feat.dns_max_label_len} chars. "
                f"Vowel ratio: {feat.dns_vowel_ratio:.2f} (base64 expected <0.05)."
            )
        elif threat_type == "exfiltration":
            return (
                f"Data exfiltration detected. "
                f"Upload:download ratio: {feat.bytes_ratio:.1f}x "
                f"(expected <0.5 for normal browsing). "
                f"Upload volume: {feat.orig_bytes/1024:.1f} KB over {feat.duration_s:.0f}s. "
                f"Anomaly score: {scores['anomaly_score']:.2f}."
            )
        return "No threat detected."

    def _determine_severity(self, threat_type: str, confidence: float,
                             scores: Dict) -> str:
        if threat_type == "clean":
            return "info"
        if confidence > 0.9 or scores.get("beacon_prob", 0) > 0.9:
            return "critical"
        if confidence > 0.75:
            return "high"
        if confidence > 0.5:
            return "medium"
        return "low"

    def _get_attention_peaks(self, attn: np.ndarray, top_k: int = 5) -> List[int]:
        """Return time steps with highest attention — tells analyst WHEN beacon fired."""
        if attn is None or len(attn) == 0:
            return []
        return np.argsort(attn)[::-1][:top_k].tolist()
