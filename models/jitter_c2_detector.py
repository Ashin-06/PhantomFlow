# models/jitter_c2_detector.py
"""
Jitter-Resilient C2 Detector (MITRE T1071 - Covert Channels)
Identifies automated C2 beacons that attempt to evade static periodicity checks
by adding random delays (jitter) to check-in cycles.
"""
import logging
from typing import Optional, List
from dataclasses import dataclass
import numpy as np

log = logging.getLogger(__name__)

@dataclass
class JitterResult:
    is_beacon: bool
    confidence: float
    estimated_jitter: float
    explanation: str
    severity: str

class JitterC2Detector:
    MIN_SEQUENCE_LENGTH = 8
    MAX_SEQUENCE_LENGTH = 25
    
    # Static beacons have CV < 0.05. Randomized beacons (jitter) have CV between 0.05 and 0.45.
    # Benign human browsing exhibits much higher variance (CV > 1.2).
    MIN_JITTER_CV = 0.05
    MAX_JITTER_CV = 0.45
    
    def __init__(self, redis_client=None):
        self.redis = redis_client

    def check_sequence(self, intervals: List[float], packet_sizes: List[int]) -> Optional[JitterResult]:
        if not intervals or len(intervals) < self.MIN_SEQUENCE_LENGTH:
            return None
            
        # Analyze the recent window of intervals and payload sizes
        seq = np.array(intervals[-self.MAX_SEQUENCE_LENGTH:], dtype=float)
        sizes = np.array(packet_sizes[-self.MAX_SEQUENCE_LENGTH:], dtype=float)

        mean_val = np.mean(seq)
        std_val = np.std(seq)
        
        # Keep short, instantaneous connections from causing division issues
        if mean_val < 0.8:
            return None

        cv = std_val / mean_val

        # 1. Check if the interval Coefficient of Variation falls within the automated jitter range
        if self.MIN_JITTER_CV <= cv <= self.MAX_JITTER_CV:
            # 2. Check for Packet Payload Uniformity
            # Automated beacons typically transmit highly consistent packet sizes (check-in metadata)
            mean_size = np.mean(sizes)
            if mean_size > 0:
                size_cv = np.std(sizes) / mean_size
            else:
                size_cv = 0.0
            
            # Normal user browsing has highly varying packet sizes (size_cv > 0.6)
            # Beacons have highly uniform packet sizes (size_cv < 0.2)
            if size_cv < 0.20:
                # Confidence scales inversely with jitter (lower CV = higher confidence)
                confidence = min(0.96, 0.70 + (0.45 - cv) * 0.50)
                
                # Check if it's a fast beacon (e.g. < 5s interval) or slow beacon
                severity = "high" if mean_val < 10.0 else "medium"
                
                return JitterResult(
                    is_beacon=True,
                    confidence=round(confidence, 3),
                    estimated_jitter=round(cv * 100, 1),
                    explanation=(
                        f"Jittered C2 beacon detected. Average interval is {mean_val:.1f} seconds "
                        f"with {cv*100:.1f}% interval jitter. Payload packet sizes are highly uniform "
                        f"(Size CV: {size_cv*100:.1f}%), indicating automated heartbeats."
                    ),
                    severity=severity
                )

        return None
