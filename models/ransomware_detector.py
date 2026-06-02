# models/ransomware_detector.py
"""
Ransomware Behaviour Detector (T1486, T1490)
Multi-signal correlation: SMB write bursts + shadow copy kill + pre-encryption C2.
Requires 2+ signals from same src within 5min to alert (reduces false positives).
"""
import time
import logging
from typing import Optional
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

@dataclass
class RansomwareResult:
    is_ransomware: bool
    signals_triggered: list
    confidence: float
    src_ip: str
    mitre_ttps: list
    explanation: str
    severity: str = "critical"

class RansomwareDetector:
    """
    Tracks per-source signals in Redis with 5min TTL.
    Fires when 2+ signals triggered from same src.
    """
    WINDOW_SECONDS = 300   # 5-minute correlation window
    MIN_SIGNALS = 2        # Need at least 2 co-occurring signals
    SMB_RATE_THRESHOLD = 30    # SMB connections/min to trigger smb_burst
    SMB_BYTES_THRESHOLD = 500_000  # >500KB over SMB = large file write
    LATERAL_THRESHOLD = 4  # internal dsts via SMB to trigger smb_spread

    MITRE = ["T1486", "T1490", "T1489", "T1021.002", "T1083"]

    def __init__(self, redis_client=None):
        self.redis = redis_client
        self._signals: dict = {}  # src_ip -> set of signal names
        self._signal_times: dict = {}

    def _record_signal(self, src_ip: str, signal: str):
        now = time.time()
        key = f"ransom:signals:{src_ip}"
        if self.redis:
            try:
                self.redis.sadd(key, signal)
                self.redis.expire(key, self.WINDOW_SECONDS)
                return
            except Exception:
                pass
        # Memory fallback
        if src_ip not in self._signals:
            self._signals[src_ip] = set()
            self._signal_times[src_ip] = now
        # Expire old signals
        if now - self._signal_times.get(src_ip, now) > self.WINDOW_SECONDS:
            self._signals[src_ip] = set()
            self._signal_times[src_ip] = now
        self._signals[src_ip].add(signal)

    def _get_signals(self, src_ip: str) -> set:
        key = f"ransom:signals:{src_ip}"
        if self.redis:
            try:
                return set(self.redis.smembers(key))
            except Exception:
                pass
        return self._signals.get(src_ip, set())

    def _smb_conn_rate(self, src_ip: str, dst_ip: str) -> float:
        """Returns estimated SMB connections/min from Redis counter."""
        bucket = str(int(time.time() / 60))
        key = f"smb_rate:{src_ip}:{dst_ip}:{bucket}"
        if self.redis:
            try:
                count = self.redis.incr(key)
                self.redis.expire(key, 120)
                return float(count)
            except Exception:
                pass
        return 0.0

    def check(self, flow: dict, lateral_movement_detected: bool = False,
              c2_detected: bool = False) -> Optional[RansomwareResult]:
        src_ip = flow.get("src_ip", flow.get("src", ""))
        dst_ip = flow.get("dst_ip", flow.get("dst", ""))
        dst_port_val = flow.get("dst_port")
        if dst_port_val is None:
            dst_port_val = flow.get("dport")
        try:
            dst_port = int(dst_port_val) if dst_port_val is not None else 0
        except (ValueError, TypeError):
            dst_port = 0
            
        try:
            orig_bytes = int(flow.get("orig_bytes") or 0)
        except (ValueError, TypeError):
            orig_bytes = 0
            
        try:
            orig_pkts = int(flow.get("orig_pkts") or 1)
        except (ValueError, TypeError):
            orig_pkts = 1
            
        try:
            duration_s = float(flow.get("duration_s") or 0.1)
        except (ValueError, TypeError):
            duration_s = 0.1
        pkts_per_sec = orig_pkts / max(duration_s, 0.001)

        if not src_ip:
            return None

        triggered = []

        # Signal 1: SMB write burst (large data over SMB at high rate)
        if dst_port == 445:
            smb_rate = self._smb_conn_rate(src_ip, dst_ip)
            if smb_rate >= self.SMB_RATE_THRESHOLD or orig_bytes >= self.SMB_BYTES_THRESHOLD:
                self._record_signal(src_ip, "smb_write_burst")
                triggered.append("smb_write_burst")

        # Signal 2: Shadow copy kill / WMI spray to many internal hosts
        if dst_port in (135, 445) and lateral_movement_detected:
            self._record_signal(src_ip, "shadow_copy_kill_pattern")
            triggered.append("shadow_copy_kill_pattern")

        # Signal 3: Pre-encryption C2 outbound
        if c2_detected:
            self._record_signal(src_ip, "pre_encrypt_c2")
            triggered.append("pre_encrypt_c2")

        # Signal 4: High-rate tiny connections to SMB (file enumeration)
        if dst_port == 445 and pkts_per_sec > 50 and orig_bytes < 10_000:
            self._record_signal(src_ip, "smb_enumeration")
            triggered.append("smb_enumeration")

        # Correlate all signals for this src
        all_signals = self._get_signals(src_ip)
        
        if len(all_signals) < self.MIN_SIGNALS:
            return None

        # Confidence = 0.70 base + 0.10 per additional signal beyond minimum
        confidence = min(0.99, 0.70 + (len(all_signals) - self.MIN_SIGNALS) * 0.10)
        
        signals_list = sorted(all_signals)
        explanation = (
            f"Ransomware behaviour correlation on {src_ip}: "
            f"{len(all_signals)} signals detected within {self.WINDOW_SECONDS//60}min window: "
            f"{', '.join(s.replace('_',' ') for s in signals_list)}. "
            f"Pattern consistent with ransomware pre-encryption phase (Conti/LockBit/BlackCat TTPs). "
            f"IMMEDIATE ISOLATION RECOMMENDED."
        )

        return RansomwareResult(
            is_ransomware=True,
            signals_triggered=signals_list,
            confidence=round(confidence, 3),
            src_ip=src_ip,
            mitre_ttps=self.MITRE,
            explanation=explanation,
            severity="critical",
        )
