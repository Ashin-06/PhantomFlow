# models/tls_fingerprint_detector.py
"""
TLS Fingerprint Detector (MITRE T1071.001, T1573.002)
Detects C2 client signatures using JA3/JA4 Client Hello fingerprints.
Logs alerts when a blacklisted hash is found or when an internal host utilizes an anomalous fingerprint.
"""
import logging
from typing import Optional, Dict
from dataclasses import dataclass

log = logging.getLogger(__name__)

@dataclass
class FingerprintResult:
    is_threat: bool
    confidence: float
    threat_name: str
    mitre_ttps: list
    explanation: str
    severity: str

class TLSFingerprintDetector:
    # Blacklisted signatures from threat intelligence feeds (abuse.ch, salesforce ja3 lists)
    BLACKLIST = {
        "e7d705a3286e19ea42f587b344ee6865": "CobaltStrike C2 Client (Default)",
        "6d37c8e9aa2ef8649e7f6d5e9b94f4f1": "Sliver C2 Client Protocol",
        "a0e9f5d64349fb13191bc781f81f42e1": "Metasploit Meterpreter Client",
        "72a589da586844d7f0818ce684948eea": "Empire C2 Client Sockets",
        "b386946a5a44d1ddcc843bc75336dfce": "Generic RAT Client / NLBrute Core",
    }

    def __init__(self, redis_client=None):
        self.redis = redis_client
        # Memory baseline fallback when Redis is offline
        self._mem_baselines: Dict[str, set] = {}

    def check(self, flow: dict) -> Optional[FingerprintResult]:
        ja3_hash = flow.get("ja3", flow.get("ja3_hash", ""))
        ja4_hash = flow.get("ja4", flow.get("ja4_hash", ""))
        src_ip = flow.get("src_ip", flow.get("src", ""))

        if not ja3_hash and not ja4_hash:
            return None

        # 1. Match against the blacklist
        for h in (ja3_hash, ja4_hash):
            if h and h in self.BLACKLIST:
                threat = self.BLACKLIST[h]
                return FingerprintResult(
                    is_threat=True,
                    confidence=0.98,
                    threat_name="blacklisted_tls_client",
                    mitre_ttps=["T1071.001", "T1573.002"],
                    explanation=(
                        f"Blacklisted TLS client fingerprint detected: {threat}. "
                        f"Matches known C2 framework Client Hello profile (Hash: {h})."
                    ),
                    severity="critical"
                )

        # 2. Check for host fingerprint behavioral drift
        if src_ip:
            h_key = ja3_hash or ja4_hash
            is_anomalous = False
            
            if self.redis:
                try:
                    baseline_key = f"baseline:ja3:{src_ip}"
                    # sadd returns 1 if element is new to the set
                    is_new = self.redis.sadd(baseline_key, h_key)
                    total_known = self.redis.scard(baseline_key)
                    if is_new == 1 and total_known > 1:
                        is_anomalous = True
                except Exception as e:
                    log.warning(f"[TLS Fingerprint] Redis baseline query failed: {e}")
                    is_anomalous = self._check_memory_baseline(src_ip, h_key)
            else:
                is_anomalous = self._check_memory_baseline(src_ip, h_key)

            if is_anomalous:
                # Sensitive internal assets get higher severity
                is_critical_asset = src_ip.startswith("10.14.1.") or src_ip.startswith("10.14.2.")
                severity = "high" if is_critical_asset else "medium"
                
                return FingerprintResult(
                    is_threat=True,
                    confidence=0.78,
                    threat_name="anomalous_tls_client",
                    mitre_ttps=["T1071.001"],
                    explanation=(
                        f"Anomalous TLS Client Hello fingerprint detected on host {src_ip}: {h_key}. "
                        f"This configuration has not been previously utilized by this asset."
                    ),
                    severity=severity
                )

        return None

    def _check_memory_baseline(self, src_ip: str, h_key: str) -> bool:
        if src_ip not in self._mem_baselines:
            self._mem_baselines[src_ip] = {h_key}
            return False
        
        if h_key not in self._mem_baselines[src_ip]:
            self._mem_baselines[src_ip].add(h_key)
            return True
        return False
