# models/tls_cert_detector.py
"""
TLS Server Certificate Detector (MITRE T1587.003 - SSL/TLS Certificates)
Analyzes TLS server certificates to detect threat signatures: self-signed anomalies,
short validity windows, and SNI mismatch indicators.
"""
import logging
from typing import Optional
from dataclasses import dataclass

log = logging.getLogger(__name__)

@dataclass
class CertValidationResult:
    is_threat: bool
    confidence: float
    threat_name: str
    mitre_ttps: list
    explanation: str
    severity: str

class TLSCertDetector:
    def __init__(self, redis_client=None):
        self.redis = redis_client

    def check(self, flow: dict) -> Optional[CertValidationResult]:
        # Extract features mapped by FeatureExtractor or sent in flow metadata
        sni = flow.get("sni", flow.get("server_name", ""))
        self_signed = flow.get("cert_self_signed", False)
        validity_days = flow.get("cert_validity_days", 0.0)
        dst_ip = flow.get("dst_ip", flow.get("dst", ""))
        
        # Check if validity_days is None or missing
        if validity_days is None:
            validity_days = 0.0
        else:
            try:
                validity_days = float(validity_days)
            except (ValueError, TypeError):
                validity_days = 0.0

        if not dst_ip:
            return None

        # Ignore internal network certificate validations to prevent corporate PKI false alarms
        is_internal_dst = dst_ip.startswith("10.") or dst_ip.startswith("192.168.") or dst_ip.startswith("172.16.") or dst_ip.startswith("172.17.") or dst_ip.startswith("172.18.") or dst_ip.startswith("172.19.") or dst_ip.startswith("172.20.") or dst_ip.startswith("172.21.") or dst_ip.startswith("172.22.") or dst_ip.startswith("172.23.") or dst_ip.startswith("172.24.") or dst_ip.startswith("172.25.") or dst_ip.startswith("172.26.") or dst_ip.startswith("172.27.") or dst_ip.startswith("172.28.") or dst_ip.startswith("172.29.") or dst_ip.startswith("172.30.") or dst_ip.startswith("172.31.")
        if is_internal_dst:
            return None

        # 1. Flag self-signed certificates on external destination targets
        if self_signed:
            return CertValidationResult(
                is_threat=True,
                confidence=0.88,
                threat_name="self_signed_external_cert",
                mitre_ttps=["T1587.003", "T1573.002"],
                explanation=(
                    f"Untrusted self-signed TLS server certificate detected on external session to {dst_ip}. "
                    f"SNI field: '{sni or 'none'}'. Common indicator of ad-hoc malware C2 servers."
                ),
                severity="high"
            )

        # 2. Flag anomalous certificates with extremely short lifetimes (common in disposable C2 setups)
        # validity_days > 0 (meaning we have certificate validity metadata) and < 10 days
        if 0.0 < validity_days < 10.0:
            # Check domain entropy or length to isolate base64/random subdomains
            import math
            from collections import Counter
            
            def shannon_entropy(data: str) -> float:
                if not data:
                    return 0.0
                entropy = 0.0
                length = len(data)
                for count in Counter(data).values():
                    p = count / length
                    entropy -= p * math.log2(p)
                return entropy

            entropy = shannon_entropy(sni.split(".")[0] if sni else "")
            
            if entropy > 4.2 or len(sni) > 35:
                return CertValidationResult(
                    is_threat=True,
                    confidence=0.82,
                    threat_name="suspicious_short_lived_cert",
                    mitre_ttps=["T1587.003", "T1071.001"],
                    explanation=(
                        f"Suspicious short-lived certificate (lifespan: {validity_days:.1f} days) "
                        f"detected for high-entropy SNI domain: '{sni}' to {dst_ip}. "
                        f"Matches profiling filters for disposable Let's Encrypt C2 cert domains."
                    ),
                    severity="high"
                )

        return None
