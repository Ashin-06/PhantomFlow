# models/shannon_entropy_detector.py
"""
Shannon Entropy Payload Detector (MITRE T1048.003 - Exfiltration Over Covert Channel)
Detects raw custom encrypted/compressed exfiltration tunnels by evaluating the Shannon entropy of payload bytes.
"""
import logging
from typing import Optional
from dataclasses import dataclass

log = logging.getLogger(__name__)

@dataclass
class EntropyResult:
    is_threat: bool
    confidence: float
    threat_name: str
    mitre_ttps: list
    explanation: str
    severity: str

class ShannonEntropyDetector:
    # Standard plaintext ports to ignore to reduce false positives
    EXCLUDED_PORTS = {
        80, 23, 21, 25, 110, 143, 8080, # HTTP, Telnet, FTP, SMTP, POP3, IMAP
        53, 67, 68, 123, 161,           # DNS, DHCP, NTP, SNMP
        137, 138, 139, 445,             # NetBIOS, SMB
    }
    
    # We also ignore standard TLS port 443 since TLS is natively high-entropy
    # but has a structured handshake. This detector targets CUSTOM encryption / obfuscation.
    EXCLUDED_PORTS.add(443)
    EXCLUDED_PORTS.add(853) # DoT

    def __init__(self, redis_client=None):
        self.redis = redis_client

    def check(self, flow: dict) -> Optional[EntropyResult]:
        dst_ip = flow.get("dst_ip", flow.get("dst", ""))
        dst_port = int(flow.get("dst_port", flow.get("dport", 0)) or 0)
        orig_bytes = int(flow.get("orig_bytes", 0) or 0)
        entropy = float(flow.get("payload_entropy", 0.0) or 0.0)
        ja3 = flow.get("ja3", flow.get("ja3_hash", ""))
        
        # Check standard exclusion criteria
        if dst_port in self.EXCLUDED_PORTS:
            return None
            
        # We only care about outbound connections with a meaningful payload size
        if orig_bytes < 50_000: # 50 KB minimum transfer
            return None

        # Exclude standard TLS sessions (which are handled by TLS cert/fingerprint detectors)
        if ja3:
            return None

        # If payload entropy is extremely high (indicating compressed, packed, or encrypted bytes)
        if entropy >= 7.2:
            # Confidence scales with entropy above the threshold
            confidence = min(0.95, 0.75 + (entropy - 7.2) * 0.20)
            
            explanation = (
                f"Custom Encrypted Tunnel / Exfiltration suspected: outbound connection to {dst_ip}:{dst_port} "
                f"carried {orig_bytes / 1000:.1f}KB of data with high Shannon entropy ({entropy:.2f}). "
                f"The session did not utilize standard TLS handshakes or ports, indicating potential obfuscated "
                f"data exfiltration. MITRE T1048.003 — Exfiltration Over Unapproved Protocol."
            )
            
            return EntropyResult(
                is_threat=True,
                confidence=round(confidence, 3),
                threat_name="high_entropy_exfil",
                mitre_ttps=["T1048.003", "T1048"],
                explanation=explanation,
                severity="critical" if orig_bytes > 500_000 else "high"
            )
            
        return None
