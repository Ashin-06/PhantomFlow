# models/doh_dot_detector.py
"""
DNS-over-HTTPS (DoH) & DNS-over-TLS (DoT) Tunneling Detector (MITRE T1071.004)
Flags DNS queries tunneled over encrypted transport to public resolvers.
"""
import logging
from typing import Optional
from dataclasses import dataclass

log = logging.getLogger(__name__)

@dataclass
class DoHDotResult:
    is_threat: bool
    confidence: float
    threat_name: str
    mitre_ttps: list
    explanation: str
    severity: str

class DoHDotDetector:
    RESOLVER_IPS = {
        "8.8.8.8", "8.8.4.4",          # Google
        "1.1.1.1", "1.0.0.1",          # Cloudflare
        "162.159.36.1", "162.159.46.1", # Cloudflare DoH IPs
        "9.9.9.9", "149.112.112.112",  # Quad9
        "94.140.14.14", "94.140.15.15", # AdGuard
        "45.90.28.0", "45.90.30.0",    # NextDNS
    }
    
    RESOLVER_DOMAINS = {
        "dns.google", "dns.google.com",
        "cloudflare-dns.com", "one.one.one.one",
        "dns.quad9.net", "dns.adguard.com",
        "dns.nextdns.io"
    }

    def __init__(self, redis_client=None):
        self.redis = redis_client

    def check(self, flow: dict) -> Optional[DoHDotResult]:
        dst_ip = flow.get("dst_ip", flow.get("dst", ""))
        dst_port = int(flow.get("dst_port", flow.get("dport", 0)) or 0)
        sni = flow.get("sni", "").lower()
        orig_bytes = int(flow.get("orig_bytes", 0) or 0)
        orig_pkts = int(flow.get("orig_pkts", 1) or 1)
        
        if not dst_ip:
            return None

        is_resolver = dst_ip in self.RESOLVER_IPS
        
        # Or if SNI points to a known public resolver
        if sni:
            for domain in self.RESOLVER_DOMAINS:
                if domain in sni:
                    is_resolver = True
                    break

        if not is_resolver:
            return None

        # Check ports: 443 (DoH) or 853 (DoT)
        if dst_port in (443, 853):
            # Evaluate telemetry: tunneling involves small, high-frequency queries
            # Typically average query/response packet size is small
            avg_pkt_size = orig_bytes / max(orig_pkts, 1)
            
            # If packet sizes are consistent with DNS queries (< 500 bytes on average)
            if avg_pkt_size < 500:
                threat_type = "doh_tunnel" if dst_port == 443 else "dot_tunnel"
                confidence = 0.92 if sni else 0.85
                severity = "high" if avg_pkt_size < 200 else "medium"
                
                explanation = (
                    f"Encrypted DNS Tunneling suspected ({threat_type.upper()}): connection to known public resolver "
                    f"{dst_ip}:{dst_port} with SNI '{sni or 'none'}'. "
                    f"Average outbound packet size is {avg_pkt_size:.0f}B, consistent with DNS tunneling encapsulation. "
                    f"MITRE T1071.004 — Application Layer Protocol: DNS."
                )
                
                return DoHDotResult(
                    is_threat=True,
                    confidence=confidence,
                    threat_name=threat_type,
                    mitre_ttps=["T1071.004", "T1071.001"],
                    explanation=explanation,
                    severity=severity
                )
        return None
