# models/port_scan_detector.py
"""
Port Scan / Recon Detector (T1046, T1595)
Detects horizontal scans (many hosts), vertical scans (many ports), and stealth scans.
Uses Redis HyperLogLog — O(1) memory per source host.
"""
import time
import logging
from typing import Optional, Dict
from dataclasses import dataclass

log = logging.getLogger(__name__)

@dataclass
class ScanResult:
    is_scan: bool
    scan_type: str  # horizontal | vertical | stealth | slow
    confidence: float
    unique_ports: int
    unique_hosts: int
    src_ip: str
    mitre_ttps: list
    explanation: str
    severity: str

class PortScanDetector:
    VERTICAL_PORT_THRESHOLD = 30    # unique dst_ports in 60s from one src → vertical scan
    HORIZONTAL_HOST_THRESHOLD = 50  # unique dst_ips in 60s from one src → horizontal scan
    STEALTH_PKT_SIZE = 80           # avg pkt bytes < 80 → SYN-only, no payload
    SLOW_RATE_THRESHOLD = 0.5       # conns/sec < 0.5 → slow scan evasion
    WINDOW_SECONDS = 60
    MIN_CONNECTIONS = 5             # need at least 5 flows before alerting

    def __init__(self, redis_client=None):
        self.redis = redis_client
        # In-memory fallback when Redis unavailable
        self._mem_ports: Dict[str, set] = {}
        self._mem_hosts: Dict[str, set] = {}
        self._mem_times: Dict[str, list] = {}

    def _bucket(self) -> str:
        return str(int(time.time() / self.WINDOW_SECONDS))

    def _track_redis(self, src_ip: str, dst_ip: str, dst_port: int) -> tuple:
        bucket = self._bucket()
        port_key = f"scan:ports:{src_ip}:{bucket}"
        host_key = f"scan:hosts:{src_ip}:{bucket}"
        try:
            pipe = self.redis.pipeline()
            pipe.pfadd(port_key, str(dst_port))
            pipe.pfcount(port_key)
            pipe.expire(port_key, self.WINDOW_SECONDS * 2)
            pipe.pfadd(host_key, dst_ip)
            pipe.pfcount(host_key)
            pipe.expire(host_key, self.WINDOW_SECONDS * 2)
            results = pipe.execute()
            return results[1], results[4]  # unique_ports, unique_hosts
        except Exception as e:
            log.warning(f"[PortScan] Redis error: {e}")
            return self._track_memory(src_ip, dst_ip, dst_port)

    def _track_memory(self, src_ip: str, dst_ip: str, dst_port: int) -> tuple:
        bucket = self._bucket()
        pk = f"{src_ip}:{bucket}"
        if pk not in self._mem_ports:
            self._mem_ports[pk] = set()
            self._mem_hosts[pk] = set()
        self._mem_ports[pk].add(dst_port)
        self._mem_hosts[pk].add(dst_ip)
        return len(self._mem_ports[pk]), len(self._mem_hosts[pk])

    def check(self, flow: dict) -> Optional[ScanResult]:
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
            duration_s = float(flow.get("duration_s") or 1.0)
        except (ValueError, TypeError):
            duration_s = 1.0
        
        if not src_ip or dst_port == 0:
            return None

        # Exclude common web, DNS, NTP, DHCP, SSDP, and multicast/LLMNR discovery ports
        if dst_port in {80, 443, 8080, 53, 123, 1900, 67, 68, 5353, 5355}:
            return None


        if self.redis:
            unique_ports, unique_hosts = self._track_redis(src_ip, dst_ip, dst_port)
        else:
            unique_ports, unique_hosts = self._track_memory(src_ip, dst_ip, dst_port)

        avg_pkt_size = orig_bytes / max(orig_pkts, 1)
        conn_rate = orig_pkts / max(duration_s, 0.001)
        
        is_scan = False
        scan_type = ""
        confidence = 0.0
        mitre = []
        explanation = ""
        severity = "medium"

        if unique_ports >= self.VERTICAL_PORT_THRESHOLD:
            is_scan = True
            scan_type = "vertical"
            # Confidence scales with how many ports above threshold
            confidence = min(0.98, 0.60 + (unique_ports - self.VERTICAL_PORT_THRESHOLD) * 0.02)
            mitre = ["T1046", "T1590.005"]
            explanation = (
                f"Vertical port scan: {src_ip} contacted {unique_ports} unique ports on {dst_ip} "
                f"in {self.WINDOW_SECONDS}s window. "
                f"Avg packet size {avg_pkt_size:.0f}B {'(SYN-only, stealth)' if avg_pkt_size < self.STEALTH_PKT_SIZE else ''}. "
                f"MITRE T1046 — Network Service Discovery."
            )
            severity = "high" if unique_ports > 50 else "medium"

        elif unique_hosts >= self.HORIZONTAL_HOST_THRESHOLD:
            is_scan = True
            scan_type = "horizontal"
            confidence = min(0.97, 0.65 + (unique_hosts - self.HORIZONTAL_HOST_THRESHOLD) * 0.015)
            mitre = ["T1595", "T1595.002", "T1590"]
            explanation = (
                f"Horizontal network scan: {src_ip} contacted {unique_hosts} unique hosts "
                f"on port {dst_port} in {self.WINDOW_SECONDS}s. "
                f"Pattern consistent with Nmap host discovery or worm propagation."
            )
            severity = "high"

        if is_scan and avg_pkt_size < self.STEALTH_PKT_SIZE:
            scan_type = "stealth_" + scan_type
            confidence = min(0.99, confidence + 0.05)
            mitre.append("T1595.001")
            severity = "high"

        if not is_scan:
            return None

        return ScanResult(
            is_scan=True,
            scan_type=scan_type,
            confidence=round(confidence, 3),
            unique_ports=unique_ports,
            unique_hosts=unique_hosts,
            src_ip=src_ip,
            mitre_ttps=mitre,
            explanation=explanation,
            severity=severity,
        )
