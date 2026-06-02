# models/brute_force_detector.py
"""
Brute Force / Credential Attack Detector (T1110)
Detects SSH, RDP, HTTP brute force and password spray attacks.
"""
import time
import logging
from typing import Optional
from dataclasses import dataclass

log = logging.getLogger(__name__)

@dataclass  
class BruteResult:
    is_brute: bool
    attack_type: str
    confidence: float
    src_ip: str
    dst_ip: str
    dst_port: int
    connections_per_min: float
    mitre_ttps: list
    explanation: str
    severity: str

class BruteForceDetector:
    WINDOW_SECONDS = 60
    # (dst_port, conns_per_min_threshold, attack_type, mitre)
    RULES = [
        (22,   10, "ssh_brute_force",   ["T1110", "T1110.001"]),
        (3389,  8, "rdp_brute_force",   ["T1110", "T1110.001"]),
        (21,   12, "ftp_brute_force",   ["T1110", "T1110.001"]),
        (25,    8, "smtp_brute_force",  ["T1110", "T1078"]),
        (110,   8, "pop3_brute_force",  ["T1110"]),
        (5432, 15, "postgres_brute",    ["T1110"]),
        (3306, 15, "mysql_brute",       ["T1110"]),
    ]
    # Password spray: same src, same port, many dst IPs
    SPRAY_THRESHOLD = 4   # unique dst hosts at same port within window
    SPRAY_RATE = 3        # min conns/min to qualify

    def __init__(self, redis_client=None):
        self.redis = redis_client
        self._mem: dict = {}
        self._spray_mem: dict = {}

    def _bucket(self) -> str:
        return str(int(time.time() / self.WINDOW_SECONDS))

    def _count_connections(self, src_ip: str, dst_ip: str, dst_port: int) -> int:
        bucket = self._bucket()
        key = f"brute:{src_ip}:{dst_ip}:{dst_port}:{bucket}"
        if self.redis:
            try:
                count = self.redis.incr(key)
                self.redis.expire(key, self.WINDOW_SECONDS * 2)
                return count
            except Exception:
                pass
        self._mem[key] = self._mem.get(key, 0) + 1
        return self._mem[key]

    def _count_spray_targets(self, src_ip: str, dst_port: int, dst_ip: str) -> int:
        bucket = self._bucket()
        key = f"spray:{src_ip}:{dst_port}:{bucket}"
        if self.redis:
            try:
                self.redis.pfadd(key, dst_ip)
                self.redis.expire(key, self.WINDOW_SECONDS * 2)
                return self.redis.pfcount(key)
            except Exception:
                pass
        if key not in self._spray_mem:
            self._spray_mem[key] = set()
        self._spray_mem[key].add(dst_ip)
        return len(self._spray_mem[key])

    def check(self, flow: dict) -> Optional[BruteResult]:
        src_ip = flow.get("src_ip", flow.get("src", ""))
        dst_ip = flow.get("dst_ip", flow.get("dst", ""))
        dst_port = int(flow.get("dst_port", flow.get("dport", 0)))
        orig_bytes = int(flow.get("orig_bytes", 0))
        duration_s = float(flow.get("duration_s", 1.0))

        if not src_ip or not dst_ip:
            return None

        conn_count = self._count_connections(src_ip, dst_ip, dst_port)
        conns_per_min = conn_count * (60.0 / self.WINDOW_SECONDS)

        # Check spray first (only for authentication/login ports defined in RULES)
        auth_ports = {r[0] for r in self.RULES}
        if dst_port in auth_ports:
            spray_targets = self._count_spray_targets(src_ip, dst_port, dst_ip)
            if spray_targets >= self.SPRAY_THRESHOLD and conns_per_min >= self.SPRAY_RATE:
                confidence = min(0.95, 0.65 + (spray_targets - self.SPRAY_THRESHOLD) * 0.05)
                return BruteResult(
                    is_brute=True,
                    attack_type="password_spray",
                    confidence=round(confidence, 3),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    connections_per_min=round(conns_per_min, 1),
                    mitre_ttps=["T1110", "T1110.003", "T1078"],
                    explanation=(
                        f"Password spray: {src_ip} attempted auth against {spray_targets} unique hosts "
                        f"on port {dst_port} at {conns_per_min:.1f} conn/min. "
                        f"One password tried against many accounts — T1110.003."
                    ),
                    severity="high",
                )


        # Check per-service brute force
        for port, threshold, attack_type, mitre in self.RULES:
            if dst_port == port and conns_per_min >= threshold:
                confidence = min(0.97, 0.60 + (conns_per_min - threshold) * 0.02)
                severity = "critical" if conns_per_min > threshold * 3 else "high"
                return BruteResult(
                    is_brute=True,
                    attack_type=attack_type,
                    confidence=round(confidence, 3),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    connections_per_min=round(conns_per_min, 1),
                    mitre_ttps=mitre,
                    explanation=(
                        f"{attack_type.replace('_',' ').title()}: {src_ip} → {dst_ip}:{dst_port} "
                        f"at {conns_per_min:.1f} connections/min "
                        f"(threshold: {threshold}/min). "
                        f"Small payload ({orig_bytes}B avg) consistent with auth probing."
                    ),
                    severity=severity,
                )

        return None
