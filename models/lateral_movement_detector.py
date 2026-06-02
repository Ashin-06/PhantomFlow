# models/lateral_movement_detector.py
"""
Lateral Movement Detector (T1021, T1570)
Detects attackers moving between internal hosts via SMB, RDP, WMI.
"""
import ipaddress
import time
import logging
from typing import Optional, List
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

INTERNAL_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

def is_internal(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in INTERNAL_NETS)
    except ValueError:
        return False

@dataclass
class LateralResult:
    is_lateral: bool
    movement_type: str
    confidence: float
    src_ip: str
    unique_internal_targets: int
    target_port: int
    mitre_ttps: list
    explanation: str
    severity: str

class LateralMovementDetector:
    WINDOW_SECONDS = 300   # 5-minute window
    THRESHOLDS = {
        445:  4,   # SMB — >4 unique internal dsts = suspicious spread
        3389: 3,   # RDP — >3 unique dsts
        135:  4,   # WMI/RPC
        5985: 3,   # WinRM
        22:   5,   # SSH internal spread
        0:    10,  # Generic: any port, 10+ internal dsts
    }
    MOVEMENT_NAMES = {
        445: "smb_spread", 3389: "rdp_spread", 135: "wmi_rpc_spread",
        5985: "winrm_spread", 22: "ssh_spread", 0: "generic_fan_out"
    }
    MITRE_MAP = {
        445:  ["T1021.002", "T1570", "T1486"],
        3389: ["T1021.001"],
        135:  ["T1047", "T1021.003"],
        5985: ["T1021.006"],
        22:   ["T1021.004"],
        0:    ["T1570", "T1021"],
    }

    def __init__(self, redis_client=None):
        self.redis = redis_client
        self._mem: dict = {}

    def _bucket(self) -> str:
        return str(int(time.time() / self.WINDOW_SECONDS))

    def _count_targets(self, src_ip: str, dst_ip: str, dst_port: int) -> int:
        bucket = self._bucket()
        key = f"lateral:{src_ip}:{dst_port}:{bucket}"
        if self.redis:
            try:
                self.redis.pfadd(key, dst_ip)
                self.redis.expire(key, self.WINDOW_SECONDS * 2)
                return self.redis.pfcount(key)
            except Exception:
                pass
        # Memory fallback
        if key not in self._mem:
            self._mem[key] = set()
        self._mem[key].add(dst_ip)
        return len(self._mem[key])

    def check(self, flow: dict) -> Optional[LateralResult]:
        src_ip = flow.get("src_ip", flow.get("src", ""))
        dst_ip = flow.get("dst_ip", flow.get("dst", ""))
        dst_port_val = flow.get("dst_port")
        if dst_port_val is None:
            dst_port_val = flow.get("dport")
        try:
            dst_port = int(dst_port_val) if dst_port_val is not None else 0
        except (ValueError, TypeError):
            dst_port = 0

        if not src_ip or not dst_ip:
            return None
        # Both must be internal
        if not is_internal(src_ip) or not is_internal(dst_ip):
            return None
        if src_ip == dst_ip:
            return None

        # Find matching rule
        port_key = dst_port if dst_port in self.THRESHOLDS else 0
        threshold = self.THRESHOLDS[port_key]
        unique_targets = self._count_targets(src_ip, dst_ip, dst_port)

        if unique_targets < threshold:
            return None

        movement_type = self.MOVEMENT_NAMES.get(port_key, "generic_fan_out")
        mitre = self.MITRE_MAP.get(port_key, ["T1021"])
        
        # Confidence scales with targets above threshold
        confidence = min(0.97, 0.65 + (unique_targets - threshold) * 0.04)
        severity = "critical" if dst_port == 445 and unique_targets > 8 else "high"

        explanation = (
            f"Lateral movement detected: {src_ip} connected to {unique_targets} unique "
            f"internal hosts on port {dst_port} ({movement_type.replace('_',' ')}) "
            f"within {self.WINDOW_SECONDS//60}min window. "
            f"{'Consistent with ransomware SMB propagation.' if dst_port == 445 else 'Consistent with attacker pivoting.'} "
            f"MITRE {', '.join(mitre)}."
        )

        return LateralResult(
            is_lateral=True,
            movement_type=movement_type,
            confidence=round(confidence, 3),
            src_ip=src_ip,
            unique_internal_targets=unique_targets,
            target_port=dst_port,
            mitre_ttps=mitre,
            explanation=explanation,
            severity=severity,
        )
