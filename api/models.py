# api/models.py
"""Pydantic schemas for PhantomFlow API."""

from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any
from enum import Enum


class ThreatType(str, Enum):
    clean = "clean"
    c2_beacon = "c2_beacon"
    dns_tunnel = "dns_tunnel"
    exfiltration = "exfiltration"
    lateral_movement = "lateral_movement"
    port_scan = "port_scan"
    brute_force = "brute_force"
    ransomware = "ransomware"
    anomaly = "anomaly"


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class SubScores(BaseModel):
    beacon_prob: float = 0.0
    dns_tunnel_prob: float = 0.0
    exfil_score: float = 0.0
    anomaly_score: float = 0.0
    lateral_movement_score: float = 0.0


class MITRETechnique(BaseModel):
    id: str
    tactic: str
    technique: str
    url: str


class PhantomFlowAlert(BaseModel):
    """Full alert schema — stored in Elasticsearch and sent to Wazuh."""
    
    # Identity
    alert_id: str
    flow_id: str
    timestamp: float
    
    # Network
    src: str
    dst: str
    dport: int
    sni: Optional[str] = None
    proto: str = "tcp"
    
    # Detection
    threat_type: ThreatType
    alert_severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    sub_scores: SubScores = SubScores()
    
    # TLS
    ja3_hash: Optional[str] = None
    ja4_hash: Optional[str] = None
    ja3_malware_score: float = 0.0
    
    # DNS (if applicable)
    dns_query: Optional[str] = None
    dns_entropy: Optional[float] = None
    
    # Explanation
    explanation: str = ""
    shap_values: Dict[str, Any] = {}
    attention_peaks: List[int] = []
    
    # MITRE
    mitre_ttps: List[str] = []
    mitre_details: List[MITRETechnique] = []
    
    # Beacon-specific
    beacon_interval_ms: Optional[float] = None
    periodicity_score: Optional[float] = None
    
    # Exfil-specific
    bytes_uploaded: Optional[int] = None
    bytes_ratio: Optional[float] = None


class AlertListResponse(BaseModel):
    alerts: List[PhantomFlowAlert]
    total: int
    page: int = 1


class StatsResponse(BaseModel):
    total_flows_analyzed: int
    alerts_today: int
    threat_breakdown: Dict[str, int]
    top_src_ips: List[Dict[str, Any]]
    models_loaded: bool
    uptime_s: int
    flows_per_sec: float


class FlowDetailResponse(BaseModel):
    flow_id: str
    features: Dict[str, Any]
    prediction: Optional[PhantomFlowAlert] = None
    packet_timeline: List[Dict[str, Any]] = []
