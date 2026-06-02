import socket
import json
import logging

logger = logging.getLogger("PhantomFlow-SIEM-Exporter")

class SIEMExporter:
    def __init__(self, host='127.0.0.1', port=514):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def send_cef(self, alert: dict):
        """Format and send a CEF (Common Event Format) Syslog message."""
        try:
            # CEF Format: CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
            # Map our severity to CEF severity (0-10)
            sev_map = {"info": 1, "low": 3, "medium": 5, "high": 8, "critical": 10}
            cef_sev = sev_map.get(alert.get("alert_severity"), 1)
            
            ext = f"src={alert.get('src')} dst={alert.get('dst')} dpt={alert.get('dport', 0)} msg={alert.get('explanation', '')}"
            
            cef_msg = f"CEF:0|PhantomFlow|ThreatHunter|1.0|{alert.get('threat_type')}|{alert.get('threat_type')} Detected|{cef_sev}|{ext}"
            
            # Syslog format: <PRI> CEF_MSG (Facility 16 (local0), Severity 4 (warning) -> PRI = 16*8 + 4 = 132)
            syslog_msg = f"<132> {cef_msg}"
            
            self.sock.sendto(syslog_msg.encode('utf-8'), (self.host, self.port))
            logger.info(f"SIEM EXPORT: Sent CEF log to {self.host}:{self.port}")
        except Exception as e:
            logger.error(f"SIEM EXPORT FAILED: {e}")
