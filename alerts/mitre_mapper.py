# alerts/mitre_mapper.py
"""
Maps detected threat types to MITRE ATT&CK techniques and tactics.
"""

class MITREMapper:
    """Maps alert categories to MITRE ATT&CK TTPs."""
    
    TTP_MAP = {
        "c2_beacon": {
            "tactics": ["Command and Control"],
            "techniques": ["T1071.001", "T1573.001", "T1573.002"],
            "descriptions": ["Application Layer Protocol: Web Protocols", "Encrypted Channel: Symmetric Cryptography"]
        },
        "dns_tunnel": {
            "tactics": ["Command and Control", "Exfiltration"],
            "techniques": ["T1048.003", "T1071.004"],
            "descriptions": ["Exfiltration Over Alternative Protocol: Exfiltration Over Symmetric Encrypted Protocol", "Application Layer Protocol: DNS"]
        },
        "exfiltration": {
            "tactics": ["Exfiltration"],
            "techniques": ["T1041", "T1048", "T1048.001"],
            "descriptions": ["Exfiltration Over C2 Channel", "Exfiltration Over Alternative Protocol: Exfiltration Over Common Port"]
        }
    }

    def get_ttps(self, threat_type: str) -> list:
        return self.TTP_MAP.get(threat_type, {}).get("techniques", [])

    def get_details(self, threat_type: str) -> dict:
        return self.TTP_MAP.get(threat_type, {"tactics": [], "techniques": [], "descriptions": []})
