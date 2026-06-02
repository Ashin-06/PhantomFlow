# pipeline/suppression.py
"""
Analyst Suppression Engine.
If an analyst marks an alert as "False Positive - Splunk Forwarder",
they create a rule. This engine blocks identical future alerts before
they hit the dashboard, dramatically reducing alert fatigue.
"""

import ipaddress
import re
from typing import Dict, List, Optional
import logging

log = logging.getLogger(__name__)


class SuppressionEngine:
    def __init__(self, db_layer):
        self.db = db_layer
        self.rules: List[Dict] = []
        self._compiled_regex = {}

    async def reload_rules(self):
        """Called periodically (e.g., every 60s) to cache rules in memory."""
        self.rules = await self.db.get_active_suppression_rules()
        self._compiled_regex.clear()
        
        for rule in self.rules:
            if rule.get("sni_pattern"):
                try:
                    self._compiled_regex[rule["rule_id"]] = re.compile(rule["sni_pattern"])
                except Exception as e:
                    log.error(f"Invalid regex in rule {rule['rule_id']}: {e}")

    def should_suppress(self, flow: dict, threat_type: str) -> Optional[Dict]:
        """
        Check if flow matches any active suppression rule.
        Returns the matched rule if suppressed, else None.
        """
        for rule in self.rules:
            # Threat Type match
            if rule.get("threat_type") and rule["threat_type"] != threat_type:
                continue

            # Dest Port match
            if rule.get("dst_port") and rule["dst_port"] != flow.get("dport"):
                continue

            # IP CIDR matches
            src_ip = ipaddress.ip_address(flow["src"])
            if rule.get("src_ip_cidr"):
                subnet = ipaddress.ip_network(rule["src_ip_cidr"])
                if src_ip not in subnet:
                    continue
                    
            dst_ip = ipaddress.ip_address(flow["dst"])
            if rule.get("dst_ip_cidr"):
                subnet = ipaddress.ip_network(rule["dst_ip_cidr"])
                if dst_ip not in subnet:
                    continue

            # SNI Regex match
            if rule.get("sni_pattern"):
                regex = self._compiled_regex.get(rule["rule_id"])
                sni = flow.get("sni", "")
                if regex and not regex.search(sni):
                    continue

            # If we get here, all specified conditions matched
            return {
                "rule_id": rule["rule_id"],
                "name": rule["name"]
            }
            
        return None
