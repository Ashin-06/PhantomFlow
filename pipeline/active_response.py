# pipeline/active_response.py
"""
Human-in-the-Loop Active Response Engine.
PhantomFlow never blocks automatically (unless confidence is 99.9% + policy allows).
It queues an action for an analyst to click "Approve".
Once approved, it talks to Firewalls, EDR, or DNS sinkholes.
"""

import httpx
import logging
from config.secrets import SecretsManager
from datetime import datetime, timedelta

log = logging.getLogger(__name__)


class ResponseAction:
    BLOCK_IP = "block_ip"
    SINKHOLE_DOMAIN = "sinkhole_domain"
    ISOLATE_HOST = "isolate_host"


class ActiveResponseEngine:
    def __init__(self, db_layer):
        self.db = db_layer
        self.secrets = SecretsManager()

    async def queue_action(self, alert_id: str, action: str, target: str, 
                           confidence: float, auto_block: bool = False):
        """
        Creates a pending action in the database.
        If auto_block is true and policy permits, executes immediately.
        """
        # Hard policy: Auto-block only for 99%+ confidence C2
        is_auto = auto_block and confidence > 0.99
        
        status = "pending"
        approved_by = "SYSTEM_AUTO" if is_auto else None
        approved_at = datetime.utcnow() if is_auto else None
        
        # All blocks expire after 24 hours automatically (failsafe)
        expires_at = datetime.utcnow() + timedelta(hours=24)

        async with self.db.transaction() as conn:
            await conn.execute("""
                INSERT INTO response_audit 
                (alert_id, action, target_ip, status, approved_by, approved_at, expires_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
            """, alert_id, action, target, status, approved_by, approved_at, expires_at)

        if is_auto:
            await self.execute_action(alert_id)

    async def execute_action(self, alert_id: str):
        """Actually talk to the external firewall/EDR APIs."""
        async with self.db.transaction() as conn:
            audit = await conn.fetchrow("""
                SELECT * FROM response_audit WHERE alert_id = $1 AND status IN ('pending', 'approved')
            """, alert_id)
            
            if not audit:
                return False

            success = False
            error = None
            try:
                if audit["action"] == ResponseAction.BLOCK_IP:
                    success = await self._palo_alto_block(audit["target_ip"])
                elif audit["action"] == ResponseAction.SINKHOLE_DOMAIN:
                    success = await self._cloudflare_dns_block(audit["target_domain"])
            except Exception as e:
                error = str(e)
                log.error(f"Action execution failed: {e}")

            new_status = "executed" if success else "failed"
            await conn.execute("""
                UPDATE response_audit 
                SET status = $1, executed_at = NOW(), error_detail = $2
                WHERE audit_id = $3
            """, new_status, error, audit["audit_id"])
            
            return success

    async def _palo_alto_block(self, ip: str) -> bool:
        """Example integration with Palo Alto Panorama."""
        # api_key = self.secrets.get_secret("phantomflow/firewall")["api_key"]
        log.warning(f"[MOCK FIREWALL] Blocking IP {ip}")
        return True

    async def _cloudflare_dns_block(self, domain: str) -> bool:
        """Example integration with Cloudflare Gateway."""
        log.warning(f"[MOCK DNS] Sinkholing domain {domain}")
        return True
