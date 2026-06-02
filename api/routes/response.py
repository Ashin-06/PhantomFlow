# api/routes/response.py
"""
Active Response API routes.
Allows analysts to queue and execute firewall blocks, DNS sinkholes, or host isolations.
"""
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import Literal
import logging

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/response", tags=["response"])

class RespondRequest(BaseModel):
    action: Literal["block_ip", "sinkhole_domain", "isolate_host"]
    target: str  # IP or domain override (defaults to alert dst_ip)
    auto_execute: bool = False  # Analyst must explicitly set True to execute immediately

class RespondResponse(BaseModel):
    alert_id: str
    action: str
    target: str
    status: str
    message: str

@router.post("/{alert_id}", response_model=RespondResponse)
async def queue_response(alert_id: str, body: RespondRequest, request: Request):
    """Queue or execute an active response action for an alert."""
    db = request.app.state.db

    # Verify alert exists
    async with db.pool.acquire() as conn:
        alert = await conn.fetchrow(
            """
            SELECT a.alert_id, a.threat_type, a.confidence, f.dst_ip
            FROM alerts a
            LEFT JOIN flows f ON a.flow_id = f.flow_id
            WHERE a.alert_id = $1::uuid
            """,
            alert_id
        )
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    # Safety gate: auto-execute only if confidence >= 0.90
    can_auto = alert["confidence"] >= 0.90 and body.auto_execute

    target = body.target or str(alert["dst_ip"] or "")
    status = "executed" if can_auto else "pending"

    import ipaddress
    target_ip = None
    target_domain = None
    if body.action == "sinkhole_domain":
        target_domain = target
    else:
        try:
            ipaddress.ip_address(target)
            target_ip = target
        except ValueError:
            target_domain = target

    try:
        async with db.pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO response_audit 
                (alert_id, action, target_ip, target_domain, status, approved_by, expires_at)
                VALUES ($1::uuid, $2, $3, $4, $5, $6, NOW() + INTERVAL '24 hours')
                ON CONFLICT DO NOTHING
            """,
                alert_id, body.action, target_ip, target_domain, status,
                "SYSTEM_AUTO" if can_auto else None
            )
            # Also update alert status to confirmed_tp since response action is taken
            await conn.execute("""
                UPDATE alerts
                SET analyst_status = 'confirmed_tp', reviewed_at = NOW()
                WHERE alert_id = $1::uuid
            """, alert_id)
    except Exception as e:
        log.error(f"[Response] DB insert/update failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

    if can_auto:
        # Mock execution — in production this calls Palo Alto / Cloudflare API
        log.warning(f"[FIREWALL] AUTO-BLOCK: {body.action} on {target} (alert {alert_id[:8]})")
        async with db.pool.acquire() as conn:
            await conn.execute(
                "UPDATE response_audit SET status='executed', executed_at=NOW() WHERE alert_id=$1::uuid AND action=$2",
                alert_id, body.action
            )
        status = "executed"
        message = f"Action '{body.action}' executed on {target}"
    else:
        message = f"Action '{body.action}' queued for analyst approval (target: {target})"

    return RespondResponse(
        alert_id=alert_id,
        action=body.action,
        target=target,
        status=status,
        message=message,
    )

@router.get("/queue")
async def list_response_queue(request: Request):
    """List all pending/executed response actions."""
    db = request.app.state.db
    async with db.pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM response_audit ORDER BY created_at DESC LIMIT 100"
        )
    return [{"audit_id": str(r["audit_id"]), "alert_id": str(r["alert_id"]),
             "action": r["action"], "target_ip": str(r["target_ip"]) if r["target_ip"] else r["target_domain"],
             "status": r["status"], "approved_by": r["approved_by"],
             "created_at": r["created_at"].isoformat() if r["created_at"] else None,
             "executed_at": r["executed_at"].isoformat() if r.get("executed_at") else None}
            for r in rows]

@router.patch("/queue/{audit_id}/approve")
async def approve_action(audit_id: str, request: Request):
    """Analyst approves a pending response action — executes it."""
    db = request.app.state.db
    async with db.pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM response_audit WHERE audit_id=$1::uuid AND status='pending'",
            audit_id
        )
        if not row:
            raise HTTPException(status_code=404, detail="Pending action not found")
        target = str(row["target_ip"]) if row["target_ip"] else row["target_domain"]
        action = row["action"]
        # Mock firewall call
        log.warning(f"[FIREWALL] ANALYST-APPROVED: {action} on {target}")
        await conn.execute(
            "UPDATE response_audit SET status='executed', executed_at=NOW(), approved_by='analyst' WHERE audit_id=$1::uuid",
            audit_id
        )
    return {"status": "executed", "action": action, "target": target}
