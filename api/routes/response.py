# api/routes/response.py
"""
Active Response API routes.
Allows analysts to queue and execute firewall blocks, DNS sinkholes, or host isolations.
"""
from fastapi import APIRouter, HTTPException, Request, Depends
from pydantic import BaseModel
from typing import Literal
import logging
from api.auth import require_role

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

    # This API has no wired enforcement provider; never report mock execution.
    if body.auto_execute:
        raise HTTPException(501, "Response execution provider is not configured; queue for review instead")

    target = body.target or str(alert["dst_ip"] or "")
    status = "pending"

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
                None
            )
            # Also update alert status to confirmed_tp since response action is taken
            await conn.execute("""
                UPDATE alerts
                SET analyst_status = 'confirmed_tp', reviewed_at = NOW()
                WHERE alert_id = $1::uuid
            """, alert_id)
    except Exception as e:
        log.error(f"[Response] DB insert/update failed: {e}")
        raise HTTPException(status_code=500, detail="Unable to queue response action")

    message = f"Action '{body.action}' queued for review; no network change has been made (target: {target})"

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

@router.patch("/queue/{audit_id}/approve", dependencies=[Depends(require_role("tier3"))])
async def approve_action(audit_id: str, request: Request):
    """Fail explicitly until an enforcement provider is connected."""
    raise HTTPException(501, "Response execution provider is not configured; no action was executed")
