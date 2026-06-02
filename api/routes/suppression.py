# api/routes/suppression.py
"""
Suppression Rules API router.
Allows analysts to view, create, toggle, and delete alert suppression rules.
"""
from fastapi import APIRouter, HTTPException, Request, Depends
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
import ipaddress
from api.auth import get_current_user

router = APIRouter(prefix="/api/suppression", tags=["suppression"])

class SuppressionRuleCreate(BaseModel):
    name: str
    description: Optional[str] = None
    src_ip_cidr: Optional[str] = None
    dst_ip_cidr: Optional[str] = None
    dst_port: Optional[int] = None
    sni_pattern: Optional[str] = None
    threat_type: Optional[str] = None
    expires_at: Optional[datetime] = None
    justification: str
    ticket_reference: Optional[str] = None

class SuppressionRuleResponse(BaseModel):
    rule_id: str
    name: str
    description: Optional[str] = None
    src_ip_cidr: Optional[str] = None
    dst_ip_cidr: Optional[str] = None
    dst_port: Optional[int] = None
    sni_pattern: Optional[str] = None
    threat_type: Optional[str] = None
    created_by: str
    created_at: datetime
    expires_at: Optional[datetime] = None
    is_active: bool
    justification: str
    ticket_reference: Optional[str] = None

def clean_cidr(ip_str: Optional[str]) -> Optional[str]:
    if not ip_str or ip_str.strip() == "":
        return None
    ip_str = ip_str.strip()
    try:
        if '/' not in ip_str:
            ip = ipaddress.ip_address(ip_str)
            return f"{ip_str}/32" if ip.version == 4 else f"{ip_str}/128"
        # Validate CIDR
        ipaddress.ip_network(ip_str, strict=False)
        return ip_str
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid IP or CIDR block: {e}")

@router.get("", response_model=List[SuppressionRuleResponse])
async def list_suppression_rules(request: Request):
    """List all suppression rules from PostgreSQL."""
    db = request.app.state.db
    async with db.pool.acquire() as conn:
        rows = await conn.fetch("SELECT * FROM suppression_rules ORDER BY created_at DESC")
    
    rules = []
    for r in rows:
        d = dict(r)
        # Convert objects to standard python types if necessary
        rules.append(SuppressionRuleResponse(
            rule_id=str(d["rule_id"]),
            name=d["name"],
            description=d.get("description"),
            src_ip_cidr=str(d["src_ip_cidr"]) if d.get("src_ip_cidr") else None,
            dst_ip_cidr=str(d["dst_ip_cidr"]) if d.get("dst_ip_cidr") else None,
            dst_port=d.get("dst_port"),
            sni_pattern=d.get("sni_pattern"),
            threat_type=d.get("threat_type"),
            created_by=d["created_by"],
            created_at=d["created_at"],
            expires_at=d.get("expires_at"),
            is_active=d["is_active"],
            justification=d["justification"],
            ticket_reference=d.get("ticket_reference")
        ))
    return rules

@router.post("", response_model=SuppressionRuleResponse)
async def create_suppression_rule(body: SuppressionRuleCreate, request: Request, user: dict = Depends(get_current_user)):
    """Create a new suppression rule."""
    db = request.app.state.db
    redis_client = getattr(request.app.state, "redis", None)
    
    src_cidr = clean_cidr(body.src_ip_cidr)
    dst_cidr = clean_cidr(body.dst_ip_cidr)
    created_by = user.get("sub", "analyst")
    
    async with db.pool.acquire() as conn:
        row = await conn.fetchrow("""
            INSERT INTO suppression_rules (
                name, description, src_ip_cidr, dst_ip_cidr, dst_port,
                sni_pattern, threat_type, expires_at, created_by,
                justification, ticket_reference, is_active
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, TRUE)
            RETURNING *
        """,
            body.name,
            body.description,
            src_cidr,
            dst_cidr,
            body.dst_port,
            body.sni_pattern,
            body.threat_type,
            body.expires_at,
            created_by,
            body.justification,
            body.ticket_reference
        )
    
    # Broadcast to Redis to reload rules in running orchestrators
    if redis_client:
        try:
            redis_client.publish("suppression:reload", "reload")
        except Exception:
            pass

    d = dict(row)
    return SuppressionRuleResponse(
        rule_id=str(d["rule_id"]),
        name=d["name"],
        description=d.get("description"),
        src_ip_cidr=str(d["src_ip_cidr"]) if d.get("src_ip_cidr") else None,
        dst_ip_cidr=str(d["dst_ip_cidr"]) if d.get("dst_ip_cidr") else None,
        dst_port=d.get("dst_port"),
        sni_pattern=d.get("sni_pattern"),
        threat_type=d.get("threat_type"),
        created_by=d["created_by"],
        created_at=d["created_at"],
        expires_at=d.get("expires_at"),
        is_active=d["is_active"],
        justification=d["justification"],
        ticket_reference=d.get("ticket_reference")
    )

@router.patch("/{rule_id}/toggle", response_model=SuppressionRuleResponse)
async def toggle_suppression_rule(rule_id: str, request: Request, user: dict = Depends(get_current_user)):
    """Toggle a suppression rule active/inactive."""
    db = request.app.state.db
    redis_client = getattr(request.app.state, "redis", None)
    
    async with db.pool.acquire() as conn:
        # Check rule exists
        exists = await conn.fetchval("SELECT 1 FROM suppression_rules WHERE rule_id = $1::uuid", rule_id)
        if not exists:
            raise HTTPException(status_code=404, detail="Rule not found")
        
        row = await conn.fetchrow("""
            UPDATE suppression_rules 
            SET is_active = NOT is_active 
            WHERE rule_id = $1::uuid
            RETURNING *
        """, rule_id)
        
    if redis_client:
        try:
            redis_client.publish("suppression:reload", "reload")
        except Exception:
            pass

    d = dict(row)
    return SuppressionRuleResponse(
        rule_id=str(d["rule_id"]),
        name=d["name"],
        description=d.get("description"),
        src_ip_cidr=str(d["src_ip_cidr"]) if d.get("src_ip_cidr") else None,
        dst_ip_cidr=str(d["dst_ip_cidr"]) if d.get("dst_ip_cidr") else None,
        dst_port=d.get("dst_port"),
        sni_pattern=d.get("sni_pattern"),
        threat_type=d.get("threat_type"),
        created_by=d["created_by"],
        created_at=d["created_at"],
        expires_at=d.get("expires_at"),
        is_active=d["is_active"],
        justification=d["justification"],
        ticket_reference=d.get("ticket_reference")
    )

@router.delete("/{rule_id}")
async def delete_suppression_rule(rule_id: str, request: Request, user: dict = Depends(get_current_user)):
    """Delete a suppression rule."""
    db = request.app.state.db
    redis_client = getattr(request.app.state, "redis", None)
    
    async with db.pool.acquire() as conn:
        exists = await conn.fetchval("SELECT 1 FROM suppression_rules WHERE rule_id = $1::uuid", rule_id)
        if not exists:
            raise HTTPException(status_code=404, detail="Rule not found")
        
        await conn.execute("DELETE FROM suppression_rules WHERE rule_id = $1::uuid", rule_id)
        
    if redis_client:
        try:
            redis_client.publish("suppression:reload", "reload")
        except Exception:
            pass

    return {"status": "success", "message": f"Rule {rule_id} successfully deleted"}
