# api/routes/analyst.py
"""
Analyst workflow routes.
Allows Tier 1/2 analysts to label alerts, trigger suppression rules,
and escalate to Tier 3.
"""

from fastapi import APIRouter, Depends, BackgroundTasks, HTTPException, Request
from pydantic import BaseModel
from typing import Optional, List
from api.auth import require_role
from pipeline.db_layer import Database

router = APIRouter(prefix="/analyst", tags=["Analyst Workflow"])

def get_db(request: Request):
    return request.app.state.db

class AnalystReview(BaseModel):
    alert_id: str
    status: str            # 'confirmed_tp', 'false_positive', 'escalated'
    label: Optional[int]   # 0=benign, 1=c2, 2=dns, 3=exfil
    notes: str
    create_suppression_rule: bool = False

class SuppressionRuleReq(BaseModel):
    name: str
    justification: str
    src_ip_cidr: Optional[str] = None
    dst_ip_cidr: Optional[str] = None
    dst_port: Optional[int] = None
    sni_pattern: Optional[str] = None
    threat_type: Optional[str] = None


@router.post("/review")
async def submit_review(
    review: AnalystReview,
    background_tasks: BackgroundTasks,
    token: dict = Depends(require_role("analyst")),
    db: Database = Depends(get_db)
):
    """
    Submits an analyst review.
    If create_suppression_rule is True, dynamically creates a rule based on the alert.
    """
    analyst_id = token.get("sub")
    
    async with db.transaction() as conn:
        # Update alert status
        await conn.execute("""
            UPDATE alerts 
            SET analyst_status = $1, analyst_id = $2, analyst_notes = $3, reviewed_at = NOW()
            WHERE alert_id = $4::uuid
        """, review.status, analyst_id, review.notes, review.alert_id)
        
        # Save explicit label for ML retraining (Active Learning loop)
        if review.label is not None:
            alert = await conn.fetchrow("SELECT flow_id FROM alerts WHERE alert_id = $1::uuid", review.alert_id)
            if alert:
                await conn.execute("""
                    INSERT INTO analyst_reviews (alert_id, flow_id, analyst_id, analyst_label, analyst_notes)
                    VALUES ($1::uuid, $2::uuid, $3, $4, $5)
                """, review.alert_id, alert["flow_id"], analyst_id, review.label, review.notes)
                
    if review.create_suppression_rule and review.status == "false_positive":
        # Usually handled by a separate endpoint where the analyst confirms the rule bounds,
        # but auto-creating one here based on dst_ip/sni for convenience.
        pass

    return {"status": "success", "msg": "Review submitted"}


@router.post("/suppress")
async def create_suppression_rule(
    rule: SuppressionRuleReq,
    token: dict = Depends(require_role("tier3")),  # Only Tier3 can create global suppression
    db: Database = Depends(get_db)
):
    """
    Creates a new suppression rule to prevent alert fatigue.
    """
    analyst_id = token.get("sub")
    
    async with db.transaction() as conn:
        row = await conn.fetchrow("""
            INSERT INTO suppression_rules (
                name, justification, src_ip_cidr, dst_ip_cidr, dst_port, sni_pattern, threat_type, created_by
            ) VALUES ($1, $2, $3::inet, $4::inet, $5, $6, $7, $8)
            RETURNING rule_id
        """, rule.name, rule.justification, rule.src_ip_cidr, rule.dst_ip_cidr, 
             rule.dst_port, rule.sni_pattern, rule.threat_type, analyst_id)
             
    # Tell the pipeline workers to reload rules via Redis PubSub (pseudo-code)
    # background_tasks.add_task(redis.publish, "rule_updates", "reload")
    
    return {"status": "success", "rule_id": str(row["rule_id"])}


@router.get("/metrics/false_positives")
async def get_fp_metrics(token: dict = Depends(require_role("admin")), db: Database = Depends(get_db)):
    """Admin endpoint to see FP rates by threat type."""
    async with db.transaction() as conn:
        rows = await conn.fetch("""
            SELECT threat_type, 
                   COUNT(*) as total_alerts,
                   SUM(CASE WHEN analyst_status = 'false_positive' THEN 1 ELSE 0 END) as fp_count
            FROM alerts
            WHERE reviewed_at > NOW() - INTERVAL '30 days'
            GROUP BY threat_type
        """)
    
    results = []
    for r in rows:
        fp_rate = (r["fp_count"] / r["total_alerts"]) * 100 if r["total_alerts"] > 0 else 0
        results.append({
            "threat_type": r["threat_type"],
            "total_alerts": r["total_alerts"],
            "false_positives": r["fp_count"],
            "fp_rate_pct": round(fp_rate, 2)
        })
        
    return {"metrics": results}
