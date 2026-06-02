from fastapi import APIRouter, Query, HTTPException, Depends, Request
from typing import Optional, List
from api.models import PhantomFlowAlert, AlertListResponse, ThreatType, Severity
import json

router = APIRouter(prefix="/api/alerts", tags=["alerts"])

def get_db(request: Request):
    return request.app.state.db

@router.get("", response_model=AlertListResponse)
async def list_alerts(
    request: Request,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    severity: Optional[Severity] = None,
    threat_type: Optional[ThreatType] = None,
    src: Optional[str] = None,
    min_confidence: float = Query(0.0, ge=0.0, le=1.0),
    status: str = Query("unreviewed"),
):
    """List alerts with filtering from PostgreSQL (asyncpg)."""
    db = get_db(request)
    
    query_parts = ["SELECT * FROM alerts WHERE 1=1"]
    args = []
    
    if severity:
        args.append(severity.value)
        query_parts.append(f"AND severity = ${len(args)}")
    if threat_type:
        args.append(threat_type.value)
        query_parts.append(f"AND threat_type = ${len(args)}")
    if src:
        args.append(src)
        # Using a join with flows for src IP filtering in a real prod schema
        # For simplicity in this endpoint with the raw SQL, we assume alerts table has src. 
        # Actually in our schema.sql, 'alerts' doesn't have 'src', it references 'flow_id'.
        # Let's do a proper join
        query_parts[0] = "SELECT a.*, f.src_ip as src, f.dst_ip as dst, f.dst_port as dport, f.sni FROM alerts a JOIN flows f ON a.flow_id = f.flow_id WHERE 1=1"
        query_parts.append(f"AND f.src_ip::text LIKE '%' || ${len(args)} || '%'")
    else:
        query_parts[0] = "SELECT a.*, f.src_ip as src, f.dst_ip as dst, f.dst_port as dport, f.sni FROM alerts a JOIN flows f ON a.flow_id = f.flow_id WHERE 1=1"

    if min_confidence > 0:
        args.append(min_confidence)
        query_parts.append(f"AND a.confidence >= ${len(args)}")
        
    if status != "all":
        args.append(status)
        query_parts.append(f"AND a.analyst_status = ${len(args)}")
        
    # Get total count
    count_query = "SELECT COUNT(*) FROM alerts a JOIN flows f ON a.flow_id = f.flow_id WHERE" + " ".join(query_parts).split("WHERE")[1]
    
    # Add pagination to main query
    query_parts.append(f"ORDER BY a.timestamp DESC LIMIT {limit} OFFSET {offset}")
    full_query = " ".join(query_parts)

    async with db.pool.acquire() as conn:
        total = await conn.fetchval(count_query, *args)
        rows = await conn.fetch(full_query, *args)

    alerts = []
    for r in rows:
        alert_dict = dict(r)
        
        # Parse mitre_ttps — stored as string like "['T1071.001', 'T1573.001']" in DB
        raw_mitre = alert_dict.get("mitre_ttps") or []
        if isinstance(raw_mitre, str):
            import ast
            try:
                raw_mitre = ast.literal_eval(raw_mitre)
            except Exception:
                raw_mitre = [x.strip().strip("'\"") for x in raw_mitre.strip("[]").split(",") if x.strip()]
        if not isinstance(raw_mitre, list):
            raw_mitre = list(raw_mitre) if raw_mitre else []
        
        # Parse shap_values — stored as jsonb but may be a string or dict
        raw_shap = alert_dict.get("shap_values") or {}
        if isinstance(raw_shap, str):
            try:
                raw_shap = json.loads(raw_shap)
            except Exception:
                try:
                    import ast
                    raw_shap = ast.literal_eval(raw_shap)
                except Exception:
                    raw_shap = {}
        
        alerts.append(PhantomFlowAlert(
            alert_id=str(alert_dict["alert_id"]),
            flow_id=str(alert_dict["flow_id"]),
            timestamp=alert_dict["timestamp"].timestamp(),
            threat_type=alert_dict["threat_type"],
            alert_severity=alert_dict["severity"],
            confidence=alert_dict["confidence"],
            src=str(alert_dict.get("src", "0.0.0.0")),
            dst=str(alert_dict.get("dst", "0.0.0.0")),
            dport=int(alert_dict.get("dport") or 0),
            sni=alert_dict.get("sni"),
            explanation=alert_dict.get("explanation", ""),
            shap_values=raw_shap,
            mitre_ttps=raw_mitre,
            analyst_status=alert_dict.get("analyst_status", "unreviewed"),
        ))

    return AlertListResponse(alerts=alerts, total=total)


@router.get("/{alert_id}", response_model=PhantomFlowAlert)
async def get_alert(request: Request, alert_id: str):
    """Get a specific alert by ID."""
    db = get_db(request)
    async with db.pool.acquire() as conn:
        r = await conn.fetchrow("""
            SELECT a.*, f.src_ip as src, f.dst_ip as dst, f.dst_port as dport, f.sni 
            FROM alerts a JOIN flows f ON a.flow_id = f.flow_id 
            WHERE a.alert_id = $1::uuid
        """, alert_id)
        
    if not r:
        raise HTTPException(status_code=404, detail="Alert not found")
        
    alert_dict = dict(r)
    
    # Parse mitre_ttps — stored as string like "['T1071.001', 'T1573.001']" in DB
    raw_mitre = alert_dict.get("mitre_ttps") or []
    if isinstance(raw_mitre, str):
        import ast
        try:
            raw_mitre = ast.literal_eval(raw_mitre)
        except Exception:
            raw_mitre = [x.strip().strip("'\"") for x in raw_mitre.strip("[]").split(",") if x.strip()]
    if not isinstance(raw_mitre, list):
        raw_mitre = list(raw_mitre) if raw_mitre else []
        
    # Parse shap_values — stored as jsonb but may be a string or dict
    raw_shap = alert_dict.get("shap_values") or {}
    if isinstance(raw_shap, str):
        try:
            raw_shap = json.loads(raw_shap)
        except Exception:
            try:
                import ast
                raw_shap = ast.literal_eval(raw_shap)
            except Exception:
                raw_shap = {}
    elif not isinstance(raw_shap, dict):
        raw_shap = dict(raw_shap) if raw_shap else {}

    return PhantomFlowAlert(
        alert_id=str(alert_dict["alert_id"]),
        flow_id=str(alert_dict["flow_id"]),
        timestamp=alert_dict["timestamp"].timestamp(),
        threat_type=alert_dict["threat_type"],
        alert_severity=alert_dict["severity"],
        confidence=alert_dict["confidence"],
        src=str(alert_dict.get("src", "0.0.0.0")),
        dst=str(alert_dict.get("dst", "0.0.0.0")),
        dport=int(alert_dict.get("dport") or 0),
        sni=alert_dict.get("sni"),
        explanation=alert_dict.get("explanation", ""),
        shap_values=raw_shap,
        mitre_ttps=raw_mitre,
        analyst_status=alert_dict.get("analyst_status", "unreviewed"),
    )


@router.post("/reset")
async def reset_database(request: Request):
    """Clear database and flush Redis cache (Clean Slate)."""
    db = get_db(request)
    redis_client = getattr(request.app.state, "redis", None)
    
    # 1. Truncate PostgreSQL tables
    if db and db.pool:
        try:
            async with db.pool.acquire() as conn:
                await conn.execute("TRUNCATE TABLE response_audit, analyst_reviews, alerts, flows CASCADE;")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Database truncation failed: {e}")
            
    # 2. Flush Redis
    if redis_client:
        try:
            redis_client.flushall()
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Redis flushall failed: {e}")
            
    return {"status": "success", "message": "Database and Redis reset successfully."}

