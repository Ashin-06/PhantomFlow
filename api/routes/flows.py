# api/routes/flows.py
from fastapi import APIRouter, Query, HTTPException, Depends, Request
from api.models import FlowDetailResponse
import json
import redis
import random
import time

router = APIRouter(prefix="/api/flows", tags=["flows"])
r = redis.Redis(host="localhost", port=6379, decode_responses=True)


@router.get("")
async def list_recent_flows(
    request: Request,
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """List recent flows from PostgreSQL database, with mock data fallback for demo/bypass mode."""
    db = request.app.state.db
    
    if not db or not db.pool:
        return {"flows": [], "total": 0}
        
    async with db.pool.acquire() as conn:
        total = await conn.fetchval("SELECT COUNT(*) FROM flows")
        rows = await conn.fetch(
            "SELECT * FROM flows ORDER BY timestamp DESC LIMIT $1 OFFSET $2",
            limit,
            offset
        )
        
    flows_list = []
    for r in rows:
        f = dict(r)
        flows_list.append({
            "flow_id": str(f["flow_id"]),
            "timestamp": f["timestamp"].timestamp() if hasattr(f["timestamp"], "timestamp") else f["timestamp"],
            "src_ip": str(f["src_ip"]),
            "dst_ip": str(f["dst_ip"]),
            "src_port": f["src_port"],
            "dst_port": f["dst_port"],
            "protocol": f["protocol"],
            "sni": f["sni"],
            "ja3_hash": f["ja3_hash"],
            "ja4_hash": f["ja4_hash"],
            "duration_s": f["duration_s"],
            "orig_bytes": f["orig_bytes"],
            "resp_bytes": f["resp_bytes"],
            "bytes_ratio": f["bytes_ratio"],
            "iat_mean_ms": f["iat_mean_ms"],
            "iat_cv": f["iat_cv"],
            "periodicity_score": f["periodicity_score"],
            "dominant_period_ms": f["dominant_period_ms"],
            "dns_query": f["dns_query"],
            "dns_entropy": f["dns_entropy"]
        })
    return {"flows": flows_list, "total": total}



@router.get("/{flow_id}", response_model=FlowDetailResponse)
def get_flow(flow_id: str):
    """Get full feature detail for a flow by UID."""
    raw = r.get(f"flow:{flow_id}")
    if not raw:
        raise HTTPException(status_code=404, detail="Flow not found")

    data = json.loads(raw)
    alert_raw = r.get(f"alert_for_flow:{flow_id}")
    alert = json.loads(alert_raw) if alert_raw else None

    # Packet timeline
    pkts_raw = r.lrange(f"pkts:{flow_id}", 0, 99)
    timeline = [json.loads(p) for p in pkts_raw]

    return FlowDetailResponse(
        flow_id=flow_id,
        features=data,
        prediction=alert,
        packet_timeline=timeline,
    )


@router.get("/{flow_id}/shap")
def get_shap_explanation(flow_id: str):
    """Get SHAP feature importance for a specific flow."""
    raw = r.get(f"shap:{flow_id}")
    if not raw:
        raise HTTPException(status_code=404, detail="No SHAP data for flow")
    return {"flow_id": flow_id, "shap_values": json.loads(raw)}
