# api/routes/triage.py
"""
Analyst Triage API — mark alerts as true/false positive and trigger model feedback.
"""
from fastapi import APIRouter, HTTPException, Request, BackgroundTasks
from pydantic import BaseModel
from typing import Literal, Optional
import logging

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/triage", tags=["triage"])

class TriageRequest(BaseModel):
    verdict: Literal["true_positive", "false_positive", "unsure"]
    notes: Optional[str] = None
    analyst_id: Optional[str] = "analyst"

class TriageResponse(BaseModel):
    alert_id: str
    verdict: str
    model_retrained: bool
    message: str

def _run_feedback(features: dict, label: int, redis_client):
    """Background task: update model from analyst feedback."""
    try:
        from pipeline.feedback_trainer import FeedbackTrainer
        trainer = FeedbackTrainer(redis_client=redis_client)
        updated = trainer.update(features, label)
        if updated:
            log.info(f"[Triage] Model updated with label={label}")
    except Exception as e:
        log.error(f"[Triage] Feedback training error: {e}")

@router.patch("/{alert_id}", response_model=TriageResponse)
async def triage_alert(
    alert_id: str,
    body: TriageRequest,
    request: Request,
    background_tasks: BackgroundTasks
):
    """Analyst verdict on an alert — updates DB and triggers incremental model update."""
    db = request.app.state.db

    async with db.pool.acquire() as conn:
        alert = await conn.fetchrow(
            "SELECT * FROM alerts WHERE alert_id = $1::uuid", alert_id
        )
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")

        db_status = "confirmed_tp" if body.verdict == "true_positive" else ("false_positive" if body.verdict == "false_positive" else "unreviewed")
        await conn.execute(
            """UPDATE alerts 
               SET analyst_status=$1, analyst_notes=$2, reviewed_at=NOW()
               WHERE alert_id=$3::uuid""",
            db_status, body.notes, alert_id
        )
        flow = await conn.fetchrow(
            "SELECT * FROM flows WHERE flow_id = $1::uuid", alert["flow_id"]
        )

    model_retrained = False
    if body.verdict in ("true_positive", "false_positive"):
        label = 1 if body.verdict == "true_positive" else 0
        
        # Reconstruct physical features for SGDClassifier retraining
        import math
        from collections import Counter
        
        def shannon_entropy(data: str) -> float:
            if not data:
                return 0.0
            entropy = 0.0
            length = len(data)
            for count in Counter(data).values():
                p = count / length
                entropy -= p * math.log2(p)
            return entropy

        if flow:
            duration = float(flow.get("duration_s") or 1.0)
            orig_bytes = float(flow.get("orig_bytes") or 0.0)
            resp_bytes = float(flow.get("resp_bytes") or 0.0)
            total_bytes = orig_bytes + resp_bytes
            
            # Estimate packet counts since they are not stored in DB
            orig_pkts = float(max(1, int(orig_bytes / 1000)))
            resp_pkts = float(max(1, int(resp_bytes / 1000)))
            total_pkts = orig_pkts + resp_pkts
            
            pkts_per_sec = total_pkts / max(0.001, duration)
            bytes_per_sec = total_bytes / max(0.001, duration)
            
            iat_mean = float(flow.get("iat_mean_ms") or 0.0)
            iat_cv = float(flow.get("iat_cv") or 0.0)
            iat_std = iat_mean * iat_cv
            
            sni_str = flow.get("sni") or ""
            ja3_hash = flow.get("ja3_hash")
            ja3_score = 0.98 if ja3_hash in ("e7d705a3286e19ea42f587b344ee6865", "b386946a5a44d1ddcc843bc75336dfce") else 0.0
            
            features = {
                "duration_s": duration,
                "total_bytes": total_bytes,
                "orig_bytes": orig_bytes,
                "orig_pkts": orig_pkts,
                "resp_bytes": resp_bytes,
                "bytes_ratio": float(flow.get("bytes_ratio") or (orig_bytes / max(resp_bytes, 1.0))),
                "pkts_per_sec": pkts_per_sec,
                "bytes_per_sec": bytes_per_sec,
                "iat_mean_ms": iat_mean,
                "iat_std_ms": iat_std,
                "iat_cv": iat_cv,
                "pkt_size_mean": total_bytes / max(1.0, total_pkts),
                "pkt_size_std": 0.0,
                "large_pkt_ratio": 0.1,
                "periodicity_score": float(flow.get("periodicity_score") or 0.0),
                "dominant_period_ms": float(flow.get("dominant_period_ms") or 0.0),
                "sni_len": float(len(sni_str)),
                "sni_entropy": shannon_entropy(sni_str),
                "tls_resumed": 0.0,
                "ja3_malware_score": ja3_score,
                "connection_count_1m": 1.0,
                "connection_count_5m": 5.0,
            }
        else:
            features = {}

        # Get redis from app state if available
        redis_client = getattr(request.app.state, "redis", None)
        background_tasks.add_task(_run_feedback, features, label, redis_client)
        model_retrained = True

    return TriageResponse(
        alert_id=alert_id,
        verdict=body.verdict,
        model_retrained=model_retrained,
        message=f"Alert marked '{body.verdict}'. {'Model update scheduled.' if model_retrained else ''}"
    )

@router.get("/stats")
async def triage_stats(request: Request):
    """Return triage statistics."""
    db = request.app.state.db
    async with db.pool.acquire() as conn:
        rows = await conn.fetch(
            """SELECT analyst_status, COUNT(*) as cnt 
               FROM alerts WHERE analyst_status IS NOT NULL 
               GROUP BY analyst_status"""
        )
    return {r["analyst_status"]: r["cnt"] for r in rows}
