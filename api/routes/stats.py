# api/routes/stats.py
from fastapi import APIRouter
from api.models import StatsResponse
import json, time, redis

router = APIRouter(prefix="/api/stats", tags=["stats"])
r = redis.Redis(host="localhost", port=6379, decode_responses=True)


@router.get("", response_model=StatsResponse)
def get_stats():
    total_flows = int(r.get("stats:total_flows") or 0)
    alerts_today = int(r.get("stats:alerts_today") or 0)
    start_time = float(r.get("stats:start_time") or time.time())
    uptime = int(time.time() - start_time)
    fpm = total_flows / max(1, uptime / 60)

    threat_breakdown = {
        "c2_beacon": int(r.get("stats:c2_beacon") or 0),
        "dns_tunnel": int(r.get("stats:dns_tunnel") or 0),
        "exfiltration": int(r.get("stats:exfil") or 0),
        "lateral_movement": int(r.get("stats:lateral_movement") or 0),
    }

    top_raw = r.get("stats:top_src") or "[]"
    top_src = json.loads(top_raw)

    return StatsResponse(
        total_flows_analyzed=total_flows,
        alerts_today=alerts_today,
        threat_breakdown=threat_breakdown,
        top_src_ips=top_src,
        models_loaded=bool(r.get("stats:models_loaded")),
        uptime_s=uptime,
        flows_per_sec=round(fpm / 60, 1),
    )


@router.get("/timeseries")
def alert_timeseries(window_minutes: int = 60, bucket_minutes: int = 5):
    """Return alert counts bucketed over time for sparkline charts."""
    now = time.time()
    buckets = []
    for i in range(window_minutes // bucket_minutes, 0, -1):
        t_start = now - i * bucket_minutes * 60
        t_end = t_start + bucket_minutes * 60
        count = int(r.zcount("alerts:timeline", t_start, t_end))
        buckets.append({
            "t": int(t_start),
            "count": count,
            "label": f"-{i * bucket_minutes}m",
        })
    return {"buckets": buckets}


@router.get("/model-performance")
def model_performance():
    """Cached model evaluation metrics from last training run."""
    raw = r.get("stats:model_metrics")
    if not raw:
        return {"message": "No metrics cached. Run evaluate.py after training."}
    return json.loads(raw)
