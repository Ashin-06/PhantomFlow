from fastapi import FastAPI, Depends, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import os
import redis
import json
import subprocess
import sys
import asyncio
from urllib.parse import quote
from fastapi.security import HTTPAuthorizationCredentials
from contextlib import asynccontextmanager

# Import routers
from api.routes import alerts
from api.auth import router as auth_router, get_current_user, require_role, verify_token
from api.routes import analyst
from api.routes import response as response_router_module, triage as triage_router_module
from api.routes import suppression as suppression_router_module
from api.routes import flows
from config.secrets import SecretsManager
from pipeline.db_layer import Database

secrets = SecretsManager()
db_creds = secrets.get_db_credentials()
DATABASE_URL = (
    f"postgresql://{quote(db_creds.get('user', 'phantom'), safe='')}:{quote(db_creds.get('password', ''), safe='')}"
    f"@{db_creds.get('host', 'localhost')}:{db_creds.get('port', '5432')}/{db_creds.get('db', 'phantomflow')}"
)
db = Database(DATABASE_URL)

# Redis setup (synchronous client for fast endpoints)
redis_config = secrets.get_secret("phantomflow/redis")
REDIS_OPTIONS = dict(host=redis_config.get("host", "localhost"),
                     port=int(os.getenv("REDIS_PORT", "6379")),
                     password=redis_config.get("password") or None,
                     decode_responses=True, socket_connect_timeout=2, socket_timeout=2)
redis_client = redis.Redis(**REDIS_OPTIONS)

# ── WebSocket Manager ────────────────────────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in list(self.active_connections):
            try:
                await connection.send_text(message)
            except Exception:
                self.disconnect(connection)

manager = ConnectionManager()

async def redis_alert_pubsub_listener(app: FastAPI):
    """Subscribes to Redis alerts:feed channel and broadcasts via WebSockets."""
    import redis.asyncio as async_redis
    while True:
        try:
            async with async_redis.Redis(**REDIS_OPTIONS) as client:
                async with client.pubsub() as pubsub:
                    await pubsub.subscribe("alerts:feed")
                    while True:
                        message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1)
                        if message:
                            await manager.broadcast(message["data"])
                        await asyncio.sleep(0.05)
        except asyncio.CancelledError:
            raise
        except redis.RedisError:
            await asyncio.sleep(3)

# ── Lifespan Handler ─────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle."""
    try:
        await asyncio.wait_for(db.connect(), timeout=5)
        print("[DB] Successfully connected to PostgreSQL database.")
    except Exception as e:
        print(f"[WARN] PostgreSQL connection failed: {e}. Database-backed endpoints are unavailable.")
    
    # Start the async pubsub listener as a background task
    pubsub_task = asyncio.create_task(redis_alert_pubsub_listener(app))
    
    yield
    
    pubsub_task.cancel()
    try:
        await pubsub_task
    except asyncio.CancelledError:
        pass
        
    redis_client.close()
    try:
        await db.close()
    except Exception:
        pass

# ── FastAPI Initialization ──────────────────────────────────────────────────
app = FastAPI(
    title="PhantomFlow API",
    description="Enterprise Network Threat Detection — ML-based covert channel detection.",
    version="2.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)
app.state.db = db
app.state.redis = redis_client

# Allowed origins
ALLOWED_ORIGINS = [origin.strip() for origin in os.getenv(
    "ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:8000"
).split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

# Register Open Routes (Authentication)
app.include_router(auth_router)

# Register Secured Routes
app.include_router(alerts.router, dependencies=[Depends(get_current_user)])
app.include_router(analyst.router, dependencies=[Depends(get_current_user)])
app.include_router(response_router_module.router, dependencies=[Depends(get_current_user)])
app.include_router(triage_router_module.router, dependencies=[Depends(get_current_user)])
app.include_router(suppression_router_module.router, dependencies=[Depends(get_current_user)])
app.include_router(flows.router, dependencies=[Depends(get_current_user)])

# WebSocket Route
@app.websocket("/api/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        message = await asyncio.wait_for(websocket.receive_json(), timeout=5)
        identity = verify_token(HTTPAuthorizationCredentials(scheme="Bearer", credentials=message.get("token", "")))
    except (HTTPException, ValueError, AttributeError, asyncio.TimeoutError, WebSocketDisconnect):
        await websocket.close(code=1008)
        return
    manager.active_connections.append(websocket)
    try:
        while True:
            # We must call receive_text or similar to detect client disconnects
            import time
            remaining = float(identity["exp"]) - time.time()
            if remaining <= 0:
                await websocket.close(code=1008)
                break
            await asyncio.wait_for(websocket.receive_text(), timeout=remaining)
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except asyncio.TimeoutError:
        await websocket.close(code=1008)
    finally:
        manager.disconnect(websocket)

# ── Training Status Endpoints ───────────────────────────────────────────────
@app.get("/api/train/status", dependencies=[Depends(get_current_user)])
def get_train_status():
    status = redis_client.get("train_status") or "idle"
    rows = int(redis_client.get("train_rows") or 0)
    accuracy = float(redis_client.get("train_accuracy") or 0.0)
    f1_macro = float(redis_client.get("train_f1_macro") or 0.0)
    current_dataset = redis_client.get("train_current_dataset") or ""
    
    # Retrieve logs and drift events
    logs = redis_client.lrange("train_logs", 0, -1)
    drift_events_raw = redis_client.lrange("train_drift_events", 0, -1)
    drift_events = []
    for d in drift_events_raw:
        try:
            drift_events.append(json.loads(d))
        except Exception:
            pass
            
    TRAIN_DATASETS = [
        "cicids2017_monday",
        "cicids2017_friday",
        "cicids2017_wednesday",
        "cicids2017_thursday",
        "ctu13_scenario1",
        "unsw_nb15_train",
        "dns_exfil_github"
    ]
    dataset_progress = {}
    for ds in TRAIN_DATASETS:
        dataset_progress[ds] = float(redis_client.get(f"train_progress:{ds}") or 0.0)

    return {
        "status": status,
        "rows": rows,
        "accuracy": accuracy,
        "f1_macro": f1_macro,
        "current_dataset": current_dataset,
        "logs": logs,
        "drift_events": drift_events,
        "dataset_progress": dataset_progress,
    }

@app.post("/api/train/run", dependencies=[Depends(require_role("admin"))])
def trigger_training():
    # Serialize status initialization and process launch across API workers.
    lock = redis_client.lock("train:launch-lock", timeout=30, blocking_timeout=0)
    if not lock.acquire(blocking=False):
        return {"status": "already_running", "message": "A training launch is already in progress."}
    try:
        if redis_client.get("train_status") == "training":
            return {"status": "already_running", "message": "Training is already in progress."}
        redis_client.set("train_status", "training")
        redis_client.set("train_rows", 0)
        redis_client.set("train_accuracy", 0.0)
        redis_client.set("train_f1_macro", 0.0)
        redis_client.set("train_current_dataset", "")
        redis_client.delete("train_drift_events", "train_logs")
        for ds in ["cicids2017_monday", "cicids2017_friday", "cicids2017_wednesday",
                   "cicids2017_thursday", "ctu13_scenario1", "unsw_nb15_train", "dns_exfil_github"]:
            redis_client.set(f"train_progress:{ds}", 0.0)
        cmd = [sys.executable, "-m", "train.run_online", "--max_rows", "5000"]
        subprocess.Popen(cmd, cwd=os.path.join(os.path.dirname(__file__), ".."))
    except (OSError, redis.RedisError):
        redis_client.set("train_status", "failed")
        raise HTTPException(503, "Training could not be started")
    finally:
        lock.release()
    return {"status": "started", "message": "Online training pipeline initiated."}

# ── Stats Endpoint ──────────────────────────────────────────────────────────
@app.get("/api/stats", dependencies=[Depends(get_current_user)])
async def get_stats():
    """Dashboard stats: threat counts, flow total, alert timeline from DB + Redis."""
    try:
        # 1. Fetch threat counts from Redis (which holds latest window counts)
        redis_counts = {
            "c2_beacon": int(redis_client.get("stats:c2_count") or 0),
            "dns_tunnel": int(redis_client.get("stats:dns_count") or 0),
            "exfiltration": int(redis_client.get("stats:exfil_count") or 0),
            "port_scan": int(redis_client.get("stats:port_scan_count") or 0),
            "lateral_movement": int(redis_client.get("stats:lateral_count") or 0),
            "brute_force": int(redis_client.get("stats:brute_count") or 0),
            "ransomware": int(redis_client.get("stats:ransomware_count") or 0),
        }
        
        # 2. Query Postgres for historical database counts (the source of truth)
        db_threat_counts = {}
        db_flows_count = 0
        if db.pool:
            try:
                async with db.pool.acquire() as conn:
                    # Retrieve threat type counts
                    rows = await conn.fetch("SELECT threat_type, COUNT(*) as cnt FROM alerts GROUP BY threat_type")
                    db_threat_counts = {r["threat_type"]: r["cnt"] for r in rows}
                    
                    # Retrieve flow count
                    db_flows_count = await conn.fetchval("SELECT COUNT(*) FROM flows") or 0
            except Exception as e:
                print(f"[WARN] Error fetching db stats: {e}")
        
        # 3. Merge DB and Redis threat counts (use the max of both)
        threat_counts = {}
        for t, r_val in redis_counts.items():
            db_val = db_threat_counts.get(t, 0)
            threat_counts[t] = max(db_val, r_val)
            
        # 4. Synchronize flows total count with a realistic base + db flows
        redis_flows = int(redis_client.get("stats:flows_total") or 0)
        base_flows = 0
        flows_total = base_flows + max(db_flows_count, redis_flows)
        
        # Calculate real flows_per_sec over the last 5 seconds (excluding the current second to avoid partial counts)
        import time
        now_sec = int(time.time())
        rate_keys = [f"stats:rate:{now_sec - i}" for i in range(1, 6)]
        rate_values = redis_client.mget(rate_keys)
        total_rate = 0
        active_secs = 0
        for val in rate_values:
            if val is not None:
                total_rate += int(val)
                active_secs += 1
        flows_per_sec = int(total_rate / 5) if active_secs > 0 else 0

        ja3_matches = int(redis_client.get("stats:ja3_matches") or 0)
        feedback_count = int(redis_client.get("feedback_count") or 0)
        last_feedback_ts = redis_client.get("last_feedback_ts")

        # Timeline: last 12 x 5min buckets
        timeline = []
        now_bucket = int(time.time() / 300)
        for i in range(11, -1, -1):
            bucket = now_bucket - i
            val = int(redis_client.get(f"stats:timeline:{bucket}") or 0)
            timeline.append(val)

        return {
            "threat_counts": threat_counts,
            "flows_total": flows_total,
            "flows_per_sec": flows_per_sec,
            "ja3_matches": ja3_matches,
            "timeline": timeline,
            "feedback_count": feedback_count,
            "last_feedback_ts": int(last_feedback_ts) if last_feedback_ts else None,
        }
    except Exception:
        raise HTTPException(503, "Telemetry is temporarily unavailable")

from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse

# Mount static files
dashboard_path = os.path.join(os.path.dirname(__file__), "..", "dashboard", "public")
app.mount("/dashboard", StaticFiles(directory=dashboard_path, html=True), name="dashboard")

@app.get("/")
def redirect_to_dashboard():
    return RedirectResponse(url="/dashboard/index.html")

@app.get("/health")
def health_check():
    return {"status": "ok", "message": "PhantomFlow API process is running. Check /ready for dependencies."}


@app.exception_handler(redis.RedisError)
async def redis_unavailable(request, exc):
    from fastapi.responses import JSONResponse
    return JSONResponse(status_code=503, content={"detail": "Telemetry storage is unavailable"})


@app.get("/ready")
async def readiness():
    """Dependency readiness, separate from process liveness at /health."""
    from fastapi.responses import JSONResponse
    checks = {"postgres": False, "redis": False}
    try:
        checks["redis"] = bool(await asyncio.to_thread(redis_client.ping))
    except redis.RedisError:
        pass
    try:
        if db.pool:
            async with db.pool.acquire(timeout=2) as conn:
                checks["postgres"] = await conn.fetchval("SELECT 1", timeout=2) == 1
    except Exception:
        pass
    ready = all(checks.values())
    return JSONResponse(status_code=200 if ready else 503,
                        content={"status": "ready" if ready else "degraded", "services": checks})


@app.middleware("http")
async def database_availability(request, call_next):
    from fastapi.responses import JSONResponse
    prefixes = ("/api/alerts", "/analyst", "/api/response", "/api/triage",
                "/api/suppression", "/api/flows")
    if request.url.path.startswith(prefixes) and db.pool is None:
        return JSONResponse(status_code=503, content={"detail": "Database is unavailable"})
    return await call_next(request)
