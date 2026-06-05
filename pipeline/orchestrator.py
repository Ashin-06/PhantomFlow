import asyncio
import json
import logging
import time
from datetime import datetime

from pipeline.redis_cache import FlowStateCache
from pipeline.db_layer import Database
from pipeline.active_response import ActiveResponseEngine
from pipeline.siem_exporter import SIEMExporter
from pipeline.baseline import BaselineLearner
from pipeline.suppression import SuppressionEngine
from config.secrets import SecretsManager
from config.logging import StructuredLogger

log = StructuredLogger("pipeline.orchestrator")
logging.basicConfig(level=logging.INFO)

import os
LEARNING_MODE = os.getenv("LEARNING_MODE", "False").lower() in ("true", "1")

# ── Setup ──────────────────────────────────────────────────────────────────────
secrets = SecretsManager()
db_creds = secrets.get_db_credentials()
DATABASE_URL = (
    f"postgresql://{db_creds.get('user', 'phantom')}:{db_creds.get('password', 'PhantomSecure2026!')}"
    f"@{db_creds.get('host', 'localhost')}:{db_creds.get('port', '5432')}/{db_creds.get('db', 'phantomflow')}"
)

siem = SIEMExporter(host="127.0.0.1", port=514)
baseline = BaselineLearner()

# ── Redis client (shared for stat counters + new detectors) ───────────────────
import redis as redis_lib
try:
    _redis = redis_lib.Redis(
        host="localhost", port=6379,
        password="PhantomSecure2026!", decode_responses=True
    )
    _redis.ping()
except Exception:
    _redis = None

# ── New Rule-Based Detectors ───────────────────────────────────────────────────
try:
    from models.port_scan_detector import PortScanDetector
    port_scan_detector = PortScanDetector(redis_client=_redis)
except Exception as _e:
    log.warning("PortScanDetector unavailable", exc=_e)
    port_scan_detector = None

try:
    from models.lateral_movement_detector import LateralMovementDetector
    lateral_detector = LateralMovementDetector(redis_client=_redis)
except Exception as _e:
    log.warning("LateralMovementDetector unavailable", exc=_e)
    lateral_detector = None

try:
    from models.brute_force_detector import BruteForceDetector
    brute_force_detector = BruteForceDetector(redis_client=_redis)
except Exception as _e:
    log.warning("BruteForceDetector unavailable", exc=_e)
    brute_force_detector = None

try:
    from models.ransomware_detector import RansomwareDetector
    ransomware_detector = RansomwareDetector(redis_client=_redis)
except Exception as _e:
    log.warning("RansomwareDetector unavailable", exc=_e)
    ransomware_detector = None

try:
    from models.tls_fingerprint_detector import TLSFingerprintDetector
    tls_fingerprint_detector = TLSFingerprintDetector(redis_client=_redis)
except Exception as _e:
    log.warning("TLSFingerprintDetector unavailable", exc=_e)
    tls_fingerprint_detector = None

try:
    from models.tls_cert_detector import TLSCertDetector
    tls_cert_detector = TLSCertDetector(redis_client=_redis)
except Exception as _e:
    log.warning("TLSCertDetector unavailable", exc=_e)
    tls_cert_detector = None

try:
    from models.jitter_c2_detector import JitterC2Detector
    jitter_c2_detector = JitterC2Detector(redis_client=_redis)
except Exception as _e:
    log.warning("JitterC2Detector unavailable", exc=_e)
    jitter_c2_detector = None

try:
    from models.doh_dot_detector import DoHDotDetector
    doh_dot_detector = DoHDotDetector(redis_client=_redis)
except Exception as _e:
    log.warning("DoHDotDetector unavailable", exc=_e)
    doh_dot_detector = None

try:
    from models.shannon_entropy_detector import ShannonEntropyDetector
    shannon_entropy_detector = ShannonEntropyDetector(redis_client=_redis)
except Exception as _e:
    log.warning("ShannonEntropyDetector unavailable", exc=_e)
    shannon_entropy_detector = None



def _redis_incr_stat(key: str):
    """Safely increment a Redis counter (best-effort, never crashes the pipeline)."""
    if _redis:
        try:
            _redis.incr(key)
        except Exception:
            pass

def _redis_incr_timeline():
    """Increment the current 5-minute alert bucket for the sparkline chart."""
    if _redis:
        try:
            bucket = int(time.time() / 300)
            key = f"stats:timeline:{bucket}"
            _redis.incr(key)
            _redis.expire(key, 3600 * 2)   # keep 2 hours of history
        except Exception:
            pass


async def check_threat_intel(ip: str) -> str:
    """
    Async threat intel enrichment.
    In production: call AbuseIPDB, VirusTotal, or internal TI platform.
    """
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
        return "Internal IP — no external TI lookup"
    # TODO: replace with real aiohttp call to AbuseIPDB API
    return "[Mock TI: check AbuseIPDB / VirusTotal in production]"


import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

class HealthCheckHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "healthy"}')
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        return

def start_health_server():
    try:
        server = HTTPServer(("0.0.0.0", 8080), HealthCheckHandler)
        server.serve_forever()
    except Exception as e:
        log.warning("Failed to start health check server", error=e)

async def redis_suppression_listener(suppression_engine: SuppressionEngine):
    """Listens for rule modifications in Redis and reloads suppression rules."""
    if _redis:
        try:
            import redis.asyncio as async_redis
            r_async = async_redis.Redis(
                host="localhost", port=6379,
                password="PhantomSecure2026!", decode_responses=True
            )
            pubsub = r_async.pubsub()
            await pubsub.subscribe("suppression:reload")
            log.info("Orchestrator subscribed to suppression:reload channel")
            while True:
                msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if msg:
                    log.info("Suppression rule change detected! Reloading rules...")
                    await suppression_engine.reload_rules()
                await asyncio.sleep(0.5)
        except asyncio.CancelledError:
            log.info("Redis suppression listener cancelled")
        except Exception as e:
            log.warning("Error in Redis suppression listener", exc=e)
        finally:
            try:
                await pubsub.unsubscribe("suppression:reload")
                await r_async.close()
            except Exception:
                pass

async def run_pipeline():
    log.info("Starting PhantomFlow Async Orchestrator",
             learning_mode=LEARNING_MODE)

    health_thread = threading.Thread(target=start_health_server, daemon=True)
    health_thread.start()
    log.info("Lightweight health check server started on port 8080")

    cache = FlowStateCache()
    db = Database(DATABASE_URL)
    await db.connect()

    suppression_engine = SuppressionEngine(db)
    await suppression_engine.reload_rules()

    active_response = ActiveResponseEngine(db)

    # Start redis suppression rules reload listener
    reload_task = asyncio.create_task(redis_suppression_listener(suppression_engine))

    # ── Load ML Ensemble ───────────────────────────────────────────────────────
    ensemble = None
    try:
        from models.ensemble import PhantomFlowEnsemble
        ensemble = PhantomFlowEnsemble()
        ensemble.load_models()
        log.info("ML ensemble loaded successfully")
    except Exception as e:
        log.warning("ML ensemble unavailable — falling back to threshold detection", exc=e)

    # ── Kafka Consumer ─────────────────────────────────────────────────────────
    try:
        from aiokafka import AIOKafkaConsumer
        consumer = AIOKafkaConsumer(
            "network-flows",
            bootstrap_servers="localhost:9092",
            group_id="phantomflow-ml-group",
            value_deserializer=lambda x: json.loads(x.decode("utf-8")),
            auto_offset_reset="latest",
            enable_auto_commit=True,
        )
        await consumer.start()
        log.info("Kafka consumer connected", topic="network-flows")

        async for message in consumer:
            try:
                await _process_flow(
                    message.value, db, cache, suppression_engine,
                    active_response, ensemble
                )
            except Exception as e:
                log.error("Flow processing error", exc=e)

    except Exception as e:
        log.error("Pipeline fatal error", exc=e)
    finally:
        reload_task.cancel()
        try:
            await reload_task
        except asyncio.CancelledError:
            pass
        if "consumer" in locals():
            await consumer.stop()
        await db.close()
        log.info("Pipeline shutdown complete")


async def _process_flow(
    flow_data: dict,
    db: Database,
    cache: FlowStateCache,
    suppression: SuppressionEngine,
    active_response: ActiveResponseEngine,
    ensemble,
) -> None:
    """
    Per-flow processing logic.
    Runs ML ensemble first, then all rule-based detectors.
    Each detector failure is isolated and never crashes the consumer.
    """
    import uuid
    flow_id = flow_data.get("uid", "unknown")
    try:
        uuid.UUID(str(flow_id))
    except ValueError:
        # Generate a valid UUID if flow_id is invalid (e.g. is connection key string)
        flow_id = str(uuid.uuid4())
        flow_data["uid"] = flow_id

    src_ip   = flow_data.get("src_ip", "0.0.0.0")
    dst_ip   = flow_data.get("dst_ip", "0.0.0.0")
    bytes_out = flow_data.get("bytes_out", flow_data.get("orig_bytes", 0))
    flow_features = None


    log.info("Processing network flow", flow_id=flow_id, src_ip=src_ip, dst_ip=dst_ip)

    cache.cache_flow(flow_id, flow_data)

    # Track total flows for dashboard counter
    _redis_incr_stat("stats:flows_total")

    # Track flow rate per second in Redis
    if _redis:
        try:
            current_sec = int(time.time())
            rate_key = f"stats:rate:{current_sec}"
            _redis.incr(rate_key)
            _redis.expire(rate_key, 15)
        except Exception:
            pass

    if LEARNING_MODE:
        baseline.observe(src_ip, bytes_out)
        return

    # ── Step 1: ML Ensemble (C2, DNS Tunnel, Exfiltration) ────────────────────
    ml_alert_dict = None
    ml_threat_type = None
    flow_features = None

    if ensemble is not None:
        try:
            from features.extractor import FlowFeatures, FeatureExtractor
            import numpy as np
            extractor = FeatureExtractor(redis_client=cache.r)

            pkt_iats   = flow_data.get("pkt_iats", [0.0] * 10)
            pkt_sizes  = flow_data.get("pkt_sizes", [0] * 10)
            flow_features = extractor.build_feature_vector(flow_data, pkt_iats, pkt_sizes)

            pkt_iats_arr  = np.array(pkt_iats, dtype=np.float32)
            pkt_sizes_arr = np.array(pkt_sizes, dtype=np.float32)
            directions    = np.zeros_like(pkt_iats_arr)
            flags         = np.zeros_like(pkt_iats_arr)
            pkt_sequence  = np.column_stack([pkt_iats_arr, pkt_sizes_arr, directions, flags]).astype(np.float32)

            flow_history = cache.get_flow_history(src_ip)
            result = ensemble.predict(flow_features, pkt_sequence, flow_history=flow_history)

            log.info("Ensemble prediction result",
                     flow_id=flow_id,
                     threat_type=result.get("threat_type"),
                     confidence=float(result.get("confidence", 0.0)),
                     sub_scores={k: float(v) if v is not None else 0.0
                                 for k, v in result.get("sub_scores", {}).items()})

            # Record history for Stage 2
            cache.record_flow_history(src_ip, {
                "duration_s":  float(flow_features.duration_s),
                "total_bytes": float(flow_features.total_bytes),
                "orig_bytes":  float(flow_features.orig_bytes),
                "orig_pkts":   float(flow_features.orig_pkts),
                "resp_bytes":  float(flow_features.total_bytes - flow_features.orig_bytes),
                "bytes_ratio": float(flow_features.bytes_ratio),
                "timestamp":   float(time.time()),
                "dst":         flow_features.dst,
            })

            if result["threat_type"] != "clean" and result["confidence"] > 0.5:
                ml_threat_type = result["threat_type"]
                ml_alert_dict = {
                    "flow_id":     flow_id,
                    "timestamp":   datetime.utcnow(),
                    "threat_type": result["threat_type"],
                    "severity":    result["alert_severity"],
                    "confidence":  result["confidence"],
                    "src":         src_ip,
                    "dst":         dst_ip,
                    "dport":       flow_data.get("dst_port", 0),
                    "sni":         flow_data.get("sni", ""),
                    "sub_scores":  result["sub_scores"],
                    "shap_values": result["shap_values"],
                    "explanation": result["explanation"],
                    "mitre_ttps":  result["mitre_ttps"],
                }
                # Update stats counters
                stat_map = {
                    "c2_beacon":    "stats:c2_count",
                    "dns_tunnel":   "stats:dns_count",
                    "exfiltration": "stats:exfil_count",
                }
                if result["threat_type"] in stat_map:
                    _redis_incr_stat(stat_map[result["threat_type"]])
                if result.get("sub_scores", {}).get("ja3_score", 0) > 0.7:
                    _redis_incr_stat("stats:ja3_matches")

        except Exception as e:
            log.error("Ensemble inference failed", exc=e)
            ensemble = None

    # ── Step 2: Threshold Fallback ─────────────────────────────────────────────
    if ml_alert_dict is None:
        is_anomaly = baseline.is_anomalous(src_ip, bytes_out)
        if bytes_out > 1_000_000 or is_anomaly:
            ml_threat_type = "exfiltration"
            ml_alert_dict = {
                "flow_id":     flow_id,
                "timestamp":   datetime.utcnow(),
                "threat_type": "exfiltration",
                "severity":    "critical",
                "confidence":  0.80,
                "src":         src_ip,
                "dst":         dst_ip,
                "dport":       flow_data.get("dst_port", 0),
                "sni":         flow_data.get("sni", ""),
                "explanation": f"Threshold: {bytes_out} bytes out",
            }
            _redis_incr_stat("stats:exfil_count")

    # ── Step 3: Rule-Based Detectors (run on every flow independently) ─────────
    rule_alerts = []

    # 3a: Port Scan
    if port_scan_detector is not None:
        try:
            scan_result = port_scan_detector.check(flow_data)
            if scan_result and scan_result.is_scan:
                rule_alerts.append({
                    "flow_id":     flow_id,
                    "timestamp":   datetime.utcnow(),
                    "threat_type": "port_scan",
                    "severity":    scan_result.severity,
                    "confidence":  scan_result.confidence,
                    "src":         src_ip,
                    "dst":         dst_ip,
                    "dport":       flow_data.get("dst_port", 0),
                    "sni":         flow_data.get("sni", ""),
                    "explanation": scan_result.explanation,
                    "mitre_ttps":  scan_result.mitre_ttps,
                    "shap_values": {"unique_ports": scan_result.unique_ports,
                                    "unique_hosts": scan_result.unique_hosts},
                    "sub_scores":  {"port_scan_confidence": scan_result.confidence},
                })
                _redis_incr_stat("stats:port_scan_count")
        except Exception as e:
            log.error("PortScanDetector error", exc=e)

    # 3b: Lateral Movement
    lateral_detected = False
    if lateral_detector is not None:
        try:
            lat_result = lateral_detector.check(flow_data)
            if lat_result and lat_result.is_lateral:
                lateral_detected = True
                rule_alerts.append({
                    "flow_id":     flow_id,
                    "timestamp":   datetime.utcnow(),
                    "threat_type": "lateral_movement",
                    "severity":    lat_result.severity,
                    "confidence":  lat_result.confidence,
                    "src":         src_ip,
                    "dst":         dst_ip,
                    "dport":       flow_data.get("dst_port", 0),
                    "sni":         flow_data.get("sni", ""),
                    "explanation": lat_result.explanation,
                    "mitre_ttps":  lat_result.mitre_ttps,
                    "shap_values": {"unique_internal_targets": lat_result.unique_internal_targets,
                                    "target_port": lat_result.target_port},
                    "sub_scores":  {"lateral_confidence": lat_result.confidence},
                })
                _redis_incr_stat("stats:lateral_count")
        except Exception as e:
            log.error("LateralMovementDetector error", exc=e)

    # 3c: Brute Force
    if brute_force_detector is not None:
        try:
            brute_result = brute_force_detector.check(flow_data)
            if brute_result and brute_result.is_brute:
                rule_alerts.append({
                    "flow_id":     flow_id,
                    "timestamp":   datetime.utcnow(),
                    "threat_type": "brute_force",
                    "severity":    brute_result.severity,
                    "confidence":  brute_result.confidence,
                    "src":         src_ip,
                    "dst":         dst_ip,
                    "dport":       flow_data.get("dst_port", 0),
                    "sni":         flow_data.get("sni", ""),
                    "explanation": brute_result.explanation,
                    "mitre_ttps":  brute_result.mitre_ttps,
                    "shap_values": {"connections_per_min": brute_result.connections_per_min,
                                    "attack_type": brute_result.attack_type},
                    "sub_scores":  {"brute_force_confidence": brute_result.confidence},
                })
                _redis_incr_stat("stats:brute_count")
        except Exception as e:
            log.error("BruteForceDetector error", exc=e)

    # 3d: Ransomware (multi-signal correlation)
    if ransomware_detector is not None:
        try:
            ransom_result = ransomware_detector.check(
                flow_data,
                lateral_movement_detected=lateral_detected,
                c2_detected=(ml_threat_type == "c2_beacon"),
            )
            if ransom_result and ransom_result.is_ransomware:
                rule_alerts.append({
                    "flow_id":     flow_id,
                    "timestamp":   datetime.utcnow(),
                    "threat_type": "ransomware",
                    "severity":    ransom_result.severity,
                    "confidence":  ransom_result.confidence,
                    "src":         src_ip,
                    "dst":         dst_ip,
                    "dport":       flow_data.get("dst_port", 0),
                    "sni":         flow_data.get("sni", ""),
                    "explanation": ransom_result.explanation,
                    "mitre_ttps":  ransom_result.mitre_ttps,
                    "shap_values": {"signals_triggered": len(ransom_result.signals_triggered)},
                    "sub_scores":  {"ransomware_signals": len(ransom_result.signals_triggered)},
                })
                _redis_incr_stat("stats:ransomware_count")
        except Exception as e:
            log.error("RansomwareDetector error", exc=e)

    # 3e: TLS Fingerprint Anomaly
    if tls_fingerprint_detector is not None:
        try:
            finger_result = tls_fingerprint_detector.check(flow_data)
            if finger_result and finger_result.is_threat:
                rule_alerts.append({
                    "flow_id":     flow_id,
                    "timestamp":   datetime.utcnow(),
                    "threat_type": "c2_beacon",
                    "severity":    finger_result.severity,
                    "confidence":  finger_result.confidence,
                    "src":         src_ip,
                    "dst":         dst_ip,
                    "dport":       flow_data.get("dst_port", 0),
                    "sni":         flow_data.get("sni", ""),
                    "explanation": finger_result.explanation,
                    "mitre_ttps":  finger_result.mitre_ttps,
                    "shap_values": {"threat_name": finger_result.threat_name,
                                    "ja3_hash": flow_data.get("ja3", flow_data.get("ja3_hash", ""))},
                    "sub_scores":  {"tls_fingerprint_confidence": finger_result.confidence},
                })
                _redis_incr_stat("stats:c2_count")
                if finger_result.threat_name == "blacklisted_tls_client":
                    _redis_incr_stat("stats:ja3_matches")
        except Exception as e:
            log.error("TLSFingerprintDetector error", exc=e)

    # 3f: TLS Certificate Anomaly
    if tls_cert_detector is not None:
        try:
            cert_result = tls_cert_detector.check(flow_data)
            if cert_result and cert_result.is_threat:
                rule_alerts.append({
                    "flow_id":     flow_id,
                    "timestamp":   datetime.utcnow(),
                    "threat_type": "c2_beacon",
                    "severity":    cert_result.severity,
                    "confidence":  cert_result.confidence,
                    "src":         src_ip,
                    "dst":         dst_ip,
                    "dport":       flow_data.get("dst_port", 0),
                    "sni":         flow_data.get("sni", ""),
                    "explanation": cert_result.explanation,
                    "mitre_ttps":  cert_result.mitre_ttps,
                    "shap_values": {"threat_name": cert_result.threat_name,
                                    "cert_validity_days": flow_data.get("cert_validity_days", 0.0),
                                    "cert_self_signed": flow_data.get("cert_self_signed", False)},
                    "sub_scores":  {"tls_cert_confidence": cert_result.confidence},
                })
                _redis_incr_stat("stats:c2_count")
        except Exception as e:
            log.error("TLSCertDetector error", exc=e)

    # 3g: Jitter C2 Beaconing
    if jitter_c2_detector is not None:
        try:
            flow_history = cache.get_flow_history(src_ip)
            if flow_history and len(flow_history) >= 2:
                sorted_history = sorted(flow_history, key=lambda x: x.get("timestamp", 0.0))
                intervals = [sorted_history[i]["timestamp"] - sorted_history[i-1]["timestamp"] for i in range(1, len(sorted_history))]
                packet_sizes = [int(x.get("total_bytes", 0)) for x in sorted_history]
                
                jitter_result = jitter_c2_detector.check_sequence(intervals, packet_sizes)
                if jitter_result and jitter_result.is_beacon:
                    rule_alerts.append({
                        "flow_id":     flow_id,
                        "timestamp":   datetime.utcnow(),
                        "threat_type": "c2_beacon",
                        "severity":    jitter_result.severity,
                        "confidence":  jitter_result.confidence,
                        "src":         src_ip,
                        "dst":         dst_ip,
                        "dport":       flow_data.get("dst_port", 0),
                        "sni":         flow_data.get("sni", ""),
                        "explanation": jitter_result.explanation,
                        "mitre_ttps":  ["T1071", "T1071.001"],
                        "shap_values": {"estimated_jitter_pct": jitter_result.estimated_jitter,
                                        "mean_interval_s": float(sum(intervals) / len(intervals)) if intervals else 0.0},
                        "sub_scores":  {"jitter_confidence": jitter_result.confidence},
                    })
                    _redis_incr_stat("stats:c2_count")
        except Exception as e:
            log.error("JitterC2Detector error", exc=e)

    # 3h: DoH/DoT Tunneling
    if doh_dot_detector is not None:
        try:
            doh_result = doh_dot_detector.check(flow_data)
            if doh_result and doh_result.is_threat:
                rule_alerts.append({
                    "flow_id":     flow_id,
                    "timestamp":   datetime.utcnow(),
                    "threat_type": "dns_tunnel",
                    "severity":    doh_result.severity,
                    "confidence":  doh_result.confidence,
                    "src":         src_ip,
                    "dst":         dst_ip,
                    "dport":       flow_data.get("dst_port", 0),
                    "sni":         flow_data.get("sni", ""),
                    "explanation": doh_result.explanation,
                    "mitre_ttps":  doh_result.mitre_ttps,
                    "shap_values": {"avg_packet_size": flow_data.get("orig_bytes", 0) / max(flow_data.get("orig_pkts", 1), 1)},
                    "sub_scores":  {"doh_dot_confidence": doh_result.confidence},
                })
                _redis_incr_stat("stats:dns_count")
        except Exception as e:
            log.error("DoHDotDetector error", exc=e)

    # 3i: Shannon Entropy Exfiltration
    if shannon_entropy_detector is not None:
        try:
            entropy_result = shannon_entropy_detector.check(flow_data)
            if entropy_result and entropy_result.is_threat:
                rule_alerts.append({
                    "flow_id":     flow_id,
                    "timestamp":   datetime.utcnow(),
                    "threat_type": "exfiltration",
                    "severity":    entropy_result.severity,
                    "confidence":  entropy_result.confidence,
                    "src":         src_ip,
                    "dst":         dst_ip,
                    "dport":       flow_data.get("dst_port", 0),
                    "sni":         flow_data.get("sni", ""),
                    "explanation": entropy_result.explanation,
                    "mitre_ttps":  entropy_result.mitre_ttps,
                    "shap_values": {"payload_entropy": flow_data.get("payload_entropy", 0.0),
                                    "orig_bytes": flow_data.get("orig_bytes", 0)},
                    "sub_scores":  {"entropy_confidence": entropy_result.confidence},
                })
                _redis_incr_stat("stats:exfil_count")
        except Exception as e:
            log.error("ShannonEntropyDetector error", exc=e)

    # ── Step 4: Collect all alerts to process ─────────────────────────────────
    all_alerts = []
    if ml_alert_dict:
        all_alerts.append(ml_alert_dict)
    all_alerts.extend(rule_alerts)

    if not all_alerts:
        return  # Clean flow — nothing to do

    # ── Step 5: Process each alert through suppression → persist → SIEM ───────
    for alert_dict in all_alerts:
        # Suppression check
        suppressed = suppression.should_suppress(alert_dict, alert_dict["threat_type"])
        is_suppressed = False
        if suppressed:
            log.info("Alert suppressed by rule",
                     rule_id=suppressed["rule_id"], flow_id=flow_id)
            alert_dict["analyst_status"] = "suppressed"
            alert_dict["analyst_notes"] = f"Auto-suppressed by rule: {suppressed['name']}"
            is_suppressed = True

        # Threat Intel enrichment (skip if suppressed)
        if not is_suppressed:
            ti_context = await check_threat_intel(dst_ip)
            alert_dict["explanation"] = str(alert_dict.get("explanation", "")) + f" | TI: {ti_context}"

        # Persist to DB
        try:
            await db.save_flow(flow_data, flow_features)
            alert_id = await db.save_alert(alert_dict)
            
            if is_suppressed:
                if db.pool:
                    async with db.pool.acquire() as conn:
                        await conn.execute("""
                            UPDATE alerts 
                            SET analyst_status = 'suppressed', 
                                analyst_notes = $1, 
                                reviewed_at = NOW() 
                            WHERE alert_id = $2::uuid
                        """, alert_dict["analyst_notes"], alert_id)
                log.info("Suppressed alert persisted to database", alert_id=alert_id)
                continue
                
            log.alert(alert_dict)
            
            # Publish to Redis Pub/Sub for WebSockets
            if _redis:
                try:
                    # Prepare JSON-serializable alert
                    ws_alert = {
                        "alert_id": alert_id,
                        "flow_id": alert_dict.get("flow_id"),
                        "timestamp": alert_dict["timestamp"].timestamp() if isinstance(alert_dict["timestamp"], datetime) else float(alert_dict["timestamp"]),
                        "threat_type": alert_dict.get("threat_type"),
                        "alert_severity": alert_dict.get("severity") or alert_dict.get("alert_severity") or "medium",
                        "confidence": float(alert_dict.get("confidence", 0.5)),
                        "src": alert_dict.get("src", "0.0.0.0"),
                        "dst": alert_dict.get("dst", "0.0.0.0"),
                        "dport": int(alert_dict.get("dport", 0)),
                        "sni": alert_dict.get("sni", ""),
                        "explanation": alert_dict.get("explanation", ""),
                        "shap_values": alert_dict.get("shap_values") or {},
                        "mitre_ttps": alert_dict.get("mitre_ttps") or [],
                        "analyst_status": "unreviewed",
                    }
                    _redis.publish("alerts:feed", json.dumps(ws_alert))
                except Exception as e:
                    log.error("Redis pubsub broadcast failed", exc=e)
        except Exception as e:
            log.error("Failed to save flow/alert to DB", exc=e)
            continue

        # SIEM export
        siem.send_cef(alert_dict)

        # Timeline counter for sparkline
        _redis_incr_timeline()

        # Active Response queue (analyst approval required)
        try:
            await active_response.queue_action(
                alert_id=alert_id,
                action="block_ip",
                target=dst_ip,
                confidence=alert_dict["confidence"],
                auto_block=False,
            )
        except Exception as e:
            log.error("Active response queue_action failed", exc=e)


if __name__ == "__main__":
    asyncio.run(run_pipeline())
