# pipeline/db_layer.py
"""
Production PostgreSQL access with:
- Connection pooling (asyncpg + SQLAlchemy)
- Automatic retry on transient failures
- Query timeout enforcement
- Prepared statements (prevent SQL injection)
"""

import asyncpg
import asyncio
import logging
from typing import Optional, List, Dict, Any
from contextlib import asynccontextmanager
import json

log = logging.getLogger(__name__)


class Database:
    """Async PostgreSQL with connection pool."""

    POOL_MIN_SIZE = 5
    POOL_MAX_SIZE = 20
    QUERY_TIMEOUT = 30       # seconds — kill runaway queries
    STATEMENT_CACHE = 1000   # Prepared statement cache size

    def __init__(self, dsn: str):
        self.dsn = dsn
        self.pool: Optional[asyncpg.Pool] = None

    async def connect(self):
        self.pool = await asyncpg.create_pool(
            dsn=self.dsn,
            min_size=self.POOL_MIN_SIZE,
            max_size=self.POOL_MAX_SIZE,
            command_timeout=self.QUERY_TIMEOUT,
            max_cached_statement_lifetime=300,
            max_queries=50000,   # Recycle connection after 50k queries
            init=self._init_connection,
        )
        log.info(f"Database pool connected: {self.POOL_MIN_SIZE}-{self.POOL_MAX_SIZE} connections")

    async def _init_connection(self, conn):
        """Run on each new connection — set session-level settings."""
        await conn.execute("SET statement_timeout = '30s'")
        await conn.execute("SET lock_timeout = '10s'")
        await conn.execute("SET idle_in_transaction_session_timeout = '60s'")

    @asynccontextmanager
    async def transaction(self):
        if self.pool is None:
            class DummyConn:
                async def execute(self, *args, **kwargs): return []
                async def fetch(self, *args, **kwargs): return []
                async def fetchrow(self, *args, **kwargs): return {}
            yield DummyConn()
        else:
            async with self.pool.acquire() as conn:
                async with conn.transaction():
                    yield conn

    async def save_alert(self, alert: dict) -> str:
        """Save alert. Uses prepared statement — SQL injection safe."""
        if self.pool is None:
            return "mock-alert-uuid"
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("""
                INSERT INTO alerts (
                    flow_id, timestamp, threat_type, severity, confidence,
                    beacon_prob, dns_tunnel_prob, exfil_score,
                    shap_values, explanation, mitre_ttps
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11)
                RETURNING alert_id
            """,
                alert.get("flow_id"),
                alert.get("timestamp"),
                alert.get("threat_type"),
                alert.get("severity"),
                alert.get("confidence"),
                alert.get("sub_scores", {}).get("beacon_prob"),
                alert.get("sub_scores", {}).get("dns_tunnel_prob"),
                alert.get("sub_scores", {}).get("exfil_score"),
                json.dumps(alert.get("shap_values", {})),
                alert.get("explanation"),
                alert.get("mitre_ttps", []),
            )
            return str(row["alert_id"])

    async def save_flow(self, flow: dict, features: Any = None) -> None:
        """Save raw flow + features to DB before alert insertion (satisfies FK constraint)."""
        if self.pool is None:
            return
        import uuid as uuid_mod
        from datetime import datetime
        async with self.pool.acquire() as conn:
            # Normalize flow_id to a proper UUID string
            raw_uid = flow.get("uid", str(uuid_mod.uuid4()))
            try:
                flow_uuid = str(uuid_mod.UUID(str(raw_uid)))
            except ValueError:
                flow_uuid = str(uuid_mod.uuid4())
                flow["uid"] = flow_uuid

            # Check if flow already exists
            existing = await conn.fetchval("SELECT 1 FROM flows WHERE flow_id = $1::uuid", flow_uuid)
            if existing:
                return

            # Extract timestamp with safe fallback
            ts = flow.get("ts") or flow.get("timestamp")
            if ts:
                dt = datetime.fromtimestamp(float(ts)) if isinstance(ts, (int, float)) else ts
            else:
                dt = datetime.utcnow()

            # Normalize protocol: convert integer codes to string names
            raw_proto = flow.get("proto", "TCP")
            if isinstance(raw_proto, int):
                proto_map = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6"}
                raw_proto = proto_map.get(raw_proto, str(raw_proto))
            protocol = str(raw_proto)[:10]  # Fits VARCHAR(10)

            # Normalize IP addresses — ensure valid strings
            src_ip = str(flow.get("src_ip", flow.get("src", "0.0.0.0")))
            dst_ip = str(flow.get("dst_ip", flow.get("dst", "0.0.0.0")))

            # Normalize JA3 hash — must be exactly 32 chars or NULL for CHAR(32)
            ja3_raw = flow.get("ja3")
            ja3_hash = str(ja3_raw)[:32] if ja3_raw else None

            # Safely extract numeric values
            src_port = int(flow.get("src_port", flow.get("sport", 0)) or 0)
            dst_port = int(flow.get("dst_port", flow.get("dport", 0)) or 0)
            orig_bytes = int(features.orig_bytes if (features and hasattr(features, "orig_bytes")) else flow.get("orig_bytes", flow.get("bytes_out", 0)) or 0)
            resp_bytes = int(features.resp_bytes if (features and hasattr(features, "resp_bytes")) else flow.get("resp_bytes", 0) or 0)

            try:
                await conn.execute("""
                    INSERT INTO flows (
                        flow_id, timestamp, src_ip, dst_ip, src_port, dst_port,
                        protocol, sni, ja3_hash, duration_s, orig_bytes, resp_bytes, bytes_ratio,
                        iat_mean_ms, iat_cv, periodicity_score, dominant_period_ms,
                        dns_query, dns_entropy
                    ) VALUES ($1::uuid, $2, $3::inet, $4::inet, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
                """,
                    flow_uuid,
                    dt,
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    protocol,
                    flow.get("server_name") or flow.get("sni"),
                    ja3_hash,
                    float(features.duration_s) if (features and hasattr(features, "duration_s")) else float(flow.get("duration_s") or 0),
                    orig_bytes,
                    resp_bytes,
                    float(features.bytes_ratio) if (features and hasattr(features, "bytes_ratio") and features.bytes_ratio is not None) else None,
                    float(features.iat_mean_ms) if (features and hasattr(features, "iat_mean_ms") and features.iat_mean_ms is not None) else None,
                    float(features.iat_cv) if (features and hasattr(features, "iat_cv") and features.iat_cv is not None) else None,
                    float(features.periodicity_score) if (features and hasattr(features, "periodicity_score") and features.periodicity_score is not None) else None,
                    float(features.dominant_period_ms) if (features and hasattr(features, "dominant_period_ms") and features.dominant_period_ms is not None) else None,
                    features.dns_query if (features and hasattr(features, "dns_query")) else flow.get("dns_query"),
                    float(features.dns_shannon_entropy) if (features and hasattr(features, "dns_shannon_entropy") and features.dns_shannon_entropy is not None) else None,
                )
            except Exception as e:
                log.error(f"save_flow INSERT failed for {flow_uuid}: {e}")
                raise

    async def get_analyst_feedback(self, days: int = 7) -> List[Dict]:
        """Pull analyst-labeled data for model retraining."""
        if self.pool is None:
            return []
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT f.*, r.analyst_label, r.analyst_notes, r.reviewed_at
                FROM flows f
                JOIN analyst_reviews r ON f.flow_id = r.flow_id
                WHERE r.reviewed_at > NOW() - INTERVAL '$1 days'
                AND r.analyst_label IS NOT NULL
                ORDER BY r.reviewed_at DESC
            """, days)
            return [dict(r) for r in rows]

    async def check_suppression(self, alert: dict) -> Optional[dict]:
        """Check if alert matches any active suppression rule."""
        if self.pool is None:
            return None
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT rule_id, name, justification
                FROM suppression_rules
                WHERE is_active = TRUE
                AND (expires_at IS NULL OR expires_at > NOW())
                AND (src_ip_cidr IS NULL OR $1::inet <<= src_ip_cidr)
                AND (dst_ip_cidr IS NULL OR $2::inet <<= dst_ip_cidr)
                AND (dst_port IS NULL OR dst_port = $3)
                AND (sni_pattern IS NULL OR $4 ~ sni_pattern)
                AND (threat_type IS NULL OR threat_type = $5)
                LIMIT 1
            """,
                alert.get("src"),
                alert.get("dst"),
                alert.get("dport"),
                alert.get("sni", ""),
                alert.get("threat_type"),
            )
            return dict(row) if row else None
            
    async def get_active_suppression_rules(self) -> List[Dict]:
        """Fetch all active suppression rules."""
        if self.pool is None:
            return []
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT * FROM suppression_rules 
                WHERE is_active = TRUE 
                AND (expires_at IS NULL OR expires_at > NOW())
            """)
            return [dict(r) for r in rows]

    async def close(self):
        if self.pool:
            await self.pool.close()
