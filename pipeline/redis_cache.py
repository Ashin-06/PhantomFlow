# pipeline/redis_cache.py
"""
Redis-based flow state management for the real-time pipeline.
Provides sliding-window counters, flow correlation, and feature caching.
"""

import json
import time
import redis
from typing import Dict, List, Optional, Any


class FlowStateCache:
    """
    Manages flow state in Redis with automatic expiry.
    
    Key patterns:
      flow:{uid}           → full flow feature dict (TTL: 5min)
      tls:{uid}            → TLS metadata (TTL: 5min)
      dns:{uid}            → DNS metadata (TTL: 5min)
      conn_count:1m:{s}:{d} → connection frequency 1-min window
      conn_count:5m:{s}:{d} → connection frequency 5-min window
      beacon_history:{src}  → list of recent beacon times for src
      alert:{uid}           → alert sent flag (dedup, TTL: 10min)
    """

    def __init__(self, host: str = "localhost", port: int = 6379,
                 db: int = 0, password: str = "PhantomSecure2026!"):
        self.r = redis.Redis(
            host=host, port=port, db=db, password=password,
            decode_responses=True,
            socket_connect_timeout=5,
        )
        self._verify_connection()

    def _verify_connection(self):
        try:
            self.r.ping()
        except redis.ConnectionError as e:
            raise RuntimeError(f"Redis connection failed: {e}")

    # === Flow correlation ===

    def cache_flow(self, uid: str, data: Dict, ttl: int = 300):
        self.r.setex(f"flow:{uid}", ttl, json.dumps(data))

    def get_flow(self, uid: str) -> Optional[Dict]:
        raw = self.r.get(f"flow:{uid}")
        return json.loads(raw) if raw else None

    def cache_tls(self, uid: str, tls_data: Dict, ttl: int = 300):
        self.r.setex(f"tls:{uid}", ttl, json.dumps(tls_data))

    def get_tls(self, uid: str) -> Dict:
        raw = self.r.get(f"tls:{uid}")
        return json.loads(raw) if raw else {}

    def cache_dns(self, uid: str, dns_data: Dict, ttl: int = 300):
        self.r.setex(f"dns:{uid}", ttl, json.dumps(dns_data))

    def get_dns(self, uid: str) -> Dict:
        raw = self.r.get(f"dns:{uid}")
        return json.loads(raw) if raw else {}

    # === Sliding window counters ===

    def increment_conn_count(self, src: str, dst: str):
        """Track connection frequency for behavioral analysis."""
        pipe = self.r.pipeline()
        for window, ttl in [("1m", 60), ("5m", 300), ("1h", 3600)]:
            key = f"conn_count:{window}:{src}:{dst}"
            pipe.incr(key)
            pipe.expire(key, ttl)
        pipe.execute()

    def get_conn_count(self, src: str, dst: str) -> Dict[str, int]:
        keys = {
            "1m": f"conn_count:1m:{src}:{dst}",
            "5m": f"conn_count:5m:{src}:{dst}",
            "1h": f"conn_count:1h:{src}:{dst}",
        }
        vals = self.r.mget(list(keys.values()))
        return {
            window: int(v or 0)
            for window, v in zip(keys.keys(), vals)
        }

    def increment_dns_query_count(self, src: str, domain: str):
        """Track per-client DNS query rate."""
        pipe = self.r.pipeline()
        for window, ttl in [("1m", 60), ("5m", 300)]:
            pipe.incr(f"dns:{window}:{src}:{domain}")
            pipe.expire(f"dns:{window}:{src}:{domain}", ttl)
            pipe.incr(f"dns_total:{window}:{src}")
            pipe.expire(f"dns_total:{window}:{src}", ttl)
        pipe.execute()

    def get_dns_query_count(self, src: str, domain: str) -> Dict[str, int]:
        vals = self.r.mget([
            f"dns:1m:{src}:{domain}",
            f"dns:5m:{src}:{domain}",
            f"dns_total:1m:{src}",
            f"dns_total:5m:{src}",
        ])
        return {
            "domain_1m": int(vals[0] or 0),
            "domain_5m": int(vals[1] or 0),
            "total_1m": int(vals[2] or 0),
            "total_5m": int(vals[3] or 0),
        }

    # === Host Connection History ===

    def record_flow_history(self, src_ip: str, flow_data: dict, max_size: int = 15):
        """Cache recent flow details for temporal context analysis."""
        key = f"flow_history:{src_ip}"
        self.r.rpush(key, json.dumps(flow_data))
        self.r.ltrim(key, -max_size, -1)
        self.r.expire(key, 3600)

    def get_flow_history(self, src_ip: str) -> List[dict]:
        """Retrieve recent flow details for temporal context analysis."""
        key = f"flow_history:{src_ip}"
        raw = self.r.lrange(key, 0, -1)
        return [json.loads(x) for x in raw]

    # === Beacon pattern tracking ===

    def record_beacon_candidate(self, src_ip: str, timestamp: float):
        """Track potential beacon timestamps for periodicity analysis."""
        key = f"beacon_history:{src_ip}"
        self.r.zadd(key, {str(timestamp): timestamp})
        # Keep last 200 timestamps per source
        self.r.zremrangebyrank(key, 0, -201)
        self.r.expire(key, 3600)

    def get_beacon_history(self, src_ip: str,
                            since: float = None) -> List[float]:
        """Get recent beacon candidate timestamps."""
        key = f"beacon_history:{src_ip}"
        min_score = since or (time.time() - 3600)
        raw = self.r.zrangebyscore(key, min_score, "+inf")
        return [float(v) for v in raw]

    # === Alert deduplication ===

    def should_alert(self, uid: str, ttl: int = 600) -> bool:
        """Returns True if this flow should generate a new alert (not duplicate)."""
        key = f"alert:{uid}"
        result = self.r.set(key, "1", ex=ttl, nx=True)
        return result is True  # nx=True means only set if not exists

    # === Global stats ===

    def increment_stat(self, stat_name: str, amount: int = 1):
        self.r.incrby(f"stats:{stat_name}", amount)

    def get_stats(self) -> Dict[str, Any]:
        keys = [
            "stats:total_flows", "stats:alerts_today",
            "stats:c2_beacon", "stats:dns_tunnel", "stats:exfil",
        ]
        vals = self.r.mget(keys)
        return {k.replace("stats:", ""): int(v or 0)
                for k, v in zip(keys, vals)}

    # === Packet buffer ===

    def push_packet(self, flow_id: str, pkt_data: Dict, max_size: int = 200):
        """Buffer packet metadata per flow for LSTM sequence building."""
        key = f"pkts:{flow_id}"
        self.r.rpush(key, json.dumps(pkt_data))
        self.r.ltrim(key, -max_size, -1)
        self.r.expire(key, 120)

    def pop_packets(self, flow_id: str) -> List[Dict]:
        """Retrieve and clear packet buffer for a flow."""
        key = f"pkts:{flow_id}"
        pipe = self.r.pipeline()
        pipe.lrange(key, 0, -1)
        pipe.delete(key)
        result = pipe.execute()
        return [json.loads(p) for p in result[0]]
