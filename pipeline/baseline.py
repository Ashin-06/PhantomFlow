import json
import redis

from config.secrets import redis_options
import logging

logger = logging.getLogger("PhantomFlow-Baseline")

class BaselineLearner:
    """Tracks traffic patterns to learn what is 'normal' for each IP."""
    def __init__(self, **options):
        self.r = redis.Redis(**(options or redis_options()))

    def observe(self, src_ip: str, bytes_out: int):
        """Record traffic stats during learning mode."""
        key = f"baseline:bytes:{src_ip}"
        
        # We store the total bytes and a count of flows to calculate the average
        # using Redis Hashes
        self.r.hincrby(key, "total_bytes", bytes_out)
        self.r.hincrby(key, "flow_count", 1)

    def is_anomalous(self, src_ip: str, bytes_out: int, threshold_multiplier: float = 5.0) -> bool:
        """Check if current traffic drastically exceeds the learned baseline."""
        key = f"baseline:bytes:{src_ip}"
        stats = self.r.hgetall(key)
        
        if not stats:
            # If we haven't learned anything about this IP, we assume it might be anomalous if it's very high.
            # But usually we want to default to False if we don't know, to prevent false positives.
            return False 

        total_bytes = int(stats.get("total_bytes", 0))
        flow_count = int(stats.get("flow_count", 1))
        
        avg_bytes = total_bytes / flow_count
        
        # If the current flow is X times larger than their historical average, flag it.
        if avg_bytes > 0 and bytes_out > (avg_bytes * threshold_multiplier):
            logger.warning(f"BASELINE DEVIATION: {src_ip} sent {bytes_out}B (Avg: {avg_bytes}B)")
            return True
            
        return False
