# sensors/manager.py
"""
Sensor Fleet Management.
Tracks the health, config state, and metrics of Zeek/Suricata sensors
distributed across the network.
"""

from datetime import datetime
import logging
from pipeline.db_layer import Database

log = logging.getLogger(__name__)


class SensorManager:
    def __init__(self, db: Database):
        self.db = db

    async def register_sensor(self, hostname: str, interface: str, location: str) -> str:
        """Registers a new sensor on boot."""
        async with self.db.transaction() as conn:
            row = await conn.fetchrow("""
                INSERT INTO sensors (hostname, interface, location)
                VALUES ($1, $2, $3)
                RETURNING sensor_id
            """, hostname, interface, location)
            return str(row["sensor_id"])

    async def heartbeat(self, sensor_id: str, flows_per_sec: float, packet_loss: float, config_hash: str):
        """Sensors call this every 10s."""
        async with self.db.transaction() as conn:
            await conn.execute("""
                UPDATE sensors 
                SET last_heartbeat = NOW(), 
                    flows_per_sec = $1, 
                    packet_loss_pct = $2,
                    config_hash = $3
                WHERE sensor_id = $4::uuid
            """, flows_per_sec, packet_loss, config_hash, sensor_id)
            
            if packet_loss > 5.0:
                log.warning(f"Sensor {sensor_id} reporting high packet loss: {packet_loss}%")

    async def get_dead_sensors(self, threshold_seconds: int = 60) -> list:
        """Find sensors that haven't checked in."""
        async with self.db.transaction() as conn:
            rows = await conn.fetch("""
                SELECT sensor_id, hostname 
                FROM sensors 
                WHERE last_heartbeat < NOW() - INTERVAL '$1 seconds'
                AND is_active = TRUE
            """, threshold_seconds)
            return [dict(r) for r in rows]
