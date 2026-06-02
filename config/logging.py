# config/logging.py
"""
Structured JSON logging to ELK stack.
Every log line is a machine-parseable JSON object.
This is what lets you search logs at 3am when something breaks.
"""

import logging
import json
import time
import traceback
from typing import Any


class StructuredLogger:
    """
    Outputs JSON logs consumed by Filebeat → Elasticsearch → Kibana.
    
    Every log line has:
    - timestamp (ISO 8601)
    - level
    - service name
    - trace_id (follows request through all microservices)
    - message
    - structured data (no string interpolation — parseable fields)
    """

    def __init__(self, service_name: str):
        self.service = service_name
        self._logger = logging.getLogger(service_name)

    def _emit(self, level: str, msg: str, **kwargs):
        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "level": level,
            "service": self.service,
            "msg": msg,
            **kwargs,
        }
        # Remove None values
        record = {k: v for k, v in record.items() if v is not None}
        print(json.dumps(record), flush=True)

    def info(self, msg: str, **kwargs):
        self._emit("INFO", msg, **kwargs)

    def warning(self, msg: str, **kwargs):
        self._emit("WARN", msg, **kwargs)

    def error(self, msg: str, exc: Exception = None, **kwargs):
        if exc:
            kwargs["exception"] = traceback.format_exc()
        self._emit("ERROR", msg, **kwargs)

    def alert(self, alert: dict):
        """Dedicated alert log — every alert gets its own structured log line."""
        self._emit(
            "ALERT",
            f"{alert.get('threat_type', 'unknown')} detected",
            alert_id=alert.get("alert_id"),
            src=alert.get("src"),
            dst=alert.get("dst"),
            threat=alert.get("threat_type"),
            confidence=alert.get("confidence"),
            severity=alert.get("alert_severity"),
            ttps=alert.get("mitre_ttps"),
        )

    def model_inference(self, flow_id: str, model: str,
                         latency_ms: float, prediction: str, confidence: float):
        self._emit(
            "INFO",
            "model inference complete",
            flow_id=flow_id,
            model=model,
            latency_ms=round(latency_ms, 2),
            prediction=prediction,
            confidence=round(confidence, 4),
        )
