# monitoring/metrics.py
"""
Prometheus metrics for every component.
Grafana dashboards alert on-call when things go wrong.
"""

from prometheus_client import (
    Counter, Histogram, Gauge, Summary, start_http_server
)

# ===== Pipeline Metrics =====

FLOWS_PROCESSED = Counter(
    "phantomflow_flows_total",
    "Total flows processed",
    ["interface", "proto"]
)

ALERTS_GENERATED = Counter(
    "phantomflow_alerts_total",
    "Total alerts generated",
    ["threat_type", "severity"]
)

INFERENCE_LATENCY = Histogram(
    "phantomflow_inference_latency_seconds",
    "Time to run full ensemble inference on one flow",
    buckets=[.001, .005, .01, .025, .05, .1, .25, .5, 1.0]
)

KAFKA_LAG = Gauge(
    "phantomflow_kafka_consumer_lag",
    "Number of messages behind in Kafka queue",
    ["topic", "partition"]
)

MODEL_ACCURACY = Gauge(
    "phantomflow_model_accuracy",
    "Current model accuracy on validation set",
    ["model_name", "metric"]
)

FALSE_POSITIVE_RATE = Gauge(
    "phantomflow_false_positive_rate",
    "Analyst-confirmed false positive rate (rolling 7d)"
)

FLOW_BUFFER_SIZE = Gauge(
    "phantomflow_flow_buffer_size",
    "Number of flows currently in processing buffer"
)

REDIS_MEMORY_USAGE = Gauge(
    "phantomflow_redis_memory_bytes",
    "Redis memory usage"
)

SENSOR_HEALTH = Gauge(
    "phantomflow_sensor_health",
    "1 if sensor is healthy, 0 if down",
    ["sensor_id", "interface"]
)


class MetricsCollector:
    """Wraps all metrics for easy use throughout the codebase."""

    def record_flow(self, interface: str, proto: str):
        FLOWS_PROCESSED.labels(interface=interface, proto=proto).inc()

    def record_alert(self, threat_type: str, severity: str):
        ALERTS_GENERATED.labels(threat_type=threat_type, severity=severity).inc()

    def record_inference(self, latency_s: float):
        INFERENCE_LATENCY.observe(latency_s)

    def update_kafka_lag(self, topic: str, partition: int, lag: int):
        KAFKA_LAG.labels(topic=topic, partition=str(partition)).set(lag)

    def update_false_positive_rate(self, rate: float):
        FALSE_POSITIVE_RATE.set(rate)

    def update_sensor_health(self, sensor_id: str, interface: str, healthy: bool):
        SENSOR_HEALTH.labels(sensor_id=sensor_id, interface=interface).set(int(healthy))

# Optional: start_http_server(9090) 
