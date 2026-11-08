from models.port_scan_detector import PortScanDetector


def flow(port):
    return {"src_ip": "10.0.0.99", "dst_ip": "10.0.0.5", "dst_port": port, "proto": 6, "bytes_out": 0, "orig_bytes": 0, "orig_pkts": 1, "duration": 0.01}


def test_a_scan_raises_one_alert_not_one_per_port():
    detector = PortScanDetector(redis_client=None)
    alerts = [r for r in (detector.check(flow(p)) for p in range(1000, 1400)) if r]
    assert len(alerts) == 1
    assert alerts[0].scan_type.endswith("vertical")


def test_a_second_scanner_still_alerts():
    detector = PortScanDetector(redis_client=None)
    for p in range(1000, 1100):
        detector.check(flow(p))
    other = [detector.check({**flow(p), "src_ip": "10.0.0.77"}) for p in range(2000, 2100)]
    assert sum(1 for r in other if r) == 1
