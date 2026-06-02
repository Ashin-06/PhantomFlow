# capture/xdp_loader.py
"""
Loads the compiled XDP program onto a network interface.
Reads perf events and pushes packet metadata to Kafka.
"""

import ctypes
import os
import struct
import json
import socket
import time
from bcc import BPF
from kafka import KafkaProducer

KAFKA_BROKER = os.getenv("KAFKA_BROKER", "localhost:9092")
INTERFACE = os.getenv("CAPTURE_INTERFACE", "eth0")
XDP_PROG = os.path.join(os.path.dirname(__file__), "xdp_capture.c")


def ip_int_to_str(ip_int: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", socket.ntohl(ip_int)))


class XDPCapture:
    def __init__(self, interface: str = INTERFACE):
        self.interface = interface
        self.producer = KafkaProducer(
            bootstrap_servers=KAFKA_BROKER,
            value_serializer=lambda v: json.dumps(v).encode(),
            compression_type="gzip",
            batch_size=65536,
            linger_ms=5,
        )
        
        print(f"[XDP] Loading BPF program on {interface}...")
        self.bpf = BPF(src_file=XDP_PROG)
        self.fn = self.bpf.load_func("xdp_flow_tracker", BPF.XDP)
        self.bpf.attach_xdp(interface, self.fn, 0)
        print(f"[XDP] Attached. Listening for packets...")

    def _handle_pkt_event(self, cpu, data, size):
        """Called for every packet event from kernel."""
        class PktEvent(ctypes.Structure):
            _fields_ = [
                ("timestamp_ns", ctypes.c_uint64),
                ("src_ip",       ctypes.c_uint32),
                ("dst_ip",       ctypes.c_uint32),
                ("src_port",     ctypes.c_uint16),
                ("dst_port",     ctypes.c_uint16),
                ("pkt_len",      ctypes.c_uint16),
                ("protocol",     ctypes.c_uint8),
                ("tcp_flags",    ctypes.c_uint8),
                ("iat_ns",       ctypes.c_uint64),
            ]
        
        event = ctypes.cast(data, ctypes.POINTER(PktEvent)).contents
        pkt = {
            "ts": event.timestamp_ns / 1e9,
            "src": ip_int_to_str(event.src_ip),
            "dst": ip_int_to_str(event.dst_ip),
            "sport": event.src_port,
            "dport": event.dst_port,
            "len": event.pkt_len,
            "proto": event.protocol,
            "flags": event.tcp_flags,
            "iat_ns": event.iat_ns,
        }
        self.producer.send("raw_packets", pkt)

    def run(self):
        self.bpf["events"].open_perf_buffer(self._handle_pkt_event, page_cnt=512)
        print("[XDP] Polling perf buffer...")
        try:
            while True:
                self.bpf.perf_buffer_poll(timeout=100)
        except KeyboardInterrupt:
            pass
        finally:
            self.cleanup()

    def cleanup(self):
        print("[XDP] Removing XDP program...")
        self.bpf.remove_xdp(self.interface, 0)
        self.producer.flush()
        self.producer.close()


if __name__ == "__main__":
    capture = XDPCapture()
    capture.run()
