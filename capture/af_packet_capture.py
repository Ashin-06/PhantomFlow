# capture/af_packet_capture.py
"""
Fallback packet capture using AF_PACKET socket.
Use this when XDP isn't available (VMs, older kernels, non-root).
Lower performance than XDP but zero dependencies.
"""

import socket
import struct
import json
import time
import os
from kafka import KafkaProducer


KAFKA_BROKER = os.getenv("KAFKA_BROKER", "localhost:9092")
INTERFACE = os.getenv("CAPTURE_INTERFACE", "eth0")


def ip_from_bytes(b: bytes) -> str:
    return ".".join(str(x) for x in b)


class AFPacketCapture:
    """Raw AF_PACKET socket capture → Kafka pipeline."""

    ETH_P_IP = 0x0800
    PROTO_TCP = 6
    PROTO_UDP = 17

    def __init__(self, interface: str = INTERFACE):
        self.interface = interface
        self.producer = KafkaProducer(
            bootstrap_servers=KAFKA_BROKER,
            value_serializer=lambda v: json.dumps(v).encode(),
            compression_type="gzip",
            batch_size=65536,
            linger_ms=10,
        )
        # Flow-level IAT tracking
        self.last_seen: dict = {}

    def open_socket(self) -> socket.socket:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                          socket.htons(self.ETH_P_IP))
        s.bind((self.interface, 0))
        s.setblocking(False)
        return s

    def parse_packet(self, raw: bytes, ts: float) -> dict | None:
        """Parse raw Ethernet frame → packet metadata dict."""
        if len(raw) < 34:
            return None

        # Ethernet header (14 bytes)
        eth_type = struct.unpack("!H", raw[12:14])[0]
        if eth_type != self.ETH_P_IP:
            return None

        # IP header (variable length)
        ip_start = 14
        if len(raw) < ip_start + 20:
            return None

        ip_hdr = raw[ip_start:ip_start + 20]
        ihl = (ip_hdr[0] & 0x0F) * 4
        proto = ip_hdr[9]
        src_ip = ip_from_bytes(ip_hdr[12:16])
        dst_ip = ip_from_bytes(ip_hdr[16:20])
        total_len = struct.unpack("!H", ip_hdr[2:4])[0]

        pkt = {
            "ts": ts,
            "src": src_ip,
            "dst": dst_ip,
            "len": total_len,
            "proto": proto,
            "flags": 0,
            "sport": 0,
            "dport": 0,
            "iat_ns": 0,
        }

        transport_start = ip_start + ihl

        if proto == self.PROTO_TCP and len(raw) >= transport_start + 20:
            tcp = raw[transport_start:transport_start + 20]
            pkt["sport"] = struct.unpack("!H", tcp[0:2])[0]
            pkt["dport"] = struct.unpack("!H", tcp[2:4])[0]
            pkt["flags"] = tcp[13]

        elif proto == self.PROTO_UDP and len(raw) >= transport_start + 8:
            udp = raw[transport_start:transport_start + 8]
            pkt["sport"] = struct.unpack("!H", udp[0:2])[0]
            pkt["dport"] = struct.unpack("!H", udp[2:4])[0]

        # Compute IAT
        flow_key = f"{src_ip}:{pkt['sport']}-{dst_ip}:{pkt['dport']}"
        last = self.last_seen.get(flow_key)
        if last:
            pkt["iat_ns"] = int((ts - last) * 1e9)
        self.last_seen[flow_key] = ts

        return pkt

    def run(self):
        s = self.open_socket()
        print(f"[AF_PACKET] Capturing on {self.interface}...")
        buf = bytearray(65536)

        try:
            while True:
                try:
                    n = s.recv_into(buf)
                    ts = time.time()
                    pkt = self.parse_packet(bytes(buf[:n]), ts)
                    if pkt:
                        self.producer.send("raw_packets", pkt)
                except BlockingIOError:
                    time.sleep(0.0001)
        except KeyboardInterrupt:
            print("[AF_PACKET] Stopping...")
        finally:
            s.close()
            self.producer.flush()
            self.producer.close()


if __name__ == "__main__":
    AFPacketCapture().run()
