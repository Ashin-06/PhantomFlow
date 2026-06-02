import logging
import json
import socket
import uuid
from scapy.all import sniff, IP, IPv6, TCP, UDP
from kafka import KafkaProducer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("PhantomFlow-Windows-Capture")

class FallbackCapture:
    def __init__(self, bootstrap_servers='localhost:9092'):
        self.producer = KafkaProducer(
            bootstrap_servers=bootstrap_servers,
            value_serializer=lambda v: json.dumps(v).encode('utf-8')
        )
        logger.info("Initialized Kafka producer for Windows fallback capture.")

    def process_packet(self, packet):
        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                proto = packet[IP].proto
                payload_len = len(packet[IP].payload)
            elif IPv6 in packet:
                src_ip = packet[IPv6].src
                dst_ip = packet[IPv6].dst
                proto = packet[IPv6].nh
                payload_len = len(packet[IPv6].payload)
            else:
                return

            # Ignore loopback interfaces to prevent feedback loops
            if src_ip in ("127.0.0.1", "::1") or dst_ip in ("127.0.0.1", "::1"):
                return

            src_port, dst_port = 0, 0
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport

            # Ignore internal management/pipeline ports (Kafka, Redis, Postgres, API, Health checks)
            ignored_ports = {9092, 6379, 5432, 5433, 8000, 8080}
            if src_port in ignored_ports or dst_port in ignored_ports:
                return

            flow_id = str(uuid.uuid4())
            metadata = {
                "uid": flow_id,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "proto": proto,
                "bytes_out": payload_len,
                "timestamp": float(packet.time)
            }
            
            self.producer.send('network-flows', value=metadata)
                
        except Exception as e:
            logger.error(f"Error processing packet: {e}")

    def start(self, interface=None):
        logger.info(f"Starting native Windows packet capture on {interface or 'all interfaces'}...")
        sniff(iface=interface, prn=self.process_packet, store=False)

if __name__ == "__main__":
    capture = FallbackCapture()
    capture.start()
