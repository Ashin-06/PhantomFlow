import logging
import json
import socket
import uuid
import struct
import hashlib
import time
from scapy.all import sniff, IP, IPv6, TCP, UDP
from kafka import KafkaProducer
import dpkt
from cryptography import x509
from cryptography.x509.oid import ExtensionOID

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("PhantomFlow-Windows-Capture")

class FallbackCapture:
    def __init__(self, bootstrap_servers='localhost:9092'):
        self.producer = KafkaProducer(
            bootstrap_servers=bootstrap_servers,
            value_serializer=lambda v: json.dumps(v).encode('utf-8')
        )
        logger.info("Initialized Kafka producer for Windows fallback capture.")
        
        # TLS Handshake Reassembly Buffers
        self.handshake_buffers = {}       # (src_ip, src_port, dst_ip, dst_port) -> bytearray
        self.handshake_timestamps = {}     # (src_ip, src_port, dst_ip, dst_port) -> float
        self.session_states = {}           # (src_ip, src_port, dst_ip, dst_port) -> dict
        self.state_timestamps = {}         # (src_ip, src_port, dst_ip, dst_port) -> float
        self.packet_count = 0

    def _shannon_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        import math
        from collections import Counter
        entropy = 0.0
        length = len(data)
        counts = Counter(data)
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 4)

    def _compute_ja3_ja4_from_ch(self, ch) -> tuple:
        try:
            version = ch.version
            ciphers = [c.code for c in ch.ciphersuites]
            ciphers = [c for c in ciphers if (c & 0x0F0F) != 0x0A0A] # Filter GREASE
            ciphers_str = "-".join(str(c) for c in ciphers)
            
            extensions_raw = ch.extensions
            ext_types = [t for t, d in extensions_raw]
            ext_types = [t for t in ext_types if (t & 0x0F0F) != 0x0A0A] # Filter GREASE
            ext_str = "-".join(str(t) for t in ext_types)
            
            curves_str = ""
            point_formats_str = ""
            sni = ""
            
            for ext_type, ext_data in extensions_raw:
                if ext_type == 0: # SNI
                    try:
                        list_len = struct.unpack("!H", ext_data[:2])[0]
                        name_type = ext_data[2]
                        name_len = struct.unpack("!H", ext_data[3:5])[0]
                        sni = ext_data[5:5+name_len].decode()
                    except Exception:
                        pass
                elif ext_type == 10: # Supported Groups
                    try:
                        length = struct.unpack("!H", ext_data[:2])[0]
                        curves = []
                        for i in range(2, length + 2, 2):
                            curve_id = struct.unpack("!H", ext_data[i:i+2])[0]
                            if (curve_id & 0x0F0F) != 0x0A0A:
                                curves.append(curve_id)
                        curves_str = "-".join(str(c) for c in curves)
                    except Exception:
                        pass
                elif ext_type == 11: # EC Point Formats
                    try:
                        length = ext_data[0]
                        formats = [ext_data[i] for i in range(1, length + 1)]
                        point_formats_str = "-".join(str(f) for f in formats)
                    except Exception:
                        pass
                        
            ja3_string = f"{version},{ciphers_str},{ext_str},{curves_str},{point_formats_str}"
            ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()
            
            # JA4 Part A
            version_str = "12" if version == 771 else "13" if version == 772 else "10"
            sni_flag = "d" if sni else "i"
            num_ciphers = f"{min(len(ciphers), 99):02d}"
            num_exts = f"{min(len(ext_types), 99):02d}"
            part_a = f"t{version_str}{sni_flag}{num_ciphers}{num_exts}"
            
            # JA4 Part B
            sorted_ciphers = ",".join(f"{c:04x}" for c in sorted(ciphers))
            part_b = hashlib.sha256(sorted_ciphers.encode()).hexdigest()[:12]
            
            # JA4 Part C
            sorted_exts = ",".join(str(t) for t in sorted(ext_types))
            part_c = hashlib.sha256(sorted_exts.encode()).hexdigest()[:12]
            
            ja4_hash = f"{part_a}_{part_b}_{part_c}"
            
            return ja3_hash, ja4_hash, sni
        except Exception as e:
            logger.warning(f"Error computing JA3/JA4: {e}")
            return "", "", ""

    def _parse_cert_chain(self, certificates) -> dict:
        if not certificates:
            return {}
        try:
            cert_der = certificates[0]
            cert = x509.load_der_x509_certificate(cert_der)
            
            subject = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()
            
            try:
                not_before = cert.not_valid_before_utc
                not_after = cert.not_valid_after_utc
            except AttributeError:
                not_before = cert.not_valid_before
                not_after = cert.not_valid_after
                
            validity_days = float((not_after - not_before).days)
            self_signed = cert.issuer == cert.subject
            
            return {
                "cert_self_signed": self_signed,
                "cert_validity_days": validity_days,
                "cert_subject": subject,
                "cert_issuer": issuer
            }
        except Exception as e:
            logger.warning(f"Error parsing certificate chain: {e}")
            return {}

    def _cleanup_expired_sessions(self):
        now = time.time()
        expired_buffers = [k for k, t in self.handshake_timestamps.items() if now - t > 10.0]
        for k in expired_buffers:
            self.handshake_buffers.pop(k, None)
            self.handshake_timestamps.pop(k, None)
            
        expired_states = [k for k, t in self.state_timestamps.items() if now - t > 60.0]
        for k in expired_states:
            self.session_states.pop(k, None)
            self.state_timestamps.pop(k, None)

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

            # Ignore loopback interfaces
            if src_ip in ("127.0.0.1", "::1") or dst_ip in ("127.0.0.1", "::1"):
                return

            src_port, dst_port = 0, 0
            payload_bytes = b""
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                payload_bytes = bytes(packet[TCP].payload)
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                payload_bytes = bytes(packet[UDP].payload)

            # Ignore internal management/pipeline ports
            ignored_ports = {9092, 6379, 5432, 5433, 8000, 8080}
            if src_port in ignored_ports or dst_port in ignored_ports:
                return

            session_key = (src_ip, src_port, dst_ip, dst_port)
            entropy = 0.0

            # 1. Shannon Payload Entropy calculation
            if payload_bytes and TCP in packet:
                entropy = self._shannon_entropy(payload_bytes)

            # 2. TLS Handshake Reassembly and Parsing
            if TCP in packet and payload_bytes:
                # If handshake record starts
                is_handshake_start = len(payload_bytes) >= 3 and payload_bytes[0] == 0x16 and payload_bytes[1] == 0x03 and (0x01 <= payload_bytes[2] <= 0x03)
                
                if is_handshake_start or session_key in self.handshake_buffers:
                    if session_key not in self.handshake_buffers:
                        self.handshake_buffers[session_key] = bytearray(payload_bytes)
                        self.handshake_timestamps[session_key] = time.time()
                    else:
                        self.handshake_buffers[session_key].extend(payload_bytes)
                    
                    # Try parsing records from buffer
                    buf = self.handshake_buffers[session_key]
                    pointer = 0
                    try:
                        while pointer + 5 <= len(buf):
                            rec_type, version, rec_len = struct.unpack("!BHH", buf[pointer:pointer+5])
                            if pointer + 5 + rec_len > len(buf):
                                break
                            
                            record_bytes = bytes(buf[pointer : pointer + 5 + rec_len])
                            pointer += 5 + rec_len
                            
                            try:
                                record = dpkt.ssl.TLSRecord(record_bytes)
                                if record.type == 22: # Handshake
                                    handshake = dpkt.ssl.TLSHandshake(record.data)
                                    
                                    if isinstance(handshake.data, dpkt.ssl.TLSClientHello):
                                        ja3_hash, ja4_hash, sni = self._compute_ja3_ja4_from_ch(handshake.data)
                                        self.session_states[session_key] = {
                                            "ja3": ja3_hash,
                                            "ja4": ja4_hash,
                                            "sni": sni
                                        }
                                        self.state_timestamps[session_key] = time.time()
                                    elif isinstance(handshake.data, dpkt.ssl.TLSCertificate):
                                        cert_info = self._parse_cert_chain(handshake.data.certificates)
                                        if session_key not in self.session_states:
                                            self.session_states[session_key] = {}
                                        self.session_states[session_key].update(cert_info)
                                        self.state_timestamps[session_key] = time.time()
                            except Exception:
                                pass
                        
                        # Discard parsed data
                        if pointer > 0:
                            self.handshake_buffers[session_key] = buf[pointer:]
                    except Exception:
                        self.handshake_buffers.pop(session_key, None)
                        self.handshake_timestamps.pop(session_key, None)

            # Cleanup expired buffers
            self.packet_count += 1
            if self.packet_count % 100 == 0:
                self._cleanup_expired_sessions()

            flow_id = str(uuid.uuid4())
            metadata = {
                "uid": flow_id,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "proto": proto,
                "bytes_out": payload_len,
                "timestamp": float(packet.time),
                "payload_entropy": entropy
            }

            # Check for TLS session state in either direction
            state = self.session_states.get(session_key) or self.session_states.get((dst_ip, dst_port, src_ip, src_port))
            if state:
                metadata.update(state)

            self.producer.send('network-flows', value=metadata)
                
        except Exception as e:
            logger.error(f"Error processing packet: {e}")

    def start(self, interface=None):
        logger.info(f"Starting native Windows packet capture on {interface or 'all interfaces'}...")
        sniff(iface=interface, prn=self.process_packet, store=False)

if __name__ == "__main__":
    capture = FallbackCapture()
    capture.start()
