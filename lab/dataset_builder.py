# lab/dataset_builder.py
"""
Converts raw PCAP files from the lab into a labeled ML-ready feature CSV.
Uses Scapy for PCAP parsing and the feature extractor for vectorization.
"""

import os
import json
import time
import redis
import numpy as np
import pandas as pd
from typing import Dict, List, Optional
from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR
from collections import defaultdict

from features.extractor import FeatureExtractor, FlowFeatures
from features.tls_features import TLSFingerprinter
from features.dns_features import DNSAnalyzer
from features.timing_features import BeaconTimingAnalyzer


class PCAPToDataset:
    """
    Processes PCAPs into labeled flow feature rows.
    
    PCAP → flows → feature vectors → labeled CSV
    """

    # Port-based protocol hints
    TLS_PORTS = {443, 8443, 4443, 993, 995, 465}
    DNS_PORT = 53

    def __init__(self):
        # Use mock Redis (no actual server needed for offline processing)
        self.redis = self._mock_redis()
        self.extractor = FeatureExtractor(self.redis)
        self.dns_analyzer = DNSAnalyzer()
        self.timing_analyzer = BeaconTimingAnalyzer()
        self.ja_fp = TLSFingerprinter()

    def _mock_redis(self):
        """In-memory mock Redis for offline PCAP processing."""
        class MockRedis:
            def __init__(self):
                self._data = {}
            def get(self, k):
                return self._data.get(k)
            def set(self, k, v, ex=None):
                self._data[k] = v
            def setex(self, k, ttl, v):
                self._data[k] = v
            def incr(self, k):
                self._data[k] = str(int(self._data.get(k, 0)) + 1)
            def expire(self, k, ttl):
                pass
        return MockRedis()

    def process_pcap(self, pcap_path: str, label: int) -> List[Dict]:
        """
        Process one PCAP file and return list of feature row dicts.
        label: 0=benign, 1=c2_beacon, 2=dns_tunnel, 3=exfil
        """
        print(f"  Reading {os.path.basename(pcap_path)}...")
        try:
            pkts = rdpcap(pcap_path)
        except Exception as e:
            print(f"  ERROR reading PCAP: {e}")
            return []

        # Group packets by 5-tuple flow
        flows: Dict[str, List] = defaultdict(list)
        for pkt in pkts:
            if not pkt.haslayer(IP):
                continue
            ip = pkt[IP]
            proto, sport, dport = "other", 0, 0

            if pkt.haslayer(TCP):
                proto = "tcp"
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
            elif pkt.haslayer(UDP):
                proto = "udp"
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport

            # Bidirectional flow key (canonical ordering)
            src, dst = ip.src, ip.dst
            if (src, sport) > (dst, dport):
                src, dst = dst, src
                sport, dport = dport, sport

            fkey = f"{src}:{sport}-{dst}:{dport}/{proto}"
            flows[fkey].append(pkt)

        print(f"  Found {len(flows)} flows")
        rows = []

        for fkey, pkt_list in flows.items():
            if len(pkt_list) < 3:
                continue

            row = self._extract_flow_features(fkey, pkt_list, label)
            if row:
                rows.append(row)

        return rows

    def _extract_flow_features(self, fkey: str,
                                 pkts: List, label: int) -> Optional[Dict]:
        """Extract all features for one flow."""
        parts = fkey.split("/")
        proto = parts[1] if len(parts) > 1 else "tcp"
        endpoints = parts[0].split("-")
        if len(endpoints) < 2:
            return None

        src_ep = endpoints[0].rsplit(":", 1)
        dst_ep = endpoints[1].rsplit(":", 1)
        src = src_ep[0] if src_ep else ""
        dst = dst_ep[0] if len(dst_ep) > 0 else ""
        dport = int(dst_ep[1]) if len(dst_ep) > 1 else 0

        # Timestamps and IATs
        timestamps = [float(p.time) for p in pkts]
        timestamps.sort()
        iats_ms = [(timestamps[i+1] - timestamps[i]) * 1000
                   for i in range(len(timestamps)-1)]

        # Packet sizes and directions
        pkt_sizes = []
        orig_bytes = resp_bytes = 0
        orig_pkts = resp_pkts = 0

        for p in pkts:
            if not p.haslayer(IP):
                continue
            size = len(p[IP])
            pkt_sizes.append(size)
            if p[IP].src == src:
                orig_bytes += size
                orig_pkts += 1
            else:
                resp_bytes += size
                resp_pkts += 1

        duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0

        # DNS features
        dns_query = ""
        for p in pkts:
            if p.haslayer(DNSQR):
                dns_query = p[DNSQR].qname.decode(errors='ignore').rstrip(".")
                break

        # Build flow record dict
        flow_record = {
            "uid": fkey,
            "src": src,
            "dst": dst,
            "dport": dport,
            "proto": proto,
            "ts": timestamps[0],
            "orig_bytes": orig_bytes,
            "resp_bytes": resp_bytes,
            "orig_pkts": orig_pkts,
            "resp_pkts": resp_pkts,
            "duration_s": duration,
            "bytes_per_sec": (orig_bytes + resp_bytes) / (duration + 1e-9),
            "pkts_per_sec": len(pkts) / (duration + 1e-9),
            "dns_query": dns_query,
        }

        # Get feature object
        features: FlowFeatures = self.extractor.build_feature_vector(
            flow_record, iats_ms, pkt_sizes
        )
        features.label = label

        # Also run timing analyzer
        timing = self.timing_analyzer.analyze(timestamps)
        features.periodicity_score = timing.get("periodicity_score", 0.0)
        features.dominant_period_ms = timing.get("dominant_period_ms", 0.0)
        features.iat_cv = timing.get("iat_cv", 0.0)

        # DNS features
        if dns_query:
            dns_feat = self.dns_analyzer.analyze(dns_query, src)
            for k, v in dns_feat.items():
                if hasattr(features, k):
                    setattr(features, k, v)

        # Convert to dict
        row = features.__dict__.copy()
        row["label"] = label
        row["flow_id"] = fkey

        return row

    def build_from_directory(self, pcap_dir: str,
                               output_csv: str = "lab/dataset.csv"):
        """
        Process all PCAPs in a directory.
        Expects filenames containing label hints: benign_, sliver_, iodine_, exfil_
        """
        LABEL_MAP = {
            "benign": 0, "normal": 0,
            "sliver": 1, "cobalt": 1, "mythic": 1, "beacon": 1, "c2": 1,
            "iodine": 2, "dnscat": 2, "dns_tunnel": 2, "tunnel": 2,
            "exfil": 3, "exfiltration": 3, "upload": 3,
        }

        all_rows = []
        for fname in sorted(os.listdir(pcap_dir)):
            if not fname.endswith(".pcap"):
                continue

            label = -1
            fname_lower = fname.lower()
            for keyword, lbl in LABEL_MAP.items():
                if keyword in fname_lower:
                    label = lbl
                    break

            if label == -1:
                print(f"  SKIP {fname} (no label match)")
                continue

            path = os.path.join(pcap_dir, fname)
            rows = self.process_pcap(path, label)
            all_rows.extend(rows)
            print(f"  {fname}: {len(rows)} flows (label={label})")

        df = pd.DataFrame(all_rows)
        df = df.fillna(0)
        df.to_csv(output_csv, index=False)
        print(f"\n[Dataset] {len(df)} total flows → {output_csv}")
        print(df["label"].value_counts().to_string())
        return df
