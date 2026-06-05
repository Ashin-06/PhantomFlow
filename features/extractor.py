# features/extractor.py
"""
Transforms raw Zeek logs + packet events into ML feature vectors.
Runs as a Kafka consumer, outputs feature records to Redis + Kafka.
"""

import json
import math
import time
import hashlib
import statistics
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
import numpy as np
import redis
from kafka import KafkaConsumer, KafkaProducer


@dataclass
class FlowFeatures:
    """Complete feature vector for a network flow."""
    # Identity
    flow_id: str = ""
    src: str = ""
    dst: str = ""
    dport: int = 0
    proto: str = ""
    timestamp: float = 0.0

    # --- TIMING FEATURES ---
    duration_s: float = 0.0
    iat_mean_ms: float = 0.0          # Mean inter-arrival time
    iat_std_ms: float = 0.0           # Jitter (std of IAT)
    iat_cv: float = 0.0               # Coefficient of variation (std/mean)
    iat_min_ms: float = 0.0
    iat_max_ms: float = 0.0
    iat_median_ms: float = 0.0
    iat_skewness: float = 0.0
    iat_kurtosis: float = 0.0
    # Periodicity score: autocorrelation at dominant lag
    periodicity_score: float = 0.0
    dominant_period_ms: float = 0.0   # Most likely beacon interval

    # --- PACKET SIZE FEATURES ---
    pkt_size_mean: float = 0.0
    pkt_size_std: float = 0.0
    pkt_size_min: float = 0.0
    pkt_size_max: float = 0.0
    pkt_size_median: float = 0.0
    pkt_size_entropy: float = 0.0     # Size distribution entropy
    small_pkt_ratio: float = 0.0      # Fraction < 100 bytes (C2 heartbeat)
    large_pkt_ratio: float = 0.0      # Fraction > 1400 bytes (exfil)

    # --- BYTE VOLUME FEATURES ---
    total_bytes: int = 0
    orig_bytes: int = 0               # Upload (client → server)
    resp_bytes: int = 0               # Download (server → client)
    bytes_ratio: float = 0.0          # orig/resp (high = exfil indicator)
    bytes_per_sec: float = 0.0
    pkts_per_sec: float = 0.0
    orig_pkts: int = 0
    resp_pkts: int = 0
    pkt_ratio: float = 0.0            # orig_pkts/resp_pkts

    # --- TLS FEATURES ---
    ja3_hash: str = ""
    ja3s_hash: str = ""
    ja4_hash: str = ""                # JA4+ (2023)
    tls_version: str = ""
    cipher_suite: str = ""
    sni: str = ""
    cert_validity_days: float = 0.0
    cert_self_signed: bool = False
    tls_resumed: bool = False
    sni_entropy: float = 0.0          # Entropy of SNI domain
    sni_len: int = 0
    # JA3 known-malware match
    ja3_malware_score: float = 0.0
    ja4_malware_score: float = 0.0

    # --- DNS FEATURES ---
    dns_query: str = ""
    dns_query_len: int = 0
    dns_label_count: int = 0
    dns_max_label_len: int = 0
    dns_unique_chars: int = 0
    dns_shannon_entropy: float = 0.0  # Key tunneling signal
    dns_bigram_entropy: float = 0.0
    dns_vowel_ratio: float = 0.0      # Low = encoded/base64
    dns_digit_ratio: float = 0.0      # High = DGA / encoded
    dns_hyphen_ratio: float = 0.0
    dns_is_ip_encoded: bool = False   # Hex IP pattern
    dns_consecutive_digits: int = 0
    dns_longest_run: int = 0          # Longest run of same char type

    # --- FLOW BEHAVIORAL ---
    tcp_flag_distribution: str = ""   # Encoded as hex string
    connection_count_1m: int = 0      # Same src-dst pairs in last 1 min
    connection_count_5m: int = 0
    unique_dst_ports_1m: int = 0      # Port scan indicator
    failed_connection_ratio: float = 0.0
    payload_entropy: float = 0.0

    # --- LABEL (for training) ---
    label: int = -1                   # -1=unlabeled, 0=benign, 1=C2, 2=DNS_tunnel, 3=exfil
    confidence: float = 0.0


class FeatureExtractor:
    """Extracts ML features from flow records and packet sequences."""

    # JA3 fingerprint databases (loaded from threat intel feeds)
    JA3_MALWARE_DB: Dict[str, float] = {}
    JA4_MALWARE_DB: Dict[str, float] = {}

    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
        self._load_fingerprint_dbs()

    def _load_fingerprint_dbs(self):
        """Load JA3/JA4 malware fingerprint databases."""
        import os
        db_path = os.path.join(os.path.dirname(__file__), "data", "ja3_malware.json")
        if os.path.exists(db_path):
            with open(db_path) as f:
                self.JA3_MALWARE_DB = json.load(f)
        
        # Built-in known C2 JA3 hashes
        # Source: https://github.com/salesforce/ja3
        known_c2_ja3 = {
            "e7d705a3286e19ea42f587b344ee6865": 1.0,  # Cobalt Strike default
            "6d37c8e9aa2ef8649e7f6d5e9b94f4f1": 1.0,  # Sliver
            "a0e9f5d64349fb13191bc781f81f42e1": 0.9,  # Metasploit
            "72a589da586844d7f0818ce684948eea": 0.8,  # Empire
            "b386946a5a44d1ddcc843bc75336dfce": 0.7,  # Generic RAT
        }
        self.JA3_MALWARE_DB.update(known_c2_ja3)

    def extract_timing_features(self, iats_ms: List[float]) -> Dict:
        """Extract comprehensive timing/IAT features."""
        if len(iats_ms) < 2:
            return {}
        
        iats = np.array(iats_ms)
        features = {
            "iat_mean_ms": float(np.mean(iats)),
            "iat_std_ms": float(np.std(iats)),
            "iat_min_ms": float(np.min(iats)),
            "iat_max_ms": float(np.max(iats)),
            "iat_median_ms": float(np.median(iats)),
        }
        
        mean = features["iat_mean_ms"]
        std = features["iat_std_ms"]
        features["iat_cv"] = std / mean if mean > 0 else 0.0
        
        # Skewness and kurtosis
        if len(iats) >= 4:
            from scipy import stats
            features["iat_skewness"] = float(stats.skew(iats))
            features["iat_kurtosis"] = float(stats.kurtosis(iats))
        
        # Periodicity via autocorrelation
        if len(iats) >= 10:
            features["periodicity_score"], features["dominant_period_ms"] = \
                self._compute_periodicity(iats)
        
        return features

    def _compute_periodicity(self, iats: np.ndarray) -> Tuple[float, float]:
        """
        Compute periodicity score using autocorrelation.
        C2 beacons show strong autocorrelation at their beacon interval.
        Returns (score, dominant_period_ms).
        """
        # Normalize
        normed = (iats - np.mean(iats)) / (np.std(iats) + 1e-9)
        
        # Full autocorrelation
        acf = np.correlate(normed, normed, mode='full')
        acf = acf[len(acf)//2:]  # Take positive lags only
        acf /= acf[0]            # Normalize to [−1, 1]
        
        # Find dominant peak (skip lag=0)
        peak_lags = np.argsort(acf[1:])[::-1][:5] + 1
        
        if len(peak_lags) == 0:
            return 0.0, 0.0
        
        dominant_lag = peak_lags[0]
        score = float(acf[dominant_lag])
        
        # Dominant period = mean IAT * dominant_lag
        period_ms = float(np.mean(iats) * dominant_lag)
        
        return max(0.0, score), period_ms

    def extract_size_features(self, pkt_sizes: List[int]) -> Dict:
        """Extract packet size distribution features."""
        if not pkt_sizes:
            return {}
        
        sizes = np.array(pkt_sizes, dtype=float)
        features = {
            "pkt_size_mean": float(np.mean(sizes)),
            "pkt_size_std": float(np.std(sizes)),
            "pkt_size_min": float(np.min(sizes)),
            "pkt_size_max": float(np.max(sizes)),
            "pkt_size_median": float(np.median(sizes)),
            "small_pkt_ratio": float(np.mean(sizes < 100)),
            "large_pkt_ratio": float(np.mean(sizes > 1400)),
        }
        
        # Size distribution entropy (bin into 16 buckets)
        hist, _ = np.histogram(sizes, bins=16, range=(0, 1500))
        hist = hist / (hist.sum() + 1e-9)
        entropy = -np.sum(hist * np.log2(hist + 1e-9))
        features["pkt_size_entropy"] = float(entropy)
        
        return features

    def extract_dns_features(self, query: str) -> Dict:
        """
        Extract DNS tunneling detection features from a query string.
        Key insight: base64/hex-encoded data has high entropy and
        unusual character distributions compared to normal domains.
        """
        if not query:
            return {}
        
        query_lower = query.lower().rstrip(".")
        labels = query_lower.split(".")
        
        # Remove TLD and second-level domain — focus on subdomains
        subdomain = ".".join(labels[:-2]) if len(labels) > 2 else labels[0]
        
        features = {
            "dns_query_len": len(query),
            "dns_label_count": len(labels),
            "dns_max_label_len": max(len(l) for l in labels),
            "dns_unique_chars": len(set(subdomain)),
        }
        
        # Shannon entropy of subdomain
        features["dns_shannon_entropy"] = self._string_entropy(subdomain)
        
        # Bigram entropy
        features["dns_bigram_entropy"] = self._bigram_entropy(subdomain)
        
        # Character class ratios
        if subdomain:
            features["dns_vowel_ratio"] = sum(c in "aeiou" for c in subdomain) / len(subdomain)
            features["dns_digit_ratio"] = sum(c.isdigit() for c in subdomain) / len(subdomain)
            features["dns_hyphen_ratio"] = subdomain.count("-") / len(subdomain)
        
        # Hex IP encoding pattern (e.g., c0a80001.evil.com)
        import re
        features["dns_is_ip_encoded"] = bool(re.match(r'^[0-9a-f]{8}', subdomain))
        
        # Consecutive digits
        digit_runs = re.findall(r'\d+', subdomain)
        features["dns_consecutive_digits"] = max((len(r) for r in digit_runs), default=0)
        
        # Longest single-char-type run
        max_run = 0
        curr_run = 1
        for i in range(1, len(subdomain)):
            same_type = (subdomain[i].isalpha() == subdomain[i-1].isalpha() and
                         subdomain[i].isdigit() == subdomain[i-1].isdigit())
            if same_type:
                curr_run += 1
                max_run = max(max_run, curr_run)
            else:
                curr_run = 1
        features["dns_longest_run"] = max_run
        
        return features

    def _string_entropy(self, s: str) -> float:
        """Shannon entropy of a string."""
        if not s:
            return 0.0
        counts = {}
        for c in s:
            counts[c] = counts.get(c, 0) + 1
        n = len(s)
        return -sum((c/n) * math.log2(c/n) for c in counts.values())

    def _bigram_entropy(self, s: str) -> float:
        """Bigram (2-gram) entropy of a string."""
        if len(s) < 2:
            return 0.0
        bigrams = [s[i:i+2] for i in range(len(s)-1)]
        counts = {}
        for bg in bigrams:
            counts[bg] = counts.get(bg, 0) + 1
        n = len(bigrams)
        return -sum((c/n) * math.log2(c/n) for c in counts.values())

    def compute_ja4(self, tls_client_hello: Dict) -> str:
        """
        Compute JA4+ fingerprint from TLS ClientHello fields.
        Format: t{tls_ver}{sni_flag}{num_ciphers}{num_exts}_{cipher_hash}_{exts_hash}
        Reference: https://github.com/FoxIO-LLC/ja4
        """
        version_map = {"TLSv1": "10", "TLSv1.1": "11", "TLSv1.2": "12", "TLSv1.3": "13"}
        tls_ver = version_map.get(tls_client_hello.get("version", ""), "00")
        
        sni = tls_client_hello.get("server_name", "")
        sni_flag = "d" if sni else "i"
        
        ciphers = sorted(tls_client_hello.get("ciphers", []))
        extensions = sorted(tls_client_hello.get("extensions", []))
        
        num_ciphers = f"{len(ciphers):02d}"
        num_exts = f"{len(extensions):02d}"
        
        cipher_str = ",".join(str(c) for c in ciphers)
        exts_str = ",".join(str(e) for e in extensions)
        
        cipher_hash = hashlib.sha256(cipher_str.encode()).hexdigest()[:12]
        exts_hash = hashlib.sha256(exts_str.encode()).hexdigest()[:12]
        
        return f"t{tls_ver}{sni_flag}{num_ciphers}{num_exts}_{cipher_hash}_{exts_hash}"

    def get_ja_malware_score(self, ja3_hash: str, ja4_hash: str = "") -> Tuple[float, float]:
        """Lookup JA3/JA4 against known-malware fingerprint databases."""
        ja3_score = self.JA3_MALWARE_DB.get(ja3_hash, 0.0)
        ja4_score = self.JA4_MALWARE_DB.get(ja4_hash, 0.0)
        return ja3_score, ja4_score

    def build_feature_vector(self, flow_record: Dict,
                              packet_iats: List[float],
                              packet_sizes: List[int]) -> FlowFeatures:
        """Build complete FlowFeatures from raw flow + packet data."""
        
        f = FlowFeatures()
        f.flow_id = flow_record.get("uid", "")
        f.src = flow_record.get("src", flow_record.get("src_ip", ""))
        f.dst = flow_record.get("dst", flow_record.get("dst_ip", ""))
        f.dport = flow_record.get("dport", flow_record.get("dst_port", 0))
        f.proto = flow_record.get("proto", "")
        f.timestamp = flow_record.get("ts", time.time())
        
        # Byte features
        f.orig_bytes = flow_record.get("orig_bytes", 0)
        f.resp_bytes = flow_record.get("resp_bytes", 0)
        f.total_bytes = f.orig_bytes + f.resp_bytes
        f.bytes_ratio = f.orig_bytes / (f.resp_bytes + 1)
        f.bytes_per_sec = flow_record.get("bytes_per_sec", 0.0)
        f.pkts_per_sec = flow_record.get("pkts_per_sec", 0.0)
        f.orig_pkts = flow_record.get("orig_pkts", 0)
        f.resp_pkts = flow_record.get("resp_pkts", 0)
        f.pkt_ratio = f.orig_pkts / (f.resp_pkts + 1)
        f.duration_s = flow_record.get("duration_s", 0.0)
        
        # Timing features
        timing = self.extract_timing_features(packet_iats)
        for k, v in timing.items():
            if hasattr(f, k):
                setattr(f, k, v)
        
        # Size features
        size = self.extract_size_features(packet_sizes)
        for k, v in size.items():
            if hasattr(f, k):
                setattr(f, k, v)
        
        f.ja3_hash = flow_record.get("ja3", "")
        f.ja3s_hash = flow_record.get("ja3s", "")
        f.tls_version = flow_record.get("tls_version", "")
        f.cipher_suite = flow_record.get("cipher", "")
        f.sni = flow_record.get("server_name", flow_record.get("sni", ""))
        f.tls_resumed = flow_record.get("resumed", False)
        f.sni_len = len(f.sni)
        f.sni_entropy = self._string_entropy(f.sni.split(".")[0] if f.sni else "")
        
        # Ingest new capture features
        f.cert_validity_days = float(flow_record.get("cert_validity_days", 0.0) or 0.0)
        f.cert_self_signed = bool(flow_record.get("cert_self_signed", False))
        f.ja4_hash = flow_record.get("ja4_hash", "")
        f.payload_entropy = float(flow_record.get("payload_entropy", 0.0) or 0.0)
        
        # JA3/JA4 malware scores
        f.ja3_malware_score, f.ja4_malware_score = self.get_ja_malware_score(
            f.ja3_hash, f.ja4_hash
        )
        
        # DNS features (if applicable)
        if flow_record.get("dns_query"):
            f.dns_query = flow_record["dns_query"]
            dns_feat = self.extract_dns_features(flow_record["dns_query"])
            for k, v in dns_feat.items():
                if hasattr(f, k):
                    setattr(f, k, v)
        
        # Context features from Redis
        if self.redis is not None:
            f.connection_count_1m = int(self.redis.get(f"conn_count:1m:{f.src}:{f.dst}") or 0)
            f.connection_count_5m = int(self.redis.get(f"conn_count:5m:{f.src}:{f.dst}") or 0)
        else:
            f.connection_count_1m = 0
            f.connection_count_5m = 0
        
        return f

    def to_numpy(self, f: FlowFeatures) -> np.ndarray:
        """Convert FlowFeatures to numpy array for ML input."""
        NUMERIC_FIELDS = [
            "duration_s", "iat_mean_ms", "iat_std_ms", "iat_cv",
            "iat_min_ms", "iat_max_ms", "iat_median_ms", "iat_skewness",
            "iat_kurtosis", "periodicity_score", "dominant_period_ms",
            "pkt_size_mean", "pkt_size_std", "pkt_size_min", "pkt_size_max",
            "pkt_size_median", "pkt_size_entropy", "small_pkt_ratio", "large_pkt_ratio",
            "total_bytes", "orig_bytes", "resp_bytes", "bytes_ratio",
            "bytes_per_sec", "pkts_per_sec", "orig_pkts", "resp_pkts", "pkt_ratio",
            "sni_entropy", "sni_len", "tls_resumed",
            "ja3_malware_score", "ja4_malware_score",
            "cert_validity_days", "cert_self_signed",
            "dns_query_len", "dns_label_count", "dns_max_label_len",
            "dns_unique_chars", "dns_shannon_entropy", "dns_bigram_entropy",
            "dns_vowel_ratio", "dns_digit_ratio", "dns_hyphen_ratio",
            "dns_is_ip_encoded", "dns_consecutive_digits", "dns_longest_run",
            "connection_count_1m", "connection_count_5m",
            "failed_connection_ratio",
        ]
        return np.array([float(getattr(f, field, 0.0)) for field in NUMERIC_FIELDS],
                        dtype=np.float32)

    FEATURE_NAMES = [
        "duration_s", "iat_mean_ms", "iat_std_ms", "iat_cv",
        "iat_min_ms", "iat_max_ms", "iat_median_ms", "iat_skewness",
        "iat_kurtosis", "periodicity_score", "dominant_period_ms",
        "pkt_size_mean", "pkt_size_std", "pkt_size_min", "pkt_size_max",
        "pkt_size_median", "pkt_size_entropy", "small_pkt_ratio", "large_pkt_ratio",
        "total_bytes", "orig_bytes", "resp_bytes", "bytes_ratio",
        "bytes_per_sec", "pkts_per_sec", "orig_pkts", "resp_pkts", "pkt_ratio",
        "sni_entropy", "sni_len", "tls_resumed",
        "ja3_malware_score", "ja4_malware_score",
        "cert_validity_days", "cert_self_signed",
        "dns_query_len", "dns_label_count", "dns_max_label_len",
        "dns_unique_chars", "dns_shannon_entropy", "dns_bigram_entropy",
        "dns_vowel_ratio", "dns_digit_ratio", "dns_hyphen_ratio",
        "dns_is_ip_encoded", "dns_consecutive_digits", "dns_longest_run",
        "connection_count_1m", "connection_count_5m",
        "failed_connection_ratio",
    ]
