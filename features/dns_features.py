# features/dns_features.py
"""
Standalone DNS feature extractor with additional NXDomain and TTL analysis.
Tracks per-domain query patterns for DGA and tunneling detection.
"""

import math
import re
import time
from collections import defaultdict
from typing import Dict, List, Optional, Tuple


# English bigram frequencies (from large corpus) — tunneling deviates significantly
ENGLISH_BIGRAMS = {
    'th': 0.0356,'he': 0.0307,'in': 0.0243,'er': 0.0205,'an': 0.0199,
    'on': 0.0177,'re': 0.0172,'nd': 0.0148,'en': 0.0141,'at': 0.0132,
    'es': 0.0132,'st': 0.0125,'ed': 0.0117,'or': 0.0115,'to': 0.0113,
}


class DNSAnalyzer:
    """
    Advanced DNS analysis for tunneling and DGA detection.
    Tracks per-domain and per-client query histories.
    """

    # Known benign TLDs and second-level domains (whitelist seed)
    BENIGN_SLDS = {
        "google.com","googleapis.com","gstatic.com","github.com",
        "amazonaws.com","cloudfront.net","fastly.net","akamai.net",
        "microsoft.com","windows.com","office.com","azure.com",
        "apple.com","icloud.com","cdn-apple.com",
    }

    # DNS tunneling tool signatures (known subdomain patterns)
    TUNNEL_REGEXES = [
        re.compile(r'^[a-f0-9]{32,}$'),              # Hex-encoded data
        re.compile(r'^[A-Za-z0-9+/]{20,}={0,2}$'),   # Base64-encoded
        re.compile(r'^[a-z0-9]{40,}$'),               # Long alphanumeric
        re.compile(r'^\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}$'),  # IP in subdomain
    ]

    def __init__(self):
        # Per-domain: list of query timestamps
        self.domain_history: Dict[str, List[float]] = defaultdict(list)
        # Per-client: query count per minute
        self.client_qps: Dict[str, List[float]] = defaultdict(list)

    def analyze(self, query: str, src_ip: str,
                qtype: str = "A", rcode: int = 0) -> Dict:
        """
        Full analysis of a single DNS query.
        Returns feature dict for ML pipeline.
        """
        now = time.time()
        query = query.lower().rstrip(".")

        # Update histories
        self.domain_history[query].append(now)
        self.client_qps[src_ip].append(now)

        # Clean old entries (>5 min window)
        cutoff = now - 300
        self.domain_history[query] = [t for t in self.domain_history[query] if t > cutoff]
        self.client_qps[src_ip] = [t for t in self.client_qps[src_ip] if t > cutoff]

        labels = query.split(".")
        # Subdomain = everything except last 2 labels (SLD + TLD)
        subdomain = ".".join(labels[:-2]) if len(labels) > 2 else labels[0]
        sld = ".".join(labels[-2:]) if len(labels) >= 2 else query

        features = {
            # Basic
            "dns_query": query,
            "dns_query_len": len(query),
            "dns_label_count": len(labels),
            "dns_max_label_len": max(len(l) for l in labels),
            "dns_unique_chars": len(set(subdomain)),

            # Entropy
            "dns_shannon_entropy": self._entropy(subdomain),
            "dns_bigram_entropy": self._bigram_entropy(subdomain),
            "dns_bigram_deviation": self._bigram_deviation(subdomain),

            # Character ratios
            "dns_vowel_ratio": self._ratio(subdomain, set("aeiou")),
            "dns_digit_ratio": self._ratio(subdomain, set("0123456789")),
            "dns_hyphen_ratio": subdomain.count("-") / max(1, len(subdomain)),
            "dns_uppercase_ratio": self._ratio(subdomain, set("ABCDEFGHIJKLMNOPQRSTUVWXYZ")),

            # Structural
            "dns_is_ip_encoded": bool(re.match(r'^[0-9a-f]{8}', subdomain)),
            "dns_consecutive_digits": self._max_run(subdomain, str.isdigit),
            "dns_consecutive_alpha": self._max_run(subdomain, str.isalpha),
            "dns_longest_run": self._longest_run(subdomain),
            "dns_num_underscores": subdomain.count("_"),

            # Tunnel pattern matching
            "dns_matches_tunnel_pattern": int(any(
                r.match(subdomain) for r in self.TUNNEL_REGEXES
            )),

            # Behavioral (require history)
            "dns_query_rate_5m": len(self.domain_history[query]),
            "dns_client_qps_5m": len(self.client_qps[src_ip]),
            "dns_is_nxdomain": int(rcode == 3),

            # Whitelist
            "dns_sld_is_known": int(sld in self.BENIGN_SLDS),

            # Context
            "dns_qtype_is_txt": int(qtype == "TXT"),   # TXT records favored by dnscat2
            "dns_qtype_is_null": int(qtype == "NULL"),  # iodine uses NULL
            "dns_qtype_is_mx": int(qtype == "MX"),
        }

        return features

    def is_tunneling(self, features: Dict, threshold: float = 4.2) -> Tuple[bool, str]:
        """
        Fast heuristic check (pre-ML filter).
        Returns (is_tunnel, reason).
        """
        entropy = features.get("dns_shannon_entropy", 0)
        max_label = features.get("dns_max_label_len", 0)
        vowel = features.get("dns_vowel_ratio", 1.0)
        query_len = features.get("dns_query_len", 0)
        pattern = features.get("dns_matches_tunnel_pattern", 0)
        qrate = features.get("dns_query_rate_5m", 0)

        if entropy > threshold:
            return True, f"shannon entropy={entropy:.2f} > {threshold}"
        if max_label > 52:
            return True, f"max label length={max_label} > 52 (DNS limit 63, tunneling uses max)"
        if vowel < 0.03 and query_len > 30:
            return True, f"vowel ratio={vowel:.3f} (base64/hex encoded)"
        if pattern:
            return True, "matches known tunnel regex pattern"
        if qrate > 200:
            return True, f"query rate={qrate}/5min (tunneling flood)"
        return False, ""

    def _entropy(self, s: str) -> float:
        if not s:
            return 0.0
        counts = {}
        for c in s:
            counts[c] = counts.get(c, 0) + 1
        n = len(s)
        return -sum((v/n) * math.log2(v/n) for v in counts.values())

    def _bigram_entropy(self, s: str) -> float:
        if len(s) < 2:
            return 0.0
        bigrams = [s[i:i+2] for i in range(len(s)-1)]
        counts = {}
        for b in bigrams:
            counts[b] = counts.get(b, 0) + 1
        n = len(bigrams)
        return -sum((v/n) * math.log2(v/n) for v in counts.values())

    def _bigram_deviation(self, s: str) -> float:
        """
        How much does this string's bigram distribution deviate
        from normal English? High deviation = likely encoded.
        """
        if len(s) < 4:
            return 0.0
        bigrams = [s[i:i+2] for i in range(len(s)-1)]
        counts = {}
        for b in bigrams:
            counts[b] = counts.get(b, 0) + 1
        n = len(bigrams)
        
        deviation = 0.0
        for bg, expected_freq in ENGLISH_BIGRAMS.items():
            observed = counts.get(bg, 0) / n
            deviation += abs(observed - expected_freq)
        return deviation

    def _ratio(self, s: str, char_set: set) -> float:
        if not s:
            return 0.0
        return sum(c in char_set for c in s) / len(s)

    def _max_run(self, s: str, pred) -> int:
        if not s:
            return 0
        max_run, cur = 0, 0
        for c in s:
            cur = cur + 1 if pred(c) else 0
            max_run = max(max_run, cur)
        return max_run

    def _longest_run(self, s: str) -> int:
        """Longest run of same character type (alpha or digit)."""
        if not s:
            return 0
        max_run, cur = 1, 1
        for i in range(1, len(s)):
            same = (s[i].isalpha() == s[i-1].isalpha() and
                    s[i].isdigit() == s[i-1].isdigit())
            cur = cur + 1 if same else 1
            max_run = max(max_run, cur)
        return max_run
