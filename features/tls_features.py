# features/tls_features.py
"""
JA3 and JA4+ TLS fingerprint computation from raw ClientHello fields.
Also includes QUIC fingerprinting for QUIC-based C2 (e.g., Brute Ratel).

JA3:  MD5(SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)
JA3S: MD5(SSLVersion,Ciphers,Extensions)
JA4:  t{ver}{sni_flag}{num_ciphers}{num_exts}_{sorted_ciphers_sha256[:12]}_{sorted_exts_sha256[:12]}
"""

import hashlib
import json
from typing import Dict, List, Optional, Set


# Extension types to exclude from JA4 (GREASE values + SNI itself)
GREASE_VALUES: Set[int] = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
    0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa
}

# JA4: extensions to exclude from hash
JA4_SKIP_EXTENSIONS = {0x0000, 0x0010}  # SNI (0), ALPN (16)


class TLSFingerprinter:
    """
    Computes JA3, JA3S, and JA4+ fingerprints from parsed TLS ClientHello.
    Input can come from Zeek SSL logs or raw Scapy TLS parsing.
    """

    @staticmethod
    def compute_ja3(client_hello: Dict) -> str:
        """
        JA3 from ClientHello dict.
        Expected keys: version, ciphers, extensions, elliptic_curves, ec_point_formats
        """
        version = client_hello.get("version", 0)
        ciphers = [c for c in client_hello.get("ciphers", []) if c not in GREASE_VALUES]
        extensions = [e for e in client_hello.get("extensions", []) if e not in GREASE_VALUES]
        curves = [c for c in client_hello.get("elliptic_curves", []) if c not in GREASE_VALUES]
        formats = client_hello.get("ec_point_formats", [])

        ja3_str = (
            f"{version},"
            f"{'-'.join(map(str, ciphers))},"
            f"{'-'.join(map(str, extensions))},"
            f"{'-'.join(map(str, curves))},"
            f"{'-'.join(map(str, formats))}"
        )
        return hashlib.md5(ja3_str.encode()).hexdigest()

    @staticmethod
    def compute_ja3s(server_hello: Dict) -> str:
        """JA3S from ServerHello dict."""
        version = server_hello.get("version", 0)
        cipher = server_hello.get("cipher", 0)
        extensions = [e for e in server_hello.get("extensions", []) if e not in GREASE_VALUES]

        ja3s_str = f"{version},{cipher},{'-'.join(map(str, extensions))}"
        return hashlib.md5(ja3s_str.encode()).hexdigest()

    @staticmethod
    def compute_ja4(client_hello: Dict) -> str:
        """
        JA4+ fingerprint (2023 standard by FoxIO).
        Format: t{tls_ver}{sni_flag}{ciphers_count}{exts_count}_{ciphers_hash}_{exts_hash}
        
        Improvements over JA3:
        - Sorted (order-independent, survives randomization)
        - Truncated SHA256 (shorter, collision-resistant)
        - Explicit TLS version field
        """
        # TLS version
        ver_map = {0x0301: "10", 0x0302: "11", 0x0303: "12", 0x0304: "13"}
        raw_ver = client_hello.get("version", 0x0303)
        tls_ver = ver_map.get(raw_ver, "00")

        # SNI flag
        sni = client_hello.get("server_name", "")
        sni_flag = "d" if sni else "i"   # d=domain, i=IP

        # Ciphers (filter GREASE, sort)
        ciphers = sorted([
            c for c in client_hello.get("ciphers", [])
            if c not in GREASE_VALUES
        ])

        # Extensions (filter GREASE + skip-list, sort)
        all_exts = client_hello.get("extensions", [])
        exts_for_hash = sorted([
            e for e in all_exts
            if e not in GREASE_VALUES and e not in JA4_SKIP_EXTENSIONS
        ])

        num_ciphers = f"{len(ciphers):02d}"
        num_exts = f"{len(all_exts):02d}"

        # Hashes
        cipher_str = ",".join(map(str, ciphers))
        exts_str = ",".join(map(str, exts_for_hash))

        # Get ALPN (first value if present)
        alpn = client_hello.get("alpn_protocols", ["00"])
        alpn_val = alpn[0][:2] if alpn else "00"

        cipher_hash = hashlib.sha256(cipher_str.encode()).hexdigest()[:12]
        exts_hash = hashlib.sha256(
            (exts_str + "_" + alpn_val).encode()
        ).hexdigest()[:12]

        return f"t{tls_ver}{sni_flag}{num_ciphers}{num_exts}_{cipher_hash}_{exts_hash}"

    @staticmethod
    def compute_ja4_from_zeek(zeek_ssl_record: Dict) -> str:
        """
        Reconstruct JA4 from Zeek SSL log fields.
        Zeek doesn't expose raw ClientHello, but has enough fields
        to approximate JA4.
        """
        version = zeek_ssl_record.get("version", "TLSv1.3")
        ver_map = {"TLSv1": "10", "TLSv1.1": "11", "TLSv1.2": "12", "TLSv1.3": "13"}
        tls_ver = ver_map.get(version, "00")

        sni = zeek_ssl_record.get("server_name", "")
        sni_flag = "d" if sni else "i"
        cipher = zeek_ssl_record.get("cipher", "")
        resumed = zeek_ssl_record.get("resumed", False)

        # Approximate: use cipher as the only "cipher" entry
        cipher_hash = hashlib.sha256(cipher.encode()).hexdigest()[:12]
        exts_hash = hashlib.sha256(
            f"{zeek_ssl_record.get('curve','')}{zeek_ssl_record.get('next_protocol','')}".encode()
        ).hexdigest()[:12]

        # Approximate counts
        num_ciphers = "01"
        num_exts = "0a"  # typical

        return f"t{tls_ver}{sni_flag}{num_ciphers}{num_exts}_{cipher_hash}_{exts_hash}"

    @staticmethod
    def parse_from_scapy(pkt) -> Dict:
        """
        Extract ClientHello fields directly from a Scapy TLS packet.
        Used during PCAP processing in the lab pipeline.
        """
        try:
            from scapy.layers.tls.handshake import TLSClientHello
            from scapy.layers.tls.extensions import TLS_Ext_ServerName
        except ImportError:
            return {}

        if not pkt.haslayer(TLSClientHello):
            return {}

        ch = pkt[TLSClientHello]
        result = {
            "version": ch.version,
            "ciphers": [int(c) for c in ch.ciphers if hasattr(ch, 'ciphers')],
            "extensions": [],
            "elliptic_curves": [],
            "ec_point_formats": [],
            "server_name": "",
            "alpn_protocols": [],
        }

        if hasattr(ch, 'ext') and ch.ext:
            for ext in ch.ext:
                ext_type = getattr(ext, 'type', 0)
                result["extensions"].append(int(ext_type))

                # SNI
                if ext_type == 0 and hasattr(ext, 'servernames'):
                    for sn in ext.servernames:
                        result["server_name"] = sn.servername.decode(errors='ignore')

                # Elliptic curves (supported_groups)
                elif ext_type == 10 and hasattr(ext, 'groups'):
                    result["elliptic_curves"] = [int(g) for g in ext.groups]

                # EC point formats
                elif ext_type == 11 and hasattr(ext, 'ecpl'):
                    result["ec_point_formats"] = [int(f) for f in ext.ecpl]

                # ALPN
                elif ext_type == 16 and hasattr(ext, 'protocols'):
                    result["alpn_protocols"] = [
                        p.protocol.decode(errors='ignore')
                        for p in ext.protocols
                    ]

        return result


class QUICFingerprinter:
    """
    QUIC (HTTP/3) transport fingerprinting.
    C2 frameworks increasingly use QUIC to bypass TLS inspection.
    Uses QUIC Initial packet characteristics.
    """

    @staticmethod
    def compute_quic_fp(quic_initial: Dict) -> str:
        """
        Fingerprint from QUIC Initial packet.
        Features: QUIC version, connection ID length, token length,
        transport parameters presence.
        """
        version = quic_initial.get("version", 0)
        dcil = quic_initial.get("dcil", 0)   # Destination Connection ID length
        scil = quic_initial.get("scil", 0)   # Source Connection ID length
        token_len = quic_initial.get("token_length", 0)
        tp_present = quic_initial.get("transport_params_present", False)

        fp_str = f"{version}_{dcil}_{scil}_{int(token_len > 0)}_{int(tp_present)}"
        return hashlib.sha256(fp_str.encode()).hexdigest()[:16]

    @staticmethod
    def is_quic(pkt_data: bytes, dport: int) -> bool:
        """Heuristic: QUIC runs on UDP/443 and starts with specific byte patterns."""
        if dport != 443:
            return False
        if len(pkt_data) < 5:
            return False
        # Long header bit (bit 7 of first byte) + fixed bit (bit 6)
        first_byte = pkt_data[0]
        return bool((first_byte & 0x80) and (first_byte & 0x40))
