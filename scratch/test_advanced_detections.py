import sys
import os

# Add root folder to python path
sys.path.append(os.path.abspath("."))

from models.tls_fingerprint_detector import TLSFingerprintDetector
from models.tls_cert_detector import TLSCertDetector
from models.jitter_c2_detector import JitterC2Detector
from models.doh_dot_detector import DoHDotDetector
from models.shannon_entropy_detector import ShannonEntropyDetector

def test_all():
    print("--- Starting Verification of 5 Advanced Threat Detectors ---")
    
    # 1. Test TLS Fingerprint Detector (JA3/JA4)
    print("\n1. Testing TLS Fingerprint Detector...")
    finger_det = TLSFingerprintDetector()
    
    # Case A: Blacklisted JA3
    flow_ja3_black = {"ja3": "e7d705a3286e19ea42f587b344ee6865", "src_ip": "10.0.0.5"}
    res_ja3_black = finger_det.check(flow_ja3_black)
    assert res_ja3_black is not None, "Blacklisted JA3 should trigger alert"
    assert res_ja3_black.is_threat, "Should be flagged as threat"
    assert res_ja3_black.threat_name == "blacklisted_tls_client", "Threat name mismatch"
    print("  [PASSED] Blacklisted JA3 correctly flagged.")
    
    # Case B: Anomalous JA3 (Behavioral drift)
    flow_ja3_anom1 = {"ja3": "99999999999999999999999999999999", "src_ip": "10.14.1.5"}
    res_ja3_anom1 = finger_det.check(flow_ja3_anom1) # First time: establishes baseline, returns None
    assert res_ja3_anom1 is None, "First observation should establish baseline"
    
    flow_ja3_anom2 = {"ja3": "88888888888888888888888888888888", "src_ip": "10.14.1.5"}
    res_ja3_anom2 = finger_det.check(flow_ja3_anom2) # Second different hash: triggers anomaly
    assert res_ja3_anom2 is not None, "Behavioral drift (new JA3 on asset) should trigger alert"
    assert res_ja3_anom2.threat_name == "anomalous_tls_client", "Should flag anomalous client hello"
    print("  [PASSED] JA3 host behavioral drift correctly flagged.")

    # 2. Test TLS Certificate Detector
    print("\n2. Testing TLS Certificate Detector...")
    cert_det = TLSCertDetector()
    
    # Case A: Self-signed cert to external target
    flow_self_signed = {"cert_self_signed": True, "dst_ip": "198.51.100.12", "sni": "evil-c2.net"}
    res_self_signed = cert_det.check(flow_self_signed)
    assert res_self_signed is not None, "Self-signed external cert should trigger alert"
    assert res_self_signed.threat_name == "self_signed_external_cert", "Threat name mismatch"
    print("  [PASSED] Self-signed external certificate correctly flagged.")
    
    # Case B: Suspicious short validity (e.g. Let's Encrypt disposable cert with high entropy SNI)
    flow_short_cert = {"cert_validity_days": 4.5, "dst_ip": "198.51.100.13", "sni": "ab12cd34ef56gh78.covertchannel-very-long-evilsni.xyz"}
    res_short_cert = cert_det.check(flow_short_cert)
    assert res_short_cert is not None, "Short validity high entropy cert should trigger alert"
    assert res_short_cert.threat_name == "suspicious_short_lived_cert", "Threat name mismatch"
    print("  [PASSED] Short validity + high entropy SNI domain correctly flagged.")

    # 3. Test Jitter C2 Detector (DTW/CV)
    print("\n3. Testing Jitter C2 Detector...")
    jitter_det = JitterC2Detector()
    
    # intervals with CV around 10-15% (automated jittered heartbeat)
    # mean = 60.0, std = ~6.0, cv = 0.1
    intervals = [60.0, 66.0, 54.0, 62.0, 58.0, 61.0, 65.0, 56.0]
    sizes = [120, 120, 120, 120, 120, 120, 120, 120] # Uniform sizes (Size CV = 0)
    res_jitter = jitter_det.check_sequence(intervals, sizes)
    assert res_jitter is not None, "Jittered C2 sequence with uniform packet size should trigger alert"
    assert res_jitter.is_beacon, "Should be flagged as C2 beacon"
    print("  [PASSED] Jittered C2 heartbeat sequence correctly flagged.")

    # 4. Test DoH/DoT Tunneling Detector
    print("\n4. Testing DoH/DoT Tunneling Detector...")
    doh_det = DoHDotDetector()
    
    # Case A: Connection to Cloudflare DoH IP with low payload sizes
    flow_doh = {"dst_ip": "1.1.1.1", "dst_port": 443, "orig_bytes": 180, "orig_pkts": 2, "sni": "cloudflare-dns.com"}
    res_doh = doh_det.check(flow_doh)
    assert res_doh is not None, "DoH resolver connection with low payload size should trigger alert"
    assert res_doh.threat_name == "doh_tunnel", "Threat name mismatch"
    print("  [PASSED] DoH resolver tunnel connection correctly flagged.")

    # Case B: Connection to Google DNS on Port 853 (DoT)
    flow_dot = {"dst_ip": "8.8.8.8", "dst_port": 853, "orig_bytes": 150, "orig_pkts": 1}
    res_dot = doh_det.check(flow_dot)
    assert res_dot is not None, "DoT resolver connection should trigger alert"
    assert res_dot.threat_name == "dot_tunnel", "Threat name mismatch"
    print("  [PASSED] DoT resolver tunnel connection correctly flagged.")

    # 5. Test Shannon Entropy Payload Detector
    print("\n5. Testing Shannon Entropy Payload Detector...")
    entropy_det = ShannonEntropyDetector()
    
    # Case A: High entropy outbound raw TCP session on non-standard port 8888
    flow_entropy = {"dst_ip": "198.51.100.22", "dst_port": 8888, "orig_bytes": 75000, "payload_entropy": 7.85, "ja3": ""}
    res_entropy = entropy_det.check(flow_entropy)
    assert res_entropy is not None, "High entropy raw TCP session should trigger exfil alert"
    assert res_entropy.threat_name == "high_entropy_exfil", "Threat name mismatch"
    print("  [PASSED] High entropy TCP payload exfiltration correctly flagged.")
    
    # Case B: Plaintext port exclusion (port 80)
    flow_port_80 = {"dst_ip": "198.51.100.22", "dst_port": 80, "orig_bytes": 75000, "payload_entropy": 7.85, "ja3": ""}
    res_port_80 = entropy_det.check(flow_port_80)
    assert res_port_80 is None, "Standard ports (80) should be excluded from entropy scan"
    print("  [PASSED] Plaintext HTTP ports excluded from entropy alerts.")

    print("\nALL 5 DETECTORS COMPILE AND PASS TEST VERIFICATION SUCCESSFULLY! [OK]")

if __name__ == "__main__":
    test_all()
