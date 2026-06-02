# lab/dataset_sources.py
"""
These are the ONLY datasets worth using for PhantomFlow.
All are free, all have the right features, all are from real traffic.
"""

DATASETS = {

    # ===== TIER 1: Has real encrypted C2 traffic =====

    "CTU-13": {
        "url": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-13-Dataset/",
        "why": "Real botnet C2 traffic captured at CTU Prague. "
               "13 scenarios, different botnets. Has actual TLS C2 sessions. "
               "Most important dataset for PhantomFlow.",
        "download": """
            # Scenario 1 (Neris botnet - IRC C2)
            wget https://mcfp.felk.cvut.cz/publicDatasets/CTU-13-Dataset/\
CTU-13-Dataset/1/capture20110810.pcap.gz
            # Scenarios 3, 4, 7, 8, 9 have HTTP/HTTPS C2
        """,
        "label_map": {
            "Botnet": 1,   # C2 beaconing
            "Normal": 0,
            "Background": 0,
        },
        "features_available": ["timing", "bytes", "flow_duration",
                                "proto", "partial_tls"],
        "rows": "~2M flows across all scenarios",
    },

    "CICIDS2017": {
        "url": "https://www.unb.ca/cic/datasets/ids-2017.html",
        "why": "Modern attacks including infiltration and botnet. "
               "Has Zeek/flow features already extracted. "
               "2017 traffic = has TLS 1.2 sessions.",
        "download": """
            # Direct CSV download (no PCAP needed)
            wget http://205.174.165.80/CICDataset/CIC-IDS-2017/Dataset/\
MachineLearningCSV.zip
            unzip MachineLearningCSV.zip
        """,
        "label_map": {
            "BENIGN": 0,
            "Bot": 1,        # C2
            "Infiltration": 3, # Exfil
            "PortScan": 2,   # Recon/lateral
            "DDoS": -1,      # Skip — not your threat model
        },
        "features_available": ["flow_duration", "packet_lengths",
                                "iat_stats", "flags", "bytes"],
        "rows": "~2.8M flows",
    },

    "CICIDS2018": {
        "url": "https://www.unb.ca/cic/datasets/ids-2018.html",
        "why": "More recent than 2017. Has infiltration + exfil scenario "
               "that maps directly to PhantomFlow's exfil detector.",
        "download": """
            # Available via AWS S3
            aws s3 sync --no-sign-request \
                s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/ \
                data/cicids2018/
        """,
        "label_map": {
            "Benign": 0,
            "Bot": 1,
            "Infilteration": 3,  # Note: typo in original dataset
        },
        "rows": "~16M flows",
    },

    "UNSW-NB15": {
        "url": "https://research.unsw.edu.au/projects/unsw-nb15-dataset",
        "why": "2015 dataset but has 9 attack categories including "
               "Backdoors (C2) and Shellcode (post-exploit). "
               "Has 49 features, good overlap with PhantomFlow.",
        "download": """
            wget https://cloudstor.aarnet.edu.au/plus/s/2DhnLGDdEECo4ys/download \
                -O unsw_nb15.zip
        """,
        "label_map": {
            0: 0,          # Normal
            "Backdoors": 1, # C2
            "Shellcode": 1, # Post-exploit = C2 phase
            "Worms": 1,
            "Generic": -1,  # Skip
            "Exploits": -1, # Skip
        },
        "rows": "~2.5M flows",
    },

    # ===== TIER 2: Specific to your threat categories =====

    "Stratosphere_IPS": {
        "url": "https://www.stratosphereips.org/datasets-overview",
        "why": "Real malware PCAPs analyzed by researchers. "
               "Many C2 scenarios. Has JA3 analysis available.",
        "download": "Manual download from website",
        "rows": "Varies per scenario",
    },

    "DNS_Exfil_Dataset": {
        "url": "https://github.com/geeksonsecurity/dns-exfiltration-dataset",
        "why": "Specifically DNS tunneling (iodine, dnscat2, dns2tcp). "
               "Critical for your DNS classifier.",
        "download": """
            git clone https://github.com/geeksonsecurity/dns-exfiltration-dataset
        """,
        "rows": "~50K DNS queries labeled tunnel/benign",
    },

    "CIRA-CIC-DoHBrw-2020": {
        "url": "https://www.unb.ca/cic/datasets/dohbrw-2020.html",
        "why": "DNS-over-HTTPS traffic — directly relevant to PhantomFlow's "
               "ability to detect C2 over DoH, which bypasses all DNS inspection.",
        "download": """
            wget http://205.174.165.80/CICDataset/CIRA-CIC-DoHBrw-2020/Dataset/
        """,
        "rows": "~1.8M DoH flows",
    },

    "BETH": {
        "url": "https://www.kaggle.com/datasets/katehighnam/beth-dataset",
        "why": "From Elastic. Real honeypot data. "
               "Has both network and host behavioral features. "
               "2021 traffic = TLS 1.3 present.",
        "rows": "~8M events",
    },
}
