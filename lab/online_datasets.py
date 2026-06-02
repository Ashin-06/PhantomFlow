# lab/online_datasets.py
"""
Every dataset here is streamable — no full download needed.
Chunks arrive, get processed, chunk is discarded from memory.
Max RAM usage at any time: ~500MB regardless of dataset size.
"""

STREAMING_DATASETS = {

    "cicids2017_monday": {
        # Monday = pure benign traffic. Label = 0 for everything.
        "url": "http://205.174.165.80/CICDataset/CIC-IDS-2017/Dataset/"
               "MachineLearningCSV/Monday-WorkingHours.pcap_ISCX.csv",
        "type": "csv_http",
        "label_col": " Label",
        "chunk_size": 10000,
        "label_map": {"BENIGN": 0},
        "has_features": ["timing", "bytes", "packets"],
        "approx_rows": 529918,
    },

    "cicids2017_tuesday": {
        # Tuesday = FTP-Patator + SSH-Patator (brute force) + benign
        "url": "http://205.174.165.80/CICDataset/CIC-IDS-2017/Dataset/"
               "MachineLearningCSV/Tuesday-WorkingHours.pcap_ISCX.csv",
        "type": "csv_http",
        "label_col": " Label",
        "chunk_size": 10000,
        "label_map": {"BENIGN": 0, "FTP-Patator": 1, "SSH-Patator": 1},
        "approx_rows": 445909,
    },

    "cicids2017_wednesday": {
        # Wednesday = DoS + Heartbleed. Most relevant — has network anomalies
        "url": "http://205.174.165.80/CICDataset/CIC-IDS-2017/Dataset/"
               "MachineLearningCSV/Wednesday-workingHours.pcap_ISCX.csv",
        "type": "csv_http",
        "label_col": " Label",
        "chunk_size": 10000,
        "label_map": {
            "BENIGN": 0,
            "DoS slowloris": 1,
            "DoS Slowhttptest": 1,
            "DoS Hulk": 1,
            "DoS GoldenEye": 1,
            "Heartbleed": 3,     # Exfil-like (data exposure)
        },
        "approx_rows": 692703,
    },

    "cicids2017_thursday": {
        # Thursday = Web attacks + Infiltration (closest to C2 exfil)
        "url": None,
        "type": "csv_http",
        "label_col": " Label",
        "chunk_size": 10000,
        "label_map": {
            "BENIGN": 0,
            "Web Attack \x96 Brute Force": 1,
            "Web Attack \x96 XSS": 1,
            "Web Attack \x96 Sql Injection": 1,
            "Infiltration": 3,   # Data exfiltration scenario
        },
        "approx_rows": 170366,
    },

    "cicids2017_friday": {
        # Friday = Botnet + PortScan + DDoS
        # BOTNET is the most important for PhantomFlow C2 detection
        "url": "http://205.174.165.80/CICDataset/CIC-IDS-2017/Dataset/"
               "MachineLearningCSV/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
        "type": "csv_http",
        "label_col": " Label",
        "chunk_size": 10000,
        "label_map": {
            "BENIGN": 0,
            "Bot": 1,         # C2 beaconing
            "PortScan": 2,    # Recon / lateral movement
            "DDoS": -1,       # Skip — not our threat model
        },
        "approx_rows": 286467,
    },

    "cicids2018_s3": {
        # 2018 dataset — on AWS S3, no auth needed
        # More recent than 2017, has infiltration + exfil scenario
        "url": "s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/"
               "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv",
        "type": "csv_s3",
        "label_col": "Label",
        "chunk_size": 10000,
        "label_map": {
            "Benign": 0,
            "Bot": 1,
            "Infilteration": 3,  # Intentional typo in dataset
            "DDOS attack-HOIC": -1,
            "DDoS attacks-LOIC-HTTP": -1,
        },
        "approx_rows": 1048567,
    },

    "unsw_nb15_train": {
        # UNSW-NB15 — 49 features, 9 attack categories
        # AARNet Cloudstor is dead, requires Kaggle Auth mirror now.
        # "url": "https://cloudstor.aarnet.edu.au/plus/s/2DhnLGDdEECo4ys/"
        #        "download?path=%2FUNSW-NB15%20-%20CSV%20Files%2Fa%20part%20of%20training%20and%20testing%20set"
        #        "&files=UNSW_NB15_training-set.csv",
        "url": None,
        "type": "csv_http",
        "label_col": "attack_cat",
        "chunk_size": 5000,
        "label_map": {
            "Normal": 0, "": 0,
            "Backdoor": 1,      # Direct C2 analog
            "Shellcode": 1,
            "Worms": 1,
            "Reconnaissance": 2,
            "Analysis": 2,
            "Exploits": -1,
            "Fuzzers": -1,
            "Generic": -1,
            "DoS": -1,
        },
        "approx_rows": 175341,
    },

    "ctu13_scenario1": {
        # CTU-13 Scenario 1 — Neris botnet (IRC C2)
        # Real botnet traffic with C2 beaconing patterns
        "url": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-42/"
               "detailed-bidirectional-flow-labels/capture20110810.binetflow",
        "type": "binetflow_http",  # Custom format
        "label_col": "Label",
        "chunk_size": 5000,
        "label_map": {
            "flow=Background": 0,
            "flow=Normal": 0,
            "flow=From-Botnet": 1,
            "flow=To-Botnet": 1,
        },
        "approx_rows": 2753885,
    },

    "ctu13_scenario9": {
        # CTU-13 Scenario 9 — Neris botnet (HTTP C2, closer to HTTPS C2)
        "url": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-50/"
               "detailed-bidirectional-flow-labels/capture20110817.binetflow",
        "type": "binetflow_http",
        "label_col": "Label",
        "chunk_size": 5000,
        "label_map": {
            "flow=Background": 0,
            "flow=Normal": 0,
            "flow=From-Botnet": 1,
            "flow=To-Botnet": 1,
        },
        "approx_rows": 1309791,
    },

    "ctu13_scenario8": {
        # CTU-13 Scenario 8 — Murlo botnet (IRC C2)
        # Out-of-sample botnet: trained on Neris, evaluated on Murlo!
        "url": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-49/detailed-bidirectional-flow-labels/capture20110816-3.binetflow",
        "type": "binetflow_http",
        "label_col": "Label",
        "chunk_size": 5000,
        "label_map": {
            "flow=Background": 0,
            "flow=Normal": 0,
            "flow=From-Botnet": 1,
            "flow=To-Botnet": 1,
        },
        "approx_rows": 100000,
    },

    "kdd99_sklearn": {
        # Built into sklearn — zero download
        # Only for testing pipeline, NOT for final results
        # (wrong era for encrypted traffic)
        "url": None,
        "type": "sklearn_builtin",
        "note": "For pipeline testing only. Do not use for paper results.",
    },

    "dns_exfil_github": {
        # DNS tunneling dataset — labeled tunnel/benign queries
        "url": "https://raw.githubusercontent.com/h2oai/app-malicious-domains/master/legit-dga_domains.csv",
        "type": "dns_csv_http",
        "label_col": "class",
        "label_map": {"legit": 0, "dga": 2},
        "chunk_size": 5000,
        "approx_rows": 135000,
    },

    # ===== NEW DATASETS =====
    "ctu13_scenario3": {
        "url": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-44/detailed-bidirectional-flow-labels/capture20110812.binetflow",
        "type": "binetflow_http",
        "label_col": "Label",
        "chunk_size": 5000,
        "label_map": {
            "flow=From-Botnet": 1,
            "flow=To-Botnet": 1,
            "flow=Normal": 0,
            "flow=Background": 0,
        },
        "approx_rows": 500000,
    },
    "ctu13_scenario4": {
        "url": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-45/detailed-bidirectional-flow-labels/capture20110815.binetflow",
        "type": "binetflow_http",
        "label_col": "Label",
        "chunk_size": 5000,
        "label_map": {
            "flow=From-Botnet": 1,
            "flow=To-Botnet": 1,
            "flow=Normal": 0,
            "flow=Background": 0,
        },
        "approx_rows": 400000,
    },
    "ctu13_scenario13": {
        "url": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-52/detailed-bidirectional-flow-labels/capture20110818-2.binetflow",
        "type": "binetflow_http",
        "label_col": "Label",
        "chunk_size": 5000,
        "label_map": {
            "flow=From-Botnet": 1,
            "flow=To-Botnet": 1,
            "flow=Normal": 0,
            "flow=Background": 0,
        },
        "approx_rows": 600000,
    },
    "cicids2017_infiltration_afternoon": {
        "url": "http://205.174.165.80/CICDataset/CIC-IDS-2017/Dataset/MachineLearningCSV/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
        "type": "csv_http",
        "label_col": " Label",
        "chunk_size": 10000,
        "label_map": {
            "BENIGN": 0,
            "Infiltration": 3,
        },
        "approx_rows": 288602,
    },
    "cicids2017_botnet": {
        "url": "http://205.174.165.80/CICDataset/CIC-IDS-2017/Dataset/MachineLearningCSV/Friday-WorkingHours-Morning.pcap_ISCX.csv",
        "type": "csv_http",
        "label_col": " Label",
        "chunk_size": 10000,
        "label_map": {
            "BENIGN": 0,
            "Bot": 1,
        },
        "approx_rows": 191033,
    },
    "cira_doh_2020": {
        "url": "http://205.174.165.80/CICDataset/CIRA-CIC-DoHBrw-2020/Dataset/CIRA-CIC-DoHBrw-2020.csv",
        "type": "csv_http",
        "label_col": "Label",
        "chunk_size": 5000,
        "label_map": {
            "Benign": 0,
            "Malicious": 2,
        },
        "approx_rows": 100000,
    },
    "iscx_vpn_2016": {
        "url": None,
        "type": "manual_download",
        "label_map": {
            "VPN": 1,
            "nonVPN": 0,
        },
        "approx_rows": 150000,
    },
}
