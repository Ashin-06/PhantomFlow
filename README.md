# PhantomFlow
**ML-based covert channel detection in encrypted network traffic. Zero decryption required.**

Detects C2 beaconing, DNS tunneling, and data exfiltration inside TLS 1.3, QUIC, and DNS-over-HTTPS using only packet metadata — no deep packet inspection needed.

---

## Architecture Overview

```
Network Interface (Zeek/Suricata)
        ↓
  Kafka (3-broker HA cluster)
        ↓
  Pipeline Workers (async, N replicas)
        ↓
  Feature Extraction                    ← timing, TLS, DNS, byte features
        ↓
  ML Ensemble Inference
  ├── LSTM Beacon Detector              ← IAT sequences → C2 periodicity
  ├── XGBoost DNS Classifier            ← entropy, bigrams → DNS tunneling
  └── IsolationForest Exfil Detector    ← bytes ratio → data exfiltration
        ↓
  Meta-Learner (Logistic Regression)
  + SHAP Explainability
  + MITRE ATT&CK Mapping
        ↓
  Suppression Engine → PostgreSQL → SIEM
        ↓
  FastAPI + Analyst Dashboard
  + Active Response (Human-in-the-Loop)
```

---

## Quick Start

### Prerequisites
- Python 3.11+
- Docker & Docker Compose
- 8GB+ RAM recommended

### 1. Clone and install
```bash
git clone <repo-url>
cd PhantomFlow/phantomflow

cp .env.example .env
# Edit .env with your credentials

pip install -r requirements.txt
```

### 2. Start infrastructure
```bash
docker compose -f docker/docker-compose.yml up -d
# Starts: Kafka, Redis, PostgreSQL
```

### 3. Initialize the database
```bash
psql -h localhost -U phantom -d phantomflow -f pipeline/schema.sql
```

### 4. Train the models (streaming — no full download needed)
```bash
# Quick test (100K rows per dataset, ~15 mins)
python -m train.run_online --max_rows 100000

# Full training (~3-4 hours, ~500MB RAM peak)
python -m train.run_online

# Track training progress
mlflow ui   # → http://localhost:5000
```

### 5. Start the pipeline
```bash
# Start the async detection pipeline
python -m pipeline.orchestrator

# Start the API
uvicorn api.main:app --host 0.0.0.0 --port 8000

# Dashboard → http://localhost:8000/dashboard
```

### 6. Production deployment
```bash
docker compose -f docker/docker-compose.prod.yml up -d
```

---

## Training Datasets

Training uses online streaming — data is fetched and processed chunk-by-chunk without downloading entire files.

| Dataset | Content | Rows |
|---------|---------|------|
| CICIDS 2017 (Mon-Fri) | Benign, Botnet C2, DoS, Exfil | ~2.1M |
| CICIDS 2018 (S3) | Botnet, Infiltration | ~1M |
| CTU-13 (Scenarios 1, 9) | Real Neris botnet C2 | ~4M |
| UNSW-NB15 | Backdoors, Shellcode | ~175K |
| DNS Exfil (Zeek log) | DNS tunneling | ~50K |

---

## Detection Capabilities

| Threat | Technique | MITRE TTP |
|--------|-----------|-----------|
| C2 Beaconing | LSTM on IAT sequences, JA3 fingerprinting | T1071.001, T1573 |
| DNS Tunneling | Shannon entropy, bigram analysis | T1048.003, T1071.004 |
| Data Exfiltration | Upload ratio anomaly, IsolationForest | T1041, T1048 |

---

## Project Structure

```
phantomflow/
├── api/                    # FastAPI backend, RS256 JWT auth, RBAC
│   ├── auth.py             # JWT verification + LDAP/AD integration
│   └── routes/
│       └── analyst.py      # Analyst review, suppression, FP metrics
├── capture/                # Packet capture (Zeek/Suricata interface)
├── config/
│   ├── logging.py          # Structured JSON logging → ELK
│   └── secrets.py          # AWS Secrets Manager / Vault integration
├── dashboard/              # Frontend UI
├── docker/
│   ├── docker-compose.yml         # Dev: single-node
│   └── docker-compose.prod.yml    # Prod: Kafka HA, Redis Sentinel, PG replica
├── features/               # Feature extraction (timing, TLS, DNS, bytes)
├── lab/                    # Dataset tools
│   ├── online_datasets.py  # Streaming dataset registry (URLs + configs)
│   ├── stream_reader.py    # HTTP/S3 streaming reader
│   └── feature_adapter.py  # Per-dataset column normalization
├── models/                 # ML model implementations
│   ├── lstm_beacon.py      # LSTM beacon detector
│   ├── dns_classifier.py   # XGBoost DNS tunnel classifier
│   ├── exfil_detector.py   # IsolationForest exfil detector
│   └── ensemble.py         # Stacking ensemble + SHAP + MITRE
├── monitoring/
│   ├── drift_detector.py   # KS-test + ADWIN concept drift detection
│   └── metrics.py          # Prometheus metrics
├── pipeline/
│   ├── orchestrator.py     # Kafka consumer → ML inference → alerts
│   ├── db_layer.py         # Async PostgreSQL (asyncpg connection pool)
│   ├── suppression.py      # Analyst suppression rules engine
│   ├── active_response.py  # Human-in-the-loop blocking actions
│   └── schema.sql          # Full PostgreSQL schema
├── sensors/
│   └── manager.py          # Sensor fleet health + config management
├── tests/
│   └── test_integration.py # Integration test framework
└── train/
    ├── run_online.py        # ← START HERE: trains all models
    ├── online_trainer.py    # Streaming incremental trainer
    ├── online_evaluator.py  # Held-out dataset evaluation
    ├── validation_pipeline.py # 8-check pre-training validator
    ├── model_registry.py   # MLflow promotion gates
    ├── federated.py        # Federated averaging (multi-org)
    └── active_learning.py  # Uncertainty sampling for analyst review
```

---

## Security Architecture

- **JWT**: RS256 asymmetric tokens (validation doesn't need private key)
- **RBAC**: Tier1/Tier2/Tier3 analyst roles via LDAP/Active Directory
- **Secrets**: AWS Secrets Manager / HashiCorp Vault (no env var secrets)
- **Active Response**: Always requires analyst approval unless confidence > 99%
- **Suppression**: CIDR + port + SNI regex rules to reduce alert fatigue
- **Audit Log**: Every blocking action is immutably logged with who approved it

---

## Research Features

- **Federated Learning**: Multiple deployments share model weights, not raw traffic
- **Active Learning**: Uncertainty sampling selects most informative flows for analyst review
- **Concept Drift Detection**: ADWIN + KS-test detect when distribution shifts
- **Cross-Dataset Validation**: Model must generalize from CICIDS → CTU-13, not just memorize
- **Temporal Validation**: Time-based splits prevent data leakage in all evaluations
