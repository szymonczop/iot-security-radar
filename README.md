# IoT Security Radar

Local IoT network monitor with real-time attack detection, ML-based traffic classification, and MITRE ATT&CK mapping. Built with the Elastic Stack (Filebeat → Logstash → Elasticsearch → Kibana) and a Python Random Forest classifier. Fully Dockerized.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        DATA SOURCES                             │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────┐     │
│  │  WiFi/tshark │  │  NF-ToN-IoT  │  │  Simulated Attack │     │
│  │  live capture│  │  benchmark   │  │  logs (generated) │     │
│  └──────┬───────┘  └──────┬───────┘  └────────┬──────────┘     │
│         └─────────────────┴──────────────────┘                 │
│                            ▼                                    │
│              ┌─────────────────────────┐                        │
│              │         FILEBEAT        │                        │
│              │   Collects & ships logs │                        │
│              └────────────┬────────────┘                        │
│                           ▼  (mTLS)                             │
│              ┌─────────────────────────┐                        │
│              │        LOGSTASH         │                        │
│              │  Parses, filters, tags  │                        │
│              └────────────┬────────────┘                        │
│                           ▼                                     │
│              ┌─────────────────────────┐                        │
│              │     ELASTICSEARCH       │                        │
│              │  Stores & indexes data  │                        │
│              └──────┬──────────┬───────┘                        │
│                     ▼          ▼                                │
│           ┌──────────────┐ ┌───────────────────┐               │
│           │    KIBANA    │ │  PYTHON ML SERVICE │               │
│           │  Dashboards  │ │  Random Forest     │               │
│           │  Alerts      │ │  MITRE ATT&CK map  │               │
│           └──────────────┘ └───────────────────┘               │
│                                                                 │
│         All services wrapped in Docker Compose + mTLS           │
└─────────────────────────────────────────────────────────────────┘
```

---

## Prerequisites

| Tool | Version |
|------|---------|
| Docker Desktop | 4.x+ (with Compose v2) |
| Python | 3.11+ |
| tshark | any (for live capture) |
| openssl | any (for cert generation) |

---

## Quick Start

### 1. Clone the repo

```bash
git clone https://github.com/szymonczop/iot-security-radar.git
cd iot-security-radar
```

### 2. Generate TLS certificates

```bash
bash tls/generate-certs.sh
```

This creates all `.pem` files expected by the ELK configs. Passphrase is `abcd1234` (matches configs).

### 3. Start the stack

```bash
docker compose up -d
```

Wait ~30 seconds for Elasticsearch to become healthy.

### 4. Verify Elasticsearch is up

```bash
curl -s -k -u elastic:changeme https://localhost:9200/_cluster/health | python3 -m json.tool
```

Expect `"status": "green"` or `"yellow"`.

### 5. Open Kibana

Navigate to [http://localhost:5601](http://localhost:5601) and log in with `elastic` / `changeme`.

Create a Data View for the `iot-radar-*` index pattern in **Stack Management → Data Views**.

---

## Python Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

All Python commands below assume the venv is activated or use `.venv/bin/python3` explicitly.

---

## Sample Data

When the stack starts, Filebeat automatically ships `sample-logs/network_traffic.json` (15 labeled events) to Elasticsearch. These appear in Kibana immediately — no extra steps needed to get started.

---

## Run the Live Demo

Captures real WiFi traffic + injects simulated attacks, scores everything with the ML model, and sends predictions to Elasticsearch in real time.

```bash
# Requires root (tshark needs raw socket access)
sudo .venv/bin/python3 scripts/live_demo_with_attacks.py --minutes 3 --attacks 300
```

Watch the Kibana dashboards update live.

---

## ML Attack Classifier

A pre-trained Random Forest model is included in `ml/model/` — no retraining needed to use the project. It achieves **97% accuracy** on the NF-ToN-IoT-v2 benchmark (9 attack classes + normal).

For a full explanation of the training pipeline, feature engineering, evaluation results, and known limitations, see **[ml/ML_METHODOLOGY.md](ml/ML_METHODOLOGY.md)**.

To re-score all benchmark events (requires the stack to be running):

```bash
.venv/bin/python3 scripts/batch_score_all.py
```

### Retrain from scratch (optional)

Requires the stack to be running and the NF-ToN-IoT-v2 dataset (see below):

```bash
.venv/bin/python3 ml/train_model.py
```

---

## Download the Benchmark Dataset (optional — for retraining only)

The NF-ToN-IoT-v2 dataset (~1 GB) is not included in this repo.

Download from HuggingFace:
```
https://huggingface.co/datasets/Western-OC2-Lab/NF-ToN-IoT-v2
```

Place the CSV files in `datasets/toniot/`, then run:

```bash
.venv/bin/python3 scripts/adapt_toniot.py
```

---

## Project Structure

```
iot-security-radar/
├── docker-compose.yml          # All 4 services + network + volumes
├── elasticsearch/
│   └── elasticsearch.yml       # TLS (PEM), single-node, xpack security
├── kibana/
│   └── kibana.yml              # Connects to ES via kibana_system user
├── logstash/
│   ├── logstash.yml            # Node settings
│   └── conf.d/pipeline.conf   # beats input → mutate → ES output
├── filebeat/
│   └── filebeat.yml            # filestream → logstash output (TLS)
├── tls/
│   └── generate-certs.sh       # Generate all certs with openssl
├── sample-logs/
│   └── network_traffic.json    # 15 sample events (shipped on first run)
├── scripts/
│   ├── live_demo_with_attacks.py  # Live WiFi capture + attack injection
│   ├── live_demo.py               # Live WiFi capture only
│   ├── capture_traffic_flows.py   # Flow-based tshark capture (current)
│   ├── capture_traffic.py         # Per-packet capture (legacy, kept for reference)
│   ├── generate_attacks.py        # Simulated attack log generator
│   ├── adapt_toniot.py            # Convert NF-ToN-IoT CSV → NDJSON
│   └── batch_score_all.py         # Score all benchmark events
├── datasets/
│   └── toniot/                    # Place NF-ToN-IoT-v2 CSVs here (see below)
├── ml/
│   ├── train_model.py          # Train Random Forest classifier
│   ├── score_and_index.py      # Score events, index predictions to ES
│   ├── ML_METHODOLOGY.md       # Full ML pipeline documentation
│   └── model/
│       ├── classifier.joblib       # Pre-trained Random Forest
│       ├── label_encoder.joblib    # Class label mapping
│       ├── feature_names.joblib    # Feature order for inference
│       ├── mitre_map.json          # Attack → MITRE ATT&CK mapping
│       ├── classification_report.txt
│       ├── confusion_matrix.png
│       └── feature_importance.png
└── requirements.txt
```

---

## Credentials (dev only — change before any real deployment)

| Service | User | Password |
|---------|------|----------|
| Elasticsearch | `elastic` | `changeme` |
| Kibana | `kibana_system` | `changeme` |
| TLS key passphrase | — | `abcd1234` |

---

## Two-Index Architecture

| Index | Contents |
|-------|----------|
| `iot-radar-*` | Raw events with ground-truth labels (benchmark + simulated + live WiFi) |
| `iot-radar-predictions` | ML model output — `ml_prediction`, `ml_confidence`, `ml_mitre_tactic` |

SOC dashboards use `iot-radar-*`. ML predictions dashboards use `iot-radar-predictions`.

---

## MITRE ATT&CK Coverage

The classifier maps predictions to 8 MITRE techniques across 6 tactics:

| Tactic | Technique | Attack Class |
|--------|-----------|--------------|
| Discovery | T1046 — Network Service Discovery | `port_scan` |
| Credential Access | T1110.001 — Brute Force: Password Guessing | `brute_force` |
| Exfiltration | T1048.001 — Exfiltration Over Alternative Protocol | `dns_exfiltration` |
| Impact | T1498.001 — Direct Network Flood | `ddos_flood` |
| Impact | T1499.001 — OS Exhaustion Flood | `dos` |
| Initial Access | T1189 — Drive-by Compromise | `xss` |
| Execution | T1059 — Command and Scripting Interpreter | `injection` |
| Persistence | T1505.003 — Web Shell | `backdoor` |

---

## License

MIT
