# IoT Security Radar — Project Plan

> **Last updated:** 2026-03-01
> **Current status:** Phases 1–3 + 5 COMPLETE. Phase 6 ~60% done. Phase 4 DROPPED. Phase 7 not started.
> **Overall completion: ~78%**
> **Project directory:** `/Users/szymonczop/iot-security-radar/`

## Progress Overview

| Phase | Name | Status | % Done |
|-------|------|--------|--------|
| 1 | Foundation — Docker + ELK + mTLS | ✅ COMPLETE | 100% |
| 2 | Real Data Collection | ✅ COMPLETE | 100% |
| 3 | Attack Simulation + Benchmark Dataset | ✅ COMPLETE | 100% |
| 4 | Threat Intelligence — Shodan, GeoIP | ~~NOT STARTED~~ **DROPPED** | — |
| 5 | ML Attack Classification | ✅ COMPLETE | 100% |
| 6 | Kibana Dashboards & Alerts | 🔄 IN PROGRESS | 60% |
| 7 | Dockerize Everything — final polish + GitHub | ❌ NOT STARTED | 0% |

**What's done:** 55,280 events indexed, RF 97% accuracy, SOC dashboard (8 panels), live demo pipeline working (flow-based tshark + ML end-to-end), `bytes_received` fixed
**What remains:** Phase 6 ML predictions dashboard + alerts, Phase 7 polish + Filebeat registry fix + README

## Why Phase 4 (Shodan) was dropped

- Only enriches `tshark-live` events with real external IPs (~0.5% of total data)
- NF-ToN-IoT and simulated data use fake/lab IPs — Shodan returns nothing for those
- Adds no value to the ML model (already trained, would need full retraining to use)
- Implementation complexity (API key, rate limits, Logstash filter) outweighs thesis benefit

## Next Steps (priority order)

| # | Task | Phase |
|---|------|-------|
| 1 | ML predictions dashboard in Kibana | 6 |
| 2 | SOC investigation walkthrough (tutorial 02) | 6 |
| 3 | Kibana alerts for critical attacks | 6 |
| 4 | Filebeat registry volume in docker-compose.yml | 7 |
| 5 | GitHub README + reproducibility | 7 |

## Data Collection Strategy

| Method | Script | Output | When to use |
|--------|--------|--------|-------------|
| Real WiFi capture | `scripts/live_demo.py --minutes X` | tshark-live events in `iot-radar-*` | Thesis demo — authentic traffic |
| WiFi + injected attacks | `scripts/live_demo_with_attacks.py --minutes X --attacks N` | tshark-live + simulated in `iot-radar-*` | Thesis demo — makes dashboard light up |
| Benchmark dataset | `scripts/adapt_toniot.py` (already done) | 50k toniot events | Academic credibility — one-time |
| Pure simulation | `scripts/generate_attacks.py` | simulated events | Testing pipeline |

**Recommended thesis demo command:**
```bash
sudo .venv/bin/python3 scripts/live_demo_with_attacks.py --minutes 3 --attacks 300
```
- Captures ~1000+ real packets from home WiFi
- Injects 300 labeled attacks (all types)
- ML model detects attacks → predictions appended to `iot-radar-predictions`
- SOC dashboard updates automatically — no Kibana changes needed
- Each run accumulates — more data = more impressive demo

## Overview
A local IoT network monitoring system that collects device logs, detects potential attacks, enriches threat data via Shodan, and classifies attacks using ML mapped to MITRE ATT&CK. Built with Data Engineering pipelines and Cybersecurity principles. Fully Dockerized so anyone can replicate it.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     DATA SOURCES                                │
│                                                                 │
│  ┌──────────┐  ┌──────────┐  ┌───────────────┐                │
│  │  Router   │  │ Real IoT │  │  Simulated    │                │
│  │  Logs     │  │ Device   │  │  Attack Logs  │                │
│  │  (WiFi)   │  │ Traffic  │  │  (generated)  │                │
│  └─────┬─────┘  └─────┬────┘  └──────┬────────┘                │
│        └───────────┬───┴─────────────┘                          │
│                    ▼                                            │
│  ┌─────────────────────────────┐                                │
│  │       FILEBEAT              │                                │
│  │  Collects & ships logs      │                                │
│  └──────────────┬──────────────┘                                │
│                 ▼                                                │
│  ┌─────────────────────────────┐                                │
│  │       LOGSTASH              │                                │
│  │  Parses, filters, enriches  │                                │
│  │  + Shodan API enrichment    │                                │
│  └──────────────┬──────────────┘                                │
│                 ▼                                                │
│  ┌─────────────────────────────┐                                │
│  │     ELASTICSEARCH           │                                │
│  │  Stores & indexes all data  │                                │
│  └───────┬─────────────┬───────┘                                │
│          ▼             ▼                                        │
│  ┌──────────────┐ ┌────────────────────┐                        │
│  │   KIBANA     │ │  PYTHON ML SERVICE  │                       │
│  │  Dashboards  │ │  Attack classifier  │                       │
│  │  Alerts      │ │  MITRE ATT&CK map  │                       │
│  │  Maps        │ │  Shodan enrichment  │                       │
│  └──────────────┘ └────────────────────┘                        │
│                                                                 │
│  All wrapped in Docker Compose + mTLS encryption                │
└─────────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Foundation (Days 1-4) — COMPLETE

**Goal:** Get the core pipeline running in Docker

### 1.1 Docker Compose — Elastic Stack
- [x] Elasticsearch container with TLS (PEM certs, xpack security)
- [x] Kibana container connected to Elasticsearch (kibana_system user)
- [x] Logstash container with beats input + mTLS
- [x] Filebeat container shipping NDJSON logs
- [x] All communicating over encrypted channels (wildcard *.local cert)
- [x] Single `docker-compose up` to start everything

### 1.2 Verify Pipeline Works
- [x] Ship sample logs through the full pipeline (15 NDJSON events)
- [x] Confirm data appears in Elasticsearch (verified: 15 docs in `iot-radar-2026.02.16`)
- [ ] Create Data View in Kibana for `iot-radar-*` index pattern
- [ ] Basic exploration in Kibana Discover

### Bugs Fixed During Phase 1
1. **PKCS#12 truststore error** — Elasticsearch couldn't read CA chain from PKCS#12. Fixed by switching to PEM files.
2. **Filebeat "unknown command container"** — Docker entrypoint issue. Fixed with explicit `command: filebeat -e --strict.perms=false`.
3. **Port 5044 conflict** — Homebrew Logstash was still running from book exercises. Fixed with `pkill -f logstash`.
4. **Dual pipeline configs** — Logstash Docker image ships with default `logstash.conf` in the pipeline dir. Our file was loaded alongside it, causing two beats inputs competing for port 5044. Fixed by mounting our entire `conf.d/` directory as the pipeline dir.

### Files Created
```
iot-security-radar/
├── docker-compose.yml              # All 4 services + network + volume
├── elasticsearch/
│   └── elasticsearch.yml           # TLS with PEM, single-node, xpack security
├── kibana/
│   └── kibana.yml                  # Connects to ES via kibana_system user
├── logstash/
│   ├── logstash.yml                # Node settings, monitoring disabled
│   └── conf.d/
│       └── pipeline.conf           # beats input (mTLS) → mutate → ES output + stdout
├── filebeat/
│   └── filebeat.yml                # filestream input (NDJSON) → logstash output (TLS)
├── sample-logs/
│   └── network_traffic.json        # 15 events: normal traffic + port scan from 10.0.0.50
└── tls/
    ├── ca-chain.cert.pem           # Root + Intermediate CA chain
    ├── wildcard.local.flex.cert.pem
    ├── wildcard.local.flex.key.nopass.pem
    ├── wildcard.local.flex.key.pem
    └── wildcard.local.flex.pkcs12
```

### Thesis Angle — Ch: Architecture & Infrastructure
1. **Describe the ELK/Elastic Stack architecture** — role of each component (Filebeat as lightweight shipper, Logstash as transformation engine, Elasticsearch as search/analytics store, Kibana as visualization layer). Compare with alternative SIEM stacks (Splunk, Graylog, Wazuh).
2. **Explain mTLS (mutual TLS) and why it matters for IoT security** — in a standard TLS handshake only the server proves identity; in mTLS both sides authenticate. This prevents rogue devices from injecting fake logs into the pipeline. Discuss the PKI hierarchy: Root CA → Intermediate CA → wildcard server cert.
3. **Compare encrypted vs unencrypted log pipelines** — what happens if an attacker intercepts log traffic? They could tamper with evidence, inject false alerts, or exfiltrate sensitive data. Cite real-world examples (e.g., SolarWinds attack tampered with logs).
4. **Docker as infrastructure-as-code** — reproducibility, isolation, version pinning. Why containerization matters for security tooling (consistent environments, no "works on my machine").
5. **Diagram:** Include the architecture diagram above. Explain data flow step by step with a real example event (e.g., a port scan from 10.0.0.50 traveling through each component).

---

## Phase 2: Real Data Collection (Days 5-8) — ✅ COMPLETE

**Goal:** Collect real data from your home network

### 2.1 Router Log Collection
- [x] ZTE AR5344 ISP router — limited logging, decided against syslog approach
- [x] Using tshark on Mac as primary data source instead

### 2.2 Network Traffic Capture
- [x] tshark installed on Mac
- [x] 265 real WiFi traffic events captured → indexed to `tshark-live`
- [x] Structured NDJSON format → Filebeat → Logstash → Elasticsearch

### 2.3 IoT Device Inventory
- [ ] Formal device inventory index in Elasticsearch — still TODO
- [ ] MAC address → device name mapping — still TODO

### Thesis Angle — Ch: Data Sources & IoT Network Analysis
1. **IoT device fingerprinting** — how to identify devices on a network by MAC address OUI (manufacturer prefix), DHCP hostname, traffic patterns, and mDNS/SSDP broadcasts. Discuss passive vs active fingerprinting techniques.
2. **Why home networks are vulnerable** — flat network topology (no segmentation), default credentials on IoT devices, no monitoring by default, devices rarely updated. Compare with enterprise networks that have VLANs, IDS, and dedicated SOC teams.
3. **Data collection challenges** — ISP routers have limited logging, IoT devices use proprietary protocols, encrypted traffic hides payload content, high volume of benign traffic drowns out anomalies. Discuss how our pipeline solves this (Filebeat as lightweight collector, Logstash for filtering noise).
4. **Network metadata vs content** — explain why we capture metadata (who talks to whom, how much, which ports) not payload content. This is both privacy-respecting and legally safer. Cite: NetFlow/IPFIX standards used by enterprise networks.
5. **Device inventory as security baseline** — you can't detect unauthorized devices without knowing what's authorized. Discuss the concept of "asset inventory" as NIST CSF foundation.

**Mini-tutorial needed:** tcpdump/tshark basics, syslog protocol

---

## Phase 3: Attack Simulation (Days 9-12) — ✅ COMPLETE

**Goal:** Generate realistic attack data and detect it

### 3.1 Simulated Attack Log Generator (Python)
- [x] Python script generates realistic attack logs in NDJSON format
- [x] Attack types implemented:
  - **Port scanning** (Nmap-style) — MITRE T1046
  - **Brute force SSH/HTTP** — MITRE T1110
  - **DNS exfiltration** — MITRE T1048
  - **ARP spoofing** (MitM) — MITRE T1557
  - **DDoS / flood** — MITRE T1498
  - **Unauthorized device joining network** — MITRE T1200
- [x] 5,000 events indexed to `simulated` (90/10 normal/attack split)
- [x] All events tagged with MITRE ATT&CK tactic + technique IDs
- [x] 14 attack types, 11 MITRE techniques, 7 MITRE tactics total across all sources

### 3.2 Benchmark Dataset Integration (NF-ToN-IoT-v2)
- [x] NF-ToN-IoT-v2 CSVs downloaded to `datasets/toniot/` (train 13.5M + test 3.4M rows)
- [x] Adapter script `scripts/adapt_toniot.py` built and run
- [x] 50,000 events indexed to `toniot_benchmark` (balanced 50/50)
- [x] Logstash pipeline updated to clean wrapper fields + set attack field defaults

### 3.3 Optional: Real Mini-Attacks (safe, local only)
- [ ] Nmap scan of own network — not done yet, still optional

### Thesis Angle — Ch: Threat Modeling & MITRE ATT&CK Framework
1. **MITRE ATT&CK framework explained** — what it is (knowledge base of adversary tactics and techniques), how it's organized (Tactics = WHY, Techniques = HOW), why it's the industry standard. Include a table mapping each simulated attack to its Tactic → Technique → Sub-technique.
2. **Why IoT devices are targeted** — weak default passwords, long patch cycles, always-on connectivity, often on the same subnet as valuable assets (PCs). Cite Mirai botnet (2016) — 600k IoT devices used for DDoS. Cite recent IoT CVEs.
3. **Simulated vs real attack data** — discuss trade-offs. Real attacks are noisy and hard to label; simulated data has perfect labels but may not capture real-world complexity. Our approach: use simulation for training, validate with real Nmap scans. Cite academic papers on synthetic IDS datasets (NSL-KDD, CICIDS2017).
4. **Benchmark dataset: NF-ToN-IoT-v2 (UNSW)** — in addition to our simulated data, we incorporate the NF-ToN-IoT-v2 benchmark dataset (Sarhan et al., 2022) from UNSW Canberra Cyber Range Lab. Key points for thesis:
   - **What it is:** 16.9 million labeled NetFlow records from a realistic IoT/IIoT testbed with 43 extended NetFlow features. Contains 9 attack types (scanning, DoS, DDoS, password cracking, XSS, injection, backdoor, ransomware, MITM) plus benign traffic.
   - **Why it's valuable:** (a) Widely cited academic benchmark — results are comparable with published research; (b) Collected from real IoT devices (fridge, thermostat, garage door, GPS tracker, etc.) — not just simulated; (c) Covers attack types beyond our simulation (XSS, injection, ransomware, backdoor) — broadens the classifier's detection capability; (d) 16.9M rows gives the ML model real statistical power.
   - **How we adapted it:** Built `scripts/adapt_toniot.py` that maps NF-ToN-IoT-v2 NetFlow columns (IPV4_SRC_ADDR, L4_SRC_PORT, IN_BYTES, etc.) to our unified NDJSON schema, adds MITRE ATT&CK tags per attack type, and infers direction/action from IP ranges. The adapter supports balanced sampling for training.
   - **3-layer training data strategy:** (1) Our simulated data = perfect labels, custom IoT topology, controlled ratios; (2) NF-ToN-IoT-v2 benchmark = real-world traffic, academic credibility; (3) Optionally real Nmap scans from our own network = ground truth validation. This combination addresses the weaknesses of any single data source.
   - **Cite:** Sarhan, M., Layeghy, S., & Portmann, M. (2022). "Towards a Standard Feature Set for Network Intrusion Detection System Datasets." *Mobile Networks and Applications.* Also cite the original TON_IoT paper: Moustafa, N. (2021). "A new distributed architecture for evaluating AI-based security systems at the edge." *IEEE IoT Journal.*
   - **Source:** https://staff.itee.uq.edu.au/marius/NIDS_datasets/ and https://huggingface.co/datasets/Nora9029/NF-ToN-IoT-v2
5. **Attack taxonomy for IoT** — map the 6 attack types to the IoT kill chain: Reconnaissance (port scan) → Initial Access (brute force) → Lateral Movement (ARP spoof) → Exfiltration (DNS exfil) → Impact (DDoS). Show how each attack manifests differently in network traffic patterns.
6. **Normal vs attack traffic ratio** — discuss why 90/10 split matters for ML. Imbalanced classes in real-world IDS. Cite: base rate fallacy in intrusion detection (Axelsson, 2000).

**Mini-tutorial needed:** MITRE ATT&CK basics, common IoT attack vectors

---

## Phase 4: Threat Intelligence Enrichment (Days 10-13) — ❌ NOT STARTED

**Goal:** Enrich attack data with external intelligence

### 4.1 Shodan Integration (Python)
- [ ] Python service that queries Shodan API for attacker IPs
- [ ] Returns: open ports, services, OS, geolocation, known vulnerabilities
- [ ] Cache results to avoid API rate limits
- [ ] Store enriched data back in Elasticsearch

### 4.2 Logstash Enrichment
- [ ] GeoIP filter — map attacker IPs to geographic locations
- [ ] DNS reverse lookup — resolve IPs to hostnames
- [ ] Abuse database lookup — check if IP is known malicious

### 4.3 Kibana Geo Visualization
- [ ] World map showing attack source locations
- [ ] Dashboard showing top attacking IPs with Shodan context

### Thesis Angle — Ch: Open Source Intelligence & Threat Enrichment
1. **OSINT (Open Source Intelligence) defined** — publicly available data used for security analysis. Explain the intelligence cycle: Collection → Processing → Analysis → Dissemination. Our pipeline automates all four stages.
2. **Shodan as a threat intelligence source** — what Shodan indexes (every internet-facing device), what data it returns (open ports, services, OS, geolocation, known CVEs). Discuss ethical considerations: Shodan exposes vulnerable devices — is that helpful or harmful?
3. **GeoIP enrichment** — how MaxMind/GeoLite2 databases map IP addresses to physical locations. Limitations: VPNs, Tor, CDNs distort location data. Accuracy varies by country. Despite limitations, geographic patterns reveal attack campaigns (e.g., attacks concentrated from specific ASNs).
4. **IP reputation databases** — AbuseIPDB, AlienVault OTX, VirusTotal. How to combine multiple sources for confidence scoring. Discuss false positive rates — legitimate scanning services (Shodan itself, Censys) appear as "attackers."
5. **Enrichment as a Data Engineering pipeline** — compare with data warehouse enrichment (joining fact tables with dimension tables). Our Logstash GeoIP filter is like a JOIN operation. Shodan lookup is like an API-based dimension table. Discuss caching strategies for rate-limited APIs.

**Mini-tutorial needed:** Shodan API, GeoIP databases

---

## Phase 5: ML Attack Classification (Days 11-15) — ✅ COMPLETE

**Goal:** Classify attacks and map to MITRE ATT&CK

### 5.1 Feature Engineering (Python/Pandas)
- [x] Data pulled from Elasticsearch using Python client (v8.x — must NOT use v9)
- [x] Features engineered from network traffic fields
- [x] Labels from attack tags in all 3 data sources

### 5.2 Classification Model
- [x] Random Forest classifier — 97% accuracy, 9 classes
- [x] Model artifacts saved to `ml/model/`
- [x] Python venv at `.venv/` (pandas, sklearn, xgboost, elasticsearch, matplotlib)

### 5.3 MITRE ATT&CK Mapping
- [x] Each predicted class maps to MITRE technique + tactic
- [x] 55,280 predictions indexed to `iot-radar-predictions`

### 5.4 Real-time Scoring (stretch goal)
- [ ] Flask/FastAPI microservice — NOT DONE, still a stretch goal

### Thesis Angle — Ch: Machine Learning for Intrusion Detection
1. **ML-based IDS vs signature-based IDS** — Signature-based (like Snort/Suricata) matches known attack patterns — fast but can't detect new attacks. ML-based learns patterns from data — can detect novel attacks but may produce false positives. Our system: ML classification as a complement to rule-based detection. Cite: Buczak & Guven (2016) survey of ML for IDS.
2. **Feature engineering for network traffic** — explain why raw packets aren't useful for ML. We extract features: bytes_sent/received ratio (asymmetric = suspicious), port numbers (well-known vs ephemeral), protocol distribution, connection frequency per source IP, time-of-day patterns, device_type. Discuss which features are most discriminative (this is your feature importance analysis).
3. **Multi-class classification approach** — why multi-class (7 classes) instead of binary (attack/normal). Discuss: Random Forest vs XGBoost vs neural network trade-offs. RF = interpretable + fast; XGBoost = better accuracy; NN = overkill for tabular data. Justify your model choice.
4. **Model evaluation for security context** — precision vs recall trade-off is critical in IDS. High recall = catch all attacks but many false alarms (alert fatigue). High precision = fewer false alarms but missed attacks. Discuss per-class metrics: missing a DDoS is worse than missing a port scan. Include confusion matrix, ROC curves, PR curves.
5. **Feature importance analysis** — this is the thesis highlight. Which network features matter most for detecting each attack type? Port scan detection relies on dest_port diversity; brute force on connection frequency; DDoS on bytes_sent volume. Present SHAP values or RF feature importances as thesis figures.
6. **MITRE ATT&CK mapping** — each ML prediction maps to a specific technique ID. Discuss confidence thresholds: when is a prediction confident enough to trigger an alert? Include a mapping table in the thesis.

**Mini-tutorial needed:** Elasticsearch Python client, model evaluation metrics

---

## Phase 6: Kibana Dashboards & Alerts (Days 14-17) — 🔄 IN PROGRESS (~25%)

**Goal:** Build the visual "IoT Security Radar"

### 6.1 Dashboards
- [x] Basic overview dashboard built (5 visualizations)
- [ ] **Overview:** Enhanced — total events, attack ratio, timeline with drill-down
- [ ] **Device Inventory:** All IoT devices, status, last seen
- [ ] **Attack Dashboard:** Attack types over time, severity distribution
- [ ] **Geo Map:** World map of attack source IPs (needs Phase 4 GeoIP first)
- [ ] **MITRE ATT&CK Heatmap:** Which techniques are most common
- [ ] **ML Insights:** Model confidence, classification breakdown, feature importances
- [ ] **Shodan Intel:** Top attacker profiles, exposed services (needs Phase 4)

### 6.2 Alerts
- [ ] Kibana alerting rules for:
  - New unknown device joins network
  - Port scan detected
  - Brute force attempt threshold exceeded
  - High-confidence attack classification

### Thesis Angle — Ch: Security Operations & Visualization
1. **SOC (Security Operations Center) concepts** — what a SOC does (monitor, detect, respond), the role of SIEM (Security Information and Event Management) tools. Our Kibana dashboards replicate a mini-SOC for a home IoT network. Compare with enterprise SIEMs (Splunk, QRadar, Elastic SIEM).
2. **Dashboard design for security analysts** — not every chart is useful. Discuss: overview dashboards (high-level KPIs) vs investigation dashboards (drill-down into specific events). Cite: Tufte's principles of information design. Our dashboards follow the "detection → triage → investigation" workflow.
3. **Alert fatigue problem** — too many alerts = analysts ignore them all. Cite studies: average SOC receives 10,000+ alerts/day, 50%+ are false positives. Our solution: ML confidence scoring reduces noise. Only high-confidence classifications trigger alerts. Discuss alert threshold tuning.
4. **MITRE ATT&CK heatmap visualization** — present attack coverage as a matrix (Tactics on X axis, Techniques on Y). Show which attack categories are most common in our data. This visual is standard in threat intelligence reports and impressive in a thesis.
5. **Geo-map of attack origins** — Kibana's Maps feature shows attack source IPs on a world map. Discuss what geographic patterns reveal about attack campaigns (botnets, nation-state actors, scanning services). Include screenshots in thesis.
6. **Real-time vs historical analysis** — Kibana supports both. Discuss the value of real-time monitoring (catch attacks in progress) vs historical analysis (identify trends, post-incident forensics).

---

## Phase 7: Dockerize Everything (Days 16-18) — ❌ NOT STARTED (~10% — Docker runs but no polish)

**Goal:** One-command deployment for anyone

### 7.1 Docker Compose
- [x] All core services running in docker-compose.yml (done in Phase 1)
- [ ] Auto-generate TLS certificates on first run
- [ ] Pre-loaded Kibana dashboards (saved objects export)
- [ ] Sample data generator runs on startup
- [ ] Health checks for all services
- [ ] README with setup instructions

### Thesis Angle — Ch: Reproducible Security Infrastructure
1. **Infrastructure as Code (IaC)** — the entire system is defined in config files (docker-compose.yml, YAML configs, pipeline configs). Anyone can clone the repo and `docker compose up` to get a working IoT security monitoring system. Compare with manual server setup — error-prone, not reproducible.
2. **TLS certificate automation** — discuss the challenge of PKI at scale. In production, tools like Let's Encrypt, cert-manager (Kubernetes), or HashiCorp Vault automate certificate issuance. Our `generate-certs.sh` script demonstrates the concept. Discuss certificate rotation and expiration monitoring.
3. **Container security considerations** — Docker containers run as isolated processes, but are NOT a security boundary. Discuss: least-privilege (don't run as root unless needed), read-only mounts (`:ro`), secrets management (don't hardcode passwords in docker-compose.yml — use `.env` files or Docker secrets).
4. **Reproducibility for academic work** — discuss why reproducibility matters in security research. Other researchers can verify findings by running the same system. Compare with academic papers that describe tools but don't provide code. Cite: reproducibility crisis in CS research.
5. **Deployment options beyond Docker** — briefly mention Kubernetes (for scaling to enterprise), cloud-managed Elastic (Elastic Cloud), and how the architecture would adapt. This shows awareness of real-world deployment considerations.

### 7.2 Final GitHub Repository Structure
```
iot-security-radar/
├── docker-compose.yml
├── README.md
├── .env.example
├── tls/
│   └── generate-certs.sh          # Auto-generates all TLS certs
├── elasticsearch/
│   └── elasticsearch.yml
├── kibana/
│   └── kibana.yml
├── logstash/
│   └── conf.d/
│       └── pipeline.conf
├── filebeat/
│   └── filebeat.yml
├── ml/
│   ├── train_model.py             # Training script
│   ├── serve_model.py             # Flask/FastAPI scoring service
│   ├── features.py                # Feature engineering
│   └── model/                     # Saved model artifacts
├── data-generator/
│   ├── generate_normal_traffic.py
│   ├── generate_attacks.py
│   └── shodan_enricher.py
├── dashboards/
│   └── kibana-export.ndjson       # Pre-built dashboards
└── docs/
    └── architecture.md
```

---

## Stretch Goals (if time permits)
- [ ] **Wazuh integration** — open-source SIEM agent for deeper host monitoring
- [ ] **Suricata/Zeek** — real IDS/network analyzer instead of just tcpdump
- [ ] **Anomaly detection** — unsupervised ML (Isolation Forest) for zero-day detection
- [ ] **Slack/email alerts** — send notifications when attacks detected
- [ ] **Elastic Agent + Fleet** — managed agent deployment via Kibana
- [ ] **Real Shodan data** — if you have a Shodan API key
- [ ] **CI/CD pipeline** — GitHub Actions to test Docker build

---

## Thesis Chapter Mapping

| Project Phase | Thesis Chapter |
|---|---|
| Phase 1: Foundation | Ch: Architecture & Infrastructure (mTLS, Elastic Stack, Docker) |
| Phase 2: Data Collection | Ch: Data Sources & IoT Network Analysis |
| Phase 3: Attack Simulation | Ch: Threat Modeling & MITRE ATT&CK Framework |
| Phase 4: Threat Intel | Ch: Open Source Intelligence & Threat Enrichment |
| Phase 5: ML Classification | Ch: Machine Learning for Intrusion Detection |
| Phase 6: Dashboards | Ch: Security Operations & Visualization |
| Phase 7: Docker | Ch: Reproducible Security Infrastructure |

---

## Tools Summary

| Tool | Role | You know it? |
|---|---|---|
| Docker Compose | Orchestration | Fairly familiar |
| Elasticsearch | Data storage & search | Learning (this book) |
| Kibana | Visualization & dashboards | Learning (this book) |
| Logstash | Log processing & enrichment | Learning (this book) |
| Filebeat | Log collection & shipping | Learning (this book) |
| Python | ML, data gen, Shodan client | Expert |
| scikit-learn / XGBoost | Attack classification | Expert |
| Pandas | Feature engineering | Expert |
| Shodan API | Threat intelligence | New — simple REST API |
| tcpdump / tshark | Network capture | New — will tutorial |
| MITRE ATT&CK | Attack classification framework | Familiar (from book) |
| Git / GitHub | Version control & sharing | Familiar |

---

## Resolved Questions
1. **Router:** ZTE AR5344 (ISP-provided) — limited logging, will use tcpdump/tshark on Mac as primary data source. Router logs as bonus if available.
2. **Shodan:** No account yet — will set up free tier (100 queries/month, enough for project)
3. **Thesis format:** To be decided later
4. **Thesis language:** To be decided later
5. **ML skills:** Expert (former Data Scientist) — can go deep on classification
6. **Python:** Expert
7. **Docker:** Fairly familiar
8. **Elastic Stack:** Learning via book, enough for project

---

## How to Resume Work
1. Start containers: `cd ~/iot-security-radar && docker compose up -d`
2. Wait ~30s for Elasticsearch healthcheck to pass
3. Verify: `curl -s -k -u elastic:changeme https://localhost:9200/_cluster/health`
4. Open Kibana: `http://localhost:5601` (login: `elastic` / `changeme`)
5. Check data: `curl -s -k -u elastic:changeme "https://localhost:9200/iot-radar-*/_count"`

---

## Dissertation Bibliography — Starting Point

> **Note:** All citations below should be verified before use in the final dissertation.
> Recommended tools: [Semantic Scholar](https://www.semanticscholar.org), [Google Scholar](https://scholar.google.com), [IEEE Xplore](https://ieeexplore.ieee.org)
> ✅ = already cited in project plan notes | ⚠️ = verify DOI extra carefully

---

### Already Referenced in Project Notes ✅

1. **Axelsson, S.** (2000). "The Base-Rate Fallacy and the Difficulty of Intrusion Detection." *ACM Transactions on Information and System Security (TISSEC)*, 3(3), 186–205. DOI: `10.1145/357830.357849`
   - *Use for: why ML-IDS false positive rates matter; imbalanced class ratios in training data*

2. **Buczak, A.L. & Guven, E.** (2016). "A Survey of Data Mining and Machine Learning Methods for Cyber Security Intrusion Detection." *IEEE Communications Surveys & Tutorials*, 18(2), 1153–1176. DOI: `10.1109/COMST.2015.2494502`
   - *Use for: ML-IDS survey, justifying Random Forest choice*

3. **Moustafa, N.** (2021). "A New Distributed Architecture for Evaluating AI-Based Security Systems at the Edge: Network TON_IoT Datasets." *Sustainable Cities and Society*, 72, 102994. DOI: `10.1016/j.scs.2021.102994`
   - *Use for: original ToN-IoT dataset paper*

4. **Sarhan, M., Layeghy, S., & Portmann, M.** (2022). "Towards a Standard Feature Set for Network Intrusion Detection System Datasets." *Mobile Networks and Applications*, 27, 357–370. DOI: `10.1007/s11036-021-01843-0`
   - *Use for: NF-ToN-IoT-v2 features, standardized NetFlow fields*

5. **Sarhan, M., Layeghy, S., Moustafa, N., & Portmann, M.** (2022). "NetFlow Datasets for Machine Learning-Based Network Intrusion Detection Systems." In *Big Data Technologies and Applications* (BDTA/WiCON 2020), Springer LNICST. DOI: `10.1007/978-3-030-72802-1_9`
   - *Use for: NF-ToN-IoT-v2 dataset — companion paper to above*

---

### Ch: Machine Learning for Intrusion Detection

6. **Sommer, R. & Paxson, V.** (2010). "Outside the Closed World: On Using Machine Learning for Network Intrusion Detection." *IEEE Symposium on Security and Privacy*, 305–316. DOI: `10.1109/SP.2010.25`
   - *Use for: why lab accuracy ≠ real-world IDS performance; pitfalls of ML-IDS. Great counterpoint to our 97% RF accuracy claim.*

7. **Khraisat, A., Gondal, I., Vamplew, P., & Kamruzzaman, J.** (2019). "Survey of Intrusion Detection Systems: Techniques, Datasets and Challenges." *Cybersecurity*, 2(20). DOI: `10.1186/s42400-019-0038-7`
   - *Use for: modern IDS survey, signature-based vs ML-based comparison*

8. **Liao, H.-J., Lin, C.-H.R., Lin, Y.-C., & Tung, K.-Y.** (2013). "Intrusion Detection System: A Comprehensive Review." *Journal of Network and Computer Applications*, 36(1), 16–24. DOI: `10.1016/j.jnca.2012.09.004`
   - *Use for: background on IDS categories and history*

---

### Ch: IoT Security — Device Threats & Attack Detection

9. **Frustaci, M., Pace, P., Aloi, G., & Fortino, G.** (2018). "Evaluating Critical Security Issues of the IoT World: Present and Future Challenges." *IEEE Internet of Things Journal*, 5(4), 2483–2495. DOI: `10.1109/JIOT.2017.2767291`
   - *Use for: why IoT devices are vulnerable (weak passwords, no patches, always-on)*

10. **Anthi, E., Williams, L., Słowińska, M., Theodorakopoulos, G., & Burnap, P.** (2019). "A Supervised Intrusion Detection System for Smart Home IoT Devices." *IEEE Internet of Things Journal*, 6(5), 9042–9053. DOI: `10.1109/JIOT.2019.2926365`
    - *Use for: directly comparable project — supervised IDS for home IoT. Very relevant.*

11. **Diro, A.A. & Chilamkurti, N.** (2018). "Distributed Attack Detection Scheme Using Deep Learning Approach for Internet of Things." *Future Generation Computer Systems*, 82, 761–768. DOI: `10.1016/j.future.2017.08.043`
    - *Use for: IoT attack detection with ML; compare with our RF approach*

---

### Ch: Threat Modeling & MITRE ATT&CK

12. **Strom, B.E., Applebaum, A., Miller, D.P., Nickels, K.C., Pennington, A.G., & Thomas, C.B.** (2018). *MITRE ATT&CK: Design and Philosophy.* MITRE Technical Report MTR180108. URL: `https://attack.mitre.org/docs/ATTACK_Design_and_Philosophy_March_2020.pdf`
    - *Use for: primary citation for MITRE ATT&CK framework itself*

13. **Xiong, W., Legrand, E., Åberg, O., & Lagerström, R.** (2022). "Cyber Security Threat Modeling Based on the MITRE Enterprise ATT&CK Matrix." *Software and Systems Modeling*, 21, 157–177. DOI: `10.1007/s10270-021-00898-7`
    - *Use for: practical application of ATT&CK matrix in threat modeling*

14. **Georgiadou, A., Mouzakitis, S., & Askounis, D.** (2021). "Assessing MITRE ATT&CK Risk Using a Cyber-Security Culture Framework." *Sensors*, 21(9), 3267. DOI: `10.3390/s21093267`
    - *Use for: MITRE ATT&CK risk assessment angle*

---

### Ch: Benchmark Datasets — Supporting NF-ToN-IoT-v2 Choice

15. **Sharafaldin, I., Lashkari, A.H., & Ghorbani, A.A.** (2018). "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization." *Proceedings of ICISSP 2018*, 108–116. DOI: `10.5220/0006639801080116`
    - *The CICIDS2017 paper. Use for: comparing benchmark datasets, justifying why we chose NF-ToN-IoT-v2*

16. **Tavallaee, M., Bagheri, E., Lu, W., & Ghorbani, A.A.** (2009). "A Detailed Analysis of the KDD CUP 99 Data Set." *IEEE Symposium on Computational Intelligence for Security and Defense Applications (CISDA)*. DOI: `10.1109/CISDA.2009.5356528`
    - *The NSL-KDD paper. Use for: history of IDS datasets, limitations of early datasets*

17. **Moustafa, N. & Slay, J.** (2015). "UNSW-NB15: A Comprehensive Data Set for Network Intrusion Detection Systems." *Military Communications and Information Systems Conference (MilCIS)*. DOI: `10.1109/MilCIS.2015.7348942`
    - *Use for: UNSW-NB15 dataset background — same lab as ToN-IoT*

18. **Ring, M., Wunderlich, S., Scheuring, D., Landes, D., & Hotho, A.** (2019). "A Survey of Network-Based Intrusion Detection Data Sets." *Computers & Security*, 86, 147–167. DOI: `10.1016/j.cose.2019.06.005`
    - *Use for: comprehensive survey of all IDS datasets — great for justifying dataset selection*

---

### Ch: Security Operations & Visualization (SOC, Alert Fatigue)

19. **Vielberth, M., Böhm, F., Fichtinger, I., & Pernul, G.** (2020). "Security Operations Center: A Systematic Study and Open Challenges." *IEEE Access*, 8, 227756–227779. DOI: `10.1109/ACCESS.2020.3045514`
    - *Use for: alert fatigue, SOC workflows, dashboard design justification*

20. **Bhatt, S., Manadhata, P.K., & Zomlot, L.** (2014). "The Operational Role of Security Information and Event Management Systems." *IEEE Security & Privacy*, 12(5), 35–41. DOI: `10.1109/MSP.2014.103`
    - *Use for: SIEM concept — why Elastic Stack as SIEM is valid; what SIEMs do*

---

### Ch: Architecture & mTLS / PKI for IoT

21. **Granjal, J., Monteiro, E., & Silva, J.S.** (2015). "Security for the Internet of Things: A Survey of Existing Protocols and Open Research Issues." *IEEE Communications Surveys & Tutorials*, 17(3), 1294–1312. DOI: `10.1109/COMST.2015.2388550`
    - *Use for: IoT security protocols survey, justifying mTLS choice*

22. **Rescorla, E.** (2018). *The Transport Layer Security (TLS) Protocol Version 1.3.* RFC 8446, IETF. URL: `https://tools.ietf.org/html/rfc8446`
    - *Use for: normative TLS reference; cite when explaining mTLS handshake*

23. **Garcia-Morchon, O., Kumar, S., & Sethi, M.** (2019). *Internet of Things (IoT) Security: State of the Art and Challenges.* RFC 8576, IETF. URL: `https://tools.ietf.org/html/rfc8576`
    - *Use for: IoT security challenges at the protocol level*

---

### Ch: OSINT & Threat Enrichment (Shodan, GeoIP)

24. **Durumeric, Z., Wustrow, E., & Halderman, J.A.** (2013). "ZMap: Fast Internet-Wide Scanning and Its Security Applications." *Proceedings of USENIX Security 2013*, 605–620.
    - *Use for: internet-wide scanning context, Shodan's methodology background*

25. **Bou-Harb, E., Debbabi, M., & Assi, C.** (2014). "Cyber Scanning: A Comprehensive Survey." *IEEE Communications Surveys & Tutorials*, 16(3), 1496–1519. ⚠️ *Verify DOI before citing*
    - *Use for: OSINT scanning and threat intelligence gathering*

---

### Ch: Reproducible Security Infrastructure (Docker)

26. **Combe, T., Martin, A., & Di Pietro, R.** (2016). "To Docker or Not to Docker: A Security Analysis." *IEEE Cloud Computing*, 3(5), 54–62. DOI: `10.1109/MCC.2016.100`
    - *Use for: Docker security trade-offs, container isolation discussion*

27. **Sultan, S., Ahmad, I., & Dimitriou, T.** (2019). "Container Security: Issues, Challenges, and the Road Ahead." *IEEE Access*, 7, 52976–52996. DOI: `10.1109/ACCESS.2019.2911732`
    - *Use for: container security best practices (least-privilege, read-only mounts)*

28. **Bernstein, D.** (2014). "Containers and Cloud: From LXC to Docker to Kubernetes." *IEEE Cloud Computing*, 1(3), 81–84. DOI: `10.1109/MCC.2014.51`
    - *Use for: Docker background and motivation for containerization*

---

### Verification Checklist (before dissertation submission)

| # | Authors | Verified? | Notes |
|---|---------|-----------|-------|
| 1 | Axelsson 2000 | ☐ | High confidence |
| 2 | Buczak & Guven 2016 | ☐ | High confidence |
| 3 | Moustafa 2021 | ☐ | High confidence |
| 4 | Sarhan et al. 2022 (Mobile Networks) | ☐ | High confidence |
| 5 | Sarhan et al. 2022 (Springer) | ☐ | High confidence |
| 6 | Sommer & Paxson 2010 | ☐ | High confidence |
| 7 | Khraisat et al. 2019 | ☐ | High confidence |
| 8 | Liao et al. 2013 | ☐ | High confidence |
| 9 | Frustaci et al. 2018 | ☐ | High confidence |
| 10 | Anthi et al. 2019 | ☐ | High confidence |
| 11 | Diro & Chilamkurti 2018 | ☐ | High confidence |
| 12 | Strom et al. 2018 (MITRE) | ☐ | High confidence |
| 13 | Xiong et al. 2022 | ☐ | High confidence |
| 14 | Georgiadou et al. 2021 | ☐ | Medium confidence |
| 15 | Sharafaldin et al. 2018 | ☐ | High confidence |
| 16 | Tavallaee et al. 2009 | ☐ | High confidence |
| 17 | Moustafa & Slay 2015 | ☐ | High confidence |
| 18 | Ring et al. 2019 | ☐ | High confidence |
| 19 | Vielberth et al. 2020 | ☐ | High confidence |
| 20 | Bhatt et al. 2014 | ☐ | High confidence |
| 21 | Granjal et al. 2015 | ☐ | High confidence |
| 22 | Rescorla 2018 (RFC 8446) | ☐ | High confidence |
| 23 | Garcia-Morchon et al. 2019 (RFC 8576) | ☐ | High confidence |
| 24 | Durumeric et al. 2013 | ☐ | High confidence |
| 25 | Bou-Harb et al. 2014 | ☐ | ⚠️ Verify DOI |
| 26 | Combe et al. 2016 | ☐ | High confidence |
| 27 | Sultan et al. 2019 | ☐ | High confidence |
| 28 | Bernstein 2014 | ☐ | High confidence |
