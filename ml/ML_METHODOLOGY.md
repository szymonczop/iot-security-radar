# ML Methodology — IoT Attack Classifier

A supervised multi-class Random Forest classifier trained to detect 9 categories of network attacks in IoT traffic, with each prediction mapped to the **MITRE ATT&CK framework**.

**Pipeline:** `Elasticsearch → Pandas → Feature Engineering → Random Forest → Predictions → Elasticsearch`

---

## 1. Data Preparation

### Source

55,280 labeled network events pulled from Elasticsearch via the Python client. Events come from three sources:

| Source | Count | Description |
|--------|-------|-------------|
| `toniot_benchmark` | 50,000 | NF-ToN-IoT-v2 benchmark dataset |
| `simulated` | 5,000 | Synthetically generated attacks |
| `tshark-live` | 265 | Real WiFi captures (no ground-truth labels) |

Only the first two sources are used for training (they have ground-truth `attack_type` labels).

### Class Merging

Some attack types had too few samples for reliable training. They were merged into parent categories based on MITRE ATT&CK tactic similarity:

| Original Class | Merged Into | Rationale |
|----------------|-------------|-----------|
| `ransomware` (1 sample) | `dos` | Both map to Impact tactic |
| `mitm` (17 samples) | `brute_force` | Both map to Credential Access |
| `unauthorized_device` (20 samples) | `port_scan` | Both are reconnaissance-adjacent |
| `brute_force_ssh` (90 samples) | `brute_force` | Sub-type of T1110.001 |
| `brute_force_http` (124 samples) | `brute_force` | Sub-type of T1110.001 |

### Final Class Distribution (9 classes)

| Class | Count | % | MITRE Technique |
|-------|-------|---|-----------------|
| `normal` | 29,500 | 53.6% | — |
| `port_scan` | 8,885 | 16.2% | T1046 |
| `xss` | 5,556 | 10.1% | T1189 |
| `ddos_flood` | 4,779 | 8.7% | T1498.001 |
| `brute_force` | 2,897 | 5.3% | T1110.001 |
| `dos` | 1,690 | 3.1% | T1499.001 |
| `injection` | 1,610 | 2.9% | T1059 |
| `dns_exfiltration` | 46 | 0.1% | T1048.001 |
| `backdoor` | 37 | 0.1% | T1505.003 |

---

## 2. Feature Engineering

26 features extracted from raw network metadata, organized in 7 categories. No IP addresses are used as features — they are identifiers, not patterns.

### Port features (6)

| Feature | Description |
|---------|-------------|
| `dest_port` | Raw destination port number |
| `source_port` | Raw source port number |
| `is_privileged_port` | `dest_port < 1024` (SSH, HTTP, DNS…) |
| `is_well_known_service` | `dest_port` in {22, 23, 53, 80, 443, 445, 993, 8080, 8443, 8883} |
| `is_ephemeral_src` | `source_port >= 49152` (client-side ephemeral) |
| `port_bucket` | Categorical bin: [0–1024), [1024–5000), [5000–10000), [10000–49152), [49152–65536) |

### Byte features (5)

| Feature | Description |
|---------|-------------|
| `bytes_sent` | Raw bytes sent |
| `bytes_received` | Raw bytes received |
| `bytes_total` | `bytes_sent + bytes_received` |
| `bytes_ratio` | `bytes_sent / bytes_total` — traffic asymmetry indicator |
| `log_bytes_total` | `log(1 + bytes_total)` — reduces skewness for extreme DDoS volumes |

**Why byte features dominate (67% of total importance):**

- Normal browsing: low sent, high received → `bytes_ratio ≈ 0.1`
- Port scan: near-zero bytes both ways → `bytes_ratio ≈ 0.5`
- DNS exfiltration: high sent, low received → `bytes_ratio ≈ 0.8`
- DDoS: high sent, zero received → `bytes_ratio ≈ 1.0`

### Protocol features (3) — one-hot encoded

`proto_tcp`, `proto_udp`, `proto_icmp`

### Direction features (3) — one-hot encoded

`dir_inbound`, `dir_outbound`, `dir_internal`

### Action feature (1)

`action_allow` — binary (allow=1, deny=0). Denied connections correlate strongly with blocked attacks.

### Device type features (5) — one-hot encoded

`devtype_iot`, `devtype_computer`, `devtype_router`, `devtype_external`, `devtype_unknown`

### Data source features (3) — one-hot encoded

`src_simulated`, `src_toniot_benchmark`, `src_tshark_live`

> **Note on feature leakage:** The `src_toniot_benchmark` feature ranks #10 in importance, meaning the model partially learns dataset identity in addition to attack patterns. For a production system, remove these source features and retrain. For this research prototype, they are acceptable.

---

## 3. Model Selection

### Why Random Forest?

| Criterion | Random Forest | XGBoost | Neural Network |
|-----------|:---:|:---:|:---:|
| Handles mixed feature types | Yes | Yes | Needs scaling |
| Feature importance built-in | Yes (Gini) | Yes (gain) | No (needs SHAP) |
| Training speed (55k rows) | Fast | Fast | Slow |
| Interpretability | High | Medium | Low |
| Handles class imbalance | `class_weight="balanced"` | `scale_pos_weight` | Custom loss |
| Overfitting risk | Low (ensemble) | Medium | High |

Random Forest offers the best balance of accuracy, interpretability, and training speed for this dataset size. Gini feature importance is a key output for analysis and is provided natively.

### Hyperparameters

```python
RandomForestClassifier(
    n_estimators=200,       # 200 trees in the forest
    max_depth=20,           # prevents overfitting
    min_samples_split=5,    # minimum samples to split a node
    min_samples_leaf=2,     # minimum samples in a leaf
    class_weight="balanced",  # auto-adjusts for class imbalance
    random_state=42,
    n_jobs=-1,              # use all CPU cores
)
```

`class_weight="balanced"` computes per-class weights as `n_samples / (n_classes × n_samples_class)`. This forces equal model attention across all classes, effectively upsampling rare classes like `backdoor` (37 samples) during training.

---

## 4. Training & Evaluation

### Train / test split

- **Train:** 44,000 events (80%), stratified by class
- **Test:** 11,000 events (20%), stratified by class

Stratified split guarantees proportional class representation in both sets — critical when rare classes like `backdoor` have only 37 total samples.

### Cross-validation

5-fold cross-validation on the training set:

- **CV F1 (weighted): 0.9711 ± 0.0019**
- Very low variance (0.0019) indicates the model is stable and not overfitting to any particular data subset.

### Test set results

| Class | Precision | Recall | F1 | Support |
|-------|-----------|--------|----|---------|
| backdoor | 1.00 | 1.00 | 1.00 | 7 |
| brute_force | 0.90 | 0.88 | 0.89 | 580 |
| ddos_flood | 0.96 | 0.93 | 0.94 | 956 |
| dns_exfiltration | 1.00 | 1.00 | 1.00 | 9 |
| dos | 0.89 | 0.91 | 0.90 | 338 |
| injection | 0.74 | 0.76 | 0.75 | 322 |
| **normal** | **1.00** | **1.00** | **1.00** | **5,900** |
| port_scan | 1.00 | 0.99 | 1.00 | 1,777 |
| xss | 0.92 | 0.95 | 0.93 | 1,111 |
| **Overall accuracy** | | | **0.97** | **11,000** |
| **Weighted avg** | **0.97** | **0.97** | **0.97** | |

### Key observations

1. **Normal traffic: 100% precision and recall** — zero false positives. The model never flags legitimate traffic as an attack, eliminating alert fatigue.
2. **Port scan: 99–100%** — distinctive pattern (many connections, sequential ports, near-zero bytes).
3. **Injection: 75% F1 (lowest)** — overlaps with `brute_force` and `xss` in network-level features. All three are HTTP-based; distinguishing them requires payload analysis, which is out of scope.
4. **DDoS vs DoS** — some confusion between the two flooding attack types. The key distinction (single vs multiple source IPs) is partially captured but not definitively separable from metadata alone.

---

## 5. Feature Importance

Top 10 most important features (Gini importance):

| Rank | Feature | Importance | Interpretation |
|------|---------|------------|----------------|
| 1 | `bytes_received` | 0.154 | Response volume — browsing is high, port scans are near-zero |
| 2 | `bytes_total` | 0.114 | Total data volume — DDoS is ~100× normal |
| 3 | `bytes_sent` | 0.113 | Request volume — exfiltration sends a lot outbound |
| 4 | `log_bytes_total` | 0.107 | Log scale catches orders-of-magnitude differences |
| 5 | `action_allow` | 0.096 | Denied connections → likely blocked attack |
| 6 | `bytes_ratio` | 0.091 | Send/receive asymmetry; normal ≈ 0.1, DDoS ≈ 1.0 |
| 7 | `dest_port` | 0.075 | SSH=22 (brute force), DNS=53 (exfil), HTTP=80/443 (XSS) |
| 8 | `source_port` | 0.040 | Ephemeral ports indicate client-initiated connections |
| 9 | `proto_udp` | 0.033 | UDP → DNS exfiltration signal |
| 10 | `src_toniot_benchmark` | 0.031 | Dataset source (see leakage note above) |

The top 6 features are all byte-volume related (combined importance ≈ 0.67). The model primarily distinguishes attacks by **how much data moves**, not by port or protocol. This aligns with the network security literature: volume-based baselines are the most robust approach for network intrusion detection.

See `ml/model/feature_importance.png` for the full bar chart.

---

## 6. MITRE ATT&CK Mapping

Each ML prediction maps to a MITRE ATT&CK technique via `ml/model/mitre_map.json`:

| Predicted Class | MITRE Tactic | MITRE Technique | Severity |
|-----------------|-------------|-----------------|----------|
| `normal` | — | — | — |
| `port_scan` | Discovery | T1046 — Network Service Discovery | medium |
| `brute_force` | Credential Access | T1110.001 — Brute Force: Password Guessing | high |
| `ddos_flood` | Impact | T1498.001 — Direct Network Flood | critical |
| `dos` | Impact | T1499.001 — OS Exhaustion Flood | high |
| `dns_exfiltration` | Exfiltration | T1048.001 — Exfiltration Over Alternative Protocol | critical |
| `injection` | Execution | T1059 — Command and Scripting Interpreter | critical |
| `xss` | Initial Access | T1189 — Drive-by Compromise | high |
| `backdoor` | Persistence | T1505.003 — Web Shell | critical |

---

## 7. Predictions Index Schema

All scored events are indexed to `iot-radar-predictions` with these additional ML fields:

| Field | Type | Description |
|-------|------|-------------|
| `ml_prediction` | keyword | Predicted attack class |
| `ml_confidence` | float | Max class probability (0–1) |
| `ml_is_attack` | boolean | `true` if prediction ≠ `normal` |
| `ml_mitre_tactic` | keyword | MITRE tactic |
| `ml_mitre_technique` | keyword | MITRE technique ID |
| `ml_mitre_technique_name` | keyword | Human-readable technique name |
| `ml_severity` | keyword | Severity from MITRE mapping |
| `ml_correct` | boolean | Whether prediction matches ground truth |
| `true_attack_type` | keyword | Original ground-truth label |

### Scoring summary (55,280 events)

- Correct predictions: 53,978 (98.1%)
- Attacks detected: 25,500
- High-confidence attacks (confidence > 0.8): 21,799

---

## 8. Known Limitations

### 1. Byte feature degradation from per-packet capture

`bytes_received` is the #1 most important feature, but the per-packet tshark capture method records only `bytes_sent` and sets `bytes_received = 0`. This degrades features #1, #2, #4, and #6 (~47% of total Gini weight) for real live captures.

| Attack | Direction | Impact |
|--------|-----------|--------|
| port_scan, brute_force, ddos_flood | inbound | Low — port and bytes_sent signals survive |
| dns_exfiltration, backdoor | outbound | High — byte asymmetry is the key signal |

**Production fix:** Replace per-packet tshark capture with a flow-level collector (NetFlow, IPFIX, or sFlow). These aggregate both directions of a connection before writing the record, preserving the byte asymmetry signal.

### 2. No temporal features

Connection frequency per IP, time-of-day patterns, and burst detection are not used. These would significantly improve detection of port scans and brute force attacks in real-time scenarios.

### 3. No payload features

Only network metadata (IPs, ports, bytes) is captured. Payload analysis would improve injection and XSS detection but raises privacy and legal concerns.

### 4. Small test sets for rare classes

`backdoor` (7 test samples) and `dns_exfiltration` (9 test samples) show F1 = 1.00 in testing. These results should be interpreted cautiously given the sample size.

### 5. Feature leakage from data source

The `src_toniot_benchmark` feature ranks #10 in importance. Remove before deploying to production.

---

## 9. Extending the Model

**Add new attack types:**
1. Add labeled events to Elasticsearch
2. Update `MERGE_MAP` in `train_model.py` if needed
3. Update `MITRE_MAP` in `train_model.py` with new technique IDs
4. Re-run `ml/train_model.py` — the pipeline handles any number of classes

**Real-time scoring:**
Replace the current batch pipeline with a FastAPI microservice called by Logstash's HTTP filter plugin. The `engineer_features()` function in `train_model.py` is the reference implementation for inference.

**Zero-day detection:**
Add an Isolation Forest trained on normal traffic only to flag unknown anomalies that the supervised classifier cannot label. Combine both models: RF for known attack classification, Isolation Forest for anomaly flagging.
