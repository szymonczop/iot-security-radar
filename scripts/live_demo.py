#!/usr/bin/env python3
"""
IoT Security Radar — Live Demo Pipeline (WiFi traffic only)
============================================================
Full end-to-end demo:
  1. Capture real WiFi traffic for X minutes (tshark)
  2. Events flow through Filebeat → Logstash → Elasticsearch automatically
  3. ML model scores the captured events
  4. Predictions appended to iot-radar-predictions (accumulates across runs)
  5. Open Kibana to see results on the SOC dashboard

Usage:
    sudo .venv/bin/python3 scripts/live_demo.py --minutes 5

Requires:
    - Docker stack running: docker compose up -d
    - sudo (tshark needs root for promiscuous mode)
"""

import warnings
warnings.filterwarnings("ignore")

import argparse
import json
import sys
import subprocess
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import joblib
import pandas as pd
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

# ── Paths ─────────────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).parent.parent
ML_DIR = PROJECT_ROOT / "ml"
MODEL_DIR = ML_DIR / "model"
DEMO_FILE = PROJECT_ROOT / "sample-logs" / "demo_traffic.json"
CAPTURE_SCRIPT = PROJECT_ROOT / "scripts" / "capture_traffic_flows.py"

# Add ml/ to path to import feature engineering functions
sys.path.insert(0, str(ML_DIR))
from train_model import engineer_features, MERGE_MAP  # noqa: E402

# ── Config ────────────────────────────────────────────────────────────────────
ES_HOST = "https://localhost:9200"
ES_USER = "elastic"
ES_PASS  = "changeme"
PRED_INDEX = "iot-radar-predictions"


# ── Phase helpers ─────────────────────────────────────────────────────────────

def connect_es():
    """Connect to Elasticsearch and verify it's reachable."""
    es = Elasticsearch(ES_HOST, basic_auth=(ES_USER, ES_PASS),
                       verify_certs=False, ssl_show_warn=False)
    try:
        version = es.info()["version"]["number"]
        print(f"  Connected to Elasticsearch {version}")
        return es
    except Exception as e:
        print(f"  ERROR: Cannot reach Elasticsearch — {e}")
        print("  Is Docker running?  →  docker compose up -d")
        sys.exit(1)


def get_session_count(es, session_start_iso, sources):
    """Count events from this session that have arrived in Elasticsearch."""
    try:
        resp = es.count(
            index="iot-radar-*",
            body={
                "query": {
                    "bool": {
                        "must": [
                            {"terms": {"capture_source.keyword": sources}},
                            {"range": {"@timestamp": {"gte": session_start_iso}}},
                        ]
                    }
                }
            },
        )
        return resp["count"]
    except Exception:
        return 0


def wait_for_ingestion(es, session_start_iso, sources, timeout=90):
    """
    Poll Elasticsearch every 5 seconds until captured events appear and stabilise.
    Returns the final count of indexed events.
    """
    print("\nPhase 3: Waiting for events to reach Elasticsearch...")
    print("  (Filebeat reads file → ships to Logstash → indexed — usually 10-30s)")

    prev_count = -1
    stable_rounds = 0
    start_time = time.time()

    while time.time() - start_time < timeout:
        count = get_session_count(es, session_start_iso, sources)
        elapsed = int(time.time() - start_time)
        print(f"  [{elapsed:>2}s] {count} events indexed so far...")

        if count > 0 and count == prev_count:
            stable_rounds += 1
            if stable_rounds >= 2:
                print(f"  Ingestion stable — {count} events ready")
                return count
        else:
            stable_rounds = 0

        prev_count = count
        time.sleep(5)

    # Timeout — proceed with whatever arrived
    count = get_session_count(es, session_start_iso, sources)
    print(f"  Timeout reached — proceeding with {count} events")
    return count


def pull_session_events(es, session_start_iso, sources):
    """Pull only the events from this demo session out of Elasticsearch."""
    query = {
        "query": {
            "bool": {
                "must": [
                    {"terms": {"capture_source.keyword": sources}},
                    {"range": {"@timestamp": {"gte": session_start_iso}}},
                ]
            }
        },
        "_source": [
            "timestamp", "@timestamp",
            "source_ip", "dest_ip", "source_port", "dest_port",
            "protocol", "bytes_sent", "bytes_received",
            "device", "device_type", "direction", "action",
            "capture_source", "attack_type", "attack_label",
        ],
        "size": 5000,
        "sort": ["_doc"],
    }

    all_hits = []
    resp = es.search(index="iot-radar-*", body=query)
    hits = resp["hits"]["hits"]
    all_hits.extend(hits)

    while len(hits) == 5000:
        query["search_after"] = hits[-1]["sort"]
        resp = es.search(index="iot-radar-*", body=query)
        hits = resp["hits"]["hits"]
        all_hits.extend(hits)

    return pd.DataFrame([h["_source"] for h in all_hits])


def score_and_append(es, df, session_start_iso):
    """
    Run the ML model on session events and APPEND predictions to iot-radar-predictions.
    Never deletes the existing index — each run accumulates.
    """
    print(f"\nPhase 4: Running ML model on {len(df)} events...")

    # Load model artifacts
    model   = joblib.load(MODEL_DIR / "classifier.joblib")
    le      = joblib.load(MODEL_DIR / "label_encoder.joblib")
    with open(MODEL_DIR / "mitre_map.json") as f:
        mitre_map = json.load(f)

    # Apply same class merging used during training
    if "attack_type" in df.columns:
        df["attack_type"] = df["attack_type"].replace(MERGE_MAP)

    # Engineer features (reuses exact same function as training)
    X, _ = engineer_features(df)

    # Predict
    predictions  = le.inverse_transform(model.predict(X))
    confidence   = np.max(model.predict_proba(X), axis=1)

    # Build prediction documents
    def safe(val):
        try:
            return None if pd.isna(val) else val
        except (TypeError, ValueError):
            return val

    docs = []
    for i, (_, row) in enumerate(df.iterrows()):
        pred  = predictions[i]
        conf  = float(confidence[i])
        mitre = mitre_map.get(pred, mitre_map["normal"])

        doc = {
            "timestamp":             safe(row.get("timestamp") or row.get("@timestamp")),
            "source_ip":             safe(row.get("source_ip")),
            "dest_ip":               safe(row.get("dest_ip")),
            "source_port":           safe(row.get("source_port")),
            "dest_port":             safe(row.get("dest_port")),
            "protocol":              safe(row.get("protocol")),
            "bytes_sent":            safe(row.get("bytes_sent")),
            "bytes_received":        safe(row.get("bytes_received")),
            "device":                safe(row.get("device")),
            "device_type":           safe(row.get("device_type")),
            "direction":             safe(row.get("direction")),
            "action":                safe(row.get("action")),
            "capture_source":        safe(row.get("capture_source")),
            # Ground truth (may be None for real live events)
            "true_attack_type":      safe(row.get("attack_type")),
            "true_attack_label":     safe(row.get("attack_label")),
            # ML output
            "ml_prediction":         pred,
            "ml_confidence":         round(conf, 4),
            "ml_is_attack":          pred != "normal",
            "ml_mitre_tactic":       mitre.get("tactic"),
            "ml_mitre_technique":    mitre.get("technique"),
            "ml_mitre_technique_name": mitre.get("technique_name"),
            "ml_severity":           mitre.get("severity"),
            # Demo metadata — useful for filtering in Kibana
            "demo_session":          session_start_iso,
        }
        docs.append(doc)

    # APPEND to existing predictions (never delete — accumulates across runs)
    print(f"  Appending {len(docs)} predictions to {PRED_INDEX}...")
    actions = [{"_index": PRED_INDEX, "_source": doc} for doc in docs]
    success, errors = bulk(es, actions, chunk_size=500, raise_on_error=False)
    err_count = len(errors) if isinstance(errors, list) else errors
    print(f"  Appended: {success}  |  Errors: {err_count}")

    return docs


def print_summary(docs, pred_index_total, session_start_iso):
    """Print a clean summary for the live demo."""
    attacks = [d for d in docs if d["ml_is_attack"]]
    normal  = [d for d in docs if not d["ml_is_attack"]]
    attack_types = Counter(d["ml_prediction"] for d in attacks)

    print("\n" + "=" * 58)
    print("  DEMO COMPLETE")
    print("=" * 58)
    print(f"  Session:          {session_start_iso}")
    print(f"  Events scored:    {len(docs)}")
    print(f"  Normal traffic:   {len(normal)}")
    print(f"  Attacks detected: {len(attacks)}")

    if attacks:
        print(f"\n  Attack breakdown:")
        for attack, count in attack_types.most_common():
            mitre_tag = ""
            for d in attacks:
                if d["ml_prediction"] == attack and d.get("ml_mitre_technique"):
                    mitre_tag = f"  [{d['ml_mitre_technique']}]"
                    break
            print(f"    {attack:<26} {count:>4} events{mitre_tag}")

    print(f"\n  iot-radar-predictions: {pred_index_total} total docs")
    print(f"\n  → Kibana:  http://localhost:5601")
    print(f"     Dashboard: IoT Security Radar — SOC Overview")
    print("=" * 58)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="IoT Security Radar — Live Demo (real WiFi traffic only)"
    )
    parser.add_argument("--minutes", "-m", type=int, default=5,
                        help="WiFi capture duration in minutes (default: 5)")
    args = parser.parse_args()

    session_start     = datetime.now(timezone.utc)
    session_start_iso = session_start.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    capture_sources   = ["tshark-live"]

    print("=" * 58)
    print("  IoT Security Radar — Live Demo")
    print("=" * 58)

    # ── Phase 1: Setup ────────────────────────────────────────────────────────
    print("\nPhase 1: Setup...")
    es = connect_es()

    # Clear demo file so Filebeat treats all new lines as fresh
    DEMO_FILE.parent.mkdir(exist_ok=True)
    DEMO_FILE.write_text("")
    print(f"  Demo file cleared: {DEMO_FILE.name}")
    print(f"  Session start:     {session_start_iso}")

    # ── Phase 2: Capture ──────────────────────────────────────────────────────
    duration_sec = args.minutes * 60
    print(f"\nPhase 2: Capturing WiFi traffic for {args.minutes} minute(s)...")
    print("  Events are shipped to Elasticsearch in real time as they're captured.")

    capture_cmd = [
        sys.executable,
        str(CAPTURE_SCRIPT),
        "--duration", str(duration_sec),
        "--output",   str(DEMO_FILE),
    ]

    proc = subprocess.Popen(capture_cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, bufsize=1)
    try:
        for line in proc.stdout:
            line = line.strip()
            if line:
                print(f"  {line}")
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        proc.wait()
        print("\n  Capture stopped by user.")

    event_count = sum(1 for _ in DEMO_FILE.open()) if DEMO_FILE.exists() else 0
    print(f"  Capture complete: {event_count} events written")

    # ── Phase 3: Wait for ingestion ───────────────────────────────────────────
    ingested = wait_for_ingestion(es, session_start_iso, capture_sources)

    if ingested == 0:
        print("\n  No events found in Elasticsearch. Possible reasons:")
        print("    - Very little WiFi traffic (try more activity or longer capture)")
        print("    - Filebeat not running: docker compose ps")
        sys.exit(1)

    # ── Phase 4: ML Scoring ───────────────────────────────────────────────────
    df = pull_session_events(es, session_start_iso, capture_sources)
    if df.empty:
        print("  Could not retrieve events for scoring.")
        sys.exit(1)

    docs = score_and_append(es, df, session_start_iso)

    # ── Phase 5: Summary ──────────────────────────────────────────────────────
    total_preds = es.count(index=PRED_INDEX)["count"]
    print_summary(docs, total_preds, session_start_iso)


if __name__ == "__main__":
    main()
