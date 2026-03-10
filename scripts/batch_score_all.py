#!/usr/bin/env python3
"""
IoT Security Radar — Batch Score All Historical Events
=======================================================
Pulls all events from iot-radar-* that have NOT yet been scored
(capture_source = toniot_benchmark) and appends predictions to
iot-radar-predictions.

Run once to populate the predictions index with the full 50k benchmark dataset.

Usage:
    .venv/bin/python3 scripts/batch_score_all.py
"""

import warnings
warnings.filterwarnings("ignore")

import json
import sys
from pathlib import Path
from datetime import datetime, timezone

import numpy as np
import joblib
import pandas as pd
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

PROJECT_ROOT = Path(__file__).parent.parent
ML_DIR       = PROJECT_ROOT / "ml"
MODEL_DIR    = ML_DIR / "model"

sys.path.insert(0, str(ML_DIR))
from train_model import engineer_features, MERGE_MAP  # noqa: E402

ES_HOST    = "https://localhost:9200"
ES_USER    = "elastic"
ES_PASS    = "changeme"
PRED_INDEX = "iot-radar-predictions"

# Score only toniot_benchmark — avoids duplicating the ~2,958 already-scored demo events
SOURCES_TO_SCORE = ["toniot_benchmark"]


def connect_es():
    es = Elasticsearch(ES_HOST, basic_auth=(ES_USER, ES_PASS),
                       verify_certs=False, ssl_show_warn=False)
    version = es.info()["version"]["number"]
    print(f"  Connected to Elasticsearch {version}")
    return es


def pull_all_events(es):
    print(f"  Pulling events with capture_source in {SOURCES_TO_SCORE}...")

    query = {
        "query": {
            "terms": {"capture_source.keyword": SOURCES_TO_SCORE}
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
        print(f"  ... pulled {len(all_hits)} events")

    print(f"  Total pulled: {len(all_hits)}")
    return pd.DataFrame([h["_source"] for h in all_hits])


def score_and_append(es, df):
    print(f"\nScoring {len(df)} events...")

    model      = joblib.load(MODEL_DIR / "classifier.joblib")
    le         = joblib.load(MODEL_DIR / "label_encoder.joblib")
    with open(MODEL_DIR / "mitre_map.json") as f:
        mitre_map = json.load(f)

    if "attack_type" in df.columns:
        df["attack_type"] = df["attack_type"].replace(MERGE_MAP)

    X, _ = engineer_features(df)

    predictions = le.inverse_transform(model.predict(X))
    confidence  = np.max(model.predict_proba(X), axis=1)

    def safe(val):
        try:
            return None if pd.isna(val) else val
        except (TypeError, ValueError):
            return val

    batch_session = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    docs = []
    for i, (_, row) in enumerate(df.iterrows()):
        pred  = predictions[i]
        conf  = float(confidence[i])
        mitre = mitre_map.get(pred, mitre_map["normal"])

        docs.append({
            "timestamp":               safe(row.get("timestamp") or row.get("@timestamp")),
            "source_ip":               safe(row.get("source_ip")),
            "dest_ip":                 safe(row.get("dest_ip")),
            "source_port":             safe(row.get("source_port")),
            "dest_port":               safe(row.get("dest_port")),
            "protocol":                safe(row.get("protocol")),
            "bytes_sent":              safe(row.get("bytes_sent")),
            "bytes_received":          safe(row.get("bytes_received")),
            "device":                  safe(row.get("device")),
            "device_type":             safe(row.get("device_type")),
            "direction":               safe(row.get("direction")),
            "action":                  safe(row.get("action")),
            "capture_source":          safe(row.get("capture_source")),
            "true_attack_type":        safe(row.get("attack_type")),
            "true_attack_label":       safe(row.get("attack_label")),
            "ml_prediction":           pred,
            "ml_confidence":           round(conf, 4),
            "ml_is_attack":            pred != "normal",
            "ml_mitre_tactic":         mitre.get("tactic"),
            "ml_mitre_technique":      mitre.get("technique"),
            "ml_mitre_technique_name": mitre.get("technique_name"),
            "ml_severity":             mitre.get("severity"),
            "demo_session":            batch_session,
        })

    # Index in chunks of 2000
    print(f"  Appending {len(docs)} predictions to {PRED_INDEX}...")
    actions = [{"_index": PRED_INDEX, "_source": doc} for doc in docs]
    success, errors = bulk(es, actions, chunk_size=2000, raise_on_error=False)
    err_count = len(errors) if isinstance(errors, list) else errors
    print(f"  Appended: {success}  |  Errors: {err_count}")

    return docs


def main():
    print("=" * 58)
    print("  IoT Security Radar — Batch Score All Events")
    print("=" * 58)

    es = connect_es()

    # Check current state
    before = es.count(index=PRED_INDEX)["count"]
    print(f"\n  iot-radar-predictions before: {before:,} docs")

    df = pull_all_events(es)
    if df.empty:
        print("No events found. Is Docker running?")
        sys.exit(1)

    docs = score_and_append(es, df)

    # Summary
    attacks = [d for d in docs if d["ml_is_attack"]]
    after   = es.count(index=PRED_INDEX)["count"]

    print("\n" + "=" * 58)
    print("  DONE")
    print("=" * 58)
    print(f"  Events scored:            {len(docs):,}")
    print(f"  Attacks detected:         {len(attacks):,}")
    print(f"  iot-radar-predictions:    {after:,} total docs")
    print(f"\n  → Open Kibana: http://localhost:5601")
    print("=" * 58)


if __name__ == "__main__":
    main()
