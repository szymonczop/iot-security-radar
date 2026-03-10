#!/usr/bin/env python3
"""
IoT Security Radar — Score Events & Index Predictions to Elasticsearch
======================================================================
Loads the trained model, scores all events from iot-radar-*, and writes
the predictions into a new index (iot-radar-predictions) for Kibana.

Usage:
    .venv/bin/python3 ml/score_and_index.py
"""

import warnings
warnings.filterwarnings("ignore")

import json
import pandas as pd
import numpy as np
import joblib

from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
from pathlib import Path

# ── Config ────────────────────────────────────────────────────────────────────
ES_HOST = "https://localhost:9200"
ES_USER = "elastic"
ES_PASS = "changeme"
SOURCE_INDEX = "iot-radar-*"
PRED_INDEX = "iot-radar-predictions"
MODEL_DIR = Path(__file__).parent / "model"

# Import feature engineering from train_model
from train_model import engineer_features, pull_data, MERGE_MAP


def main():
    # Load model artifacts
    print("Loading model artifacts...")
    model = joblib.load(MODEL_DIR / "classifier.joblib")
    le = joblib.load(MODEL_DIR / "label_encoder.joblib")
    feature_names = joblib.load(MODEL_DIR / "feature_names.joblib")
    with open(MODEL_DIR / "mitre_map.json") as f:
        mitre_map = json.load(f)

    # Connect to Elasticsearch
    es = Elasticsearch(
        ES_HOST,
        basic_auth=(ES_USER, ES_PASS),
        verify_certs=False,
        ssl_show_warn=False,
    )
    print(f"Connected to Elasticsearch: {es.info()['version']['number']}")

    # Pull data
    df = pull_data(es, SOURCE_INDEX)

    # Merge rare classes (same as training)
    df["attack_type"] = df["attack_type"].replace(MERGE_MAP)

    # Engineer features
    X, _ = engineer_features(df)

    # Score
    print("Scoring all events...")
    predictions = le.inverse_transform(model.predict(X))
    probabilities = model.predict_proba(X)
    confidence = np.max(probabilities, axis=1)

    # Build prediction documents
    print(f"Building {len(df)} prediction documents...")

    # Helper to safely get a value from a row (handles NaN → None)
    def safe_val(val):
        if pd.isna(val):
            return None
        return val

    docs = []
    for idx, row in df.iterrows():
        pred_class = predictions[len(docs)]
        conf = confidence[len(docs)]
        mitre = mitre_map.get(pred_class, mitre_map["normal"])

        doc = {
            # Original fields — use timestamp if available, fall back to @timestamp
            "timestamp": safe_val(row.get("timestamp")) or safe_val(row.get("@timestamp")),
            "source_ip": safe_val(row.get("source_ip")),
            "dest_ip": safe_val(row.get("dest_ip")),
            "source_port": safe_val(row.get("source_port")),
            "dest_port": safe_val(row.get("dest_port")),
            "protocol": safe_val(row.get("protocol")),
            "bytes_sent": safe_val(row.get("bytes_sent")),
            "bytes_received": safe_val(row.get("bytes_received")),
            "device": safe_val(row.get("device")),
            "device_type": safe_val(row.get("device_type")),
            "direction": safe_val(row.get("direction")),
            "action": safe_val(row.get("action")),
            "capture_source": safe_val(row.get("capture_source")),
            # Ground truth
            "true_attack_type": safe_val(row.get("attack_type")),
            "true_attack_label": safe_val(row.get("attack_label")),
            # ML predictions
            "ml_prediction": pred_class,
            "ml_confidence": round(float(conf), 4),
            "ml_is_attack": pred_class != "normal",
            # MITRE ATT&CK mapping from prediction
            "ml_mitre_tactic": mitre.get("tactic"),
            "ml_mitre_technique": mitre.get("technique"),
            "ml_mitre_technique_name": mitre.get("technique_name"),
            "ml_severity": mitre.get("severity"),
            # Correctness
            "ml_correct": pred_class == row.get("attack_type"),
        }
        docs.append(doc)

    # Delete old predictions index if exists
    if es.indices.exists(index=PRED_INDEX):
        print(f"Deleting old {PRED_INDEX} index...")
        es.indices.delete(index=PRED_INDEX)

    # Bulk index
    print(f"Indexing {len(docs)} predictions to {PRED_INDEX}...")
    actions = [
        {"_index": PRED_INDEX, "_source": doc}
        for doc in docs
    ]

    success, errors = bulk(es, actions, chunk_size=2000, raise_on_error=False)
    print(f"  Indexed: {success}, Errors: {len(errors) if isinstance(errors, list) else errors}")

    # Summary
    correct = sum(1 for d in docs if d["ml_correct"])
    attacks_detected = sum(1 for d in docs if d["ml_is_attack"])
    high_conf_attacks = sum(1 for d in docs if d["ml_is_attack"] and d["ml_confidence"] > 0.8)

    print(f"\n  Summary:")
    print(f"    Total events scored:    {len(docs)}")
    print(f"    Correct predictions:    {correct} ({correct/len(docs):.1%})")
    print(f"    Attacks detected:       {attacks_detected}")
    print(f"    High-confidence attacks: {high_conf_attacks} (confidence > 0.8)")
    print(f"\n  New index: {PRED_INDEX}")
    print(f"  Create a Kibana Data View for '{PRED_INDEX}' to visualize ML results!")


if __name__ == "__main__":
    main()
