#!/usr/bin/env python3
"""
IoT Security Radar — ML Attack Classifier
==========================================
Pulls labeled network events from Elasticsearch, engineers features,
trains a multi-class classifier, and evaluates performance.

Usage (from project root):
    .venv/bin/python3 ml/train_model.py

Outputs:
    ml/model/classifier.joblib    — trained model
    ml/model/label_encoder.joblib — label encoder
    ml/model/feature_names.joblib — feature list
    ml/model/confusion_matrix.png
    ml/model/feature_importance.png
    ml/model/classification_report.txt
"""

import warnings
warnings.filterwarnings("ignore")

import json
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("Agg")  # headless — no GUI needed
import matplotlib.pyplot as plt
import seaborn as sns
import joblib

from elasticsearch import Elasticsearch
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report, confusion_matrix, ConfusionMatrixDisplay
)
from pathlib import Path

# ── Config ────────────────────────────────────────────────────────────────────
ES_HOST = "https://localhost:9200"
ES_USER = "elastic"
ES_PASS = "changeme"
INDEX = "iot-radar-*"
MODEL_DIR = Path(__file__).parent / "model"
RANDOM_STATE = 42

# ── Step 1: Pull data from Elasticsearch ──────────────────────────────────────

def pull_data(es: Elasticsearch, index: str, batch_size: int = 5000) -> pd.DataFrame:
    """Pull all labeled events from Elasticsearch using scroll API."""
    print("Step 1: Pulling data from Elasticsearch...")

    # Only pull events that have attack labels (skip the 15 old Phase 1 samples)
    query = {
        "query": {
            "bool": {
                "must": [
                    {"exists": {"field": "attack_label"}}
                ],
                "must_not": [
                    # Skip events without proper labels
                    {"term": {"attack_type.keyword": ""}}
                ]
            }
        },
        "_source": [
            "timestamp", "@timestamp",
            "source_ip", "dest_ip", "source_port", "dest_port",
            "protocol", "bytes_sent", "bytes_received",
            "device", "device_type", "direction", "action",
            "capture_source", "attack_type", "attack_label",
            "mitre_tactic", "mitre_technique", "severity",
        ]
    }

    # Use search_after for efficient pagination (better than scroll for large datasets)
    all_hits = []
    query["size"] = batch_size
    query["sort"] = ["_doc"]
    resp = es.search(index=index, body=query)
    hits = resp["hits"]["hits"]
    all_hits.extend(hits)

    while len(hits) == batch_size:
        last_sort = hits[-1]["sort"]
        query["search_after"] = last_sort
        resp = es.search(index=index, body=query)
        hits = resp["hits"]["hits"]
        all_hits.extend(hits)
        print(f"  ... pulled {len(all_hits)} events")

    print(f"  Total: {len(all_hits)} events pulled")

    # Convert to DataFrame
    records = [h["_source"] for h in all_hits]
    df = pd.DataFrame(records)
    return df


# ── Step 2: Feature Engineering ───────────────────────────────────────────────

def engineer_features(df: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
    """
    Transform raw network fields into ML-ready features.

    Feature categories:
    1. Port-based    — dest_port ranges, well-known ports, ephemeral ports
    2. Byte-based    — bytes_sent/received, ratio, total
    3. Protocol      — one-hot encoded (tcp, udp, icmp)
    4. Direction     — one-hot encoded (inbound, outbound, internal)
    5. Action        — binary (allow=1, deny=0)
    6. Device type   — one-hot encoded
    7. Derived       — is_privileged_port, port_entropy proxy
    """
    print("Step 2: Engineering features...")

    feat = pd.DataFrame()

    # --- Port features ---
    feat["dest_port"] = pd.to_numeric(df["dest_port"], errors="coerce").fillna(0).astype(int)
    feat["source_port"] = pd.to_numeric(df["source_port"], errors="coerce").fillna(0).astype(int)
    feat["is_privileged_port"] = (feat["dest_port"] < 1024).astype(int)
    feat["is_well_known_service"] = feat["dest_port"].isin(
        [22, 23, 53, 80, 443, 445, 993, 8080, 8443, 8883]
    ).astype(int)
    feat["is_ephemeral_src"] = (feat["source_port"] >= 49152).astype(int)

    # Port buckets (categorical ranges)
    feat["port_bucket"] = pd.cut(
        feat["dest_port"],
        bins=[0, 1024, 5000, 10000, 49152, 65536],
        labels=[0, 1, 2, 3, 4],
        right=False, include_lowest=True,
    ).astype(float).fillna(0).astype(int)

    # --- Byte features ---
    feat["bytes_sent"] = pd.to_numeric(df["bytes_sent"], errors="coerce").fillna(0)
    feat["bytes_received"] = pd.to_numeric(df["bytes_received"], errors="coerce").fillna(0)
    feat["bytes_total"] = feat["bytes_sent"] + feat["bytes_received"]
    feat["bytes_ratio"] = np.where(
        feat["bytes_total"] > 0,
        feat["bytes_sent"] / feat["bytes_total"],
        0.5
    )
    feat["log_bytes_total"] = np.log1p(feat["bytes_total"])

    # --- Protocol (one-hot) ---
    protocol = df["protocol"].fillna("unknown").str.lower()
    for proto in ["tcp", "udp", "icmp"]:
        feat[f"proto_{proto}"] = (protocol == proto).astype(int)

    # --- Direction (one-hot) ---
    direction = df["direction"].fillna("unknown").str.lower()
    for d in ["inbound", "outbound", "internal"]:
        feat[f"dir_{d}"] = (direction == d).astype(int)

    # --- Action ---
    feat["action_allow"] = (df["action"].fillna("allow").str.lower() == "allow").astype(int)

    # --- Device type (one-hot) ---
    device_type = df["device_type"].fillna("unknown").str.lower()
    for dt in ["iot", "computer", "router", "external", "unknown"]:
        feat[f"devtype_{dt}"] = (device_type == dt).astype(int)

    # --- Capture source (one-hot) ---
    source = df["capture_source"].fillna("unknown").str.lower()
    for cs in ["simulated", "toniot_benchmark", "tshark-live"]:
        feat[f"src_{cs.replace('-', '_')}"] = (source == cs).astype(int)

    feature_names = list(feat.columns)
    print(f"  {len(feature_names)} features engineered: {feature_names}")

    return feat, feature_names


# ── Step 3: Train Model ──────────────────────────────────────────────────────

def train_model(
    X_train: pd.DataFrame,
    y_train: np.ndarray,
    feature_names: list[str],
) -> RandomForestClassifier:
    """
    Train a Random Forest classifier.

    Why Random Forest?
    - Handles mixed feature types well (binary, continuous, categorical)
    - Provides feature importance (great for thesis)
    - Fast to train on 55k rows
    - Interpretable — can explain which features drive each prediction
    - Robust to outliers and doesn't require feature scaling
    - XGBoost may be slightly more accurate but RF is more explainable
    """
    print("Step 3: Training Random Forest classifier...")

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight="balanced",  # handle class imbalance
        random_state=RANDOM_STATE,
        n_jobs=-1,  # use all CPU cores
    )

    model.fit(X_train, y_train)

    # Cross-validation on training set
    print("  Running 5-fold cross-validation...")
    cv_scores = cross_val_score(model, X_train, y_train, cv=5, scoring="f1_weighted", n_jobs=-1)
    print(f"  CV F1 (weighted): {cv_scores.mean():.4f} +/- {cv_scores.std():.4f}")

    return model


# ── Step 4: Evaluate ──────────────────────────────────────────────────────────

def evaluate_model(
    model: RandomForestClassifier,
    X_test: pd.DataFrame,
    y_test: np.ndarray,
    label_encoder: LabelEncoder,
    feature_names: list[str],
):
    """Generate evaluation plots and reports."""
    print("Step 4: Evaluating model...")

    y_pred = model.predict(X_test)
    class_names = label_encoder.classes_

    # --- Classification Report ---
    report = classification_report(y_test, y_pred, target_names=class_names, zero_division=0)
    print("\n" + report)

    report_path = MODEL_DIR / "classification_report.txt"
    with open(report_path, "w") as f:
        f.write("IoT Security Radar — Classification Report\n")
        f.write("=" * 60 + "\n\n")
        f.write(report)
    print(f"  Report saved: {report_path}")

    # --- Confusion Matrix ---
    cm = confusion_matrix(y_test, y_pred)
    fig, ax = plt.subplots(figsize=(14, 11))
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=class_names)
    disp.plot(ax=ax, cmap="Blues", xticks_rotation=45, values_format="d")
    ax.set_title("IoT Security Radar — Confusion Matrix", fontsize=14, pad=15)
    plt.tight_layout()
    cm_path = MODEL_DIR / "confusion_matrix.png"
    fig.savefig(cm_path, dpi=150)
    plt.close(fig)
    print(f"  Confusion matrix saved: {cm_path}")

    # --- Feature Importance ---
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]

    fig, ax = plt.subplots(figsize=(12, 8))
    top_n = min(20, len(feature_names))
    top_idx = indices[:top_n]
    ax.barh(
        [feature_names[i] for i in reversed(top_idx)],
        importances[list(reversed(top_idx))],
        color=sns.color_palette("viridis", top_n),
    )
    ax.set_xlabel("Feature Importance (Gini)")
    ax.set_title("IoT Security Radar — Top Feature Importances", fontsize=14)
    plt.tight_layout()
    fi_path = MODEL_DIR / "feature_importance.png"
    fig.savefig(fi_path, dpi=150)
    plt.close(fig)
    print(f"  Feature importance saved: {fi_path}")

    # Print top 10 features
    print("\n  Top 10 most important features:")
    for i, idx in enumerate(indices[:10]):
        print(f"    {i+1}. {feature_names[idx]:30s} {importances[idx]:.4f}")


# ── Step 5: MITRE ATT&CK Mapping ─────────────────────────────────────────────

# Maps each attack_type to its MITRE ATT&CK tags
MITRE_MAP = {
    "normal":              {"tactic": None, "technique": None, "technique_name": None, "severity": None},
    "port_scan":           {"tactic": "Discovery", "technique": "T1046", "technique_name": "Network Service Discovery", "severity": "medium"},
    "brute_force_ssh":     {"tactic": "Credential Access", "technique": "T1110.001", "technique_name": "Brute Force: Password Guessing", "severity": "high"},
    "brute_force_http":    {"tactic": "Credential Access", "technique": "T1110.001", "technique_name": "Brute Force: Password Guessing", "severity": "high"},
    "brute_force":         {"tactic": "Credential Access", "technique": "T1110.001", "technique_name": "Brute Force: Password Guessing", "severity": "high"},
    "dns_exfiltration":    {"tactic": "Exfiltration", "technique": "T1048.001", "technique_name": "Exfiltration Over Alternative Protocol", "severity": "critical"},
    "ddos_flood":          {"tactic": "Impact", "technique": "T1498.001", "technique_name": "Network Denial of Service: Direct Network Flood", "severity": "critical"},
    "dos":                 {"tactic": "Impact", "technique": "T1499.001", "technique_name": "Endpoint Denial of Service: OS Exhaustion Flood", "severity": "high"},
    "unauthorized_device": {"tactic": "Initial Access", "technique": "T1200", "technique_name": "Hardware Additions", "severity": "low"},
    "xss":                 {"tactic": "Initial Access", "technique": "T1189", "technique_name": "Drive-by Compromise", "severity": "high"},
    "injection":           {"tactic": "Execution", "technique": "T1059", "technique_name": "Command and Scripting Interpreter", "severity": "critical"},
    "backdoor":            {"tactic": "Persistence", "technique": "T1505.003", "technique_name": "Server Software Component: Web Shell", "severity": "critical"},
    "ransomware":          {"tactic": "Impact", "technique": "T1486", "technique_name": "Data Encrypted for Impact", "severity": "critical"},
    "mitm":                {"tactic": "Credential Access", "technique": "T1557", "technique_name": "Adversary-in-the-Middle", "severity": "high"},
}


# Merge rare attack classes (< 10 samples) into nearest parent category
# This prevents stratified split failures and gives the model enough samples
MERGE_MAP = {
    "ransomware": "dos",            # both are Impact tactic
    "mitm": "brute_force",          # both are Credential Access tactic
    "unauthorized_device": "port_scan",  # both are recon-adjacent
    "brute_force_ssh": "brute_force",
    "brute_force_http": "brute_force",
}

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    # Connect to Elasticsearch
    es = Elasticsearch(
        ES_HOST,
        basic_auth=(ES_USER, ES_PASS),
        verify_certs=False,
        ssl_show_warn=False,
    )
    print(f"Connected to Elasticsearch: {es.info()['version']['number']}\n")

    # Pull data
    df = pull_data(es, INDEX)

    # Quick data overview
    print(f"\n  Dataset shape: {df.shape}")
    print(f"  Attack label distribution:")
    print(df["attack_label"].value_counts().to_string(header=False))
    print(f"\n  Attack type distribution:")
    print(df["attack_type"].value_counts().to_string(header=False))
    print()

    df["attack_type"] = df["attack_type"].replace(MERGE_MAP)
    print("  Merged rare classes:")
    for old, new in MERGE_MAP.items():
        print(f"    {old} -> {new}")
    print(f"\n  Attack type distribution (after merge):")
    print(df["attack_type"].value_counts().to_string(header=False))

    # Feature engineering
    X, feature_names = engineer_features(df)

    # Encode target variable
    le = LabelEncoder()
    y = le.fit_transform(df["attack_type"])
    print(f"\n  Classes ({len(le.classes_)}): {list(le.classes_)}")

    # Train/test split (stratified to preserve class ratios)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=RANDOM_STATE
    )
    print(f"  Train: {len(X_train)} | Test: {len(X_test)}\n")

    # Train
    model = train_model(X_train, y_train, feature_names)

    # Evaluate
    evaluate_model(model, X_test, y_test, le, feature_names)

    # Save model artifacts
    joblib.dump(model, MODEL_DIR / "classifier.joblib")
    joblib.dump(le, MODEL_DIR / "label_encoder.joblib")
    joblib.dump(feature_names, MODEL_DIR / "feature_names.joblib")
    # Save MITRE mapping as JSON for the scoring service
    with open(MODEL_DIR / "mitre_map.json", "w") as f:
        json.dump(MITRE_MAP, f, indent=2)

    print(f"\n  Model artifacts saved to: {MODEL_DIR}/")
    print("  - classifier.joblib")
    print("  - label_encoder.joblib")
    print("  - feature_names.joblib")
    print("  - mitre_map.json")
    print("\nDone!")


if __name__ == "__main__":
    main()
