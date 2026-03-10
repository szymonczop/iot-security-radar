#!/usr/bin/env python3
"""
IoT Security Radar — Live Demo Pipeline (WiFi + simulated attacks)
===================================================================
Same as live_demo.py but injects N simulated attacks into the demo file
before ingestion — makes the Kibana dashboard light up with alerts.

Usage:
    sudo .venv/bin/python3 scripts/live_demo_with_attacks.py --minutes 5 --attacks 100

Arguments:
    --minutes   How many minutes to capture real WiFi traffic (default: 5)
    --attacks   How many simulated attack events to inject (default: 100)

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
from datetime import datetime, timezone
from pathlib import Path

# ── Shared infrastructure from live_demo.py ──────────────────────────────────
# live_demo.py contains all the shared helpers (connect_es, wait_for_ingestion,
# pull_session_events, score_and_append, print_summary).
SCRIPTS_DIR = Path(__file__).parent
sys.path.insert(0, str(SCRIPTS_DIR))
from live_demo import (  # noqa: E402
    connect_es, wait_for_ingestion, pull_session_events,
    score_and_append, print_summary,
    DEMO_FILE, CAPTURE_SCRIPT, PRED_INDEX,
)

# Attack generator functions from generate_attacks.py
from generate_attacks import generate_events  # noqa: E402


# ── Attack injection ──────────────────────────────────────────────────────────

def inject_attacks(n_attacks, demo_file):
    """
    Generate N attack events and append them to the demo file.
    Filebeat will pick them up and ship them alongside the real traffic.
    """
    print(f"\nPhase 2b: Injecting {n_attacks} simulated attack events...")

    # Generate attacks-only events using the existing generator
    events = generate_events(
        total=n_attacks,
        attack_ratio=1.0,    # 100% attacks
        attacks_only=True,
    )

    # Trim to exactly n_attacks
    events = events[:n_attacks]

    with open(demo_file, "a") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")

    # Count attack types for info
    from collections import Counter
    types = Counter(e["attack_type"] for e in events)
    print(f"  Injected {len(events)} events:")
    for attack_type, count in types.most_common():
        print(f"    {attack_type:<26} {count:>4}")

    return len(events)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="IoT Security Radar — Live Demo (real WiFi + simulated attacks)"
    )
    parser.add_argument("--minutes", "-m", type=int, default=5,
                        help="WiFi capture duration in minutes (default: 5)")
    parser.add_argument("--attacks", "-a", type=int, default=100,
                        help="Number of simulated attack events to inject (default: 100)")
    args = parser.parse_args()

    session_start     = datetime.now(timezone.utc)
    session_start_iso = session_start.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    # Both tshark-live AND simulated events are from this session
    capture_sources = ["tshark-live", "simulated"]

    print("=" * 58)
    print("  IoT Security Radar — Live Demo (+ Attack Injection)")
    print("=" * 58)

    # ── Phase 1: Setup ────────────────────────────────────────────────────────
    print("\nPhase 1: Setup...")
    es = connect_es()

    DEMO_FILE.parent.mkdir(exist_ok=True)
    DEMO_FILE.write_text("")
    print(f"  Demo file cleared: {DEMO_FILE.name}")
    print(f"  Session start:     {session_start_iso}")
    print(f"  Plan: {args.minutes} min WiFi capture + {args.attacks} simulated attacks")

    # ── Phase 2: Capture real WiFi traffic ────────────────────────────────────
    duration_sec = args.minutes * 60
    print(f"\nPhase 2: Capturing WiFi traffic for {args.minutes} minute(s)...")

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

    real_event_count = sum(1 for _ in DEMO_FILE.open()) if DEMO_FILE.exists() else 0
    print(f"  Real traffic captured: {real_event_count} events")

    # ── Phase 2b: Inject simulated attacks ────────────────────────────────────
    injected = inject_attacks(args.attacks, DEMO_FILE)
    total_in_file = real_event_count + injected
    print(f"  Total events in demo file: {total_in_file} ({real_event_count} real + {injected} simulated)")

    # ── Phase 3: Wait for ingestion ───────────────────────────────────────────
    ingested = wait_for_ingestion(es, session_start_iso, capture_sources)

    if ingested == 0:
        print("\n  No events found in Elasticsearch. Possible reasons:")
        print("    - Filebeat not running: docker compose ps")
        print("    - Ingestion still in progress — wait 30s and check Kibana")
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
