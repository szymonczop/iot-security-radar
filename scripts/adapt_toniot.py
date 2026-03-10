#!/usr/bin/env python3
"""
IoT Security Radar — NF-ToN-IoT-v2 Dataset Adapter

Converts the NF-ToN-IoT-v2 NetFlow dataset (16.9M labeled flows from UNSW)
into our NDJSON schema so it can be ingested alongside our simulated data.

Dataset source:
  https://huggingface.co/datasets/Nora9029/NF-ToN-IoT-v2
  https://staff.itee.uq.edu.au/marius/NIDS_datasets/

Download the CSV first, then run:
    python3 adapt_toniot.py --input NF-ToN-IoT-v2.csv --output ../sample-logs/toniot_traffic.json
    python3 adapt_toniot.py --input NF-ToN-IoT-v2.csv --max-rows 10000  # sample for testing
    python3 adapt_toniot.py --input NF-ToN-IoT-v2.csv --max-rows 50000 --balanced  # balanced sample
"""

import argparse
import csv
import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Column mapping: NF-ToN-IoT-v2 → our schema
# ---------------------------------------------------------------------------
# NF-ToN-IoT-v2 columns we use:
#   IPV4_SRC_ADDR, L4_SRC_PORT, IPV4_DST_ADDR, L4_DST_PORT,
#   PROTOCOL, IN_BYTES, OUT_BYTES, Label (0/1), Attack (type string)

# Protocol number → name mapping (IANA)
PROTO_MAP = {
    "0": "hopopt", "1": "icmp", "2": "igmp", "6": "tcp",
    "17": "udp", "41": "ipv6", "47": "gre", "50": "esp",
    "58": "icmpv6", "89": "ospf", "132": "sctp",
}

# Map TON_IoT attack labels → our attack_type + MITRE ATT&CK
ATTACK_MAP = {
    "scanning": {
        "attack_type": "port_scan",
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1046",
        "mitre_technique_name": "Network Service Discovery",
        "severity": "medium",
    },
    "ddos": {
        "attack_type": "ddos_flood",
        "mitre_tactic": "Impact",
        "mitre_technique": "T1498.001",
        "mitre_technique_name": "Network Denial of Service: Direct Network Flood",
        "severity": "critical",
    },
    "dos": {
        "attack_type": "dos",
        "mitre_tactic": "Impact",
        "mitre_technique": "T1499.001",
        "mitre_technique_name": "Endpoint Denial of Service: OS Exhaustion Flood",
        "severity": "high",
    },
    "password": {
        "attack_type": "brute_force",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110.001",
        "mitre_technique_name": "Brute Force: Password Guessing",
        "severity": "high",
    },
    "xss": {
        "attack_type": "xss",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1189",
        "mitre_technique_name": "Drive-by Compromise",
        "severity": "high",
    },
    "injection": {
        "attack_type": "injection",
        "mitre_tactic": "Execution",
        "mitre_technique": "T1059",
        "mitre_technique_name": "Command and Scripting Interpreter",
        "severity": "critical",
    },
    "backdoor": {
        "attack_type": "backdoor",
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1505.003",
        "mitre_technique_name": "Server Software Component: Web Shell",
        "severity": "critical",
    },
    "ransomware": {
        "attack_type": "ransomware",
        "mitre_tactic": "Impact",
        "mitre_technique": "T1486",
        "mitre_technique_name": "Data Encrypted for Impact",
        "severity": "critical",
    },
    "mitm": {
        "attack_type": "mitm",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1557",
        "mitre_technique_name": "Adversary-in-the-Middle",
        "severity": "high",
    },
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def is_private_ip(ip: str) -> bool:
    return (ip.startswith("10.") or ip.startswith("192.168.") or
            ip.startswith("172.16.") or ip.startswith("172.17.") or
            ip.startswith("172.18.") or ip.startswith("172.19.") or
            ip.startswith("172.2") or ip.startswith("172.3"))


def infer_direction(src_ip: str, dst_ip: str) -> str:
    src_priv = is_private_ip(src_ip)
    dst_priv = is_private_ip(dst_ip)
    if src_priv and dst_priv:
        return "internal"
    elif src_priv and not dst_priv:
        return "outbound"
    else:
        return "inbound"


def convert_row(row: dict, timestamp: str) -> dict | None:
    try:
        src_ip = row.get("IPV4_SRC_ADDR", "").strip()
        dst_ip = row.get("IPV4_DST_ADDR", "").strip()
        if not src_ip or not dst_ip:
            return None

        src_port = int(float(row.get("L4_SRC_PORT", 0)))
        dst_port = int(float(row.get("L4_DST_PORT", 0)))
        proto_num = str(int(float(row.get("PROTOCOL", 0))))
        protocol = PROTO_MAP.get(proto_num, f"proto_{proto_num}")
        in_bytes = int(float(row.get("IN_BYTES", 0)))
        out_bytes = int(float(row.get("OUT_BYTES", 0)))

        label_num = str(row.get("Label", "0")).strip()
        attack_str = str(row.get("Attack", "Benign")).strip().lower()

        is_attack = label_num == "1" and attack_str != "benign"
        direction = infer_direction(src_ip, dst_ip)

        event = {
            "timestamp": timestamp,
            "source_ip": src_ip,
            "dest_ip": dst_ip,
            "source_port": src_port,
            "dest_port": dst_port,
            "protocol": protocol,
            "bytes_sent": out_bytes,
            "bytes_received": in_bytes,
            "device": "unknown",
            "device_type": "iot",
            "direction": direction,
            "action": "deny" if is_attack else "allow",
            "capture_source": "toniot_benchmark",
            "attack_type": "normal",
            "attack_label": "normal",
            "mitre_tactic": None,
            "mitre_technique": None,
            "mitre_technique_name": None,
            "severity": None,
        }

        if is_attack and attack_str in ATTACK_MAP:
            m = ATTACK_MAP[attack_str]
            event["attack_type"] = m["attack_type"]
            event["attack_label"] = "attack"
            event["mitre_tactic"] = m["mitre_tactic"]
            event["mitre_technique"] = m["mitre_technique"]
            event["mitre_technique_name"] = m["mitre_technique_name"]
            event["severity"] = m["severity"]
        elif is_attack:
            # Unknown attack type — keep generic label
            event["attack_type"] = attack_str
            event["attack_label"] = "attack"
            event["severity"] = "medium"

        return event
    except (ValueError, KeyError) as e:
        print(f"  Skipping malformed row: {e}", file=sys.stderr)
        return None


def main():
    parser = argparse.ArgumentParser(
        description="Adapt NF-ToN-IoT-v2 dataset to IoT Security Radar NDJSON schema"
    )
    parser.add_argument("--input", type=str, required=True,
                        help="Path to NF-ToN-IoT-v2 CSV file")
    parser.add_argument("--output", type=str, default=None,
                        help="Output NDJSON path (default: ../sample-logs/toniot_traffic.json)")
    parser.add_argument("--max-rows", type=int, default=None,
                        help="Limit number of rows to convert (default: all)")
    parser.add_argument("--balanced", action="store_true",
                        help="Sample balanced classes (equal normal/attack ratio)")
    parser.add_argument("--seed", type=int, default=42,
                        help="Random seed (default: 42)")
    args = parser.parse_args()

    random.seed(args.seed)

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: Input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    if args.output is None:
        script_dir = Path(__file__).resolve().parent
        output_path = script_dir.parent / "sample-logs" / "toniot_traffic.json"
    else:
        output_path = Path(args.output)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Generate synthetic timestamps (original dataset has no timestamps)
    base_ts = datetime.now(timezone.utc) - timedelta(hours=6)

    print(f"Reading {input_path}...")

    # If balanced sampling, we need two passes (or reservoir sampling)
    if args.balanced and args.max_rows:
        half = args.max_rows // 2
        normal_rows = []
        attack_rows = []

        with open(input_path, "r", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                label = str(row.get("Label", "0")).strip()
                attack = str(row.get("Attack", "Benign")).strip().lower()
                is_attack = label == "1" and attack != "benign"
                if is_attack:
                    attack_rows.append(row)
                else:
                    normal_rows.append(row)
                # Stop early if we have way more than enough
                if len(normal_rows) > half * 10 and len(attack_rows) > half * 10:
                    break

        random.shuffle(normal_rows)
        random.shuffle(attack_rows)
        selected = normal_rows[:half] + attack_rows[:half]
        random.shuffle(selected)

        print(f"  Balanced sample: {min(half, len(normal_rows))} normal + "
              f"{min(half, len(attack_rows))} attack")

        written = 0
        with open(output_path, "w") as out:
            for i, row in enumerate(selected):
                ts = base_ts + timedelta(milliseconds=i * 100)
                ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"
                event = convert_row(row, ts_str)
                if event:
                    out.write(json.dumps(event, default=str) + "\n")
                    written += 1
    else:
        # Single-pass conversion
        written = 0
        skipped = 0
        with open(input_path, "r", newline="") as f, open(output_path, "w") as out:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader):
                if args.max_rows and i >= args.max_rows:
                    break
                ts = base_ts + timedelta(milliseconds=i * 100)
                ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"
                event = convert_row(row, ts_str)
                if event:
                    out.write(json.dumps(event, default=str) + "\n")
                    written += 1
                else:
                    skipped += 1

    # Count stats
    attack_types = {}
    normal_count = 0
    with open(output_path, "r") as f:
        for line in f:
            ev = json.loads(line)
            if ev["attack_label"] == "attack":
                at = ev["attack_type"]
                attack_types[at] = attack_types.get(at, 0) + 1
            else:
                normal_count += 1

    total = normal_count + sum(attack_types.values())
    print(f"\nWrote {total} events to {output_path}")
    print(f"  Normal:  {normal_count}")
    print(f"  Attacks: {sum(attack_types.values())}")
    if attack_types:
        print("\n  Attack breakdown:")
        for atype, count in sorted(attack_types.items(), key=lambda x: -x[1]):
            print(f"    {atype:20s} {count:7d}")


if __name__ == "__main__":
    main()
