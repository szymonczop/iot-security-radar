#!/usr/bin/env python3
"""
IoT Security Radar — Simulated Traffic Generator

Generates realistic normal + attack network traffic as NDJSON,
compatible with the existing Filebeat -> Logstash -> Elasticsearch pipeline.

Usage:
    python3 generate_attacks.py --events 5000 --attack-ratio 0.1
    python3 generate_attacks.py --events 10000 --attack-ratio 0.15
    python3 generate_attacks.py --attacks-only --events 500
"""

import argparse
import json
import random
import string
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Network topology — known devices on the local IoT network
# ---------------------------------------------------------------------------
KNOWN_DEVICES = [
    {"ip": "192.168.1.145", "device": "MacBook-Air", "device_type": "computer"},
    {"ip": "192.168.1.100", "device": "Desktop-PC", "device_type": "computer"},
    {"ip": "192.168.1.101", "device": "Laptop-Work", "device_type": "computer"},
    {"ip": "192.168.1.20", "device": "Samsung-Dryer", "device_type": "iot"},
    {"ip": "192.168.1.21", "device": "LG-WashingMachine", "device_type": "iot"},
    {"ip": "192.168.1.22", "device": "Philips-Hue-Bridge", "device_type": "iot"},
    {"ip": "192.168.1.23", "device": "Ring-Doorbell", "device_type": "iot"},
    {"ip": "192.168.1.24", "device": "Nest-Thermostat", "device_type": "iot"},
    {"ip": "192.168.1.25", "device": "Echo-Dot", "device_type": "iot"},
    {"ip": "192.168.1.30", "device": "SmartTV-LG", "device_type": "iot"},
]

EXTERNAL_IPS = [
    "104.16.40.2", "142.250.185.78", "157.240.1.35", "52.26.134.56",
    "54.239.28.85", "13.107.42.14", "151.101.1.140", "198.41.215.10",
    "34.117.59.81", "172.217.14.99", "99.86.38.50", "23.45.67.89",
]

CDN_IPS = ["99.86.38.50", "23.45.67.89", "151.101.1.140", "198.41.215.10"]
DNS_SERVERS = ["8.8.8.8", "1.1.1.1", "8.8.4.4"]
ATTACKER_IPS = [f"10.0.0.{i}" for i in range(50, 70)]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def random_ephemeral_port():
    return random.randint(49152, 65535)


def random_timestamp(base: datetime, offset_ms: int) -> str:
    ts = base + timedelta(milliseconds=offset_ms)
    return ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"


def base_event(timestamp: str, src_ip: str, dst_ip: str, src_port: int,
               dst_port: int, protocol: str, bytes_sent: int,
               bytes_received: int, device: str, device_type: str,
               action: str, direction: str) -> dict:
    return {
        "timestamp": timestamp,
        "source_ip": src_ip,
        "dest_ip": dst_ip,
        "source_port": src_port,
        "dest_port": dst_port,
        "protocol": protocol,
        "bytes_sent": bytes_sent,
        "bytes_received": bytes_received,
        "device": device,
        "device_type": device_type,
        "direction": direction,
        "action": action,
        "capture_source": "simulated",
        "attack_type": "normal",
        "attack_label": "normal",
        "mitre_tactic": None,
        "mitre_technique": None,
        "mitre_technique_name": None,
        "severity": None,
    }


def tag_attack(event: dict, attack_type: str, tactic: str,
               technique: str, technique_name: str, severity: str) -> dict:
    event["attack_type"] = attack_type
    event["attack_label"] = "attack"
    event["mitre_tactic"] = tactic
    event["mitre_technique"] = technique
    event["mitre_technique_name"] = technique_name
    event["severity"] = severity
    return event


# ---------------------------------------------------------------------------
# Normal traffic generators  (each returns a list of events)
# ---------------------------------------------------------------------------

def gen_web_browsing(ts: str) -> list[dict]:
    dev = random.choice(KNOWN_DEVICES)
    ext = random.choice(EXTERNAL_IPS)
    return [base_event(
        ts, dev["ip"], ext, random_ephemeral_port(), 443, "tcp",
        random.randint(500, 3000), random.randint(2000, 50000),
        dev["device"], dev["device_type"], "allow", "outbound",
    )]


def gen_dns_query(ts: str) -> list[dict]:
    dev = random.choice(KNOWN_DEVICES)
    dns = random.choice(DNS_SERVERS)
    return [base_event(
        ts, dev["ip"], dns, random_ephemeral_port(), 53, "udp",
        random.randint(40, 80), random.randint(80, 180),
        dev["device"], dev["device_type"], "allow", "outbound",
    )]


def gen_iot_heartbeat(ts: str) -> list[dict]:
    dev = random.choice([d for d in KNOWN_DEVICES if d["device_type"] == "iot"])
    ext = random.choice(EXTERNAL_IPS[:4])
    return [base_event(
        ts, dev["ip"], ext, random_ephemeral_port(), 8883, "tcp",
        random.randint(50, 200), random.randint(50, 200),
        dev["device"], dev["device_type"], "allow", "outbound",
    )]


def gen_mdns_ssdp(ts: str) -> list[dict]:
    dev = random.choice(KNOWN_DEVICES)
    mcast = random.choice(["224.0.0.251", "239.255.255.250"])
    port = 5353 if mcast == "224.0.0.251" else 1900
    return [base_event(
        ts, dev["ip"], mcast, port, port, "udp",
        random.randint(80, 200), random.randint(80, 200),
        dev["device"], dev["device_type"], "allow", "internal",
    )]


def gen_smb_share(ts: str) -> list[dict]:
    computers = [d for d in KNOWN_DEVICES if d["device_type"] == "computer"]
    src, dst = random.sample(computers, 2)
    return [base_event(
        ts, src["ip"], dst["ip"], random_ephemeral_port(), 445, "tcp",
        random.randint(1000, 10000), random.randint(1000, 10000),
        src["device"], src["device_type"], "allow", "internal",
    )]


def gen_streaming(ts: str) -> list[dict]:
    dev = random.choice(KNOWN_DEVICES)
    cdn = random.choice(CDN_IPS)
    return [base_event(
        ts, dev["ip"], cdn, random_ephemeral_port(), 443, "tcp",
        random.randint(200, 800), random.randint(50000, 500000),
        dev["device"], dev["device_type"], "allow", "outbound",
    )]


NORMAL_GENERATORS = [
    (gen_web_browsing, 35),
    (gen_dns_query, 25),
    (gen_iot_heartbeat, 15),
    (gen_mdns_ssdp, 10),
    (gen_smb_share, 5),
    (gen_streaming, 10),
]


def gen_normal_event(ts: str) -> list[dict]:
    funcs, weights = zip(*NORMAL_GENERATORS)
    chosen = random.choices(funcs, weights=weights, k=1)[0]
    return chosen(ts)


# ---------------------------------------------------------------------------
# Attack traffic generators  (each returns a burst of related events)
# ---------------------------------------------------------------------------

def gen_port_scan(base_ts: datetime, offset_ms: int) -> list[dict]:
    attacker = random.choice(ATTACKER_IPS)
    target = random.choice(KNOWN_DEVICES)
    ports = random.sample(range(1, 1024), random.randint(15, 40))
    events = []
    for i, port in enumerate(sorted(ports)):
        ts = random_timestamp(base_ts, offset_ms + i * random.randint(5, 30))
        ev = base_event(
            ts, attacker, target["ip"], random_ephemeral_port(), port, "tcp",
            0, 0, "unknown", "unknown", "deny", "inbound",
        )
        tag_attack(ev, "port_scan", "Discovery",
                   "T1046", "Network Service Discovery", "medium")
        events.append(ev)
    return events


def gen_brute_force_ssh(base_ts: datetime, offset_ms: int) -> list[dict]:
    attacker = random.choice(ATTACKER_IPS)
    target = random.choice(KNOWN_DEVICES)
    attempts = random.randint(20, 50)
    events = []
    for i in range(attempts):
        ts = random_timestamp(base_ts, offset_ms + i * random.randint(200, 800))
        action = "deny" if random.random() < 0.85 else "allow"
        ev = base_event(
            ts, attacker, target["ip"], random_ephemeral_port(), 22, "tcp",
            random.randint(40, 120), random.randint(40, 120),
            "unknown", "unknown", action, "inbound",
        )
        tag_attack(ev, "brute_force_ssh", "Credential Access",
                   "T1110.001", "Brute Force: Password Guessing", "high")
        events.append(ev)
    return events


def gen_brute_force_http(base_ts: datetime, offset_ms: int) -> list[dict]:
    attacker = random.choice(ATTACKER_IPS)
    target = random.choice(KNOWN_DEVICES)
    port = random.choice([80, 443])
    attempts = random.randint(20, 50)
    events = []
    for i in range(attempts):
        ts = random_timestamp(base_ts, offset_ms + i * random.randint(100, 500))
        action = "deny" if random.random() < 0.9 else "allow"
        ev = base_event(
            ts, attacker, target["ip"], random_ephemeral_port(), port, "tcp",
            random.randint(200, 800), random.randint(200, 1200),
            "unknown", "unknown", action, "inbound",
        )
        tag_attack(ev, "brute_force_http", "Credential Access",
                   "T1110.001", "Brute Force: Password Guessing", "high")
        events.append(ev)
    return events


def gen_dns_exfiltration(base_ts: datetime, offset_ms: int) -> list[dict]:
    dev = random.choice([d for d in KNOWN_DEVICES if d["device_type"] == "iot"])
    ext_dns = random.choice(["185.199.108.1", "203.0.113.53"])
    queries = random.randint(15, 35)
    events = []
    for i in range(queries):
        ts = random_timestamp(base_ts, offset_ms + i * random.randint(500, 2000))
        encoded = ''.join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(30, 60)))
        ev = base_event(
            ts, dev["ip"], ext_dns, random_ephemeral_port(), 53, "udp",
            random.randint(200, 500), random.randint(40, 80),
            dev["device"], dev["device_type"], "allow", "outbound",
        )
        tag_attack(ev, "dns_exfiltration", "Exfiltration",
                   "T1048.001", "Exfiltration Over Alternative Protocol: Exfiltration Over Symmetric Encrypted Non-C2 Protocol", "critical")
        events.append(ev)
    return events


def gen_ddos_flood(base_ts: datetime, offset_ms: int) -> list[dict]:
    target = random.choice(KNOWN_DEVICES)
    port = random.choice([80, 443, 8080])
    num_sources = random.randint(10, 20)
    sources = [f"10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
               for _ in range(num_sources)]
    packets_per_source = random.randint(5, 15)
    events = []
    for i in range(num_sources * packets_per_source):
        src = sources[i % num_sources]
        ts = random_timestamp(base_ts, offset_ms + i * random.randint(1, 10))
        ev = base_event(
            ts, src, target["ip"], random_ephemeral_port(), port, "tcp",
            random.randint(500, 2000), 0,
            "unknown", "unknown", "deny", "inbound",
        )
        tag_attack(ev, "ddos_flood", "Impact",
                   "T1498.001", "Network Denial of Service: Direct Network Flood", "critical")
        events.append(ev)
    return events


def gen_unauthorized_device(base_ts: datetime, offset_ms: int) -> list[dict]:
    rogue_ip = f"192.168.1.{random.randint(200, 250)}"
    events = []
    # rogue device communicates with internal IoT devices and external servers
    targets = random.sample(KNOWN_DEVICES, 3) + [{"ip": random.choice(EXTERNAL_IPS)}]
    for i, t in enumerate(targets):
        ts = random_timestamp(base_ts, offset_ms + i * random.randint(1000, 5000))
        dst_port = random.choice([80, 443, 8883, 5353, 23])
        ev = base_event(
            ts, rogue_ip, t["ip"], random_ephemeral_port(), dst_port, "tcp",
            random.randint(100, 2000), random.randint(100, 2000),
            "unknown", "unknown", "allow", "internal" if t["ip"].startswith("192.168") else "outbound",
        )
        tag_attack(ev, "unauthorized_device", "Initial Access",
                   "T1200", "Hardware Additions", "low")
        events.append(ev)
    return events


ATTACK_GENERATORS = [
    (gen_port_scan, 25),
    (gen_brute_force_ssh, 20),
    (gen_brute_force_http, 15),
    (gen_dns_exfiltration, 15),
    (gen_ddos_flood, 15),
    (gen_unauthorized_device, 10),
]


# ---------------------------------------------------------------------------
# Main generation logic
# ---------------------------------------------------------------------------

def generate_events(total: int, attack_ratio: float, attacks_only: bool) -> list[dict]:
    base_ts = datetime.now(timezone.utc) - timedelta(hours=1)
    events: list[dict] = []
    ms_cursor = 0

    if attacks_only:
        # Generate only attack events until we reach `total`
        funcs, weights = zip(*ATTACK_GENERATORS)
        while len(events) < total:
            chosen = random.choices(funcs, weights=weights, k=1)[0]
            ms_cursor += random.randint(100, 2000)
            burst = chosen(base_ts, ms_cursor)
            events.extend(burst)
        return sorted(events[:total], key=lambda e: e["timestamp"])

    num_attacks = int(total * attack_ratio)
    num_normal = total - num_attacks

    # Generate normal events
    for _ in range(num_normal):
        ms_cursor += random.randint(50, 500)
        ts = random_timestamp(base_ts, ms_cursor)
        events.extend(gen_normal_event(ts))

    # Generate attack bursts until we have enough attack events
    attack_events: list[dict] = []
    funcs, weights = zip(*ATTACK_GENERATORS)
    while len(attack_events) < num_attacks:
        chosen = random.choices(funcs, weights=weights, k=1)[0]
        # Place attacks at random points in the timeline
        attack_offset = random.randint(0, ms_cursor) if ms_cursor > 0 else 0
        burst = chosen(base_ts, attack_offset)
        attack_events.extend(burst)

    events.extend(attack_events[:num_attacks])

    # Sort by timestamp, trim to exact count
    events.sort(key=lambda e: e["timestamp"])
    return events[:total]


def main():
    parser = argparse.ArgumentParser(
        description="Generate simulated IoT network traffic with labeled attacks"
    )
    parser.add_argument("--events", type=int, default=5000,
                        help="Total number of events to generate (default: 5000)")
    parser.add_argument("--attack-ratio", type=float, default=0.10,
                        help="Fraction of events that are attacks (default: 0.10)")
    parser.add_argument("--attacks-only", action="store_true",
                        help="Generate only attack events (ignores --attack-ratio)")
    parser.add_argument("--output", type=str, default=None,
                        help="Output file path (default: ../sample-logs/simulated_traffic.json)")
    parser.add_argument("--seed", type=int, default=None,
                        help="Random seed for reproducibility")
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    # Default output path relative to this script
    if args.output is None:
        script_dir = Path(__file__).resolve().parent
        output_path = script_dir.parent / "sample-logs" / "simulated_traffic.json"
    else:
        output_path = Path(args.output)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"Generating {args.events} events "
          f"({'attacks only' if args.attacks_only else f'{args.attack_ratio:.0%} attack ratio'})...")

    events = generate_events(args.events, args.attack_ratio, args.attacks_only)

    with open(output_path, "w") as f:
        for event in events:
            f.write(json.dumps(event, default=str) + "\n")

    # Stats
    attack_count = sum(1 for e in events if e["attack_label"] == "attack")
    normal_count = len(events) - attack_count
    attack_types = {}
    for e in events:
        if e["attack_label"] == "attack":
            attack_types[e["attack_type"]] = attack_types.get(e["attack_type"], 0) + 1

    print(f"\nWrote {len(events)} events to {output_path}")
    print(f"  Normal:  {normal_count}")
    print(f"  Attacks: {attack_count} ({attack_count/len(events):.1%})")
    if attack_types:
        print("\n  Attack breakdown:")
        for atype, count in sorted(attack_types.items(), key=lambda x: -x[1]):
            print(f"    {atype:25s} {count:5d}")


if __name__ == "__main__":
    main()
