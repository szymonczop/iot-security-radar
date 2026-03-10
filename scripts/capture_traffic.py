#!/usr/bin/env python3
"""
IoT Security Radar — Live Network Traffic Capture
===================================================
Runs tshark on your WiFi interface and writes NDJSON logs that Filebeat
picks up and ships through the Elastic pipeline.

Usage:
    sudo python3 capture_traffic.py                  # default: 5 minutes
    sudo python3 capture_traffic.py --duration 600   # 10 minutes
    sudo python3 capture_traffic.py --duration 0     # run forever (Ctrl+C to stop)

Output: ../sample-logs/live_traffic.json (NDJSON)
"""

import subprocess
import json
import sys
import signal
import argparse
from datetime import datetime, timezone

# ── Known devices on the network ──────────────────────────────────────────────
# Maps IP addresses to friendly names and device types.
# Update this as you discover more devices on your network!
KNOWN_DEVICES = {
    "192.168.1.1":   {"device": "ZTE-Router",        "device_type": "router"},
    "192.168.1.64":  {"device": "Xiaomi-MiTV",       "device_type": "iot"},
    "192.168.1.145": {"device": "MacBook-Air",        "device_type": "computer"},
    "192.168.1.51":  {"device": "Unknown-Device-51",  "device_type": "unknown"},
    # Add your Samsung dryer, LG washing machine, etc. when they connect:
    # "192.168.1.XX": {"device": "Samsung-Dryer",     "device_type": "iot"},
    # "192.168.1.XX": {"device": "LG-WashingMachine", "device_type": "iot"},
}

# Protocol number → name mapping (from IANA)
PROTOCOLS = {
    "1": "icmp",
    "6": "tcp",
    "17": "udp",
    "58": "icmpv6",
}

# ── Helpers ───────────────────────────────────────────────────────────────────

def lookup_device(ip):
    """Look up device name and type from known devices table."""
    if ip in KNOWN_DEVICES:
        return KNOWN_DEVICES[ip]
    # Check if it's a local network device we don't recognize
    if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
        return {"device": f"unknown-{ip}", "device_type": "unknown"}
    return {"device": "external", "device_type": "external"}


def classify_direction(src_ip, dst_ip):
    """Classify traffic direction based on IP addresses."""
    src_local = src_ip.startswith("192.168.") or src_ip.startswith("10.") or src_ip.startswith("172.")
    dst_local = dst_ip.startswith("192.168.") or dst_ip.startswith("10.") or dst_ip.startswith("172.")

    if src_local and dst_local:
        return "internal"
    elif src_local and not dst_local:
        return "outbound"
    elif not src_local and dst_local:
        return "inbound"
    else:
        return "passthrough"


def parse_tshark_line(line):
    """Parse a tab-separated tshark output line into an NDJSON event."""
    parts = line.strip().split("\t")
    if len(parts) < 9:
        return None

    epoch, src_ip, dst_ip, tcp_src, tcp_dst, udp_src, udp_dst, proto_num, frame_len = parts[:9]

    # Skip lines with missing IPs (e.g., ARP, IPv6-only)
    if not src_ip or not dst_ip:
        return None

    # Determine ports (TCP takes priority, then UDP)
    src_port = int(tcp_src) if tcp_src else (int(udp_src) if udp_src else 0)
    dst_port = int(tcp_dst) if tcp_dst else (int(udp_dst) if udp_dst else 0)

    # Convert epoch to ISO timestamp
    try:
        ts = datetime.fromtimestamp(float(epoch), tz=timezone.utc).isoformat()
    except (ValueError, OSError):
        ts = datetime.now(timezone.utc).isoformat()

    # Look up device info
    src_device = lookup_device(src_ip)
    dst_device = lookup_device(dst_ip)

    # Build the event — same schema as our sample data
    event = {
        "timestamp": ts,
        "source_ip": src_ip,
        "dest_ip": dst_ip,
        "source_port": src_port,
        "dest_port": dst_port,
        "protocol": PROTOCOLS.get(proto_num, f"proto-{proto_num}"),
        "bytes_sent": int(frame_len) if frame_len else 0,
        "bytes_received": 0,  # tshark captures one direction at a time
        "device": src_device["device"],
        "device_type": src_device["device_type"],
        "direction": classify_direction(src_ip, dst_ip),
        "action": "allow",  # captured traffic = allowed through
        "capture_source": "tshark-live",
    }

    return event


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Capture live network traffic as NDJSON")
    parser.add_argument("--interface", "-i", default="en0", help="Network interface (default: en0)")
    parser.add_argument("--duration", "-d", type=int, default=300, help="Capture duration in seconds (0 = forever)")
    parser.add_argument("--output", "-o", default=None, help="Output file path")
    args = parser.parse_args()

    if args.output:
        output_path = args.output
    else:
        output_path = "/Users/szymonczop/iot-security-radar/sample-logs/live_traffic.json"

    # Build tshark command
    tshark_cmd = [
        "tshark",
        "-i", args.interface,
        "-l",  # line-buffered output (flush each packet immediately)
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
        "-e", "ip.proto",
        "-e", "frame.len",
        "-E", "separator=\t",
    ]

    if args.duration > 0:
        tshark_cmd.extend(["-a", f"duration:{args.duration}"])

    event_count = 0

    print(f"Starting capture on {args.interface} for {'forever' if args.duration == 0 else f'{args.duration}s'}...")
    print(f"Writing to: {output_path}")
    print(f"Known devices: {len(KNOWN_DEVICES)}")
    print("Press Ctrl+C to stop early.\n")

    # Handle Ctrl+C gracefully
    def signal_handler(sig, frame):
        print(f"\n\nCapture stopped. {event_count} events written to {output_path}")
        sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)

    with open(output_path, "a") as f:  # append mode — don't overwrite previous captures
        proc = subprocess.Popen(
            tshark_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

        try:
            for line in proc.stdout:
                event = parse_tshark_line(line)
                if event:
                    f.write(json.dumps(event) + "\n")
                    f.flush()  # ensure Filebeat can read it immediately
                    event_count += 1

                    if event_count % 100 == 0:
                        print(f"  {event_count} events captured...")

        except KeyboardInterrupt:
            proc.terminate()

        proc.wait()

    print(f"\nDone! {event_count} events written to {output_path}")
    print(f"Filebeat will pick these up automatically if Docker is running.")


if __name__ == "__main__":
    main()
