#!/usr/bin/env python3
"""
IoT Security Radar — Flow-Based Network Traffic Capture
=======================================================
Captures network traffic as bidirectional FLOWS instead of per-packet records.
This gives proper bytes_sent AND bytes_received for every event — fixing the
#1 ML feature (bytes_received) which was always 0 in capture_traffic.py.

How it works (two phases):
  Phase 1: tshark writes raw packets to a temp pcap file for N seconds
  Phase 2: Python reads the pcap, groups packets into flows, writes NDJSON

TCP flows are correlated by tcp.stream (tshark assigns the same ID to all
packets in a connection, both directions). UDP flows are correlated by 5-tuple
within a 30-second inactivity window.

Usage:
    sudo .venv/bin/python3 scripts/capture_traffic_flows.py
    sudo .venv/bin/python3 scripts/capture_traffic_flows.py --duration 300 --output sample-logs/demo_traffic.json

Arguments:
    --interface  Network interface (default: en0)
    --duration   Capture duration in seconds (default: 300)
    --output     Output NDJSON file path
"""

import subprocess
import json
import sys
import argparse
import os
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

# ── Known devices on the network ──────────────────────────────────────────────
# Same table as capture_traffic.py — keep in sync
KNOWN_DEVICES = {
    "192.168.1.1":   {"device": "ZTE-Router",        "device_type": "router"},
    "192.168.1.64":  {"device": "Xiaomi-MiTV",       "device_type": "iot"},
    "192.168.1.145": {"device": "MacBook-Air",        "device_type": "computer"},
    "192.168.1.51":  {"device": "Unknown-Device-51",  "device_type": "unknown"},
}

PROTOCOLS = {
    "1":  "icmp",
    "6":  "tcp",
    "17": "udp",
    "58": "icmpv6",
}

UDP_FLOW_TIMEOUT = 30  # seconds of inactivity before a UDP flow is considered closed


# ── Helpers (identical to capture_traffic.py) ─────────────────────────────────

def lookup_device(ip):
    if ip in KNOWN_DEVICES:
        return KNOWN_DEVICES[ip]
    if ip.startswith(("192.168.", "10.", "172.")):
        return {"device": f"unknown-{ip}", "device_type": "unknown"}
    return {"device": "external", "device_type": "external"}


def classify_direction(src_ip, dst_ip):
    src_local = src_ip.startswith(("192.168.", "10.", "172."))
    dst_local = dst_ip.startswith(("192.168.", "10.", "172."))
    if src_local and dst_local:
        return "internal"
    elif src_local and not dst_local:
        return "outbound"
    elif not src_local and dst_local:
        return "inbound"
    return "passthrough"


# ── Phase 1: Capture raw packets to pcap ──────────────────────────────────────

def capture_pcap(interface, duration, pcap_path):
    """Run tshark to write raw packets to a pcap file, print a countdown."""
    print(f"  Interface: {interface},  Duration: {duration}s")
    print(f"  Writing pcap to: {pcap_path}")

    cmd = ["tshark", "-i", interface, "-w", pcap_path]
    if duration > 0:
        cmd.extend(["-a", f"duration:{duration}"])

    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    start = time.time()
    try:
        while proc.poll() is None:
            elapsed = int(time.time() - start)
            remaining = max(0, duration - elapsed)
            print(f"  Capturing... {elapsed:>3}s elapsed, {remaining:>3}s remaining", end="\r")
            time.sleep(1)
    except KeyboardInterrupt:
        proc.terminate()
        proc.wait()
        print("\n  Capture stopped by user.")

    proc.wait()
    print()

    if os.path.exists(pcap_path):
        size_kb = os.path.getsize(pcap_path) / 1024
        print(f"  Pcap written: {size_kb:.1f} KB")
    else:
        print("  WARNING: No pcap file produced (no traffic on interface?)")


# ── Phase 2: Extract per-packet fields from pcap ──────────────────────────────

def extract_packets(pcap_path):
    """
    Run tshark -r on the pcap and extract one row per packet.
    Returns a list of dicts with raw numeric/string values.

    Key field: tcp.stream — tshark assigns the same integer ID to every packet
    in a TCP connection (both directions). This is the basis for TCP correlation.
    """
    print(f"  Reading pcap: {pcap_path}")

    cmd = [
        "tshark", "-r", pcap_path,
        "-T", "fields",
        "-e", "frame.time_epoch",  # col 0
        "-e", "ip.src",            # col 1
        "-e", "ip.dst",            # col 2
        "-e", "tcp.srcport",       # col 3
        "-e", "tcp.dstport",       # col 4
        "-e", "udp.srcport",       # col 5
        "-e", "udp.dstport",       # col 6
        "-e", "ip.proto",          # col 7
        "-e", "frame.len",         # col 8
        "-e", "tcp.stream",        # col 9  (empty for non-TCP)
        "-E", "separator=\t",
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    packets = []
    for line in result.stdout.splitlines():
        parts = line.strip().split("\t")
        if len(parts) < 10:
            continue

        epoch, src_ip, dst_ip = parts[0], parts[1], parts[2]
        tcp_src, tcp_dst = parts[3], parts[4]
        udp_src, udp_dst = parts[5], parts[6]
        proto_num, frame_len, tcp_stream = parts[7], parts[8], parts[9]

        if not src_ip or not dst_ip:
            continue

        try:
            epoch_f = float(epoch)
        except ValueError:
            continue

        src_port = int(tcp_src) if tcp_src else (int(udp_src) if udp_src else 0)
        dst_port = int(tcp_dst) if tcp_dst else (int(udp_dst) if udp_dst else 0)

        packets.append({
            "epoch":      epoch_f,
            "src_ip":     src_ip,
            "dst_ip":     dst_ip,
            "src_port":   src_port,
            "dst_port":   dst_port,
            "proto_num":  proto_num,
            "frame_len":  int(frame_len) if frame_len else 0,
            "tcp_stream": tcp_stream,
        })

    print(f"  Packets extracted: {len(packets)}")
    return packets


# ── Phase 3a: Correlate TCP flows ─────────────────────────────────────────────

def correlate_tcp_flows(packets):
    """
    Group TCP packets by tcp.stream number.

    tshark assigns the same tcp.stream ID to all packets in a connection
    (SYN from client AND SYN-ACK from server AND all data packets).
    The first packet's src_ip is treated as the "forward" direction.

    Result: one flow record per TCP connection with:
      bytes_sent     = total bytes from forward direction (client → server)
      bytes_received = total bytes from reverse direction (server → client)
    """
    streams = {}

    for pkt in packets:
        if pkt["proto_num"] != "6" or not pkt["tcp_stream"]:
            continue

        sid = pkt["tcp_stream"]

        if sid not in streams:
            streams[sid] = {
                "epoch":       pkt["epoch"],
                "src_ip":      pkt["src_ip"],
                "dst_ip":      pkt["dst_ip"],
                "src_port":    pkt["src_port"],
                "dst_port":    pkt["dst_port"],
                "proto_num":   pkt["proto_num"],
                "bytes_sent":  0,
                "bytes_received": 0,
            }

        flow = streams[sid]
        if pkt["src_ip"] == flow["src_ip"]:
            flow["bytes_sent"] += pkt["frame_len"]
        else:
            flow["bytes_received"] += pkt["frame_len"]

    return list(streams.values())


# ── Phase 3b: Correlate UDP flows ─────────────────────────────────────────────

def correlate_udp_flows(packets):
    """
    Group UDP packets by (src_ip, dst_ip, src_port, dst_port) 5-tuple.

    Unlike TCP, UDP has no stream concept. We identify the reverse direction
    by looking for a packet whose (src,dst,sport,dport) is the mirror of an
    existing flow key. Flows expire after UDP_FLOW_TIMEOUT seconds of inactivity.

    Result: one flow record per UDP conversation.
    """
    # key = (src_ip, dst_ip, src_port, dst_port) of the FORWARD direction
    flows = {}

    for pkt in packets:
        if pkt["proto_num"] != "17":
            continue

        fwd_key = (pkt["src_ip"], pkt["dst_ip"], pkt["src_port"], pkt["dst_port"])
        rev_key = (pkt["dst_ip"], pkt["src_ip"], pkt["dst_port"], pkt["src_port"])

        if fwd_key in flows:
            flow = flows[fwd_key]
            if pkt["epoch"] - flow["last_seen"] <= UDP_FLOW_TIMEOUT:
                flow["bytes_sent"] += pkt["frame_len"]
                flow["last_seen"] = pkt["epoch"]
            else:
                # Old flow timed out — start fresh with this packet as a new forward flow
                flows[fwd_key] = _new_udp_flow(pkt)
                flows[fwd_key]["bytes_sent"] = pkt["frame_len"]

        elif rev_key in flows:
            flow = flows[rev_key]
            if pkt["epoch"] - flow["last_seen"] <= UDP_FLOW_TIMEOUT:
                flow["bytes_received"] += pkt["frame_len"]
                flow["last_seen"] = pkt["epoch"]
            # If timed out: a late reverse packet for a dead flow — skip it

        else:
            flows[fwd_key] = _new_udp_flow(pkt)
            flows[fwd_key]["bytes_sent"] = pkt["frame_len"]

    return list(flows.values())


def _new_udp_flow(pkt):
    return {
        "epoch":          pkt["epoch"],
        "src_ip":         pkt["src_ip"],
        "dst_ip":         pkt["dst_ip"],
        "src_port":       pkt["src_port"],
        "dst_port":       pkt["dst_port"],
        "proto_num":      pkt["proto_num"],
        "bytes_sent":     0,
        "bytes_received": 0,
        "last_seen":      pkt["epoch"],
    }


# ── Phase 3c: Other protocols (ICMP etc.) ─────────────────────────────────────

def correlate_other_flows(packets):
    """
    ICMP and other protocols — emit each packet as an individual event.
    bytes_received stays 0 (no practical way to correlate ICMP request/reply).
    """
    flows = []
    for pkt in packets:
        if pkt["proto_num"] in ("6", "17"):
            continue
        flows.append({
            "epoch":          pkt["epoch"],
            "src_ip":         pkt["src_ip"],
            "dst_ip":         pkt["dst_ip"],
            "src_port":       pkt["src_port"],
            "dst_port":       pkt["dst_port"],
            "proto_num":      pkt["proto_num"],
            "bytes_sent":     pkt["frame_len"],
            "bytes_received": 0,
        })
    return flows


# ── Phase 4: Convert flows to NDJSON events ───────────────────────────────────

def flows_to_events(flows):
    """
    Convert internal flow records to the standard project NDJSON schema.
    This is the same schema produced by capture_traffic.py and generate_attacks.py.
    """
    events = []
    for flow in flows:
        src_ip = flow["src_ip"]
        dst_ip = flow["dst_ip"]

        try:
            ts = datetime.fromtimestamp(flow["epoch"], tz=timezone.utc).isoformat()
        except (ValueError, OSError):
            ts = datetime.now(timezone.utc).isoformat()

        src_device = lookup_device(src_ip)
        protocol   = PROTOCOLS.get(flow["proto_num"], f"proto-{flow['proto_num']}")

        events.append({
            "timestamp":      ts,
            "source_ip":      src_ip,
            "dest_ip":        dst_ip,
            "source_port":    flow["src_port"],
            "dest_port":      flow["dst_port"],
            "protocol":       protocol,
            "bytes_sent":     flow["bytes_sent"],
            "bytes_received": flow["bytes_received"],   # ← now properly populated
            "device":         src_device["device"],
            "device_type":    src_device["device_type"],
            "direction":      classify_direction(src_ip, dst_ip),
            "action":         "allow",
            "capture_source": "tshark-live",
        })

    return events


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Capture live network traffic as bidirectional flow records"
    )
    parser.add_argument("--interface", "-i", default="en0",
                        help="Network interface (default: en0)")
    parser.add_argument("--duration", "-d", type=int, default=300,
                        help="Capture duration in seconds (default: 300)")
    parser.add_argument("--output", "-o", default=None,
                        help="Output NDJSON file path")
    args = parser.parse_args()

    output_path = args.output or str(
        Path(__file__).parent.parent / "sample-logs" / "live_traffic.json"
    )
    pcap_path = f"/tmp/iot_radar_{int(time.time())}.pcap"

    print("=" * 58)
    print("  IoT Radar — Flow-Based Capture")
    print("=" * 58)

    try:
        # ── Phase 1: Capture ──────────────────────────────────────────────────
        print("\nPhase 1: Capturing packets to pcap...")
        capture_pcap(args.interface, args.duration, pcap_path)

        if not os.path.exists(pcap_path) or os.path.getsize(pcap_path) == 0:
            print("No traffic captured. Is the interface correct?")
            sys.exit(1)

        # ── Phase 2: Extract ──────────────────────────────────────────────────
        print("\nPhase 2: Extracting packet fields...")
        packets = extract_packets(pcap_path)

        if not packets:
            print("No IP packets found in capture.")
            sys.exit(1)

        # ── Phase 3: Correlate ────────────────────────────────────────────────
        print("\nPhase 3: Correlating packets into flows...")
        tcp_flows   = correlate_tcp_flows(packets)
        udp_flows   = correlate_udp_flows(packets)
        other_flows = correlate_other_flows(packets)
        all_flows   = tcp_flows + udp_flows + other_flows

        print(f"  TCP flows:   {len(tcp_flows)}")
        print(f"  UDP flows:   {len(udp_flows)}")
        print(f"  Other:       {len(other_flows)}")
        print(f"  Total flows: {len(all_flows)}")

        # ── Phase 4: Build events ─────────────────────────────────────────────
        events  = flows_to_events(all_flows)
        bidir   = sum(1 for e in events if e["bytes_received"] > 0)
        unidir  = len(events) - bidir
        print(f"\n  Bidirectional flows (bytes_received > 0): {bidir}")
        print(f"  Unidirectional flows (ICMP / unanswered):  {unidir}")

        # ── Write NDJSON ──────────────────────────────────────────────────────
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "a") as f:
            for event in events:
                f.write(json.dumps(event) + "\n")

        print(f"\nDone. {len(events)} flow events written to {output_path}")
        print("Filebeat will pick these up automatically if Docker is running.")

    finally:
        if os.path.exists(pcap_path):
            os.remove(pcap_path)


if __name__ == "__main__":
    main()
