"""
Sends real, wire-format NetFlow v5 UDP packets at a FlowWatch collector.
Useful for testing the full pipeline (collector -> engines -> dashboard)
before you've wired up a router, switch, or softflowd to export real flows.

Usage:
    python3 tools/replay_generator.py                     # normal traffic only
    python3 tools/replay_generator.py --scenario portscan  # inject an attack
    python3 tools/replay_generator.py --target 10.0.0.5:2055
"""

import argparse
import random
import socket
import struct
import time
import ipaddress

NORMAL_DEVICES = [
    "10.0.10.11", "10.0.10.12", "10.0.10.13",  # corporate workstations
]
SERVERS = ["10.0.20.10", "10.0.20.11"]  # e.g. DB, app server
IOT = ["10.0.30.21", "10.0.30.22"]
EXTERNAL = ["93.184.216.34", "142.250.72.14", "104.16.85.20"]

SCENARIOS = ["normal", "dos", "portscan", "iot_lateral", "exfil"]


def ip_to_int(ip):
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def build_packet(records, flow_seq_start=1):
    """records: list of dicts with src_ip,dst_ip,src_port,dst_port,protocol,packets,octets,duration_ms"""
    now = time.time()
    sys_uptime_ms = int((now % 100000) * 1000)
    header = struct.pack(
        "!HHIIIIBBH", 5, len(records), sys_uptime_ms,
        int(now), 0, flow_seq_start, 0, 0, 0
    )
    body = b""
    for r in records:
        first = max(0, sys_uptime_ms - r["duration_ms"])
        last = sys_uptime_ms
        body += struct.pack(
            "!IIIHHIIIIHHBBBBHHBBH",
            ip_to_int(r["src_ip"]), ip_to_int(r["dst_ip"]), 0,
            0, 0,
            r["packets"], r["octets"], first, last,
            r["src_port"], r["dst_port"], 0, r.get("tcp_flags", 0x18),
            r["protocol"], 0, 0, 0, 24, 24, 0,
        )
    return header + body


def normal_flow():
    src = random.choice(NORMAL_DEVICES)
    dst = random.choice(SERVERS + EXTERNAL)
    return {
        "src_ip": src, "dst_ip": dst,
        "src_port": random.randint(40000, 60000),
        "dst_port": random.choice([443, 443, 443, 80, 22]),
        "protocol": 6,
        "packets": random.randint(5, 60),
        "octets": random.randint(500, 60000),
        "duration_ms": random.randint(100, 5000),
    }


def dos_flow(target):
    return {
        "src_ip": f"185.220.10.{random.randint(1,254)}", "dst_ip": target,
        "src_port": random.randint(1024, 65535), "dst_port": 80,
        "protocol": 6, "packets": random.randint(2000, 8000),
        "octets": random.randint(200000, 900000), "duration_ms": random.randint(50, 300),
    }


def portscan_flow(target, port):
    return {
        "src_ip": "203.0.113.77", "dst_ip": target,
        "src_port": random.randint(1024, 65535), "dst_port": port,
        "protocol": 6, "packets": 1, "octets": 60, "duration_ms": 5,
        "tcp_flags": 0x02,
    }


def iot_lateral_flow():
    return {
        "src_ip": random.choice(IOT), "dst_ip": random.choice(SERVERS),
        "src_port": random.randint(1024, 65535), "dst_port": 3306,
        "protocol": 6, "packets": random.randint(10, 40), "octets": random.randint(2000, 20000),
        "duration_ms": random.randint(200, 2000),
    }


def exfil_flow():
    src = random.choice(SERVERS)
    return {
        "src_ip": src, "dst_ip": "198.51.100.23",
        "src_port": random.randint(1024, 65535), "dst_port": 443,
        "protocol": 6, "packets": random.randint(50, 150),
        "octets": random.randint(500000, 2000000), "duration_ms": random.randint(20000, 60000),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="127.0.0.1:2055")
    ap.add_argument("--scenario", choices=SCENARIOS, default="normal")
    ap.add_argument("--rate", type=float, default=2.0, help="packets per second")
    args = ap.parse_args()

    host, port = args.target.split(":")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    seq = 1

    print(f"Sending NetFlow v5 to {host}:{port} | scenario={args.scenario} | Ctrl+C to stop")
    try:
        while True:
            records = [normal_flow() for _ in range(random.randint(3, 8))]

            if args.scenario == "dos":
                records += [dos_flow(random.choice(SERVERS)) for _ in range(10)]
            elif args.scenario == "portscan":
                target = random.choice(SERVERS)
                records += [portscan_flow(target, p) for p in random.sample(range(1, 1024), 8)]
            elif args.scenario == "iot_lateral":
                records += [iot_lateral_flow() for _ in range(3)]
            elif args.scenario == "exfil":
                records += [exfil_flow() for _ in range(2)]

            packet = build_packet(records, flow_seq_start=seq)
            sock.sendto(packet, (host, int(port)))
            seq += len(records)
            time.sleep(1.0 / args.rate)
    except KeyboardInterrupt:
        print("\nstopped.")


if __name__ == "__main__":
    main()
