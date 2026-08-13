"""
NetFlow v5 collector.

Listens on a UDP socket for NetFlow v5 export packets (the format spoken by
softflowd, most Cisco IOS devices, MikroTik, pfSense/OPNsense, and nprobe in
v5 mode) and turns each packet into a list of flow records.

NetFlow v5 wire format (RFC-ish, no formal RFC but this is the de-facto spec):

Header (24 bytes):
    version         u16
    count           u16   -- number of flow records in this packet (<=30)
    sys_uptime      u32   -- ms since exporter boot
    unix_secs       u32   -- export time, seconds
    unix_nsecs      u32   -- export time, residual nanoseconds
    flow_sequence   u32   -- running counter of flows exported
    engine_type     u8
    engine_id       u8
    sampling        u16   -- sampling mode (2 bits) + interval (14 bits)

Flow record (48 bytes each):
    src_addr    u32  (packed IPv4)
    dst_addr    u32
    next_hop    u32
    input_if    u16
    output_if   u16
    packets     u32  -- packets in this flow
    octets      u32  -- bytes in this flow
    first       u32  -- sys_uptime at start of flow (ms)
    last        u32  -- sys_uptime at end of flow (ms)
    src_port    u16
    dst_port    u16
    pad1        u8
    tcp_flags   u8   -- OR of all TCP flags seen in the flow
    protocol    u8   -- IANA protocol number (6=TCP, 17=UDP, 1=ICMP, ...)
    tos         u8
    src_as      u16
    dst_as      u16
    src_mask    u8
    dst_mask    u8
    pad2        u16
"""

import socket
import struct
import threading
import time
import queue
import ipaddress

HEADER_FMT = "!HHIIIIBBH"
HEADER_LEN = struct.calcsize(HEADER_FMT)  # 24

RECORD_FMT = "!IIIHHIIIIHHBBBBHHBBH"
RECORD_LEN = struct.calcsize(RECORD_FMT)  # 48

PROTOCOL_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP"}


def _int_to_ip(n: int) -> str:
    return str(ipaddress.IPv4Address(n))


def parse_packet(data: bytes):
    """Parse one NetFlow v5 UDP payload into a list of flow dicts.

    Returns [] if the packet is too short or not version 5 (so a stray
    packet on the port can't crash the collector).
    """
    if len(data) < HEADER_LEN:
        return []

    version, count, sys_uptime, unix_secs, unix_nsecs, flow_seq, eng_type, eng_id, sampling = (
        struct.unpack(HEADER_FMT, data[:HEADER_LEN])
    )
    if version != 5:
        return []

    flows = []
    offset = HEADER_LEN
    for _ in range(count):
        if offset + RECORD_LEN > len(data):
            break
        (
            src_addr, dst_addr, next_hop, input_if, output_if,
            packets, octets, first, last,
            src_port, dst_port, pad1, tcp_flags, protocol, tos,
            src_as, dst_as, src_mask, dst_mask, pad2,
        ) = struct.unpack(RECORD_FMT, data[offset:offset + RECORD_LEN])
        offset += RECORD_LEN

        duration_ms = max(0, last - first)
        export_time = unix_secs + unix_nsecs / 1e9

        flows.append({
            "src_ip": _int_to_ip(src_addr),
            "dst_ip": _int_to_ip(dst_addr),
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": PROTOCOL_NAMES.get(protocol, str(protocol)),
            "protocol_num": protocol,
            "packets": packets,
            "bytes": octets,
            "duration_ms": duration_ms,
            "tcp_flags": tcp_flags,
            "tos": tos,
            "input_if": input_if,
            "output_if": output_if,
            "flow_seq": flow_seq,
            "exported_at": export_time,
            "observed_at": time.time(),
        })
    return flows


class NetFlowV5Collector:
    """Runs a UDP listener in a background thread and pushes parsed flows
    onto a thread-safe queue for the rest of the app to consume."""

    def __init__(self, bind_host="0.0.0.0", port=2055, out_queue: queue.Queue = None):
        self.bind_host = bind_host
        self.port = port
        self.out_queue = out_queue if out_queue is not None else queue.Queue(maxsize=100_000)
        self._sock = None
        self._thread = None
        self._running = threading.Event()
        self.packets_received = 0
        self.flows_received = 0
        self.malformed_packets = 0

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.bind_host, self.port))
        self._sock.settimeout(1.0)
        self._running.set()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return self

    def stop(self):
        self._running.clear()
        if self._thread:
            self._thread.join(timeout=2)
        if self._sock:
            self._sock.close()

    def _loop(self):
        while self._running.is_set():
            try:
                data, addr = self._sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break

            self.packets_received += 1
            flows = parse_packet(data)
            if not flows and len(data) > 0:
                self.malformed_packets += 1
                continue

            for flow in flows:
                flow["exporter_ip"] = addr[0]
                self.flows_received += 1
                try:
                    self.out_queue.put_nowait(flow)
                except queue.Full:
                    pass  # drop under extreme load rather than block the collector

    def stats(self):
        return {
            "packets_received": self.packets_received,
            "flows_received": self.flows_received,
            "malformed_packets": self.malformed_packets,
            "queue_depth": self.out_queue.qsize(),
            "bind": f"{self.bind_host}:{self.port}",
        }
