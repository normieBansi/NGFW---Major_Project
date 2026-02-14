"""
log_parser.py — Robust OPNsense filterlog syslog parser.

Listens on a UDP socket for RFC 5424 syslog messages containing OPNsense
filterlog entries and extracts structured packet metadata.

OPNsense filterlog CSV format (after the syslog header):
  field index  meaning (varies by IP version / protocol)
  ─────────────────────────────────────────────────────
  Common header (indices 0-8):
    0  rule number
    1  sub-rule number
    2  anchor
    3  tracker ID
    4  interface  (e.g. "le1")
    5  reason     (match / state)
    6  action     (pass / block)
    7  direction  (in / out)
    8  IP version (4 / 6)

  IPv4 specific (indices 9-20):
    9   TOS
    10  ECN
    11  TTL
    12  ID
    13  Offset
    14  Flags
    15  Protocol ID
    16  Protocol name (tcp / udp / icmp)
    17  Packet length
    18  Src IP
    19  Dst IP

  After IPv4 base, protocol-specific fields start at index 20:
    TCP  → 20: src_port, 21: dst_port, 22: data_length, 23: tcp_flags, …
    UDP  → 20: src_port, 21: dst_port, 22: data_length
    ICMP → 20: icmp_type, 21: …

This parser handles the three major protocols (TCP, UDP, ICMP) and
silently drops lines that don't match the expected format.
"""

import socket
import threading
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Callable, List

from src.config import (
    SYSLOG_LISTEN_HOST,
    SYSLOG_LISTEN_PORT,
    SYSLOG_BUFFER_SIZE,
)
from src.utils import setup_logging, safe_int

logger = setup_logging("log_parser")

# ──────────────────────────────────────────────
# Data class for parsed packets
# ──────────────────────────────────────────────

@dataclass
class ParsedPacket:
    """Structured representation of one filterlog entry."""
    timestamp: float              # epoch seconds
    interface: str = ""
    action: str = ""              # pass | block
    direction: str = ""           # in | out
    ip_version: int = 4
    protocol: str = ""            # tcp | udp | icmp
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    packet_length: int = 0
    tcp_flags: str = ""           # e.g. "S", "SA", "FA", "R"
    ttl: int = 0
    icmp_type: int = -1
    raw_line: str = ""


# ──────────────────────────────────────────────
# Filterlog CSV parser
# ──────────────────────────────────────────────

# Regex to strip the syslog header and isolate the filterlog CSV payload.
# Matches RFC 5424 and common BSD-style syslog prefixes.
_SYSLOG_HEADER_RE = re.compile(
    r"(?:<\d+>)?"                       # optional PRI
    r"(?:\d)?\s*"                        # optional version
    r"(?:\S+\s+)?"                       # optional timestamp
    r"(?:\S+\s+)?"                       # optional hostname
    r"(?:filterlog)(?:\[\d+\])?:\s*"     # program name
    r"(.*)"                              # CSV payload (capture group 1)
)

# Fallback: just look for filterlog: anywhere in the line
_FILTERLOG_FALLBACK_RE = re.compile(r"filterlog(?:\[\d+\])?:\s*(.*)")


def _extract_csv(raw: str) -> Optional[str]:
    """Strip syslog envelope, return the CSV payload or None."""
    m = _SYSLOG_HEADER_RE.search(raw)
    if m:
        return m.group(1).strip()
    m = _FILTERLOG_FALLBACK_RE.search(raw)
    if m:
        return m.group(1).strip()
    return None


def parse_filterlog_line(raw: str) -> Optional[ParsedPacket]:
    """
    Parse a single syslog line containing a filterlog CSV payload.

    Returns a ParsedPacket on success, or None if the line is
    malformed / unsupported.
    """
    csv_payload = _extract_csv(raw)
    if not csv_payload:
        return None

    fields = csv_payload.split(",")

    # Need at least 20 fields for the IPv4 base header
    if len(fields) < 20:
        logger.debug("Dropped short filterlog line (%d fields)", len(fields))
        return None

    pkt = ParsedPacket(
        timestamp=datetime.now().timestamp(),
        raw_line=raw,
    )

    try:
        pkt.interface = fields[4].strip()
        pkt.action = fields[6].strip().lower()
        pkt.direction = fields[7].strip().lower()
        pkt.ip_version = safe_int(fields[8], 4)
    except IndexError:
        return None

    # ── IPv4 parsing ──
    if pkt.ip_version == 4:
        try:
            pkt.ttl = safe_int(fields[11])
            protocol_name = fields[16].strip().lower()
            pkt.protocol = protocol_name
            pkt.packet_length = safe_int(fields[17])
            pkt.src_ip = fields[18].strip()
            pkt.dst_ip = fields[19].strip()
        except IndexError:
            return None

        # Protocol-specific fields (index 20+)
        if protocol_name == "tcp" and len(fields) >= 24:
            pkt.src_port = safe_int(fields[20])
            pkt.dst_port = safe_int(fields[21])
            pkt.tcp_flags = fields[23].strip() if len(fields) > 23 else ""
        elif protocol_name == "udp" and len(fields) >= 22:
            pkt.src_port = safe_int(fields[20])
            pkt.dst_port = safe_int(fields[21])
        elif protocol_name == "icmp" and len(fields) >= 21:
            pkt.icmp_type = safe_int(fields[20])

    # ── IPv6 parsing (simplified) ──
    elif pkt.ip_version == 6:
        # IPv6 filterlog layout shifts indices; handle the basics.
        try:
            pkt.protocol = fields[13].strip().lower() if len(fields) > 13 else ""
            pkt.packet_length = safe_int(fields[14]) if len(fields) > 14 else 0
            pkt.src_ip = fields[15].strip() if len(fields) > 15 else ""
            pkt.dst_ip = fields[16].strip() if len(fields) > 16 else ""
        except IndexError:
            return None
    else:
        return None

    return pkt


# ──────────────────────────────────────────────
# UDP Syslog Listener
# ──────────────────────────────────────────────

class SyslogListener:
    """
    Non-blocking UDP syslog listener.

    Receives syslog datagrams, parses them, and dispatches ParsedPacket
    objects to a list of registered callback functions.
    """

    def __init__(
        self,
        host: str = SYSLOG_LISTEN_HOST,
        port: int = SYSLOG_LISTEN_PORT,
    ):
        self.host = host
        self.port = port
        self._callbacks: List[Callable[[ParsedPacket], None]] = []
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._sock: Optional[socket.socket] = None

    # ── public API ──

    def register_callback(self, cb: Callable[[ParsedPacket], None]) -> None:
        """Register a function to receive every successfully parsed packet."""
        self._callbacks.append(cb)

    def start(self) -> None:
        """Start listening in a background daemon thread."""
        if self._running:
            logger.warning("Listener already running")
            return

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.settimeout(1.0)  # allow periodic check of _running flag
        self._running = True

        self._thread = threading.Thread(target=self._listen_loop, daemon=True)
        self._thread.start()
        logger.info("Syslog listener started on %s:%d", self.host, self.port)

    def stop(self) -> None:
        """Gracefully stop the listener."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)
        if self._sock:
            self._sock.close()
        logger.info("Syslog listener stopped")

    # ── internal ──

    def _listen_loop(self) -> None:
        while self._running:
            try:
                data, addr = self._sock.recvfrom(SYSLOG_BUFFER_SIZE) # type: ignore
            except socket.timeout:
                continue
            except OSError:
                break

            try:
                raw = data.decode("utf-8", errors="replace")
            except Exception:
                continue

            pkt = parse_filterlog_line(raw)
            if pkt is None:
                continue

            for cb in self._callbacks:
                try:
                    cb(pkt)
                except Exception as exc:  # pragma: no cover
                    logger.error("Callback error: %s", exc)


# ──────────────────────────────────────────────
# Convenience: parse a local log file (for training data)
# ──────────────────────────────────────────────

def parse_log_file(path: str) -> List[ParsedPacket]:
    """Parse an entire log file and return a list of ParsedPackets."""
    packets: List[ParsedPacket] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            pkt = parse_filterlog_line(line.strip())
            if pkt:
                packets.append(pkt)
    logger.info("Parsed %d packets from %s", len(packets), path)
    return packets
