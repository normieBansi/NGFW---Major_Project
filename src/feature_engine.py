"""
feature_engine.py — Sliding-window feature extraction.

Maintains per-source-IP packet buffers and computes a 15-dimensional
feature vector every time a window is flushed.  The feature set is
designed to capture:

  • Volume metrics       (PPS, bytes/s, burst score)
  • Size statistics       (mean & std of packet length)
  • Protocol distribution (TCP / UDP / ICMP ratios)
  • TCP flag ratios       (SYN / FIN / RST / ACK)
  • Timing statistics     (inter-arrival mean & std)
  • Destination diversity (unique destination ports)

These features are sufficient to distinguish normal traffic from
L2/L3/L4 anomalies such as ARP floods, ICMP floods, SYN floods,
UDP floods, and connection bursts.
"""

import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Callable, Optional

import numpy as np

from src.log_parser import ParsedPacket
from src.config import (
    WINDOW_SIZE_SECONDS,
    WINDOW_SLIDE_SECONDS,
    MIN_PACKETS_FOR_INFERENCE,
    FEATURE_COLUMNS,
)
from src.utils import setup_logging

logger = setup_logging("feature_engine")


# ──────────────────────────────────────────────
# Feature vector (one per window per source IP)
# ──────────────────────────────────────────────

@dataclass
class FeatureVector:
    """Numeric feature vector produced from a sliding window."""
    src_ip: str
    window_start: float
    window_end: float
    values: Dict[str, float] = field(default_factory=dict)

    def as_list(self) -> List[float]:
        """Return feature values in the canonical column order."""
        return [self.values.get(col, 0.0) for col in FEATURE_COLUMNS]

    def as_dict(self) -> Dict[str, float]:
        return dict(self.values)


# ──────────────────────────────────────────────
# Per-IP packet buffer
# ──────────────────────────────────────────────

class _IPBuffer:
    """Thread-safe packet accumulator for a single source IP."""

    def __init__(self):
        self.lock = threading.Lock()
        self.packets: List[ParsedPacket] = []

    def add(self, pkt: ParsedPacket) -> None:
        with self.lock:
            self.packets.append(pkt)

    def flush(self, cutoff_ts: float) -> List[ParsedPacket]:
        """Remove and return packets older than *cutoff_ts*."""
        with self.lock:
            keep, flushed = [], []
            for p in self.packets:
                if p.timestamp >= cutoff_ts:
                    keep.append(p)
                else:
                    flushed.append(p)
            self.packets = keep
            return flushed

    def snapshot(self, window_start: float) -> List[ParsedPacket]:
        """Return packets within the window (non-destructive)."""
        with self.lock:
            return [p for p in self.packets if p.timestamp >= window_start]


# ──────────────────────────────────────────────
# Feature computation
# ──────────────────────────────────────────────

def _compute_features(
    src_ip: str,
    packets: List[ParsedPacket],
    window_start: float,
    window_end: float,
) -> FeatureVector:
    """
    Compute the 15-feature vector from a list of packets that belong
    to a single source IP within a specific time window.
    """
    n = len(packets)
    duration = max(window_end - window_start, 0.001)

    # ── Volume ──
    pps = n / duration
    total_bytes = sum(p.packet_length for p in packets)
    bytes_per_second = total_bytes / duration

    # ── Packet size statistics ──
    lengths = [p.packet_length for p in packets]
    avg_pkt_len = float(np.mean(lengths)) if lengths else 0.0
    std_pkt_len = float(np.std(lengths)) if len(lengths) > 1 else 0.0

    # ── Protocol counts ──
    tcp_count = sum(1 for p in packets if p.protocol == "tcp")
    udp_count = sum(1 for p in packets if p.protocol == "udp")
    icmp_count = sum(1 for p in packets if p.protocol == "icmp")
    tcp_ratio = tcp_count / n if n else 0.0
    udp_ratio = udp_count / n if n else 0.0
    icmp_ratio = icmp_count / n if n else 0.0

    # ── TCP flag ratios (relative to TCP packets) ──
    def _flag_ratio(flag_char: str) -> float:
        if tcp_count == 0:
            return 0.0
        return sum(
            1 for p in packets
            if p.protocol == "tcp" and flag_char in p.tcp_flags.upper()
        ) / tcp_count

    syn_ratio = _flag_ratio("S")
    fin_ratio = _flag_ratio("F")
    rst_ratio = _flag_ratio("R")
    ack_ratio = _flag_ratio("A")

    # ── Inter-arrival time statistics ──
    timestamps = sorted(p.timestamp for p in packets)
    if len(timestamps) > 1:
        iat = np.diff(timestamps) * 1000  # milliseconds
        inter_arrival_mean = float(np.mean(iat))
        inter_arrival_std = float(np.std(iat))
    else:
        inter_arrival_mean = 0.0
        inter_arrival_std = 0.0

    # ── Destination port diversity ──
    dst_ports = set(p.dst_port for p in packets if p.dst_port > 0)
    unique_dst_ports = float(len(dst_ports))

    # ── Burst score: max packets in any 1-second sub-window ──
    burst_score = 0.0
    if timestamps:
        bucket_start = timestamps[0]
        count_in_bucket = 0
        j = 0
        for i, ts in enumerate(timestamps):
            while j < len(timestamps) and timestamps[j] - ts < 1.0:
                j += 1
            count_in_bucket = j - i
            burst_score = max(burst_score, float(count_in_bucket))

    fv = FeatureVector(
        src_ip=src_ip,
        window_start=window_start,
        window_end=window_end,
        values={
            "pps": pps,
            "bytes_per_second": bytes_per_second,
            "avg_pkt_len": avg_pkt_len,
            "std_pkt_len": std_pkt_len,
            "syn_ratio": syn_ratio,
            "fin_ratio": fin_ratio,
            "rst_ratio": rst_ratio,
            "ack_ratio": ack_ratio,
            "tcp_ratio": tcp_ratio,
            "udp_ratio": udp_ratio,
            "icmp_ratio": icmp_ratio,
            "inter_arrival_mean": inter_arrival_mean,
            "inter_arrival_std": inter_arrival_std,
            "unique_dst_ports": unique_dst_ports,
            "burst_score": burst_score,
        },
    )
    return fv


# ──────────────────────────────────────────────
# Feature Engine (main class)
# ──────────────────────────────────────────────

class FeatureEngine:
    """
    Consumes ParsedPacket objects, buffers them per source IP,
    and periodically emits FeatureVector objects via registered callbacks.

    Typical usage:
        engine = FeatureEngine()
        engine.register_callback(my_handler)
        engine.start()
        # … feed packets with engine.ingest(pkt) …
        engine.stop()
    """

    def __init__(
        self,
        window_size: float = WINDOW_SIZE_SECONDS,
        slide_interval: float = WINDOW_SLIDE_SECONDS,
        min_packets: int = MIN_PACKETS_FOR_INFERENCE,
    ):
        self.window_size = window_size
        self.slide_interval = slide_interval
        self.min_packets = min_packets

        self._buffers: Dict[str, _IPBuffer] = defaultdict(_IPBuffer)
        self._callbacks: List[Callable[[FeatureVector], None]] = []
        self._running = False
        self._thread: Optional[threading.Thread] = None

    # ── public API ──

    def register_callback(self, cb: Callable[[FeatureVector], None]) -> None:
        self._callbacks.append(cb)

    def ingest(self, pkt: ParsedPacket) -> None:
        """Add a parsed packet to the appropriate IP buffer."""
        if pkt.src_ip:
            self._buffers[pkt.src_ip].add(pkt)

    def start(self) -> None:
        """Start the periodic window-flush thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._window_loop, daemon=True)
        self._thread.start()
        logger.info(
            "Feature engine started (window=%ss, slide=%ss)",
            self.window_size,
            self.slide_interval,
        )

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Feature engine stopped")

    def compute_now(self, src_ip: str, packets: List[ParsedPacket]) -> Optional[FeatureVector]:
        """One-shot feature computation (used for training data generation)."""
        if len(packets) < self.min_packets:
            return None
        now = time.time()
        return _compute_features(src_ip, packets, now - self.window_size, now)

    # ── internal ──

    def _window_loop(self) -> None:
        while self._running:
            time.sleep(self.slide_interval)
            now = time.time()
            window_start = now - self.window_size
            for src_ip, buf in list(self._buffers.items()):
                packets = buf.snapshot(window_start)
                if len(packets) < self.min_packets:
                    continue
                fv = _compute_features(src_ip, packets, window_start, now)
                for cb in self._callbacks:
                    try:
                        cb(fv)
                    except Exception as exc:
                        logger.error("Feature callback error: %s", exc)

            # Prune stale packets (older than 2× window)
            cutoff = now - (self.window_size * 2)
            for buf in self._buffers.values():
                buf.flush(cutoff)
