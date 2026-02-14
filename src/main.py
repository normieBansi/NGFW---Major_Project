"""
main.py — Orchestrator for the AI-Augmented Firewall engine.

Wires together:
  SyslogListener  →  FeatureEngine  →  AnomalyDetector  →  DefenseEngine

Usage:
    # 1. Train the model first (one-time or periodic):
    python -m src.model_trainer

    # 2. Start the live detection engine:
    python -m src.main
"""

import os
import sys
import signal
import time

from src.config import MODEL_PATH, SCALER_PATH
from src.log_parser import SyslogListener
from src.feature_engine import FeatureEngine
from src.detector import AnomalyDetector
from src.defense import DefenseEngine
from src.utils import setup_logging

logger = setup_logging("main")

# ──────────────────────────────────────────────
# Graceful shutdown
# ──────────────────────────────────────────────
_shutdown_requested = False


def _signal_handler(signum, frame):
    global _shutdown_requested
    logger.info("Shutdown signal received")
    _shutdown_requested = True


# ──────────────────────────────────────────────
# Main pipeline
# ──────────────────────────────────────────────

def run() -> None:
    """Start the full detection pipeline."""

    # Validate model exists
    if not os.path.isfile(MODEL_PATH) or not os.path.isfile(SCALER_PATH):
        logger.error(
            "Trained model not found at %s / %s.  "
            "Run `python -m src.model_trainer` first.",
            MODEL_PATH,
            SCALER_PATH,
        )
        sys.exit(1)

    # ── Instantiate components ──
    listener = SyslogListener()
    feature_engine = FeatureEngine()
    detector = AnomalyDetector()
    defense = DefenseEngine()

    # ── Wire the pipeline ──
    #  listener  →  feature_engine.ingest
    listener.register_callback(feature_engine.ingest)

    #  feature_engine  →  detector.evaluate
    def on_feature_vector(fv):
        alert = detector.evaluate(fv)
        if alert:
            defense.handle_alert(alert)

    feature_engine.register_callback(on_feature_vector)

    # ── Register alert callback for logging ──
    def on_alert(alert):
        logger.warning(
            "ALERT  src=%s  score=%.4f  pps=%.1f  syn_ratio=%.2f  "
            "udp_ratio=%.2f  icmp_ratio=%.2f  burst=%.0f",
            alert.src_ip,
            alert.score,
            alert.feature_vector.values.get("pps", 0),
            alert.feature_vector.values.get("syn_ratio", 0),
            alert.feature_vector.values.get("udp_ratio", 0),
            alert.feature_vector.values.get("icmp_ratio", 0),
            alert.feature_vector.values.get("burst_score", 0),
        )

    detector.register_callback(on_alert)

    # ── Start ──
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    listener.start()
    feature_engine.start()

    logger.info("=" * 60)
    logger.info("  AI-Augmented Firewall Engine — RUNNING")
    logger.info("  Listening for syslog on UDP %s:%d",
                listener.host, listener.port)
    logger.info("=" * 60)

    # ── Main loop (idle until shutdown) ──
    try:
        while not _shutdown_requested:
            time.sleep(1)
    except KeyboardInterrupt:
        pass

    # ── Shutdown ──
    logger.info("Shutting down…")
    feature_engine.stop()
    listener.stop()

    stats = defense.get_stats()
    logger.info(
        "Session stats — blocks: %d, skipped (cooldown): %d, API errors: %d",
        stats["blocks"],
        stats["skipped_cooldown"],
        stats["api_errors"],
    )
    logger.info("Engine stopped")


if __name__ == "__main__":
    run()
