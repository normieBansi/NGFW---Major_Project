"""
model_trainer.py — Train and persist the Isolation Forest anomaly detector.

This module provides:
  1. Synthetic baseline data generation (for initial model training when
     only limited real syslog data is available).
  2. CSV-based training from captured syslog log files.
  3. Model + scaler saving / loading helpers.

The trained model is an sklearn IsolationForest wrapped with a
StandardScaler for feature normalization.  Both are serialised to
disk via joblib.
"""

import os
import time
import random
from typing import List, Optional, Tuple

import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from src.config import (
    MODEL_PATH,
    SCALER_PATH,
    IF_N_ESTIMATORS,
    IF_CONTAMINATION,
    IF_MAX_SAMPLES,
    IF_RANDOM_STATE,
    FEATURE_COLUMNS,
    TRAINING_DATA_DIR,
    BASELINE_CSV,
)
from src.feature_engine import FeatureEngine, FeatureVector
from src.log_parser import ParsedPacket, parse_log_file
from src.utils import setup_logging

logger = setup_logging("model_trainer")


# ──────────────────────────────────────────────
# Synthetic baseline generator
# ──────────────────────────────────────────────

def generate_synthetic_baseline(n_windows: int = 500) -> pd.DataFrame:
    """
    Create a DataFrame of *normal* traffic feature vectors using
    random sampling that mimics typical baseline behavior:
      • Low PPS (1–30)
      • Mixed protocols
      • Low SYN ratio
      • Modest packet sizes

    This is useful for bootstrapping a model before real captures are
    available.
    """
    rng = np.random.default_rng(seed=42)
    rows = []
    for _ in range(n_windows):
        pps = rng.uniform(1, 30)
        avg_len = rng.uniform(40, 1400)
        tcp_r = rng.uniform(0.3, 0.8)
        udp_r = rng.uniform(0.0, 1.0 - tcp_r)
        icmp_r = max(0.0, 1.0 - tcp_r - udp_r)
        row = {
            "pps": pps,
            "bytes_per_second": pps * avg_len,
            "avg_pkt_len": avg_len,
            "std_pkt_len": rng.uniform(10, 300),
            "syn_ratio": rng.uniform(0.0, 0.25),
            "fin_ratio": rng.uniform(0.0, 0.2),
            "rst_ratio": rng.uniform(0.0, 0.05),
            "ack_ratio": rng.uniform(0.2, 0.8),
            "tcp_ratio": tcp_r,
            "udp_ratio": udp_r,
            "icmp_ratio": icmp_r,
            "inter_arrival_mean": rng.uniform(30, 500),
            "inter_arrival_std": rng.uniform(5, 150),
            "unique_dst_ports": rng.integers(1, 15),
            "burst_score": rng.uniform(1, 15),
        }
        rows.append(row)
    df = pd.DataFrame(rows, columns=FEATURE_COLUMNS)
    logger.info("Generated %d synthetic baseline windows", n_windows)
    return df


def generate_synthetic_attacks(n_windows: int = 100) -> pd.DataFrame:
    """
    Generate synthetic *attack* traffic feature windows for
    contamination-aware training or evaluation.

    Each row represents one of several attack profiles chosen at random:
      • SYN flood   – very high PPS, SYN ratio ≈1
      • UDP flood   – very high PPS, UDP ratio ≈1
      • ICMP flood  – high PPS, ICMP ratio ≈1
      • Port scan   – moderate PPS, many unique dst ports
    """
    rng = np.random.default_rng(seed=99)
    attack_profiles = ["syn_flood", "udp_flood", "icmp_flood", "port_scan"]
    rows = []
    for _ in range(n_windows):
        atype = rng.choice(attack_profiles)
        if atype == "syn_flood":
            pps = rng.uniform(200, 5000)
            row = {
                "pps": pps,
                "bytes_per_second": pps * rng.uniform(40, 60),
                "avg_pkt_len": rng.uniform(40, 60),
                "std_pkt_len": rng.uniform(0, 5),
                "syn_ratio": rng.uniform(0.9, 1.0),
                "fin_ratio": 0.0,
                "rst_ratio": rng.uniform(0.0, 0.05),
                "ack_ratio": rng.uniform(0.0, 0.05),
                "tcp_ratio": 1.0,
                "udp_ratio": 0.0,
                "icmp_ratio": 0.0,
                "inter_arrival_mean": rng.uniform(0.1, 5),
                "inter_arrival_std": rng.uniform(0.01, 2),
                "unique_dst_ports": rng.integers(1, 5),
                "burst_score": rng.uniform(100, 2000),
            }
        elif atype == "udp_flood":
            pps = rng.uniform(300, 8000)
            row = {
                "pps": pps,
                "bytes_per_second": pps * rng.uniform(100, 1400),
                "avg_pkt_len": rng.uniform(100, 1400),
                "std_pkt_len": rng.uniform(0, 20),
                "syn_ratio": 0.0,
                "fin_ratio": 0.0,
                "rst_ratio": 0.0,
                "ack_ratio": 0.0,
                "tcp_ratio": 0.0,
                "udp_ratio": 1.0,
                "icmp_ratio": 0.0,
                "inter_arrival_mean": rng.uniform(0.05, 3),
                "inter_arrival_std": rng.uniform(0.01, 1),
                "unique_dst_ports": rng.integers(1, 3),
                "burst_score": rng.uniform(200, 3000),
            }
        elif atype == "icmp_flood":
            pps = rng.uniform(200, 4000)
            row = {
                "pps": pps,
                "bytes_per_second": pps * rng.uniform(64, 128),
                "avg_pkt_len": rng.uniform(64, 128),
                "std_pkt_len": rng.uniform(0, 10),
                "syn_ratio": 0.0,
                "fin_ratio": 0.0,
                "rst_ratio": 0.0,
                "ack_ratio": 0.0,
                "tcp_ratio": 0.0,
                "udp_ratio": 0.0,
                "icmp_ratio": 1.0,
                "inter_arrival_mean": rng.uniform(0.1, 5),
                "inter_arrival_std": rng.uniform(0.01, 2),
                "unique_dst_ports": 0,
                "burst_score": rng.uniform(100, 1500),
            }
        else:  # port_scan
            pps = rng.uniform(50, 300)
            row = {
                "pps": pps,
                "bytes_per_second": pps * rng.uniform(40, 60),
                "avg_pkt_len": rng.uniform(40, 60),
                "std_pkt_len": rng.uniform(0, 10),
                "syn_ratio": rng.uniform(0.8, 1.0),
                "fin_ratio": 0.0,
                "rst_ratio": rng.uniform(0.0, 0.1),
                "ack_ratio": 0.0,
                "tcp_ratio": 1.0,
                "udp_ratio": 0.0,
                "icmp_ratio": 0.0,
                "inter_arrival_mean": rng.uniform(3, 20),
                "inter_arrival_std": rng.uniform(1, 10),
                "unique_dst_ports": rng.integers(50, 500),
                "burst_score": rng.uniform(10, 100),
            }
        rows.append(row)
    df = pd.DataFrame(rows, columns=FEATURE_COLUMNS)
    logger.info("Generated %d synthetic attack windows", n_windows)
    return df


# ──────────────────────────────────────────────
# Training from captured log files
# ──────────────────────────────────────────────

def features_from_log_file(
    log_path: str,
    window_size: float = 5.0,
) -> pd.DataFrame:
    """
    Parse a syslog capture file and compute feature windows per source IP.

    Packets are grouped by source IP, then sliced into non-overlapping
    windows of *window_size* seconds.
    """
    packets = parse_log_file(log_path)
    if not packets:
        logger.warning("No packets parsed from %s", log_path)
        return pd.DataFrame(columns=FEATURE_COLUMNS)

    engine = FeatureEngine(window_size=window_size, min_packets=1)

    # Group by src_ip
    from collections import defaultdict
    ip_groups = defaultdict(list)
    for p in packets:
        ip_groups[p.src_ip].append(p)

    rows = []
    for src_ip, pkts in ip_groups.items():
        pkts.sort(key=lambda p: p.timestamp)
        start = pkts[0].timestamp
        end = pkts[-1].timestamp
        t = start
        while t < end:
            win_pkts = [p for p in pkts if t <= p.timestamp < t + window_size]
            if win_pkts:
                fv = engine.compute_now(src_ip, win_pkts)
                if fv:
                    rows.append(fv.as_dict())
            t += window_size

    df = pd.DataFrame(rows, columns=FEATURE_COLUMNS).fillna(0.0)
    logger.info("Extracted %d feature windows from %s", len(df), log_path)
    return df


# ──────────────────────────────────────────────
# Model training
# ──────────────────────────────────────────────

def train_model(
    training_df: pd.DataFrame,
    n_estimators: int = IF_N_ESTIMATORS,
    contamination: float = IF_CONTAMINATION,
    max_samples=IF_MAX_SAMPLES,
    random_state: int = IF_RANDOM_STATE,
) -> Tuple[IsolationForest, StandardScaler]:
    """
    Fit an Isolation Forest on the provided feature DataFrame.

    Returns the trained model and fitted scaler as a tuple.
    """
    logger.info(
        "Training Isolation Forest on %d samples × %d features",
        len(training_df),
        len(FEATURE_COLUMNS),
    )

    X = training_df[FEATURE_COLUMNS].values.astype(np.float64)

    # Standardize features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        max_samples=max_samples, # type: ignore
        random_state=random_state,
        n_jobs=-1,
    )
    model.fit(X_scaled)

    logger.info("Model training complete")
    return model, scaler


def save_model(
    model: IsolationForest,
    scaler: StandardScaler,
    model_path: str = MODEL_PATH,
    scaler_path: str = SCALER_PATH,
) -> None:
    """Persist model and scaler to disk."""
    os.makedirs(os.path.dirname(model_path) or ".", exist_ok=True)
    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)
    logger.info("Model saved → %s", model_path)
    logger.info("Scaler saved → %s", scaler_path)


def load_model(
    model_path: str = MODEL_PATH,
    scaler_path: str = SCALER_PATH,
) -> Tuple[IsolationForest, StandardScaler]:
    """Load a previously saved model and scaler."""
    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
    logger.info("Model loaded ← %s", model_path)
    return model, scaler


# ──────────────────────────────────────────────
# CLI entry point
# ──────────────────────────────────────────────

def main() -> None:
    """
    Train the model.  Attempts to use real log data from data/ directory;
    falls back to synthetic generation if no log files are found.
    """
    os.makedirs(TRAINING_DATA_DIR, exist_ok=True)

    # Try to load real captured data
    log_files = [
        os.path.join(TRAINING_DATA_DIR, f)
        for f in os.listdir(TRAINING_DATA_DIR)
        if f.endswith(".log")
    ] if os.path.isdir(TRAINING_DATA_DIR) else []

    if log_files:
        logger.info("Found %d log files for training", len(log_files))
        dfs = [features_from_log_file(lf) for lf in log_files]
        training_df = pd.concat(dfs, ignore_index=True)
    else:
        logger.info("No log files found — using synthetic baseline data")
        baseline = generate_synthetic_baseline(500)
        # Optionally add a small fraction of attack data as contamination
        # so the model sees the boundary
        training_df = baseline

    if training_df.empty:
        logger.error("No training data available")
        return

    # Save training data CSV for reference
    csv_path = os.path.join(TRAINING_DATA_DIR, "training_features.csv")
    training_df.to_csv(csv_path, index=False)
    logger.info("Training features saved → %s", csv_path)

    model, scaler = train_model(training_df)
    save_model(model, scaler)

    # Quick sanity check with synthetic attacks
    attacks = generate_synthetic_attacks(50)
    X_atk = scaler.transform(attacks[FEATURE_COLUMNS].values)
    preds = model.predict(X_atk)
    anomaly_pct = (preds == -1).sum() / len(preds) * 100
    logger.info(
        "Sanity check: %.1f%% of synthetic attacks flagged as anomalies",
        anomaly_pct,
    )


if __name__ == "__main__":
    main()
