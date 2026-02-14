"""
utils.py — Shared utility functions.
"""

import logging
import os
import sys
from datetime import datetime

from src.config import LOG_LEVEL, LOG_FILE, LOG_FORMAT


def setup_logging(name: str = "ngfw") -> logging.Logger:
    """Configure and return a logger with file + console handlers."""
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

    formatter = logging.Formatter(LOG_FORMAT)

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # File handler (create directory if needed)
    log_dir = os.path.dirname(LOG_FILE)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
    fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    return logger


def ts_now() -> float:
    """Return current timestamp as a float (seconds since epoch)."""
    return datetime.now().timestamp()


def safe_int(value: str, default: int = 0) -> int:
    """Parse an integer safely, returning *default* on failure."""
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def safe_float(value: str, default: float = 0.0) -> float:
    """Parse a float safely, returning *default* on failure."""
    try:
        return float(value)
    except (ValueError, TypeError):
        return default
