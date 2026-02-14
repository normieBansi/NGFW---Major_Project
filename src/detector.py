"""
detector.py — Real-time anomaly detection using a trained Isolation Forest.

Receives FeatureVector objects from the FeatureEngine, runs inference,
and emits alerts when anomalous behavior is detected.  Implements a
consecutive-window confirmation strategy to reduce false positives.
"""

import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple

import numpy as np

from src.config import (
    MODEL_PATH,
    SCALER_PATH,
    FEATURE_COLUMNS,
    ANOMALY_THRESHOLD_CONSECUTIVE,
)
from src.feature_engine import FeatureVector
from src.model_trainer import load_model
from src.utils import setup_logging

logger = setup_logging("detector")


@dataclass
class AnomalyAlert:
    """Represents a confirmed anomaly event."""
    src_ip: str
    timestamp: float
    score: float               # Isolation Forest decision score (negative = anomaly)
    feature_vector: FeatureVector
    consecutive_count: int     # How many consecutive anomaly windows


class AnomalyDetector:
    """
    Stateful detector that wraps the Isolation Forest model.

    For each source IP it tracks the number of consecutive anomaly
    windows.  An AnomalyAlert is emitted only when the count reaches
    ANOMALY_THRESHOLD_CONSECUTIVE, avoiding single-window false
    positives.
    """

    def __init__(
        self,
        model_path: str = MODEL_PATH,
        scaler_path: str = SCALER_PATH,
        consecutive_threshold: int = ANOMALY_THRESHOLD_CONSECUTIVE,
    ):
        self.model, self.scaler = load_model(model_path, scaler_path)
        self.consecutive_threshold = consecutive_threshold

        # Per-IP state: consecutive anomaly window count
        self._consecutive: dict[str, int] = defaultdict(int)
        # Callbacks that receive confirmed AnomalyAlerts
        self._callbacks: List[Callable[[AnomalyAlert], None]] = []

        logger.info(
            "Detector initialised (consecutive threshold = %d)",
            self.consecutive_threshold,
        )

    def register_callback(self, cb: Callable[[AnomalyAlert], None]) -> None:
        self._callbacks.append(cb)

    def evaluate(self, fv: FeatureVector) -> Optional[AnomalyAlert]:
        """
        Evaluate a single FeatureVector.

        Returns an AnomalyAlert if the consecutive threshold is met,
        otherwise returns None but updates internal state.
        """
        x = np.array([fv.as_list()], dtype=np.float64)
        x_scaled = self.scaler.transform(x)

        prediction = self.model.predict(x_scaled)[0]     # +1 normal, -1 anomaly
        score = self.model.decision_function(x_scaled)[0] # lower = more anomalous

        src_ip = fv.src_ip

        if prediction == -1:
            self._consecutive[src_ip] += 1
            logger.debug(
                "Anomaly window for %s (score=%.4f, consec=%d)",
                src_ip, score, self._consecutive[src_ip],
            )
            if self._consecutive[src_ip] >= self.consecutive_threshold:
                alert = AnomalyAlert(
                    src_ip=src_ip,
                    timestamp=time.time(),
                    score=score,
                    feature_vector=fv,
                    consecutive_count=self._consecutive[src_ip],
                )
                # Dispatch to callbacks
                for cb in self._callbacks:
                    try:
                        cb(alert)
                    except Exception as exc:
                        logger.error("Alert callback error: %s", exc)
                return alert
        else:
            # Reset consecutive counter on a normal window
            if self._consecutive.get(src_ip, 0) > 0:
                logger.debug("Normal window for %s — resetting counter", src_ip)
            self._consecutive[src_ip] = 0

        return None

    def reset(self, src_ip: str) -> None:
        """Manually reset the consecutive counter for a source IP."""
        self._consecutive[src_ip] = 0
