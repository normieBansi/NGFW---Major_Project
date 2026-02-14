"""
defense.py — Automated firewall response via OPNsense API.

When the detector raises an AnomalyAlert, the defense module:
  1. Checks if the IP is already blocked (cooldown / alias membership).
  2. Adds the IP to the OPNsense firewall alias (ml_blocklist).
  3. Triggers a firewall reconfigure so the rule takes effect.
  4. Records the block event to avoid redundant API calls.

The OPNsense REST API uses HTTP Basic auth with an API key/secret
pair.  SSL verification is disabled for the lab's self-signed cert.
"""

import time
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Set

import requests
import urllib3

from src.config import (
    OPNSENSE_API_KEY,
    OPNSENSE_API_SECRET,
    OPNSENSE_VERIFY_SSL,
    ALIAS_ADD_URL,
    ALIAS_RECONFIGURE_URL,
    BLOCK_COOLDOWN_SECONDS,
)
from src.detector import AnomalyAlert
from src.utils import setup_logging

# Suppress InsecureRequestWarning for self-signed certs in the lab
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = setup_logging("defense")


@dataclass
class BlockRecord:
    """Tracks when an IP was last blocked to enforce cooldown."""
    ip: str
    blocked_at: float
    alert_score: float


class DefenseEngine:
    """
    Receives AnomalyAlerts and translates them into firewall API
    calls that block the offending source IP.
    """

    def __init__(
        self,
        api_key: str = OPNSENSE_API_KEY,
        api_secret: str = OPNSENSE_API_SECRET,
        verify_ssl: bool = OPNSENSE_VERIFY_SSL,
        cooldown: float = BLOCK_COOLDOWN_SECONDS,
    ):
        self.auth = (api_key, api_secret)
        self.verify = verify_ssl
        self.cooldown = cooldown

        self._block_history: Dict[str, BlockRecord] = {}
        self._lock = threading.Lock()
        self._stats = {"blocks": 0, "skipped_cooldown": 0, "api_errors": 0}

    # ── public API ──

    def handle_alert(self, alert: AnomalyAlert) -> bool:
        """
        Process an anomaly alert.  Returns True if the IP was
        successfully blocked, False otherwise.
        """
        ip = alert.src_ip
        now = time.time()

        with self._lock:
            # Check cooldown
            if ip in self._block_history:
                elapsed = now - self._block_history[ip].blocked_at
                if elapsed < self.cooldown:
                    logger.info(
                        "SKIP block %s — cooldown active (%.0fs remaining)",
                        ip,
                        self.cooldown - elapsed,
                    )
                    self._stats["skipped_cooldown"] += 1
                    return False

        # Attempt to add IP to alias
        if not self._add_to_alias(ip):
            return False

        # Trigger firewall reconfigure
        self._reconfigure()

        # Record the block
        with self._lock:
            self._block_history[ip] = BlockRecord(
                ip=ip,
                blocked_at=now,
                alert_score=alert.score,
            )
            self._stats["blocks"] += 1

        logger.warning(
            "🛡️  BLOCKED %s  (score=%.4f, consecutive=%d)",
            ip,
            alert.score,
            alert.consecutive_count,
        )
        return True

    def get_stats(self) -> dict:
        """Return a copy of defense statistics."""
        return dict(self._stats)

    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is currently within its cooldown window."""
        with self._lock:
            rec = self._block_history.get(ip)
            if rec is None:
                return False
            return (time.time() - rec.blocked_at) < self.cooldown

    # ── OPNsense API calls ──

    def _add_to_alias(self, ip: str) -> bool:
        """POST the IP to the firewall alias."""
        try:
            resp = requests.post(
                ALIAS_ADD_URL,
                auth=self.auth,
                json={"address": ip},
                verify=self.verify,
                timeout=10,
            )
            if resp.status_code == 200:
                logger.info("Added %s to firewall alias", ip)
                return True
            else:
                logger.error(
                    "Alias API returned %d: %s",
                    resp.status_code,
                    resp.text[:200],
                )
                self._stats["api_errors"] += 1
                return False
        except requests.RequestException as exc:
            logger.error("Alias API request failed: %s", exc)
            self._stats["api_errors"] += 1
            return False

    def _reconfigure(self) -> None:
        """Tell OPNsense to apply alias changes."""
        try:
            resp = requests.post(
                ALIAS_RECONFIGURE_URL,
                auth=self.auth,
                json={},
                verify=self.verify,
                timeout=15,
            )
            if resp.status_code == 200:
                logger.info("Firewall reconfigure triggered")
            else:
                logger.error(
                    "Reconfigure API returned %d: %s",
                    resp.status_code,
                    resp.text[:200],
                )
        except requests.RequestException as exc:
            logger.error("Reconfigure API failed: %s", exc)
