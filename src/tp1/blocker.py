"""Automatic attacker IP blocking using iptables."""

from __future__ import annotations

import logging
import os
import subprocess
from datetime import datetime
from pathlib import Path

LOGGER = logging.getLogger(__name__)


def is_root_user() -> bool:
    """Return True when running with root privileges."""
    return hasattr(os, "geteuid") and os.geteuid() == 0


def block_ip(ip_address: str, log_file: Path) -> bool:
    """Block source IP using iptables and append to log.

    Args:
        ip_address: Source IPv4/IPv6 string to block.
        log_file: File used to persist blocking events.

    Returns:
        True when the rule was successfully applied.
    """
    if os.name != "posix":
        LOGGER.warning("Blocage iptables supporte uniquement sur Linux.")
        return False

    command = ["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
    try:
        subprocess.run(command, check=True, capture_output=True, text=True)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        with log_file.open("a", encoding="utf-8") as handle:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            handle.write(f"{ts} | BLOCKED | {ip_address}\n")
        LOGGER.warning("IP bloquee: %s", ip_address)
        return True
    except subprocess.CalledProcessError as exc:
        LOGGER.error("Echec blocage iptables pour %s: %s", ip_address, exc.stderr)
        return False
