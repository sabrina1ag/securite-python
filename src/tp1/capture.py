"""Packet capture utilities for live network traffic."""

from __future__ import annotations

import logging
import signal
import time
from dataclasses import dataclass
from threading import Event

from scapy.all import Packet, conf, sniff
from scapy.arch import get_if_list

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class CaptureResult:
    """Container for packet capture results.

    Attributes:
        packets: Captured packets in order of arrival.
        interface: Interface used for capture.
        started_at: Epoch timestamp when capture started.
        ended_at: Epoch timestamp when capture ended.
    """

    packets: list[Packet]
    interface: str
    started_at: float
    ended_at: float

    @property
    def duration(self) -> float:
        """Return capture duration in seconds."""
        return max(0.0, self.ended_at - self.started_at)


def detect_default_interface(interface: str | None = None) -> str:
    """Detect the interface used for capture.

    Args:
        interface: Preferred interface from CLI, if provided.

    Returns:
        The validated network interface name.

    Raises:
        RuntimeError: If no valid interface is available.
    """
    available = get_if_list()
    if interface:
        if interface not in available:
            raise RuntimeError(f"Interface introuvable: {interface}")
        return interface

    conf_iface = str(getattr(conf, "iface", "") or "")
    if conf_iface and conf_iface in available:
        return conf_iface

    for candidate in available:
        if candidate.lower() != "lo":
            return candidate

    if available:
        return available[0]
    raise RuntimeError("Aucune interface reseau disponible.")


def capture_packets(
    interface: str | None = None,
    duration: int | None = None,
    verbose: bool = False,
) -> CaptureResult:
    """Capture packets in real time with graceful SIGINT stop.

    Args:
        interface: Optional interface name. Auto-detected if omitted.
        duration: Capture duration in seconds. If None, waits for Ctrl+C.
        verbose: When True, logs each captured packet summary.

    Returns:
        Capture result with packets and metadata.

    Raises:
        RuntimeError: If capture setup or sniffing fails.
    """
    selected_interface = detect_default_interface(interface)
    stop_event = Event()
    packets: list[Packet] = []
    started_at = time.time()
    previous_handler = signal.getsignal(signal.SIGINT)

    def _handle_sigint(signum: int, _frame: object) -> None:
        """Handle Ctrl+C to stop sniff cleanly."""
        LOGGER.info("SIGINT recu (%s), arret de la capture...", signum)
        stop_event.set()

    def _on_packet(packet: Packet) -> None:
        """Store packet and optionally log details."""
        packets.append(packet)
        if verbose:
            LOGGER.info("Paquet capture: %s", packet.summary())

    def _should_stop(_packet: Packet) -> bool:
        """Signal sniff termination when requested."""
        return stop_event.is_set()

    if duration is not None and duration <= 0:
        raise RuntimeError("La duree doit etre un entier strictement positif.")

    signal.signal(signal.SIGINT, _handle_sigint)
    try:
        LOGGER.info(
            "Demarrage capture sur %s (duree=%s)",
            selected_interface,
            duration if duration is not None else "infinie",
        )
        if duration is not None:
            sniff(
                iface=selected_interface,
                prn=_on_packet,
                stop_filter=_should_stop,
                timeout=duration,
                store=False,
            )
        else:
            while not stop_event.is_set():
                sniff(
                    iface=selected_interface,
                    prn=_on_packet,
                    stop_filter=_should_stop,
                    timeout=1,
                    store=False,
                )
    except PermissionError as exc:
        raise RuntimeError("Droits insuffisants pour la capture reseau.") from exc
    except OSError as exc:
        raise RuntimeError(f"Erreur reseau pendant la capture: {exc}") from exc
    finally:
        signal.signal(signal.SIGINT, previous_handler)

    ended_at = time.time()
    LOGGER.info(
        "Capture terminee: %d paquets en %.2fs", len(packets), ended_at - started_at
    )
    return CaptureResult(
        packets=packets,
        interface=selected_interface,
        started_at=started_at,
        ended_at=ended_at,
    )
