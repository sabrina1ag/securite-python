"""Command-line interface for the TP1 network analyzer."""

from __future__ import annotations

import argparse
import logging
import platform
from pathlib import Path

from tp1.analyzer import TrafficAnalyzer
from tp1.blocker import block_ip, is_root_user
from tp1.capture import capture_packets
from tp1.report import generate_pdf_report


def _configure_logging(verbose: bool) -> None:
    """Configure logging level and format.

    Args:
        verbose: Enable debug-like verbosity when True.
    """
    level = logging.INFO if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


def parse_args() -> argparse.Namespace:
    """Parse command-line options.

    Returns:
        Parsed argument namespace.
    """
    parser = argparse.ArgumentParser(prog="python -m tp1")
    parser.add_argument(
        "--interface",
        type=str,
        default=None,
        help="Interface reseau (defaut: auto-detection)",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=None,
        help="Duree en secondes (defaut: infini jusqu'a Ctrl+C)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=".",
        help="Repertoire de sortie du PDF (defaut: ./)",
    )
    parser.add_argument(
        "--block",
        dest="block",
        action="store_true",
        help="Activer le blocage automatique iptables",
    )
    parser.add_argument(
        "--no-block",
        dest="block",
        action="store_false",
        help="Desactiver le blocage automatique iptables",
    )
    parser.set_defaults(block=False)
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Afficher les paquets en temps reel dans le terminal",
    )
    return parser.parse_args()


def run() -> int:
    """Execute end-to-end workflow for capture and report.

    Returns:
        Exit code, where 0 means success.
    """
    args = parse_args()
    _configure_logging(args.verbose)
    logger = logging.getLogger(__name__)

    if platform.system().lower() != "linux":
        logger.error("Ce projet fonctionne uniquement sur Linux.")
        return 1

    if args.block and not is_root_user():
        logger.warning("Blocage actif mais droits root absents: iptables peut echouer.")

    try:
        capture_result = capture_packets(
            interface=args.interface, duration=args.duration, verbose=args.verbose
        )
        analyzer = TrafficAnalyzer()
        analysis = analyzer.analyze_packets(capture_result.packets)

        if args.block:
            blocked_log = Path(args.output) / "blocked.log"
            seen_ips: set[str] = set()
            for event in analysis.attacks:
                if event.source_ip in seen_ips or event.source_ip == "unknown":
                    continue
                if block_ip(event.source_ip, blocked_log):
                    seen_ips.add(event.source_ip)

        report_path = generate_pdf_report(
            analysis=analysis,
            interface=capture_result.interface,
            duration=capture_result.duration,
            output_dir=Path(args.output),
        )
        logger.warning("Analyse terminee. Rapport: %s", report_path.resolve())
        return 0
    except RuntimeError as exc:
        logger.error("Erreur d'execution: %s", exc)
        return 2
    except PermissionError:
        logger.error("Droits insuffisants pour executer les operations reseau.")
        return 3
    except OSError as exc:
        logger.error("Erreur systeme: %s", exc)
        return 4


if __name__ == "__main__":
    raise SystemExit(run())
