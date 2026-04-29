"""CLI entrypoint for TP2 shellcode analysis."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from tp2.analyzer import analyze_shellcode, split_shellcode_blocks


def _build_parser() -> argparse.ArgumentParser:
    """Create the CLI parser."""
    parser = argparse.ArgumentParser(prog="tp2")
    parser.add_argument(
        "-f",
        "--file",
        required=True,
        type=Path,
        help="Chemin du fichier contenant le shellcode.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Active les logs detaillees.",
    )
    return parser


def _configure_logging(verbose: bool) -> None:
    """Configure command logging."""
    level = logging.INFO if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


def cli() -> int:
    """Run TP2 CLI and print analysis results."""
    args = _build_parser().parse_args()
    _configure_logging(args.verbose)
    logger = logging.getLogger(__name__)

    if not args.file.exists():
        logger.error("Fichier introuvable: %s", args.file)
        return 2

    content = args.file.read_text(encoding="utf-8", errors="ignore")
    blocks = split_shellcode_blocks(content)
    if not blocks:
        logger.error("Aucun shellcode detecte dans le fichier.")
        return 3

    for block_name, shellcode in blocks:
        print(f"[{block_name}] Testing shellcode of size {len(shellcode)}B")
        result = analyze_shellcode(shellcode)
        print("Shellcode analysed !")
        print("- Strings detectees:")
        if result.extracted_strings:
            for value in result.extracted_strings:
                print(f"  - {value}")
        else:
            print("  - (aucune chaine printable)")

        print("- Analyse Pylibemu:")
        print(result.pylibemu_analysis)
        print("- Analyse Capstone:")
        print(result.capstone_analysis)
        print("- Explication (heuristique locale):")
        print(result.llm_analysis)
        print("=" * 72)

    return 0


if __name__ == "__main__":
    raise SystemExit(cli())
