"""Core analysis functions for TP2 shellcode project."""

from __future__ import annotations

import logging
import re
import string
from dataclasses import dataclass

LOGGER = logging.getLogger(__name__)

_HEX_ESCAPE_RE = re.compile(r"\\x([0-9a-fA-F]{2})")


@dataclass(slots=True)
class ShellcodeAnalysis:
    """Aggregate shellcode analysis outputs."""

    size: int
    extracted_strings: list[str]
    pylibemu_analysis: str
    capstone_analysis: str
    llm_analysis: str


def parse_shellcode_text(content: str) -> bytes:
    """Parse shellcode from text containing escaped bytes.

    Args:
        content: Raw text from a shellcode file.

    Returns:
        Decoded shellcode bytes.
    """
    chunks = _HEX_ESCAPE_RE.findall(content)
    if chunks:
        return bytes(int(chunk, 16) for chunk in chunks)
    return content.encode("latin-1", errors="ignore")


def split_shellcode_blocks(content: str) -> list[tuple[str, bytes]]:
    """Extract named shellcode blocks from the input text.

    Args:
        content: Text containing one or multiple shellcodes.

    Returns:
        List of tuples ``(block_name, shellcode_bytes)``.
    """
    pattern = re.compile(r"niveau\s*:\s*([^\n:]+)\s*:\s*", re.IGNORECASE)
    matches = list(pattern.finditer(content))
    if not matches:
        return [("shellcode", parse_shellcode_text(content))]

    blocks: list[tuple[str, bytes]] = []
    for index, match in enumerate(matches):
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(content)
        block_name = match.group(1).strip().lower()
        block_text = content[start:end]
        blocks.append((block_name, parse_shellcode_text(block_text)))
    return blocks


def get_shellcode_strings(shellcode: bytes, min_length: int = 4) -> list[str]:
    """Return printable strings embedded in shellcode bytes.

    Args:
        shellcode: Shellcode bytes.
        min_length: Minimum length for extracted strings.

    Returns:
        Extracted ASCII-like strings sorted by appearance.
    """
    printable = set(string.printable) - {"\x0b", "\x0c", "\r", "\n", "\t"}
    current: list[str] = []
    found: list[str] = []
    for byte in shellcode:
        char = chr(byte)
        if char in printable:
            current.append(char)
        else:
            if len(current) >= min_length:
                found.append("".join(current))
            current = []
    if len(current) >= min_length:
        found.append("".join(current))
    return found


def get_pylibemu_analysis(shellcode: bytes) -> str:
    """Return pylibemu emulation analysis for shellcode.

    Args:
        shellcode: Shellcode bytes.

    Returns:
        Emulation report or explicit fallback message.
    """
    try:
        import pylibemu  # type: ignore
    except ImportError:
        return "pylibemu indisponible dans cet environnement."

    try:
        emulator = pylibemu.Emulator()
        emulator.run(shellcode)
        profile = getattr(emulator, "emu_profile_output", "")
        if profile:
            return str(profile)
        if hasattr(emulator, "test"):
            return str(emulator.test())
        return "Emulation terminee, aucun profile detaille disponible."
    except Exception as exc:  # noqa: BLE001
        LOGGER.exception("Erreur pylibemu: %s", exc)
        return f"Erreur pylibemu: {exc}"


def get_capstone_analysis(shellcode: bytes, max_instructions: int = 80) -> str:
    """Return disassembly using Capstone.

    Args:
        shellcode: Shellcode bytes.
        max_instructions: Maximum displayed instruction count.

    Returns:
        Human-readable disassembly or fallback message.
    """
    try:
        from capstone import CS_ARCH_X86, CS_MODE_32, Cs  # type: ignore
    except ImportError:
        return "Capstone indisponible dans cet environnement."

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    lines: list[str] = []
    for index, instruction in enumerate(md.disasm(shellcode, 0x1000)):
        if index >= max_instructions:
            lines.append("... sortie tronquee ...")
            break
        line = (
            f"0x{instruction.address:08x}: "
            f"{instruction.mnemonic} {instruction.op_str}"
        )
        lines.append(line.rstrip())
    return "\n".join(lines) if lines else "Aucune instruction decodee."


def get_llm_analysis(shellcode: bytes) -> str:
    """Return a local heuristic explanation (LLM-like summary).

    Args:
        shellcode: Shellcode bytes.

    Returns:
        Textual explanation inferred from extracted indicators.
    """
    strings_found = get_shellcode_strings(shellcode)
    capstone_report = get_capstone_analysis(shellcode, max_instructions=120)
    pylibemu_report = get_pylibemu_analysis(shellcode)

    indicators: list[str] = []
    joined = " | ".join(strings_found).lower()
    if any(
        token in joined for token in ["cmd.exe", "net user", "add", "administrator"]
    ):
        indicators.append(
            "probable execution de commandes systeme Windows "
            "(creation/modification de compte)."
        )
    if any(token in joined for token in ["ws2_", "socket", "connect"]):
        indicators.append("comportement orienté reseau/reverse shell probable.")
    if "createprocess" in pylibemu_report.lower():
        indicators.append("appel CreateProcess observe via emulation.")
    if "winexec" in capstone_report.lower() or "winexec" in pylibemu_report.lower():
        indicators.append("execution d'une commande via WinExec probable.")

    if not indicators:
        indicators.append(
            "shellcode probablement chargeur dynamique API (resolveur kernel32/ws2_32)."
        )

    return (
        "Ce shellcode semble malveillant. "
        f"Taille analysee: {len(shellcode)} octets. "
        "Indices principaux: " + " ".join(indicators)
    )


def analyze_shellcode(shellcode: bytes) -> ShellcodeAnalysis:
    """Run all shellcode analysis routines.

    Args:
        shellcode: Shellcode bytes.

    Returns:
        Aggregated analysis object.
    """
    return ShellcodeAnalysis(
        size=len(shellcode),
        extracted_strings=get_shellcode_strings(shellcode),
        pylibemu_analysis=get_pylibemu_analysis(shellcode),
        capstone_analysis=get_capstone_analysis(shellcode),
        llm_analysis=get_llm_analysis(shellcode),
    )
