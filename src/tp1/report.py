"""PDF report generation utilities."""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path

import matplotlib.pyplot as plt
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    Image,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from tp1.analyzer import AnalysisResult

LOGGER = logging.getLogger(__name__)


def _footer(canvas: object, doc: object) -> None:
    """Render page number in report footer."""
    canvas.saveState()
    canvas.setFont("Helvetica", 9)
    canvas.drawString(40, 20, f"Page {doc.page}")
    canvas.restoreState()


def _build_protocol_table(analysis: AnalysisResult) -> Table:
    """Build protocol statistics table."""
    total = analysis.total_packets or 1
    rows = [["Protocole", "Nombre de paquets", "% du trafic"]]
    for protocol, count in sorted(
        analysis.protocol_counts.items(), key=lambda item: item[1], reverse=True
    ):
        percent = round((count / total) * 100, 2)
        rows.append([protocol, str(count), f"{percent}%"])

    table = Table(rows, colWidths=[150, 180, 120])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("ALIGN", (1, 1), (-1, -1), "CENTER"),
            ]
        )
    )
    return table


def _create_protocol_chart(analysis: AnalysisResult, output_dir: Path) -> Path:
    """Create bar chart image and return its path."""
    protocols = list(analysis.protocol_counts.keys())
    values = [analysis.protocol_counts[name] for name in protocols]
    chart_path = output_dir / "protocol_chart.png"

    plt.figure(figsize=(8, 4))
    plt.bar(protocols, values, color="#2f5597")
    plt.xlabel("Protocoles")
    plt.ylabel("Nombre de paquets")
    plt.title("Repartition du trafic par protocole")
    plt.xticks(rotation=35, ha="right")
    plt.tight_layout()
    plt.savefig(chart_path, dpi=140)
    plt.close()
    return chart_path


def generate_pdf_report(
    analysis: AnalysisResult, interface: str, duration: float, output_dir: Path
) -> Path:
    """Generate professional PDF report from analysis.

    Args:
        analysis: Aggregated packet analysis output.
        interface: Captured interface name.
        duration: Capture duration in seconds.
        output_dir: Destination directory for report.

    Returns:
        Absolute path to generated PDF file.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_path = output_dir / f"rapport_{timestamp}.pdf"
    styles = getSampleStyleSheet()
    story: list[object] = []

    story.append(Paragraph("Rapport d'analyse reseau", styles["Title"]))
    story.append(
        Paragraph(
            (
                f"Date/heure: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>"
                f"Interface: {interface}<br/>"
                f"Duree: {duration:.2f} s"
            ),
            styles["Normal"],
        )
    )
    story.append(Spacer(1, 12))

    story.append(Paragraph("Tableau des protocoles", styles["Heading2"]))
    story.append(_build_protocol_table(analysis))
    story.append(Spacer(1, 12))

    if analysis.protocol_counts:
        chart_path = _create_protocol_chart(analysis, output_dir)
        story.append(Paragraph("Graphique des protocoles", styles["Heading2"]))
        story.append(Image(str(chart_path), width=470, height=235))
        story.append(Spacer(1, 12))

    story.append(Paragraph("Analyse de securite", styles["Heading2"]))
    if not analysis.attacks:
        story.append(
            Paragraph(
                '<font color="green">✅ Aucune activite suspecte detectee</font>',
                styles["Normal"],
            )
        )
    else:
        rows = [["Type", "Protocole", "IP", "MAC", "Timestamp", "Occurrences"]]
        for event in analysis.attacks:
            rows.append(
                [
                    event.attack_type,
                    event.protocol,
                    event.source_ip,
                    event.source_mac,
                    event.timestamp,
                    str(event.occurrences),
                ]
            )
        attack_table = Table(rows, colWidths=[85, 60, 90, 95, 105, 55])
        attack_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                ]
            )
        )
        story.append(attack_table)

    doc = SimpleDocTemplate(str(report_path), pagesize=A4)
    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    LOGGER.info("Rapport genere: %s", report_path)
    return report_path
