"""ReportLab flowables for Vrika scan compliance framework cards."""

from __future__ import annotations

from dataclasses import dataclass

from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, Spacer, Table, TableStyle

from .components import escape_html, truncate_text
from .vrika_branding import COLOR_VRIKA_PURPLE_LIGHT

COLOR_COMPLIANT = colors.HexColor("#87ae73")
COLOR_NON_COMPLIANT = colors.HexColor("#AD151A")


@dataclass(frozen=True)
class FrameworkCard:
    name: str
    score: float
    passed: int
    failed: int
    total: int
    services: str


def build_framework_card(
    card: FrameworkCard,
    title_style: ParagraphStyle,
    body_style: ParagraphStyle,
) -> Table:
    """Render one compliance framework summary card."""
    title = escape_html(truncate_text(card.name, 70))
    if card.total:
        score_line = (
            f"{card.score:.1f}% compliant "
            f"({card.passed:,} of {card.total:,} requirements passed)"
        )
    else:
        score_line = "No evaluated requirements"

    services = escape_html(truncate_text(card.services or "N/A", 120))
    header = Paragraph(f"<b>{title}</b>", title_style)
    stats_row = [
        [
            Paragraph(
                f'<font color="#AD151A"><b>{card.failed:,}</b></font><br/>Failed reqs',
                body_style,
            ),
            Paragraph(
                f'<font color="#87ae73"><b>{card.passed:,}</b></font><br/>Passed reqs',
                body_style,
            ),
            Paragraph(
                f"<b>{card.score:.1f}%</b><br/>Score",
                body_style,
            ),
        ]
    ]
    stats_table = Table(stats_row, colWidths=[1.6 * inch, 1.6 * inch, 1.2 * inch])
    stats_table.setStyle(
        TableStyle(
            [
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )

    outer = Table(
        [
            [header],
            [Paragraph(score_line, body_style)],
            [stats_table],
            [Paragraph(f"<b>Services:</b> {services}", body_style)],
        ],
        colWidths=[5.2 * inch],
    )
    outer.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 1, COLOR_VRIKA_PURPLE_LIGHT),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F8F6FC")),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    return outer


def build_framework_card_grid(
    cards: list[FrameworkCard],
    title_style: ParagraphStyle,
    body_style: ParagraphStyle,
) -> list:
    """Return flowables for a vertical stack of framework cards."""
    flowables: list = []
    for card in cards:
        flowables.append(build_framework_card(card, title_style, body_style))
        flowables.append(Spacer(1, 0.12 * inch))
    return flowables


def build_pass_fail_status_bar(
    passed: int,
    failed: int,
    width: float = 4.5 * inch,
) -> Table:
    """Horizontal green/red pass-fail bar inspired by the HTML reference."""
    total = passed + failed
    if total <= 0:
        return Table([["No evaluated controls"]], colWidths=[width])

    pass_width = width * (passed / total)
    fail_width = width - pass_width
    bar = Table(
        [["", ""]],
        colWidths=[pass_width or 0.01, fail_width or 0.01],
        rowHeights=[0.22 * inch],
    )
    bar.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, 0), COLOR_COMPLIANT),
                ("BACKGROUND", (1, 0), (1, 0), COLOR_NON_COMPLIANT),
                ("BOX", (0, 0), (-1, -1), 0, colors.white),
            ]
        )
    )

    legend = Table(
        [
            [
                Paragraph(
                    f'<font color="#87ae73">■</font> {passed:,} PASS',
                    ParagraphStyle("lg", fontSize=9, fontName="PlusJakartaSans"),
                ),
                Paragraph(
                    f'<font color="#AD151A">■</font> {failed:,} FAIL',
                    ParagraphStyle("lg2", fontSize=9, fontName="PlusJakartaSans"),
                ),
            ]
        ],
        colWidths=[width / 2, width / 2],
    )
    legend.setStyle(TableStyle([("ALIGN", (0, 0), (-1, -1), "LEFT")]))

    wrapper = Table([[bar], [legend]], colWidths=[width])
    wrapper.setStyle(TableStyle([("LEFTPADDING", (0, 0), (-1, -1), 0)]))
    return wrapper
