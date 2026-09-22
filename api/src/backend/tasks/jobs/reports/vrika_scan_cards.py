"""ReportLab flowables for Vrika scan compliance framework cards."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import Circle, Drawing, Rect, String
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.platypus import (
    Image,
    KeepTogether,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from .components import escape_html, truncate_text
from .vrika_branding import COLOR_VRIKA_PURPLE, COLOR_VRIKA_PURPLE_PALE

logger = logging.getLogger(__name__)
COLOR_COMPLIANT = colors.HexColor("#16856B")
COLOR_NON_COMPLIANT = colors.HexColor("#C43D53")
COLOR_BORDER = colors.HexColor("#E4E7EF")
COLOR_INK = colors.HexColor("#202B42")
COLOR_MUTED = colors.HexColor("#647084")


def _fit_logo(path: str, max_w: float, max_h: float) -> Image | None:
    """Return an Image scaled to fit within (max_w, max_h), preserving ratio."""
    from reportlab.lib.utils import ImageReader

    reader = ImageReader(path)
    iw, ih = reader.getSize()
    if not iw or not ih:
        return Image(path, width=max_w, height=max_h)
    scale = min(max_w / iw, max_h / ih)
    img = Image(path, width=iw * scale, height=ih * scale)
    img.hAlign = "LEFT"
    return img


@dataclass(frozen=True)
class FrameworkCard:
    name: str
    score: float
    passed: int
    failed: int
    total: int
    services: str
    logo_path: str | None = None


def build_framework_card(
    card: FrameworkCard,
    title_style: ParagraphStyle,
    body_style: ParagraphStyle,
    width: float = 5.2 * inch,
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
    title_style = ParagraphStyle(
        "FrameworkTitle",
        parent=title_style,
        fontSize=9,
        leading=12,
        textColor=COLOR_INK,
    )
    body_style = ParagraphStyle(
        "FrameworkBody",
        parent=body_style,
        fontSize=8,
        leading=11,
        textColor=COLOR_MUTED,
    )
    inner_width = width - 20
    title_para = Paragraph(title, title_style)

    # Header: framework logo (if available) + name, so cards match the
    # Compliance section's per-framework branding.
    header: object = title_para
    if card.logo_path:
        try:
            logo = _fit_logo(card.logo_path, max_w=30, max_h=22)
        except Exception:
            logger.exception("Unable to render compliance logo %s", card.logo_path)
            logo = None
        if logo is not None:
            header_tbl = Table(
                [[logo, title_para]],
                colWidths=[38, inner_width - 38],
            )
            header_tbl.setStyle(
                TableStyle(
                    [
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                        ("LEFTPADDING", (0, 0), (-1, -1), 0),
                        ("RIGHTPADDING", (0, 0), (0, 0), 8),
                        ("TOPPADDING", (0, 0), (-1, -1), 0),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
                    ]
                )
            )
            header = header_tbl
    stats_table = Table(
        [
            [
                Paragraph(
                    f'<font color="#C43D53">{card.failed:,}</font><br/>Failed reqs',
                    body_style,
                ),
                Paragraph(
                    f'<font color="#16856B">{card.passed:,}</font><br/>Passed reqs',
                    body_style,
                ),
                Paragraph(
                    f'<font color="#684CB6">{card.score:.1f}%</font><br/>Score',
                    body_style,
                ),
            ]
        ],
        colWidths=[inner_width / 3] * 3,
    )
    stats_table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 2),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
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
        colWidths=[width],
        hAlign="LEFT",
    )
    outer.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
                ("BACKGROUND", (0, 0), (-1, 0), COLOR_VRIKA_PURPLE_PALE),
                ("LINEABOVE", (0, 0), (-1, 0), 2, COLOR_VRIKA_PURPLE),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )
    return outer


def build_framework_card_grid(
    cards: list[FrameworkCard],
    title_style: ParagraphStyle,
    body_style: ParagraphStyle,
    width: float = 6.2 * inch,
) -> list:
    """Keep each pair of equal-width cards together across page breaks."""
    flowables: list = []
    gap = 12
    card_width = (width - gap) / 2
    for start in range(0, len(cards), 2):
        pair = [
            build_framework_card(card, title_style, body_style, width=card_width)
            for card in cards[start : start + 2]
        ]
        row = Table(
            [[pair[0], "", pair[1] if len(pair) == 2 else ""]],
            colWidths=[card_width, gap, card_width],
            hAlign="LEFT",
        )
        row.setStyle(
            TableStyle(
                [
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 0),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                    ("TOPPADDING", (0, 0), (-1, -1), 0),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
                ]
            )
        )
        flowables.append(KeepTogether([row, Spacer(1, 12)]))
    return flowables


def build_pass_fail_status_bar(
    passed: int,
    failed: int,
    width: float = 4.5 * inch,
) -> Table:
    """A vector status bar with exact segment widths and a text legend."""
    total = passed + failed
    legend_style = ParagraphStyle(
        "StatusLegend",
        fontSize=8,
        leading=11,
        fontName="PlusJakartaSans",
        textColor=COLOR_MUTED,
    )
    if total <= 0:
        return Table(
            [[Paragraph("No evaluated controls", legend_style)]], colWidths=[width]
        )

    pass_width = width * (passed / total)
    bar = Drawing(width, 8)
    if passed:
        bar.add(Rect(0, 0, pass_width, 8, fillColor=COLOR_COMPLIANT, strokeColor=None))
    if failed:
        bar.add(
            Rect(
                pass_width,
                0,
                width - pass_width,
                8,
                fillColor=COLOR_NON_COMPLIANT,
                strokeColor=None,
            )
        )

    legend = Table(
        [
            [
                Paragraph(
                    f'<font color="#16856B">{passed:,} PASS</font>',
                    legend_style,
                ),
                Paragraph(
                    f'<font color="#C43D53">{failed:,} FAIL</font>',
                    legend_style,
                ),
            ]
        ],
        colWidths=[width / 2, width / 2],
    )
    legend.setStyle(
        TableStyle(
            [
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )

    wrapper = Table([[bar], [legend]], colWidths=[width])
    wrapper.setStyle(
        TableStyle(
            [
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )
    return wrapper


def build_severity_chart(severity: dict[str, int], width: float) -> Drawing:
    drawing = Drawing(width, 110)
    maximum = max(
        (severity.get(key, 0) for key in ("critical", "high", "medium", "low")),
        default=0,
    )
    count_width = max(
        51,
        max(
            stringWidth(f"{severity.get(key, 0):,}", "PlusJakartaSans", 9)
            for key in ("critical", "high", "medium", "low")
        )
        + 8,
    )
    track_width = width - 49 - count_width
    for index, (key, color) in enumerate(
        [
            ("critical", "#B4233B"),
            ("high", "#D86A35"),
            ("medium", "#C39428"),
            ("low", "#4B87A7"),
        ]
    ):
        y = 86 - index * 25
        value = severity.get(key, 0)
        drawing.add(
            String(
                0,
                y,
                key.title(),
                fontName="PlusJakartaSans",
                fontSize=8,
                fillColor=COLOR_MUTED,
            )
        )
        drawing.add(
            Rect(
                49,
                y - 1,
                track_width,
                7,
                fillColor=colors.HexColor("#F0F2F6"),
                strokeColor=None,
            )
        )
        if maximum and value:
            drawing.add(
                Rect(
                    49,
                    y - 1,
                    track_width * value / maximum,
                    7,
                    fillColor=colors.HexColor(color),
                    strokeColor=None,
                )
            )
        drawing.add(
            String(
                width,
                y,
                f"{value:,}",
                textAnchor="end",
                fontName="PlusJakartaSans",
                fontSize=9,
                fillColor=COLOR_INK,
            )
        )
    return drawing


def build_outcome_chart(passed: int, failed: int, width: float) -> Drawing:
    drawing = Drawing(width, 110)
    total = passed + failed
    diameter = 100
    if total:
        pie = Pie()
        pie.x, pie.y = 0, 5
        pie.width = pie.height = diameter
        pie.data = [failed, passed]
        pie.labels = []
        pie.slices.strokeWidth = 0
        pie.slices.strokeColor = None
        pie.slices[0].fillColor = COLOR_NON_COMPLIANT
        pie.slices[1].fillColor = COLOR_COMPLIANT
        drawing.add(pie)
    else:
        drawing.add(Circle(50, 55, 50, fillColor=COLOR_BORDER, strokeColor=None))
    drawing.add(Circle(50, 55, 33, fillColor=colors.white, strokeColor=None))
    total_label = f"{total:,}"
    total_size = min(12, 12 * 60 / stringWidth(total_label, "PlusJakartaSans", 12))
    drawing.add(
        String(
            50,
            58,
            total_label,
            textAnchor="middle",
            fontName="PlusJakartaSans",
            fontSize=total_size,
            fillColor=COLOR_INK,
        )
    )
    drawing.add(
        String(
            50,
            44,
            "evaluated",
            textAnchor="middle",
            fontName="PlusJakartaSans",
            fontSize=7,
            fillColor=COLOR_MUTED,
        )
    )
    for index, (label, value, color) in enumerate(
        [
            ("Failed", failed, COLOR_NON_COMPLIANT),
            ("Passed", passed, COLOR_COMPLIANT),
        ]
    ):
        y = 84 - index * 44
        percentage = f"{value / total:.0%}" if total else "N/A"
        drawing.add(
            String(
                116,
                y,
                label,
                fontName="PlusJakartaSans",
                fontSize=8,
                fillColor=COLOR_MUTED,
            )
        )
        value_label = f"{value:,} | {percentage}"
        value_size = min(
            10, 10 * (width - 116) / stringWidth(value_label, "PlusJakartaSans", 10)
        )
        drawing.add(
            String(
                116,
                y - 16,
                value_label,
                fontName="PlusJakartaSans",
                fontSize=value_size,
                fillColor=color,
            )
        )
    return drawing
