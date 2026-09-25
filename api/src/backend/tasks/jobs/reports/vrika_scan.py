"""Vrika-branded scan-level PDF reports (executive and full)."""

from __future__ import annotations

import io
import os
from dataclasses import dataclass
from typing import Any

from api.db_router import READ_REPLICA_ALIAS
from api.db_utils import rls_transaction
from api.models import (
    Finding,
    Provider,
    Scan,
    ScanCategorySummary,
    ScanSummary,
    StatusChoices,
)
from celery.utils.log import get_task_logger
from django.db.models import Case, Count, IntegerField, Max, Sum, TextField, Value, When
from django.db.models.functions import Cast
from prowler.lib.check.compliance_models import Compliance
from reportlab.lib.colors import HexColor, white
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.platypus import (
    Image,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from .base import _register_fonts, create_pdf_styles
from .components import (
    ColumnConfig,
    escape_html,
    truncate_text,
)
from .config import FINDINGS_TABLE_CHUNK_SIZE, get_framework_config
from .vrika_branding import (
    COLOR_VRIKA_PURPLE,
    COLOR_VRIKA_PURPLE_PALE,
    get_branded_display_name,
    get_compliance_logo_path,
    get_footer_right_text,
    get_pdf_theme,
    resolve_report_logo,
)
from .vrika_scan_cards import (
    FrameworkCard,
    build_framework_card_grid,
    build_outcome_chart,
    build_pass_fail_status_bar,
    build_severity_chart,
)
from .vrika_scan_narrative import (
    ScanNarrativeContext,
    build_executive_summary_paragraphs,
    build_key_observations,
    build_recommended_next_steps,
)

logger = get_task_logger(__name__)

SEVERITY_ORDER = ("critical", "high", "medium", "low", "informational", "unknown")
TOP_RISKS_LIMIT = 15
FRAMEWORK_CARD_LIMIT = 12
# AWS ships 80+ compliance frameworks; scanning all of them stalls the worker.
MAX_FRAMEWORKS_TO_SCAN = 30
APPENDIX_CHECKS_PER_DOMAIN = 25
APPENDIX_DOMAIN_LIMIT = 15

PAGE_MARGIN = 0.6 * inch
FRAME_PADDING = 6
COLOR_GRID_LIGHT = HexColor("#E4E7EF")
COLOR_TEXT_DARK = HexColor("#202B42")
COLOR_TEXT_MUTED = HexColor("#647084")
SEVERITY_TEXT_COLORS = {
    "critical": "#B4232A",
    "high": "#E4572E",
    "medium": "#C77700",
    "low": "#8A6D00",
    "informational": "#6B7280",
    "unknown": "#475569",
}


@dataclass(frozen=True)
class TopRiskRow:
    check_id: str
    title: str
    severity: str
    resource_count: int
    description: str


@dataclass(frozen=True)
class DomainSummaryRow:
    category: str
    failed: int
    critical_high: int
    total: int

    @property
    def pass_rate(self) -> float:
        if self.total <= 0:
            return 100.0
        passed = self.total - self.failed
        return (passed / self.total) * 100


def _format_duration(seconds: int | None) -> str:
    if not seconds:
        return "N/A"
    minutes, secs = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours} hr {minutes} min {secs} sec"
    if minutes:
        return f"{minutes} min {secs} sec"
    return f"{secs} sec"


def _humanize_category(category: str) -> str:
    return (category or "general").replace("-", " ").replace("_", " ").title()


def _services_from_check_ids(check_ids: set[str] | list[str]) -> str:
    services: set[str] = set()
    for check_id in check_ids:
        parts = str(check_id).split("_")
        if len(parts) >= 2:
            services.add(parts[1])
    return ", ".join(sorted(services)[:14])


def _short_framework_name(compliance_id: str, compliance_obj: Any) -> str:
    config = get_framework_config(compliance_id)
    if config:
        return get_branded_display_name(config.display_name)
    for attr in ("Name", "Framework"):
        value = getattr(compliance_obj, attr, None)
        if value:
            return truncate_text(str(value).replace("-", " "), 55)
    return truncate_text(compliance_id.replace("_", " ").title(), 55)


def _aggregate_scan_stats(tenant_id: str, scan_id: str) -> dict[str, int]:
    totals = ScanSummary.objects.filter(tenant_id=tenant_id, scan_id=scan_id).aggregate(
        passed=Sum("_pass"),
        failed=Sum("fail"),
        muted=Sum("muted"),
        total=Sum("total"),
    )
    return {
        "passed": int(totals["passed"] or 0),
        "failed": int(totals["failed"] or 0),
        "muted": int(totals["muted"] or 0),
        "total": int(totals["total"] or 0),
    }


def _severity_breakdown(tenant_id: str, scan_id: str) -> dict[str, int]:
    rows = (
        ScanSummary.objects.filter(tenant_id=tenant_id, scan_id=scan_id)
        .values("severity")
        .annotate(failed=Sum("fail"))
    )
    return {row["severity"]: int(row["failed"] or 0) for row in rows}


def _security_score(stats: dict[str, int]) -> float:
    evaluated = stats["passed"] + stats["failed"]
    if evaluated <= 0:
        return 100.0
    return (stats["passed"] / evaluated) * 100


def _load_domain_summaries(tenant_id: str, scan_id: str) -> list[DomainSummaryRow]:
    rows = ScanCategorySummary.objects.filter(tenant_id=tenant_id, scan_id=scan_id)
    by_category: dict[str, dict[str, int]] = {}
    for row in rows:
        cat = row.category or "general"
        bucket = by_category.setdefault(
            cat, {"failed": 0, "total": 0, "critical_high": 0}
        )
        bucket["failed"] += int(row.failed_findings or 0)
        bucket["total"] += int(row.total_findings or 0)
        if str(row.severity).lower() in ("critical", "high"):
            bucket["critical_high"] += int(row.failed_findings or 0)

    summaries = [
        DomainSummaryRow(
            category=cat,
            failed=data["failed"],
            critical_high=data["critical_high"],
            total=data["total"],
        )
        for cat, data in by_category.items()
    ]
    summaries.sort(key=lambda item: item.failed, reverse=True)
    return summaries


def _load_framework_cards(
    provider_type: str, tenant_id: str, scan_id: str, limit: int = FRAMEWORK_CARD_LIMIT
) -> list[FrameworkCard]:
    from tasks.jobs.threatscore_utils import (
        _aggregate_requirement_statistics_from_database,
        _calculate_requirements_data_from_statistics,
    )

    stats = _aggregate_requirement_statistics_from_database(tenant_id, scan_id)
    frameworks = Compliance.get_bulk(provider_type)
    cards: list[FrameworkCard] = []

    # Prefer well-known frameworks, then scan a bounded subset (not all 80+).
    def _framework_rank(compliance_id: str) -> tuple[int, str]:
        config = get_framework_config(compliance_id)
        if config is not None:
            return (0, compliance_id)
        return (1, compliance_id)

    ranked_ids = sorted(frameworks.keys(), key=_framework_rank)
    for compliance_id in ranked_ids[:MAX_FRAMEWORKS_TO_SCAN]:
        compliance_obj = frameworks[compliance_id]
        _, requirements = _calculate_requirements_data_from_statistics(
            compliance_obj, stats
        )
        if not requirements:
            continue

        passed_reqs = sum(
            1
            for req in requirements
            if req["attributes"].get("status") == StatusChoices.PASS
        )
        total_reqs = len(requirements)
        score = (passed_reqs / total_reqs * 100) if total_reqs else 0.0
        failed_reqs = total_reqs - passed_reqs

        check_ids: set[str] = set()
        for requirement in getattr(compliance_obj, "Requirements", []):
            check_ids.update(getattr(requirement, "Checks", []) or [])

        cards.append(
            FrameworkCard(
                name=_short_framework_name(compliance_id, compliance_obj),
                score=score,
                passed=passed_reqs,
                failed=failed_reqs,
                total=total_reqs,
                services=_services_from_check_ids(check_ids),
                logo_path=get_compliance_logo_path(compliance_id),
            )
        )

    cards.sort(key=lambda item: item.score)
    return cards[:limit]


def _load_top_risks(
    tenant_id: str, scan_id: str, limit: int = TOP_RISKS_LIMIT
) -> list[TopRiskRow]:
    severity_rank = Case(
        *[
            When(severity=severity, then=Value(idx))
            for idx, severity in enumerate(SEVERITY_ORDER[:2])
        ],
        default=Value(99),
        output_field=IntegerField(),
    )
    rows = (
        Finding.all_objects.filter(
            tenant_id=tenant_id,
            scan_id=scan_id,
            muted=False,
            status=StatusChoices.FAIL,
            severity__in=SEVERITY_ORDER[:2],
        )
        .values("check_id")
        .annotate(
            title=Max(Cast("check_metadata__checktitle", output_field=TextField())),
            description=Max(
                Cast("check_metadata__checkdescription", output_field=TextField())
            ),
            severity=Max("severity"),
            resource_count=Count("id"),
            severity_rank=severity_rank,
        )
        .order_by("severity_rank", "-resource_count")[:limit]
    )

    results: list[TopRiskRow] = []
    for row in rows:
        title = row["title"] or str(row["check_id"]).replace("_", " ").title()
        severity = str(row["severity"] or "").capitalize()
        description = truncate_text(str(row["description"] or ""), 160)
        results.append(
            TopRiskRow(
                check_id=str(row["check_id"]),
                title=title,
                severity=severity,
                resource_count=int(row["resource_count"] or 0),
                description=description,
            )
        )
    return results


def _load_appendix_rows(
    tenant_id: str,
    scan_id: str,
    category: str,
    limit: int = APPENDIX_CHECKS_PER_DOMAIN,
) -> list[dict[str, str]]:
    rows = (
        Finding.all_objects.filter(
            tenant_id=tenant_id,
            scan_id=scan_id,
            muted=False,
            status=StatusChoices.FAIL,
            categories__contains=[category],
        )
        .values("check_id")
        .annotate(
            title=Max(Cast("check_metadata__checktitle", output_field=TextField())),
            remediation=Max(
                Cast(
                    "check_metadata__remediation__recommendation__text",
                    output_field=TextField(),
                )
            ),
            severity=Max("severity"),
            resource_count=Count("id"),
        )
        .order_by("-resource_count")[:limit]
    )
    appendix: list[dict[str, str]] = []
    for row in rows:
        remediation = str(row["remediation"] or "").strip()
        remediation = remediation.replace("**", "").replace("\n", " ")
        appendix.append(
            {
                "title": row["title"] or str(row["check_id"]).replace("_", " ").title(),
                "severity": str(row["severity"] or "").capitalize(),
                "resources": str(int(row["resource_count"] or 0)),
                "remediation": truncate_text(
                    remediation or "Review in Vrika dashboard for remediation steps.",
                    200,
                ),
            }
        )
    return appendix


class VrikaScanReportGenerator:
    """Generate Vrika-branded executive or full scan PDFs."""

    def __init__(self, include_all_findings: bool = False) -> None:
        self.include_all_findings = include_all_findings
        self.styles = create_pdf_styles()
        self.theme = get_pdf_theme()
        self._body_style = ParagraphStyle(
            "VrikaBody",
            parent=getSampleStyleSheet()["Normal"],
            fontSize=9.3,
            leading=13.5,
            alignment=TA_LEFT,
            textColor=COLOR_TEXT_DARK,
            fontName="PlusJakartaSans",
        )
        self._bullet_style = ParagraphStyle(
            "VrikaBullet",
            parent=self._body_style,
            leftIndent=12,
            bulletIndent=0,
            spaceBefore=3,
            spaceAfter=3,
        )
        self._score_style = ParagraphStyle(
            "VrikaScore",
            parent=getSampleStyleSheet()["Normal"],
            fontSize=28,
            leading=32,
            alignment=TA_LEFT,
            textColor=COLOR_VRIKA_PURPLE,
            fontName="PlusJakartaSans",
        )

        self._content_width = A4[0] - 2 * PAGE_MARGIN - 2 * FRAME_PADDING

        self._section_title_style = ParagraphStyle(
            "VrikaSectionTitle",
            fontName="PlusJakartaSans",
            fontSize=13,
            leading=16,
            textColor=COLOR_TEXT_DARK,
            alignment=TA_LEFT,
        )
        self._subsection_title_style = ParagraphStyle(
            "VrikaSubsectionTitle",
            fontName="PlusJakartaSans",
            fontSize=11,
            leading=14,
            textColor=COLOR_VRIKA_PURPLE,
            alignment=TA_LEFT,
        )
        self._th_left = ParagraphStyle(
            "VrikaThLeft",
            fontName="PlusJakartaSans",
            fontSize=8,
            leading=11,
            textColor=COLOR_TEXT_MUTED,
            alignment=TA_LEFT,
        )
        self._th_center = ParagraphStyle(
            "VrikaThCenter", parent=self._th_left, alignment=TA_CENTER
        )
        self._td_left = ParagraphStyle(
            "VrikaTdLeft",
            fontName="PlusJakartaSans",
            fontSize=8.5,
            leading=12,
            textColor=COLOR_TEXT_DARK,
            alignment=TA_LEFT,
        )
        self._td_center = ParagraphStyle(
            "VrikaTdCenter", parent=self._td_left, alignment=TA_CENTER
        )
        self._cover_title_style = ParagraphStyle(
            "VrikaCoverTitle",
            fontName="PlusJakartaSans",
            fontSize=24,
            leading=30,
            textColor=COLOR_TEXT_DARK,
            alignment=TA_LEFT,
        )
        self._cover_subtitle_style = ParagraphStyle(
            "VrikaCoverSubtitle",
            fontName="PlusJakartaSans",
            fontSize=10,
            leading=14,
            textColor=COLOR_VRIKA_PURPLE,
            alignment=TA_LEFT,
        )
        self._meta_style = ParagraphStyle(
            "VrikaMeta",
            fontName="PlusJakartaSans",
            fontSize=7.5,
            leading=10,
            textColor=COLOR_TEXT_MUTED,
            alignment=TA_LEFT,
        )
        self._meta_value_style = ParagraphStyle(
            "VrikaMetaValue",
            fontName="PlusJakartaSans",
            fontSize=9.5,
            leading=13,
            textColor=COLOR_TEXT_DARK,
            alignment=TA_LEFT,
        )

    def _section_header(self, title: str, top_gap: float = 0.16) -> list[Any]:
        """Keep a restrained section heading attached to the following content."""
        band = Table(
            [[Paragraph(title, self._section_title_style)]],
            colWidths=[self._content_width],
        )
        band.setStyle(
            TableStyle(
                [
                    ("LINEBEFORE", (0, 0), (0, -1), 3, COLOR_VRIKA_PURPLE),
                    ("LINEBELOW", (0, 0), (-1, -1), 0.5, COLOR_GRID_LIGHT),
                    ("LEFTPADDING", (0, 0), (-1, -1), 10),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ]
            )
        )
        band.keepWithNext = True
        gap = Spacer(1, 7)
        gap.keepWithNext = True
        return [Spacer(1, top_gap * inch), band, gap]

    def _severity_cell_style(self, severity: str) -> ParagraphStyle:
        color = SEVERITY_TEXT_COLORS.get(severity.strip().lower(), "#374151")
        return ParagraphStyle(
            f"VrikaSev_{severity}",
            parent=self._td_center,
            textColor=HexColor(color),
        )

    def _styled_table(
        self,
        data: list[dict[str, Any]],
        columns: list[ColumnConfig],
        severity_field: str | None = None,
        group_title: str | None = None,
    ) -> Table:
        """Branded data table: sans headers, soft striping, severity coloring."""
        header_cells = [
            Paragraph(
                f"<b>{escape_html(c.header)}</b>",
                self._th_left if c.align == "LEFT" else self._th_center,
            )
            for c in columns
        ]
        table_data: list[list[Any]] = [header_cells]
        header_row = 0
        if group_title:
            table_data.insert(
                0,
                [Paragraph(escape_html(group_title), self._subsection_title_style)]
                + [""] * (len(columns) - 1),
            )
            header_row = 1
        for item in data:
            row: list[Any] = []
            for c in columns:
                value = c.field(item) if callable(c.field) else item.get(c.field, "")
                text = "" if value is None else str(value)
                if severity_field and c.field == severity_field:
                    cell_style = self._severity_cell_style(text)
                    if text.lower() == "unknown":
                        text = "Unknown / Unrated"
                    row.append(Paragraph(f"<b>{escape_html(text)}</b>", cell_style))
                else:
                    cell_style = self._td_left if c.align == "LEFT" else self._td_center
                    row.append(Paragraph(escape_html(text), cell_style))
            table_data.append(row)

        table = Table(
            table_data,
            colWidths=[c.width for c in columns],
            repeatRows=header_row + 1,
            hAlign="LEFT",
        )
        style = [
            ("BACKGROUND", (0, header_row), (-1, header_row), HexColor("#F0F2F7")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, header_row), 7),
            ("BOTTOMPADDING", (0, 0), (-1, header_row), 7),
            ("TOPPADDING", (0, header_row + 1), (-1, -1), 4),
            ("BOTTOMPADDING", (0, header_row + 1), (-1, -1), 4),
            (
                "ROWBACKGROUNDS",
                (0, header_row + 1),
                (-1, -1),
                [white, HexColor("#FAFBFD")],
            ),
            ("LINEBELOW", (0, header_row + 1), (-1, -1), 0.4, COLOR_GRID_LIGHT),
            ("LINEBELOW", (0, header_row), (-1, header_row), 0.6, COLOR_GRID_LIGHT),
        ]
        if group_title:
            style.extend(
                [
                    ("SPAN", (0, 0), (-1, 0)),
                    ("BACKGROUND", (0, 0), (-1, 0), COLOR_VRIKA_PURPLE_PALE),
                    ("LINEBEFORE", (0, 0), (0, 0), 3, COLOR_VRIKA_PURPLE),
                ]
            )
        for idx, col in enumerate(columns):
            style.append(("ALIGN", (idx, 0), (idx, -1), col.align))
        table.setStyle(TableStyle(style))
        return table

    def generate(
        self,
        tenant_id: str,
        scan_id: str,
        provider_id: str,
        output_path: str,
    ) -> None:
        # Resolve the report logo once: tenant custom logo (if uploaded) or the
        # default product logo. BytesIO for custom logos, a path for the default.
        self._logo_source = resolve_report_logo(tenant_id)

        with rls_transaction(tenant_id, using=READ_REPLICA_ALIAS):
            scan = Scan.all_objects.select_related("provider").get(id=scan_id)
            provider = (
                scan.provider
                if scan.provider_id
                else Provider.objects.get(id=provider_id)
            )

            stats = _aggregate_scan_stats(tenant_id, scan_id)
            severity = _severity_breakdown(tenant_id, scan_id)
            score = _security_score(stats)
            domains = _load_domain_summaries(tenant_id, scan_id)
            framework_cards = _load_framework_cards(
                provider.provider, tenant_id, scan_id
            )
            top_risks = _load_top_risks(tenant_id, scan_id)

            evaluated = stats["passed"] + stats["failed"]
            fail_pct = (stats["failed"] / evaluated * 100) if evaluated else 0.0
            narrative_ctx = ScanNarrativeContext(
                provider_label=provider.provider.upper(),
                score=score,
                passed=stats["passed"],
                failed=stats["failed"],
                muted=stats["muted"],
                total=stats["total"],
                fail_pct=fail_pct,
                critical_count=severity.get("critical", 0),
                high_count=severity.get("high", 0),
                top_domains=[(d.category, d.failed) for d in domains[:5]],
            )

            parent_dir = os.path.dirname(output_path)
            if parent_dir and not os.path.isdir(parent_dir):
                os.makedirs(parent_dir, exist_ok=True)

            doc = SimpleDocTemplate(
                output_path,
                pagesize=A4,
                title="Vrika Security Report",
                author=self.theme.pdf_author,
                creator=self.theme.pdf_creator,
                leftMargin=PAGE_MARGIN,
                rightMargin=PAGE_MARGIN,
                topMargin=PAGE_MARGIN,
                bottomMargin=PAGE_MARGIN,
            )

            elements: list[Any] = []
            elements.extend(self._page_header(scan, provider))
            elements.extend(self._summary_metrics(scan, stats, score, severity))
            elements.extend(self._executive_summary(narrative_ctx))
            elements.extend(self._key_observations(narrative_ctx))
            elements.append(PageBreak())
            elements.extend(self._account_overview(scan, provider))
            elements.extend(self._controls_overview(stats, score, severity))
            elements.extend(self._security_domains(domains))
            if framework_cards:
                elements.append(PageBreak())
                elements.extend(self._compliance_overview(framework_cards))
            if top_risks:
                elements.append(PageBreak())
                elements.extend(self._top_risks(top_risks))
            elements.extend(self._recommended_next_steps(narrative_ctx))

            if self.include_all_findings and domains:
                elements.append(PageBreak())
                elements.extend(self._appendix_by_domain(tenant_id, scan_id, domains))

            doc.build(
                elements,
                onFirstPage=self._footer,
                onLaterPages=self._footer,
            )

    def _footer(self, canvas, doc) -> None:
        canvas.saveState()
        left = doc.leftMargin + FRAME_PADDING
        right = left + self._content_width
        canvas.setStrokeColor(COLOR_GRID_LIGHT)
        canvas.setLineWidth(0.5)
        canvas.line(left, 0.43 * inch, right, 0.43 * inch)
        canvas.setFont("PlusJakartaSans", 8)
        canvas.setFillColor(COLOR_TEXT_MUTED)
        canvas.drawString(left, 0.25 * inch, f"Page {doc.page}")
        canvas.drawRightString(right, 0.25 * inch, get_footer_right_text())
        if doc.page > 1:
            canvas.drawString(
                left, A4[1] - 0.32 * inch, "Cloud Security Posture Report"
            )
            label = (
                "Full Security Report"
                if self.include_all_findings
                else "Executive Security Report"
            )
            canvas.drawRightString(right, A4[1] - 0.32 * inch, label)
        canvas.restoreState()

    def _build_logo_flowable(self) -> Image | None:
        """Build the header logo, preserving aspect ratio within a fixed box.

        ``self._logo_source`` is either a filesystem path (default logo) or a
        ``BytesIO`` (tenant custom logo). Returns ``None`` if the source is
        missing or unreadable so the header renders without a logo.
        """
        from reportlab.lib.utils import ImageReader

        source = getattr(self, "_logo_source", None)
        if source is None:
            return None

        max_w, max_h = 1.4 * inch, 0.55 * inch
        try:
            if isinstance(source, str):
                if not os.path.exists(source):
                    return None
                reader = ImageReader(source)
                img_source: Any = source
            else:
                # BytesIO: read dimensions, then hand a fresh buffer to Image so
                # the reader's cursor position cannot break rendering.
                source.seek(0)
                data = source.read()
                if not data:
                    return None
                reader = ImageReader(io.BytesIO(data))
                img_source = io.BytesIO(data)

            iw, ih = reader.getSize()
            if not iw or not ih:
                return Image(img_source, width=max_w, height=max_h)

            scale = min(max_w / iw, max_h / ih)
            return Image(img_source, width=iw * scale, height=ih * scale)
        except Exception:
            logger.exception("Failed to build report logo flowable")
            return None

    def _page_header(self, scan: Scan, provider: Provider) -> list[Any]:
        elements: list[Any] = []
        logo = self._build_logo_flowable()
        report_type = (
            "Full Security Report"
            if self.include_all_findings
            else "Executive Security Report"
        )
        completed = scan.completed_at or scan.inserted_at
        completed_text = completed.strftime("%b %d, %Y") if completed else "N/A"
        masthead = Table(
            [
                [
                    logo
                    or Paragraph(
                        escape_html(get_footer_right_text()), self._cover_subtitle_style
                    ),
                    Paragraph(
                        f"{report_type.upper()}<br/>{escape_html(provider.provider.upper())}"
                        f" / {completed_text}",
                        ParagraphStyle(
                            "ReportEdition", parent=self._meta_style, alignment=2
                        ),
                    ),
                ]
            ],
            colWidths=[self._content_width * 0.35, self._content_width * 0.65],
        )
        masthead.setStyle(
            TableStyle(
                [
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 0),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
                ]
            )
        )
        elements.append(masthead)
        elements.append(
            Paragraph("Cloud Security Posture Report", self._cover_title_style)
        )
        elements.append(Spacer(1, 6))
        elements.append(
            Paragraph(
                escape_html(provider.alias or provider.uid or "Cloud Account"),
                self._cover_subtitle_style,
            )
        )
        elements.append(Spacer(1, 16))
        return elements

    def _summary_metrics(
        self, scan: Scan, stats: dict[str, int], score: float, severity: dict[str, int]
    ) -> list[Any]:
        gap = 10
        width = (self._content_width - 2 * gap) / 3
        metrics = [
            (
                "SECURITY SCORE",
                f"{score:.2f}%",
                "Overall finding pass rate",
                COLOR_VRIKA_PURPLE,
            ),
            (
                "CRITICAL + HIGH",
                f"{severity.get('critical', 0) + severity.get('high', 0):,}",
                "Failed findings to prioritize",
                HexColor("#C43D53"),
            ),
            (
                "RESOURCES SCANNED",
                f"{scan.unique_resource_count:,}",
                f"{stats['passed'] + stats['failed']:,} evaluated controls",
                COLOR_TEXT_DARK,
            ),
        ]
        cards = []
        for label, value, detail, color in metrics:
            card = Table(
                [
                    [Paragraph(label, self._meta_style)],
                    [
                        Paragraph(
                            value,
                            ParagraphStyle(
                                "MetricValue",
                                parent=self._score_style,
                                fontSize=min(
                                    24,
                                    24
                                    * (width - 20)
                                    / stringWidth(value, "PlusJakartaSans", 24),
                                ),
                                leading=28,
                                textColor=color,
                            ),
                        )
                    ],
                    [Paragraph(detail, self._meta_style)],
                ],
                colWidths=[width],
            )
            card.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, -1), HexColor("#F7F8FC")),
                        ("LINEABOVE", (0, 0), (-1, 0), 2, color),
                        ("LEFTPADDING", (0, 0), (-1, -1), 10),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                        ("TOPPADDING", (0, 0), (-1, 0), 10),
                        ("BOTTOMPADDING", (0, -1), (-1, -1), 10),
                    ]
                )
            )
            cards.append(card)
        row = Table(
            [[cards[0], "", cards[1], "", cards[2]]],
            colWidths=[width, gap, width, gap, width],
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
        return [row, Spacer(1, 6)]

    def _executive_summary(self, ctx: ScanNarrativeContext) -> list[Any]:
        elements: list[Any] = self._section_header("Executive Summary")
        for paragraph in build_executive_summary_paragraphs(ctx):
            elements.append(Paragraph(paragraph, self._body_style))
            elements.append(Spacer(1, 0.08 * inch))
        return elements

    def _key_observations(self, ctx: ScanNarrativeContext) -> list[Any]:
        elements: list[Any] = self._section_header("Key Observations")
        for bullet in build_key_observations(ctx):
            elements.append(Paragraph(f"• {bullet}", self._bullet_style))
        return elements

    def _account_overview(self, scan: Scan, provider: Provider) -> list[Any]:
        elements: list[Any] = self._section_header("Account Overview")
        completed = scan.completed_at or scan.inserted_at
        rows = [
            ["Provider", provider.provider.upper()],
            ["Account ID", provider.uid or "N/A"],
            ["Alias", provider.alias or "N/A"],
            [
                "Scan completed",
                completed.strftime("%b %d, %Y %I:%M %p") if completed else "N/A",
            ],
            ["Duration", _format_duration(scan.duration)],
            ["Resources scanned", f"{scan.unique_resource_count:,}"],
        ]
        table = Table(
            [
                [
                    Paragraph(escape_html(label), self._meta_value_style),
                    Paragraph(escape_html(value), self._td_left),
                ]
                for label, value in rows
            ],
            colWidths=[self._content_width * 0.27, self._content_width * 0.73],
            hAlign="LEFT",
        )
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), HexColor("#F7F8FC")),
                    ("LINEBELOW", (0, 0), (-1, -1), 0.5, COLOR_GRID_LIGHT),
                    ("BOX", (0, 0), (-1, -1), 0.5, COLOR_GRID_LIGHT),
                    ("ROWBACKGROUNDS", (1, 0), (1, -1), [white, HexColor("#FBFAFE")]),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 10),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        elements.append(KeepTogether([table]))
        return elements

    def _controls_overview(
        self,
        stats: dict[str, int],
        score: float,
        severity: dict[str, int],
    ) -> list[Any]:
        elements: list[Any] = self._section_header("Controls Overview")
        evaluated = stats["passed"] + stats["failed"]
        gap = 18
        column_width = (self._content_width - gap) / 2
        left_rows = [
            [Paragraph("<b>Security score</b>", self._body_style)],
            [Paragraph(f"{score:.2f}%", self._score_style)],
            [
                Paragraph(
                    f"{stats['passed']:,} of {evaluated:,} controls passed",
                    ParagraphStyle(
                        "scoreSub",
                        parent=self._body_style,
                        fontSize=9,
                        alignment=TA_LEFT,
                    ),
                )
            ],
        ]
        left_col = Table(left_rows, colWidths=[column_width])
        right_col = Table(
            [
                [Paragraph("Control status", self._body_style)],
                [
                    build_pass_fail_status_bar(
                        stats["passed"], stats["failed"], column_width
                    )
                ],
            ],
            colWidths=[column_width],
        )
        panels = []
        for title, drawing in [
            ("Failed by severity", build_severity_chart(severity, column_width)),
            (
                "Finding outcomes",
                build_outcome_chart(stats["passed"], stats["failed"], column_width),
            ),
        ]:
            panel = Table(
                [[Paragraph(title, self._body_style)], [drawing]],
                colWidths=[column_width],
            )
            panels.append(panel)
        layout = Table(
            [[left_col, "", right_col], [panels[0], "", panels[1]]],
            colWidths=[column_width, gap, column_width],
            hAlign="LEFT",
        )
        for table in [left_col, right_col, *panels, layout]:
            table.setStyle(
                TableStyle(
                    [
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("LEFTPADDING", (0, 0), (-1, -1), 0),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                        ("TOPPADDING", (0, 0), (-1, -1), 3),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                    ]
                )
            )
        elements.append(KeepTogether([layout]))
        if severity.get("unknown", 0):
            elements.append(
                Paragraph(
                    f"{severity['unknown']:,} findings are Unknown / Unrated and "
                    "require review. Unknown does not mean low risk.",
                    self._body_style,
                )
            )
        return elements

    def _security_domains(self, domains: list[DomainSummaryRow]) -> list[Any]:
        elements: list[Any] = self._section_header("Security Domains at a Glance")
        if not domains:
            elements.append(
                Paragraph("No domain summary data available.", self._body_style)
            )
            return elements

        rows = [
            {
                "domain": _humanize_category(d.category),
                "failed": str(d.failed),
                "critical_high": str(d.critical_high),
                "pass_rate": f"{d.pass_rate:.1f}%",
            }
            for d in domains[:12]
        ]
        columns = [
            ColumnConfig("Domain", self._content_width * 0.44, "domain", align="LEFT"),
            ColumnConfig("Failed", self._content_width * 0.16, "failed"),
            ColumnConfig(
                "Critical + High", self._content_width * 0.24, "critical_high"
            ),
            ColumnConfig("Pass rate", self._content_width * 0.16, "pass_rate"),
        ]
        elements.append(self._styled_table(rows, columns))
        return elements

    def _compliance_overview(self, cards: list[FrameworkCard]) -> list[Any]:
        elements: list[Any] = self._section_header("Compliance Overview")
        elements.append(
            Paragraph(
                "Top frameworks ranked by compliance score (worst first). "
                "Each card summarizes requirement pass/fail status for the scan.",
                self._body_style,
            )
        )
        elements.append(Spacer(1, 0.1 * inch))
        card_title_style = ParagraphStyle(
            "CardTitle",
            parent=self._body_style,
            fontSize=11,
            alignment=TA_LEFT,
        )
        card_body_style = ParagraphStyle(
            "CardBody",
            parent=self._body_style,
            fontSize=9,
            alignment=TA_LEFT,
        )
        elements.extend(
            build_framework_card_grid(
                cards, card_title_style, card_body_style, width=self._content_width
            )
        )
        return elements

    def _top_risks(self, risks: list[TopRiskRow]) -> list[Any]:
        elements: list[Any] = self._section_header("Top Critical &amp; High Risks")
        elements.append(
            Paragraph(
                "Highest-priority failed checks deduplicated by control, "
                "ordered by severity and affected resources.",
                self._body_style,
            )
        )
        elements.append(Spacer(1, 0.08 * inch))
        rows = [
            {
                "title": truncate_text(r.title, 80),
                "severity": r.severity,
                "resources": str(r.resource_count),
                "why": r.description or "Review in Vrika dashboard for full context.",
            }
            for r in risks
        ]
        columns = [
            ColumnConfig("Risk", self._content_width * 0.35, "title", align="LEFT"),
            ColumnConfig("Severity", self._content_width * 0.13, "severity"),
            ColumnConfig("Resources", self._content_width * 0.13, "resources"),
            ColumnConfig(
                "Why it matters", self._content_width * 0.39, "why", align="LEFT"
            ),
        ]
        elements.append(self._styled_table(rows, columns, severity_field="severity"))
        return elements

    def _recommended_next_steps(self, ctx: ScanNarrativeContext) -> list[Any]:
        elements: list[Any] = self._section_header("Recommended Next Steps")
        for step in build_recommended_next_steps(ctx):
            elements.append(Paragraph(f"• {step}", self._bullet_style))
        return elements

    def _appendix_by_domain(
        self,
        tenant_id: str,
        scan_id: str,
        domains: list[DomainSummaryRow],
    ) -> list[Any]:
        elements: list[Any] = self._section_header(
            "Appendix — Findings by Security Domain"
        )
        elements.append(
            Paragraph(
                "Detailed failed checks grouped by domain. Each row is deduplicated "
                f"by control (top {APPENDIX_CHECKS_PER_DOMAIN} per domain).",
                self._body_style,
            )
        )
        elements.append(Spacer(1, 0.1 * inch))
        columns = [
            ColumnConfig("Risk", self._content_width * 0.33, "title", align="LEFT"),
            ColumnConfig("Severity", self._content_width * 0.13, "severity"),
            ColumnConfig("Resources", self._content_width * 0.13, "resources"),
            ColumnConfig(
                "Remediation", self._content_width * 0.41, "remediation", align="LEFT"
            ),
        ]

        for domain in domains[:APPENDIX_DOMAIN_LIMIT]:
            if domain.failed <= 0:
                continue
            appendix_rows = _load_appendix_rows(tenant_id, scan_id, domain.category)
            if not appendix_rows:
                continue
            elements.append(Spacer(1, 0.08 * inch))
            chunk_size = FINDINGS_TABLE_CHUNK_SIZE
            for start in range(0, len(appendix_rows), chunk_size):
                chunk = appendix_rows[start : start + chunk_size]
                elements.append(
                    self._styled_table(
                        chunk,
                        columns,
                        severity_field="severity",
                        group_title=_humanize_category(domain.category),
                    )
                )
                elements.append(Spacer(1, 0.08 * inch))
        return elements


def generate_vrika_executive_report(
    tenant_id: str,
    scan_id: str,
    provider_id: str,
    output_path: str,
) -> None:
    _register_fonts()
    VrikaScanReportGenerator(include_all_findings=False).generate(
        tenant_id, scan_id, provider_id, output_path
    )
    logger.info("Vrika executive scan report written to %s", output_path)


def generate_vrika_full_report(
    tenant_id: str,
    scan_id: str,
    provider_id: str,
    output_path: str,
) -> None:
    _register_fonts()
    VrikaScanReportGenerator(include_all_findings=True).generate(
        tenant_id, scan_id, provider_id, output_path
    )
    logger.info("Vrika full scan report written to %s", output_path)
