"""Vrika-branded scan-level PDF reports (executive and full)."""

from __future__ import annotations

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
from django.db.models import Case, Count, IntegerField, Max, Sum, Value, When
from prowler.lib.check.compliance_models import Compliance
from reportlab.lib.enums import TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Image,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from .base import _register_fonts, create_pdf_styles
from .charts import create_horizontal_bar_chart, create_pie_chart
from .components import ColumnConfig, create_data_table, truncate_text
from .config import COLOR_GRAY, FINDINGS_TABLE_CHUNK_SIZE, get_framework_config
from .vrika_branding import (
    COLOR_VRIKA_PURPLE,
    COLOR_VRIKA_PURPLE_LIGHT,
    COLOR_VRIKA_PURPLE_PALE,
    get_branded_display_name,
    get_footer_right_text,
    get_pdf_theme,
    get_primary_logo_path,
)
from .vrika_scan_cards import (
    FrameworkCard,
    build_framework_card_grid,
    build_pass_fail_status_bar,
)
from .vrika_scan_narrative import (
    ScanNarrativeContext,
    build_executive_summary_paragraphs,
    build_key_observations,
    build_recommended_next_steps,
)

logger = get_task_logger(__name__)

SEVERITY_ORDER = ("critical", "high", "medium", "low", "informational")
TOP_RISKS_LIMIT = 15
FRAMEWORK_CARD_LIMIT = 12
APPENDIX_CHECKS_PER_DOMAIN = 25
APPENDIX_DOMAIN_LIMIT = 15

SEVERITY_CHART_COLORS = ["#C70000", "#FFC600", "#E49B0F", "#B2911C", "#9CA3AF"]
PIE_COLORS = ["#AD151A", "#87ae73"]


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

    for compliance_id, compliance_obj in frameworks.items():
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
            title=Max("check_metadata__checktitle"),
            description=Max("check_metadata__checkdescription"),
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
            title=Max("check_metadata__checktitle"),
            description=Max("check_metadata__checkdescription"),
            severity=Max("severity"),
            resource_count=Count("id"),
        )
        .order_by("-resource_count")[:limit]
    )
    appendix: list[dict[str, str]] = []
    for row in rows:
        appendix.append(
            {
                "title": row["title"] or str(row["check_id"]).replace("_", " ").title(),
                "severity": str(row["severity"] or "").capitalize(),
                "resources": str(int(row["resource_count"] or 0)),
                "description": truncate_text(str(row["description"] or ""), 120),
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
            fontSize=10,
            leading=14,
            alignment=TA_JUSTIFY,
            textColor=COLOR_GRAY,
            fontName="PlusJakartaSans",
        )
        self._bullet_style = ParagraphStyle(
            "VrikaBullet",
            parent=self._body_style,
            leftIndent=12,
            bulletIndent=0,
            spaceBefore=4,
            spaceAfter=4,
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

    def generate(
        self,
        tenant_id: str,
        scan_id: str,
        provider_id: str,
        output_path: str,
    ) -> None:
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
        framework_cards = _load_framework_cards(provider.provider, tenant_id, scan_id)
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
            leftMargin=0.75 * inch,
            rightMargin=0.75 * inch,
            topMargin=0.75 * inch,
            bottomMargin=0.75 * inch,
        )

        elements: list[Any] = []
        elements.extend(self._page_header(scan, provider))
        elements.extend(self._executive_summary(narrative_ctx))
        elements.extend(self._key_observations(narrative_ctx))
        elements.extend(self._account_overview(scan, provider))
        elements.extend(self._controls_overview(stats, score, severity))
        elements.append(PageBreak())
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
        canvas.setFont("PlusJakartaSans", 9)
        canvas.setFillColorRGB(0.4, 0.4, 0.4)
        canvas.drawString(doc.leftMargin, 0.45 * inch, f"Page {doc.page}")
        canvas.drawRightString(
            doc.pagesize[0] - doc.rightMargin, 0.45 * inch, get_footer_right_text()
        )
        canvas.restoreState()

    def _page_header(self, scan: Scan, provider: Provider) -> list[Any]:
        elements: list[Any] = []
        logo_path = get_primary_logo_path()
        if os.path.exists(logo_path):
            elements.append(Image(logo_path, width=1.8 * inch, height=0.9 * inch))

        completed = scan.completed_at or scan.inserted_at
        meta_bits = [
            f"<b>Provider:</b> {provider.provider.upper()}",
            f"<b>Account:</b> {provider.uid or 'N/A'}",
        ]
        if completed:
            meta_bits.append(f"<b>Completed:</b> {completed.strftime('%b %d, %Y')}")
        meta_bits.append(f"<b>Resources:</b> {scan.unique_resource_count:,}")
        elements.append(Paragraph(" &nbsp;|&nbsp; ".join(meta_bits), self._body_style))
        elements.append(Spacer(1, 0.15 * inch))

        report_type = (
            "Full Security Report"
            if self.include_all_findings
            else "Executive Security Report"
        )
        elements.append(
            Paragraph("Vrika Security Posture Report", self.styles["title"])
        )
        elements.append(
            Paragraph(
                f"{report_type} — {provider.alias or provider.uid or 'Cloud Account'}",
                self.styles["h2"],
            )
        )
        elements.append(Spacer(1, 0.1 * inch))
        return elements

    def _executive_summary(self, ctx: ScanNarrativeContext) -> list[Any]:
        elements: list[Any] = [Paragraph("Executive Summary", self.styles["h1"])]
        for paragraph in build_executive_summary_paragraphs(ctx):
            elements.append(Paragraph(paragraph, self._body_style))
            elements.append(Spacer(1, 0.08 * inch))
        return elements

    def _key_observations(self, ctx: ScanNarrativeContext) -> list[Any]:
        elements: list[Any] = [
            Spacer(1, 0.1 * inch),
            Paragraph("Key Observations", self.styles["h1"]),
        ]
        for bullet in build_key_observations(ctx):
            elements.append(Paragraph(f"• {bullet}", self._bullet_style))
        return elements

    def _account_overview(self, scan: Scan, provider: Provider) -> list[Any]:
        elements: list[Any] = [
            Spacer(1, 0.12 * inch),
            Paragraph("Account Overview", self.styles["h1"]),
        ]
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
        table = Table(rows, colWidths=[2 * inch, 4.2 * inch])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), COLOR_VRIKA_PURPLE),
                    ("TEXTCOLOR", (0, 0), (0, -1), (1, 1, 1)),
                    ("FONTNAME", (0, 0), (-1, -1), "PlusJakartaSans"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("GRID", (0, 0), (-1, -1), 0.5, COLOR_VRIKA_PURPLE_LIGHT),
                    ("BACKGROUND", (1, 0), (1, -1), COLOR_VRIKA_PURPLE_PALE),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ]
            )
        )
        elements.append(table)
        return elements

    def _controls_overview(
        self,
        stats: dict[str, int],
        score: float,
        severity: dict[str, int],
    ) -> list[Any]:
        elements: list[Any] = [
            Spacer(1, 0.15 * inch),
            Paragraph("Controls Overview", self.styles["h1"]),
        ]
        evaluated = stats["passed"] + stats["failed"]

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
            [Paragraph("<b>Control status</b>", self._body_style)],
            [build_pass_fail_status_bar(stats["passed"], stats["failed"], 3.2 * inch)],
        ]
        left_col = Table(left_rows, colWidths=[3.4 * inch])
        left_col.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP")]))

        chart_flowables: list[Any] = []
        sev_labels = [s.title() for s in SEVERITY_ORDER[:4]]
        sev_values = [float(severity.get(name, 0)) for name in SEVERITY_ORDER[:4]]
        max_sev = max(sev_values) if sev_values else 0
        if max_sev > 0:
            sev_buffer = create_horizontal_bar_chart(
                labels=sev_labels,
                values=sev_values,
                xlabel="Failed findings",
                title="Failed by severity",
                colors=SEVERITY_CHART_COLORS[: len(sev_labels)],
                figsize=(4.2, 2.8),
                x_limit=(0, max(max_sev * 1.15, 1)),
                show_labels=False,
                label_fontsize=10,
            )
            chart_flowables.append(
                Image(sev_buffer, width=3.4 * inch, height=2.2 * inch)
            )

        if stats["passed"] + stats["failed"] > 0:
            pie_buffer = create_pie_chart(
                labels=["Failed", "Passed"],
                values=[float(stats["failed"]), float(stats["passed"])],
                colors=PIE_COLORS,
                figsize=(3.5, 3.0),
                autopct="%1.0f%%",
                title="Finding outcomes",
            )
            chart_flowables.append(Spacer(1, 0.08 * inch))
            chart_flowables.append(
                Image(pie_buffer, width=2.8 * inch, height=2.4 * inch)
            )

        right_col = Table(
            [[item] for item in chart_flowables]
            or [[Paragraph("No chart data", self._body_style)]],
            colWidths=[3.4 * inch],
        )
        right_col.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP")]))

        layout = Table([[left_col, right_col]], colWidths=[3.5 * inch, 3.5 * inch])
        layout.setStyle(
            TableStyle(
                [
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 0),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ]
            )
        )
        elements.append(layout)
        return elements

    def _security_domains(self, domains: list[DomainSummaryRow]) -> list[Any]:
        elements: list[Any] = [
            Paragraph("Security Domains at a Glance", self.styles["h1"])
        ]
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
            ColumnConfig("Domain", 2.4 * inch, "domain", align="LEFT"),
            ColumnConfig("Failed", 0.9 * inch, "failed"),
            ColumnConfig("Critical+High", 1.1 * inch, "critical_high"),
            ColumnConfig("Pass rate", 1.0 * inch, "pass_rate"),
        ]
        elements.append(
            create_data_table(
                data=rows,
                columns=columns,
                header_color=COLOR_VRIKA_PURPLE,
                normal_style=self.styles["normal_center"],
            )
        )
        return elements

    def _compliance_overview(self, cards: list[FrameworkCard]) -> list[Any]:
        elements: list[Any] = [
            Paragraph("Compliance Overview", self.styles["h1"]),
            Paragraph(
                "Top frameworks ranked by compliance score (worst first). "
                "Each card summarizes requirement pass/fail status for the scan.",
                self._body_style,
            ),
            Spacer(1, 0.1 * inch),
        ]
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
            build_framework_card_grid(cards, card_title_style, card_body_style)
        )
        return elements

    def _top_risks(self, risks: list[TopRiskRow]) -> list[Any]:
        elements: list[Any] = [
            Paragraph("Top Critical &amp; High Risks", self.styles["h1"]),
            Paragraph(
                "Highest-priority failed checks deduplicated by control, "
                "ordered by severity and affected resources.",
                self._body_style,
            ),
            Spacer(1, 0.08 * inch),
        ]
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
            ColumnConfig("Risk", 2.3 * inch, "title", align="LEFT"),
            ColumnConfig("Severity", 0.75 * inch, "severity"),
            ColumnConfig("Resources", 0.8 * inch, "resources"),
            ColumnConfig("Why it matters", 2.35 * inch, "why", align="LEFT"),
        ]
        elements.append(
            create_data_table(
                data=rows,
                columns=columns,
                header_color=COLOR_VRIKA_PURPLE,
                normal_style=self.styles["normal_center"],
            )
        )
        return elements

    def _recommended_next_steps(self, ctx: ScanNarrativeContext) -> list[Any]:
        elements: list[Any] = [
            Spacer(1, 0.12 * inch),
            Paragraph("Recommended Next Steps", self.styles["h1"]),
        ]
        for step in build_recommended_next_steps(ctx):
            elements.append(Paragraph(f"• {step}", self._bullet_style))
        return elements

    def _appendix_by_domain(
        self,
        tenant_id: str,
        scan_id: str,
        domains: list[DomainSummaryRow],
    ) -> list[Any]:
        elements: list[Any] = [
            Paragraph("Appendix — Findings by Security Domain", self.styles["h1"]),
            Paragraph(
                "Detailed failed checks grouped by domain. Each row is deduplicated "
                f"by control (top {APPENDIX_CHECKS_PER_DOMAIN} per domain).",
                self._body_style,
            ),
            Spacer(1, 0.1 * inch),
        ]
        columns = [
            ColumnConfig("Risk", 2.2 * inch, "title", align="LEFT"),
            ColumnConfig("Severity", 0.75 * inch, "severity"),
            ColumnConfig("Resources", 0.75 * inch, "resources"),
            ColumnConfig("Summary", 2.5 * inch, "description", align="LEFT"),
        ]

        for domain in domains[:APPENDIX_DOMAIN_LIMIT]:
            if domain.failed <= 0:
                continue
            appendix_rows = _load_appendix_rows(tenant_id, scan_id, domain.category)
            if not appendix_rows:
                continue
            elements.append(
                Paragraph(
                    _humanize_category(domain.category),
                    self.styles["h2"],
                )
            )
            chunk_size = FINDINGS_TABLE_CHUNK_SIZE
            for start in range(0, len(appendix_rows), chunk_size):
                chunk = appendix_rows[start : start + chunk_size]
                elements.append(
                    create_data_table(
                        data=chunk,
                        columns=columns,
                        header_color=COLOR_VRIKA_PURPLE,
                        normal_style=self.styles["normal_center"],
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
