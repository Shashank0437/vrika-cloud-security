"""Vrika-branded scan-level PDF reports (executive and full)."""

from __future__ import annotations

import os
from typing import Any

from api.db_router import READ_REPLICA_ALIAS
from api.db_utils import rls_transaction
from api.models import Finding, Provider, Scan, ScanSummary, StatusChoices
from celery.utils.log import get_task_logger
from django.db.models import Sum
from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.finding import Finding as FindingOutput
from reportlab.lib.enums import TA_JUSTIFY
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
from .components import ColumnConfig, create_data_table, create_info_table
from .config import COLOR_GRAY, FINDINGS_TABLE_CHUNK_SIZE, MAX_FINDINGS_PER_CHECK
from .provider_metadata import build_provider_metadata
from .vrika_branding import (
    COLOR_VRIKA_PURPLE,
    COLOR_VRIKA_PURPLE_LIGHT,
    COLOR_VRIKA_PURPLE_PALE,
    get_footer_right_text,
    get_pdf_theme,
    get_primary_logo_path,
)

logger = get_task_logger(__name__)

TOP_FINDINGS_LIMIT = 25
FULL_FINDINGS_SEVERITY_ORDER = ("critical", "high", "medium", "low", "informational")


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


def _load_top_findings(
    tenant_id: str,
    scan_id: str,
    prowler_provider: Any,
    limit: int = TOP_FINDINGS_LIMIT,
) -> list[FindingOutput]:
    severity_rank = {name: idx for idx, name in enumerate(FULL_FINDINGS_SEVERITY_ORDER)}
    findings: list[tuple[int, FindingOutput]] = []

    qs = (
        Finding.all_objects.filter(
            tenant_id=tenant_id,
            scan_id=scan_id,
            muted=False,
            status=StatusChoices.FAIL,
        )
        .prefetch_related("resources", "resources__tags")
        .order_by("uid")[:2000]
    )

    for model in qs:
        output = FindingOutput.transform_api_finding(model, prowler_provider)
        sev = str(getattr(output, "severity", "informational")).lower()
        rank = severity_rank.get(sev, len(severity_rank))
        findings.append((rank, output))

    findings.sort(key=lambda item: item[0])
    return [item[1] for item in findings[:limit]]


def _load_all_failed_findings(
    tenant_id: str,
    scan_id: str,
    prowler_provider: Any,
) -> list[FindingOutput]:
    results: list[FindingOutput] = []
    qs = (
        Finding.all_objects.filter(
            tenant_id=tenant_id,
            scan_id=scan_id,
            muted=False,
            status=StatusChoices.FAIL,
        )
        .prefetch_related("resources", "resources__tags")
        .order_by("severity", "uid")
        .iterator(chunk_size=500)
    )
    count = 0
    cap = MAX_FINDINGS_PER_CHECK * 500 if MAX_FINDINGS_PER_CHECK else None
    for model in qs:
        results.append(FindingOutput.transform_api_finding(model, prowler_provider))
        count += 1
        if cap and count >= cap:
            break
    return results


def _framework_summaries(
    provider_type: str, tenant_id: str, scan_id: str
) -> list[tuple[str, float, int, int]]:
    from tasks.jobs.threatscore_utils import (
        _aggregate_requirement_statistics_from_database,
        _calculate_requirements_data_from_statistics,
    )

    summaries: list[tuple[str, float, int, int]] = []
    stats = _aggregate_requirement_statistics_from_database(tenant_id, scan_id)
    frameworks = Compliance.get_bulk(provider_type)

    for compliance_id, compliance_obj in sorted(frameworks.items()):
        _, requirements = _calculate_requirements_data_from_statistics(
            compliance_obj, stats
        )
        if not requirements:
            continue
        passed = sum(
            1
            for req in requirements
            if req["attributes"].get("status") == StatusChoices.PASS
        )
        total = len(requirements)
        score = (passed / total * 100) if total else 0.0
        name = getattr(compliance_obj, "Framework", compliance_id)
        summaries.append((name, score, passed, total))
        if len(summaries) >= 12:
            break

    summaries.sort(key=lambda item: item[1])
    return summaries


class VrikaScanReportGenerator:
    """Generate Vrika-branded executive or full scan PDFs."""

    def __init__(self, include_all_findings: bool = False) -> None:
        self.include_all_findings = include_all_findings
        self.styles = create_pdf_styles()
        self.theme = get_pdf_theme()

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
            prowler_provider = build_provider_metadata(provider)

        stats = _aggregate_scan_stats(tenant_id, scan_id)
        severity = _severity_breakdown(tenant_id, scan_id)
        score = _security_score(stats)
        top_findings = _load_top_findings(tenant_id, scan_id, prowler_provider)
        framework_rows = _framework_summaries(provider.provider, tenant_id, scan_id)
        all_findings = (
            _load_all_failed_findings(tenant_id, scan_id, prowler_provider)
            if self.include_all_findings
            else []
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
        elements.extend(self._cover(scan, provider, stats, score))
        elements.append(PageBreak())
        elements.extend(self._executive_summary(stats, score, severity))
        elements.extend(self._account_overview(provider))
        elements.extend(self._controls_overview(stats, score, severity))
        if framework_rows:
            elements.append(PageBreak())
            elements.extend(self._regulation_summary(framework_rows))
        if top_findings:
            elements.append(PageBreak())
            elements.extend(
                self._findings_section("Top Critical & High Findings", top_findings)
            )
        if all_findings:
            elements.append(PageBreak())
            elements.extend(
                self._findings_section(
                    "All Failed Findings",
                    all_findings,
                    chunked=True,
                )
            )

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
        right_text = get_footer_right_text()
        canvas.drawRightString(
            doc.pagesize[0] - doc.rightMargin, 0.45 * inch, right_text
        )
        canvas.restoreState()

    def _cover(
        self,
        scan: Scan,
        provider: Provider,
        stats: dict[str, int],
        score: float,
    ) -> list[Any]:
        elements: list[Any] = []
        logo_path = get_primary_logo_path()
        if os.path.exists(logo_path):
            elements.append(Image(logo_path, width=2.4 * inch, height=1.2 * inch))
        elements.append(Spacer(1, 0.3 * inch))

        title = (
            "Vrika Full Security Report"
            if self.include_all_findings
            else "Vrika Executive Security Report"
        )
        elements.append(Paragraph(title, self.styles["title"]))
        elements.append(Spacer(1, 0.15 * inch))
        elements.append(Paragraph("Security Posture Assessment", self.styles["h2"]))
        elements.append(Spacer(1, 0.25 * inch))

        completed = scan.completed_at or scan.inserted_at
        info_rows = [
            ("Provider:", provider.provider.upper()),
            ("Account ID:", provider.uid or "N/A"),
            ("Alias:", provider.alias or "N/A"),
            ("Scan ID:", str(scan.id)),
            (
                "Completed:",
                completed.strftime("%b %d, %Y %I:%M %p") if completed else "N/A",
            ),
            ("Duration:", _format_duration(scan.duration)),
            ("Resources:", f"{scan.unique_resource_count:,}"),
            ("Security Score:", f"{score:.2f}%"),
            ("Findings:", f"{stats['failed']:,} failed / {stats['total']:,} total"),
        ]
        elements.append(
            create_info_table(
                rows=info_rows,
                label_color=self.theme.info_label_color,
                value_bg_color=self.theme.info_value_bg_color,
                normal_style=self.styles["normal_center"],
            )
        )
        return elements

    def _executive_summary(
        self,
        stats: dict[str, int],
        score: float,
        severity: dict[str, int],
    ) -> list[Any]:
        elements: list[Any] = []
        elements.append(Paragraph("Executive Summary", self.styles["h1"]))

        fail_pct = (
            (stats["failed"] / (stats["passed"] + stats["failed"]) * 100)
            if (stats["passed"] + stats["failed"])
            else 0
        )
        critical = severity.get("critical", 0) + severity.get("high", 0)

        body = (
            f"This report summarizes the cloud security posture for the scanned account. "
            f"The assessment evaluated <b>{stats['passed'] + stats['failed']:,}</b> control checks "
            f"with a security score of <b>{score:.2f}%</b>. "
            f"<b>{fail_pct:.1f}%</b> of evaluated checks failed, including "
            f"<b>{critical:,}</b> critical and high severity findings that should be prioritized."
        )
        normal = ParagraphStyle(
            "ExecBody",
            parent=getSampleStyleSheet()["Normal"],
            fontSize=10,
            leading=14,
            alignment=TA_JUSTIFY,
            textColor=COLOR_GRAY,
            fontName="PlusJakartaSans",
        )
        elements.append(Paragraph(body, normal))
        elements.append(Spacer(1, 0.15 * inch))
        return elements

    def _account_overview(self, provider: Provider) -> list[Any]:
        elements: list[Any] = []
        elements.append(Spacer(1, 0.1 * inch))
        elements.append(Paragraph("Account Overview", self.styles["h1"]))
        rows = [
            ["Provider", provider.provider.upper()],
            ["Account ID", provider.uid or "N/A"],
            ["Alias", provider.alias or "N/A"],
        ]
        table = Table(rows, colWidths=[2 * inch, 4 * inch])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), COLOR_VRIKA_PURPLE),
                    ("TEXTCOLOR", (0, 0), (0, -1), (1, 1, 1)),
                    ("FONTNAME", (0, 0), (-1, -1), "PlusJakartaSans"),
                    ("GRID", (0, 0), (-1, -1), 0.5, COLOR_VRIKA_PURPLE_LIGHT),
                    ("BACKGROUND", (1, 0), (1, -1), COLOR_VRIKA_PURPLE_PALE),
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
        elements: list[Any] = []
        elements.append(Spacer(1, 0.15 * inch))
        elements.append(Paragraph("Controls Overview", self.styles["h1"]))
        elements.append(
            Paragraph(
                f"<b>Security score:</b> {score:.2f}% — "
                f"{stats['passed']:,} passed, {stats['failed']:,} failed, {stats['muted']:,} muted",
                self.styles["normal_center"],
            )
        )
        sev_rows = [["Severity", "Failed Count"]] + [
            [name.title(), str(severity.get(name, 0))]
            for name in FULL_FINDINGS_SEVERITY_ORDER
        ]
        sev_table = Table(sev_rows, colWidths=[2.5 * inch, 2 * inch])
        sev_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), COLOR_VRIKA_PURPLE),
                    ("TEXTCOLOR", (0, 0), (-1, 0), (1, 1, 1)),
                    ("FONTNAME", (0, 0), (-1, -1), "PlusJakartaSans"),
                    ("GRID", (0, 0), (-1, -1), 0.5, COLOR_VRIKA_PURPLE_LIGHT),
                    ("ALIGN", (1, 1), (1, -1), "RIGHT"),
                ]
            )
        )
        elements.append(sev_table)
        return elements

    def _regulation_summary(self, rows: list[tuple[str, float, int, int]]) -> list[Any]:
        elements: list[Any] = []
        elements.append(Paragraph("Regulation-Level Summary", self.styles["h1"]))
        table_rows = [["Framework", "Score", "Passed", "Total"]] + [
            [name, f"{score:.1f}%", str(passed), str(total)]
            for name, score, passed, total in rows
        ]
        table = Table(table_rows, colWidths=[3 * inch, 1 * inch, 1 * inch, 1 * inch])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), COLOR_VRIKA_PURPLE),
                    ("TEXTCOLOR", (0, 0), (-1, 0), (1, 1, 1)),
                    ("FONTNAME", (0, 0), (-1, -1), "PlusJakartaSans"),
                    ("GRID", (0, 0), (-1, -1), 0.5, COLOR_VRIKA_PURPLE_LIGHT),
                    ("ALIGN", (1, 1), (-1, -1), "CENTER"),
                ]
            )
        )
        elements.append(table)
        return elements

    def _findings_section(
        self,
        title: str,
        findings: list[FindingOutput],
        chunked: bool = False,
    ) -> list[Any]:
        elements: list[Any] = []
        elements.append(Paragraph(title, self.styles["h1"]))
        columns = [
            ColumnConfig("Check", 1.8 * inch, "check_id"),
            ColumnConfig("Finding", 2.2 * inch, "title"),
            ColumnConfig("Severity", 0.8 * inch, "severity"),
            ColumnConfig("Region", 0.9 * inch, "region"),
        ]

        def row_mapper(f: FindingOutput) -> dict[str, str]:
            return {
                "check_id": str(getattr(f, "check_id", "") or ""),
                "title": str(getattr(f, "title", "") or "")[:120],
                "severity": str(getattr(f, "severity", "") or ""),
                "region": str(getattr(f, "region", "") or ""),
            }

        chunk_size = FINDINGS_TABLE_CHUNK_SIZE if chunked else len(findings) or 1
        for start in range(0, len(findings), chunk_size):
            chunk = findings[start : start + chunk_size]
            rows = [row_mapper(f) for f in chunk]
            elements.append(
                create_data_table(
                    data=rows,
                    columns=columns,
                    header_color=COLOR_VRIKA_PURPLE,
                )
            )
            elements.append(Spacer(1, 0.1 * inch))
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
