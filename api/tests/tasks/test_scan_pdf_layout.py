"""Layout and content-preservation checks, with no database or cloud access."""

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from reportlab.lib.pagesizes import A4
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Table
from tasks.jobs.reports import vrika_scan as reports
from tasks.jobs.reports.vrika_scan_cards import FrameworkCard, build_framework_card_grid
from tasks.jobs.reports.vrika_scan_narrative import (
    ScanNarrativeContext,
    build_executive_summary_paragraphs,
    build_key_observations,
    build_recommended_next_steps,
)


@pytest.fixture
def generator():
    return reports.VrikaScanReportGenerator()


def paragraphs(flowables):
    for item in flowables:
        if isinstance(item, Paragraph):
            yield item.getPlainText()
        elif isinstance(item, KeepTogether):
            yield from paragraphs(item._content)
        elif isinstance(item, Table):
            for row in item._cellvalues:
                for cell in row:
                    yield from paragraphs(
                        cell if isinstance(cell, (list, tuple)) else [cell]
                    )


def assert_within_width(flowables, width):
    for item in flowables:
        if isinstance(item, KeepTogether):
            assert_within_width(item._content, width)
        elif isinstance(item, Table):
            actual_width, _ = item.wrap(width, A4[1])
            assert actual_width <= width + 0.1
            for row_index, row in enumerate(item._cellvalues):
                for column_index, cell in enumerate(row):
                    style = item._cellStyles[row_index][column_index]
                    available = (
                        item._colWidths[column_index]
                        - style.leftPadding
                        - style.rightPadding
                    )
                    assert_within_width(
                        cell if isinstance(cell, (list, tuple)) else [cell], available
                    )
        elif hasattr(item, "wrap") and not isinstance(item, Paragraph):
            actual_width, _ = item.wrap(width, A4[1])
            assert actual_width <= width + 0.1


@pytest.fixture
def context():
    return ScanNarrativeContext(
        provider_label="AZURE",
        score=22.73,
        passed=25,
        failed=85,
        muted=3,
        total=113,
        fail_pct=77.3,
        critical_count=1,
        high_count=41,
        top_domains=[("logging", 26), ("vulnerabilities", 14)],
    )


def test_all_narrative_text_is_preserved(generator, context):
    for method, build in [
        (generator._executive_summary, build_executive_summary_paragraphs),
        (generator._key_observations, build_key_observations),
        (generator._recommended_next_steps, build_recommended_next_steps),
    ]:
        rendered = " ".join(paragraphs(method(context)))
        for text in build(context):
            assert Paragraph(text, generator._body_style).getPlainText() in rendered


def test_metadata_values_are_complete_and_escaped(generator):
    provider = SimpleNamespace(
        provider="azure",
        uid="subscription-" + "abc123-" * 18,
        alias="Production <East> & Operations",
    )
    scan = SimpleNamespace(
        completed_at=datetime(2026, 9, 22, 5, 31, tzinfo=UTC),
        inserted_at=datetime(2026, 9, 22, 5, 30, tzinfo=UTC),
        duration=97,
        unique_resource_count=34,
    )
    flowables = generator._page_header(scan, provider) + generator._account_overview(
        scan, provider
    )
    text = " ".join(paragraphs(flowables))
    for value in [
        provider.uid,
        provider.alias,
        "AZURE",
        "34",
        "1 min 37 sec",
        "Sep 22, 2026",
        "05:31 AM",
    ]:
        assert value in text
    assert_within_width(flowables, generator._content_width)


def test_controls_fit_page_and_keep_pass_fail_score(generator):
    flowables = generator._controls_overview(
        {"passed": 25, "failed": 85, "muted": 3, "total": 113},
        22.73,
        {"critical": 1, "high": 41, "medium": 38, "low": 5},
    )
    assert_within_width(flowables, generator._content_width)
    text = " ".join(paragraphs(flowables))
    for value in ["22.73%", "25", "85", "110"]:
        assert value in text


def test_domain_and_risk_tables_keep_every_supplied_row(generator):
    domains = [
        reports.DomainSummaryRow(f"domain-{index}", index + 1, index, 30)
        for index in range(12)
    ]
    risks = [
        reports.TopRiskRow(
            f"check-{index}",
            f"Unique security risk {index}",
            "High",
            index + 1,
            f"Complete impact description {index} & remediation context.",
        )
        for index in range(15)
    ]
    flowables = generator._security_domains(domains) + generator._top_risks(risks)
    text = " ".join(paragraphs(flowables))
    for domain in domains:
        assert reports._humanize_category(domain.category) in text
        assert f"{domain.pass_rate:.1f}%" in text
    for risk in risks:
        assert risk.title in text
        assert risk.description in text
    assert_within_width(flowables, generator._content_width)


def test_compliance_grid_keeps_all_twelve_frameworks(generator):
    cards = [
        FrameworkCard(
            name=f"Compliance framework {index}",
            score=23.4,
            passed=17,
            failed=56,
            total=73,
            services="compute, identity, storage, database",
        )
        for index in range(12)
    ]
    flowables = build_framework_card_grid(
        cards,
        generator._body_style,
        generator._body_style,
        width=generator._content_width,
    )
    assert len(flowables) == 6
    text = " ".join(paragraphs(flowables))
    for card in cards:
        assert card.name in text
        assert card.services in text
    for value in ["23.4%", "17", "56", "73"]:
        assert value in text
    assert_within_width(flowables, generator._content_width)


def test_section_headers_stay_with_their_content(generator):
    flowables = generator._section_header("Security Domains at a Glance")
    headings = [item for item in flowables if isinstance(item, (Table, Paragraph))]
    assert headings and all(item.getKeepWithNext() for item in headings)


@pytest.mark.parametrize(
    "passed,failed", [(0, 0), (500, 0), (0, 500), (2000000000, 10)]
)
def test_outcome_edge_cases_render_without_loss(generator, tmp_path, passed, failed):
    stats = {"passed": passed, "failed": failed, "muted": 0, "total": passed + failed}
    severity = {"critical": failed, "high": 0, "medium": 0, "low": 0}
    flowables = generator._controls_overview(
        stats, reports._security_score(stats), severity
    )
    assert_within_width(flowables, generator._content_width)
    destination = tmp_path / "outcomes.pdf"
    SimpleDocTemplate(
        str(destination),
        pagesize=A4,
        leftMargin=reports.PAGE_MARGIN,
        rightMargin=reports.PAGE_MARGIN,
    ).build(flowables)
    assert destination.read_bytes().startswith(b"%PDF-")


def test_odd_compliance_grid_keeps_final_card(generator):
    cards = [
        FrameworkCard(f"Framework {index}", 50, 2, 2, 4, "compute, storage")
        for index in range(3)
    ]
    flowables = build_framework_card_grid(
        cards,
        generator._body_style,
        generator._body_style,
        width=generator._content_width,
    )
    assert len(flowables) == 2
    assert "Framework 2" in " ".join(paragraphs(flowables))
    assert_within_width(flowables, generator._content_width)


def test_appendix_keeps_existing_rows_and_scope(generator, monkeypatch):
    generator.include_all_findings = True
    rows = [
        {
            "title": f"Appendix control {index}",
            "severity": "High",
            "resources": str(index + 1),
            "remediation": f"Full remediation text {index}",
        }
        for index in range(reports.APPENDIX_CHECKS_PER_DOMAIN)
    ]
    monkeypatch.setattr(reports, "_load_appendix_rows", lambda *args: rows)
    flowables = generator._appendix_by_domain(
        "tenant", "scan", [reports.DomainSummaryRow("logging", 25, 15, 30)]
    )
    text = " ".join(paragraphs(flowables))
    for row in rows:
        assert row["title"] in text
        assert row["remediation"] in text
    domain_tables = [
        item for item in flowables if isinstance(item, Table) and item.repeatRows == 2
    ]
    assert len(domain_tables) == 1
    assert "Logging" in " ".join(paragraphs([domain_tables[0]]))
    assert_within_width(flowables, generator._content_width)
