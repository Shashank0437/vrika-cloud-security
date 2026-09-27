"""Tests for Vrika scan PDF narrative and data helpers."""

from __future__ import annotations

import io
from types import SimpleNamespace

import pytest
from api.models import Provider
from prowler.lib.check.compliance_models import Compliance
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate
from tasks.jobs.reports import vrika_scan
from tasks.jobs.reports.config import get_framework_config
from tasks.jobs.reports.vrika_scan import (
    _humanize_category,
    _services_from_check_ids,
    _short_framework_name,
)
from tasks.jobs.reports.vrika_scan_cards import FrameworkCard, build_framework_card
from tasks.jobs.reports.vrika_scan_narrative import (
    ScanNarrativeContext,
    build_executive_summary_paragraphs,
    build_key_observations,
    build_recommended_next_steps,
)


def _sample_context() -> ScanNarrativeContext:
    return ScanNarrativeContext(
        provider_label="AWS",
        score=62.7,
        passed=10832,
        failed=6437,
        muted=0,
        total=17269,
        fail_pct=37.3,
        critical_count=10,
        high_count=690,
        top_domains=[("identity-access", 2100), ("logging", 980)],
    )


def test_executive_summary_includes_score_and_domains():
    paragraphs = build_executive_summary_paragraphs(_sample_context())
    joined = " ".join(paragraphs)
    assert "62.70%" in joined
    assert "37.3%" in joined
    assert "Identity Access" in joined
    assert "critical" in joined.lower()


def test_key_observations_include_fail_rate_and_worst_domain():
    bullets = build_key_observations(_sample_context())
    joined = " ".join(bullets)
    assert "37.3%" in joined
    assert "700" in joined  # critical + high
    assert "Identity Access" in joined


def test_recommended_next_steps_prioritized():
    steps = build_recommended_next_steps(_sample_context())
    joined = " ".join(steps)
    assert "P1" in joined
    assert "P2" in joined
    assert "Identity Access" in joined


def test_humanize_category():
    assert _humanize_category("identity-access") == "Identity Access"


def test_services_from_check_ids():
    services = _services_from_check_ids(
        {"s3_bucket_public", "iam_user_mfa", "ec2_instance_public"}
    )
    assert "s3" in services
    assert "iam" in services
    assert "ec2" in services


def test_short_framework_name_preserves_identity():
    obj = SimpleNamespace(Framework="CIS", Provider="AWS", Version="2.0")
    assert _short_framework_name("cis_2.0_aws", obj) == "CIS AWS v2.0"


@pytest.mark.parametrize("provider", Provider.ProviderChoices.values)
def test_framework_catalog_titles_are_distinct_and_keep_versions(provider):
    frameworks = Compliance.get_bulk(provider)
    names = [_short_framework_name(key, obj) for key, obj in frameworks.items()]
    assert len(names) == len(set(names)), dict(zip(frameworks, names))
    for name, obj in zip(names, frameworks.values()):
        if obj.Version:
            assert obj.Version in name


def test_framework_names_do_not_confuse_cisa_and_cis():
    obj = SimpleNamespace(
        Framework="CISA-SCuBA", Provider="GoogleWorkspace", Version="0.6"
    )
    assert get_framework_config("cisa_scuba_0.6_googleworkspace") is None
    assert _short_framework_name("cisa_scuba_0.6_googleworkspace", obj) == (
        "CISA SCuBA Google Workspace v0.6"
    )


@pytest.mark.parametrize("enabled, brand", [("true", "Vrika"), ("false", "Prowler")])
def test_framework_name_keeps_vrika_branding(monkeypatch, enabled, brand):
    monkeypatch.setenv("VRIKA_PDF_BRANDING", enabled)
    obj = SimpleNamespace(Framework="ProwlerThreatScore", Provider="AWS", Version="1.0")
    assert (
        _short_framework_name("prowler_threatscore_aws", obj)
        == f"{brand} ThreatScore AWS v1.0"
    )


@pytest.mark.parametrize(
    "metadata, expected",
    [
        (
            {"Framework": "NIST-800-171-Revision-2", "Provider": "AWS", "Version": ""},
            "NIST 800 171 Revision 2 AWS",
        ),
        (
            {"Name": "A framework & its <revision>", "Version": None},
            "A framework & its <revision>",
        ),
        ({}, "custom framework revision 2"),
    ],
)
def test_framework_name_fallbacks_keep_revision_details(metadata, expected):
    name = _short_framework_name(
        "custom_framework_revision_2", SimpleNamespace(**metadata)
    )
    assert name == expected
    styles = getSampleStyleSheet()
    card = FrameworkCard(name, 0, 0, 0, 0, "")
    rendered = build_framework_card(card, styles["Heading2"], styles["BodyText"])
    assert rendered._cellvalues[0][0].getPlainText() == name


def test_framework_card_wraps_long_titles_without_removing_versions():
    obj = SimpleNamespace(
        Framework="A long compliance framework name " * 4,
        Provider="GitHub",
        Version="1.2.3",
    )
    name = _short_framework_name("custom", obj)
    assert len(name) > 70
    card = FrameworkCard(
        name=name, score=50, passed=1, failed=1, total=2, services="repository"
    )
    styles = getSampleStyleSheet()
    flowable = build_framework_card(
        card, styles["Heading2"], styles["BodyText"], width=220
    )
    assert flowable._cellvalues[0][0].getPlainText() == name
    output = io.BytesIO()
    SimpleDocTemplate(output).build([flowable])
    assert output.getvalue().startswith(b"%PDF-")


def test_framework_cards_keep_original_requirement_scores(monkeypatch):
    frameworks = Compliance.get_bulk("github")
    monkeypatch.setattr(vrika_scan.Compliance, "get_bulk", lambda provider: frameworks)
    monkeypatch.setattr(
        "tasks.jobs.threatscore_utils._aggregate_requirement_statistics_from_database",
        lambda *args: {},
    )
    monkeypatch.setattr(
        "tasks.jobs.threatscore_utils._calculate_requirements_data_from_statistics",
        lambda obj, stats: (
            None,
            [
                {"attributes": {"status": "PASS" if index < 5 else "FAIL"}}
                for index in range(len(obj.Requirements))
            ],
        ),
    )
    cards = vrika_scan._load_framework_cards("github", "unused", "unused")
    assert [(card.name, card.passed, card.failed, card.total) for card in cards] == [
        ("CIS GitHub v1.0", 5, 116, 121),
        ("CIS GitHub v1.2.0", 5, 115, 120),
    ]
    assert cards[0].score == pytest.approx(5 / 121 * 100)
    assert cards[1].score == pytest.approx(5 / 120 * 100)
