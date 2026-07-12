"""Tests for Vrika scan PDF narrative and data helpers."""

from __future__ import annotations

from tasks.jobs.reports.vrika_scan import (
    _humanize_category,
    _services_from_check_ids,
    _short_framework_name,
)
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


def test_short_framework_name_uses_registry():
    class _Obj:
        Framework = "AWS-Well-Architected-Framework-Security-Pillar"
        Name = "AWS WAF Security Pillar"

    name = _short_framework_name("cis_2.0_aws", _Obj())
    assert name == "CIS Benchmark"
