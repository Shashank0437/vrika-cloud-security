"""Data-driven narrative text for Vrika scan PDF reports."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScanNarrativeContext:
    provider_label: str
    score: float
    passed: int
    failed: int
    muted: int
    total: int
    fail_pct: float
    critical_count: int
    high_count: int
    top_domains: list[tuple[str, int]]


def _humanize_category(category: str) -> str:
    label = (category or "general").replace("-", " ").replace("_", " ")
    return label.title()


def _score_band(score: float) -> str:
    if score >= 80:
        return "strong adherence to security best practices"
    if score >= 60:
        return (
            "moderate adherence to security best practices, with room for improvement"
        )
    if score >= 40:
        return (
            "significant gaps against security best practices that need a "
            "structured remediation plan"
        )
    return (
        "critical gaps against security best practices that require "
        "immediate executive attention"
    )


def build_executive_summary_paragraphs(ctx: ScanNarrativeContext) -> list[str]:
    evaluated = ctx.passed + ctx.failed
    domain_bits = []
    for name, failed in ctx.top_domains[:4]:
        if failed > 0:
            domain_bits.append(
                f"<b>{_humanize_category(name)}</b> ({failed:,} failed checks)"
            )

    domain_sentence = ""
    if domain_bits:
        if len(domain_bits) == 1:
            domain_sentence = (
                f" The assessment highlights elevated risk in {domain_bits[0]}."
            )
        else:
            domain_sentence = (
                " The assessment highlights elevated risk in "
                + ", ".join(domain_bits[:-1])
                + f", and {domain_bits[-1]}."
            )

    p1 = (
        f"This report provides a business-oriented overview of the current "
        f"<b>{ctx.provider_label}</b> security posture. The scan evaluated "
        f"<b>{evaluated:,}</b> control checks across identity, data protection, "
        f"infrastructure hardening, monitoring, and operational best practices."
    )
    p2 = (
        f"The account achieved an overall security score of <b>{ctx.score:.2f}%</b>, "
        f"with <b>{ctx.fail_pct:.1f}%</b> of evaluated controls failing."
        f"{domain_sentence}"
    )
    p3 = (
        f"There are <b>{ctx.critical_count:,}</b> critical and "
        f"<b>{ctx.high_count:,}</b> high severity failed findings that should be "
        f"prioritized for remediation. This level of exposure indicates "
        f"{_score_band(ctx.score)}."
    )
    return [p1, p2, p3]


def build_key_observations(ctx: ScanNarrativeContext) -> list[str]:
    evaluated = ctx.passed + ctx.failed
    observations = [
        (
            f"Nearly <b>{ctx.fail_pct:.1f}%</b> of the evaluated controls failed, "
            f"indicating a significant scope for improving {ctx.provider_label} "
            f"security practices."
        ),
        (
            f"<b>{ctx.critical_count + ctx.high_count:,}</b> critical and high "
            f"severity findings highlight the urgency for prioritized remediation."
        ),
        (
            f"The current security score of <b>{ctx.score:.2f}%</b> suggests "
            f"{_score_band(ctx.score)}."
        ),
    ]
    if evaluated:
        observations.append(
            f"<b>{ctx.passed:,}</b> of <b>{evaluated:,}</b> evaluated controls passed; "
            f"<b>{ctx.failed:,}</b> require attention ({ctx.muted:,} muted)."
        )
    if ctx.top_domains:
        worst_name, worst_failed = ctx.top_domains[0]
        observations.append(
            f"The highest concentration of failures is in "
            f"<b>{_humanize_category(worst_name)}</b> ({worst_failed:,} failed checks)."
        )
    return observations


def build_recommended_next_steps(ctx: ScanNarrativeContext) -> list[str]:
    steps = []
    if ctx.critical_count:
        steps.append(
            f"<b>P1 — Critical:</b> Remediate {ctx.critical_count:,} critical findings "
            f"within 30 days; validate fixes with a follow-up scan."
        )
    if ctx.high_count:
        steps.append(
            f"<b>P2 — High:</b> Address {ctx.high_count:,} high severity findings "
            f"within 60 days, starting with identity and data exposure risks."
        )
    if ctx.top_domains:
        domain = _humanize_category(ctx.top_domains[0][0])
        steps.append(
            f"<b>P3 — Domain focus:</b> Run a targeted remediation sprint for "
            f"<b>{domain}</b>, which accounts for the largest share of failures."
        )
    if not steps:
        steps.append(
            "Maintain current controls and schedule regular scans to detect "
            "configuration drift."
        )
    return steps
