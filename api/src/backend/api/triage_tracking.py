"""Retained context for human-tracked findings, independent of scan retention."""

from datetime import datetime
from itertools import islice

from api.models import Finding, FindingTriage, FindingTriageEvent, Scan, StateChoices
from django.db.models import Exists, OuterRef
from django.db.models.functions import Coalesce


def tracked_triages(queryset=None):
    queryset = queryset if queryset is not None else FindingTriage.objects.all()
    return queryset.filter(
        Exists(
            FindingTriageEvent.objects.filter(
                tenant_id=OuterRef("tenant_id"),
                triage_id=OuterRef("id"),
                kind__in=["status", "note"],
            )
        )
    )


def latest_completed_scan(tenant_id, provider_id):
    return (
        Scan.objects.filter(
            tenant_id=tenant_id, provider_id=provider_id, state=StateChoices.COMPLETED
        )
        .annotate(scan_time=Coalesce("started_at", "inserted_at"))
        .order_by("-scan_time", "-id")
        .first()
    )


def finding_snapshot(finding):
    return {
        "finding_id": str(finding.id),
        "scan_id": str(finding.scan_id),
        "observed_at": (
            finding.scan.started_at or finding.scan.inserted_at
        ).isoformat(),
        "provider_uid": finding.scan.provider.uid,
        "check_id": finding.check_id,
        "title": (finding.check_metadata or {}).get("checktitle") or finding.check_id,
        "severity": finding.severity,
        "result": finding.status,
        "muted": finding.muted,
        "resources": [
            {
                "uid": resource.uid,
                "name": resource.name,
                "region": resource.region,
                "service": resource.service,
                "type": resource.type,
            }
            for resource in finding.resources.all()
        ],
    }


def retain_finding_snapshot(triage, finding):
    previous = triage.snapshot
    if not previous or not previous.get("observed_at"):
        return finding_snapshot(finding)
    current_key = (
        finding.scan.started_at or finding.scan.inserted_at,
        str(finding.scan_id),
        str(finding.id),
    )
    previous_key = (
        datetime.fromisoformat(previous["observed_at"]),
        previous["scan_id"],
        previous["finding_id"],
    )
    if current_key > previous_key:
        return finding_snapshot(finding)
    if current_key == previous_key:
        # Resource/mapping retention must not erase already captured identities.
        return {**previous, "muted": finding.muted}
    return previous


def refresh_tracked_context(scan):
    """Called under the provider lock; also backfills pre-upgrade tracked rows."""
    latest = latest_completed_scan(scan.tenant_id, scan.provider_id)
    if latest is None or latest.id != scan.id:
        return
    rows = tracked_triages().filter(
        tenant_id=scan.tenant_id, provider_id=scan.provider_id
    )
    iterator = rows.order_by("id").iterator(chunk_size=500)
    while batch := list(islice(iterator, 500)):
        findings = {
            finding.uid: finding
            for finding in (
                Finding.objects.filter(
                    tenant_id=scan.tenant_id,
                    scan__provider_id=scan.provider_id,
                    scan__state=StateChoices.COMPLETED,
                    uid__in=[row.finding_uid for row in batch],
                )
                .annotate(scan_time=Coalesce("scan__started_at", "scan__inserted_at"))
                .order_by("uid", "-scan_time", "-scan_id", "-id")
                .distinct("uid")
                .select_related("scan__provider")
                .prefetch_related("resources")
            )
        }
        for row in batch:
            finding = findings.get(row.finding_uid)
            if (
                finding
                and finding.status in {"PASS", "FAIL"}
                and (
                    row.last_scan_started_at is None
                    or (
                        finding.scan.started_at or finding.scan.inserted_at,
                        str(finding.scan_id),
                    )
                    > (row.last_scan_started_at, str(row.last_scan_id))
                )
            ):
                from api.triage import _apply_result

                _apply_result(row, finding.status, finding.scan)
            if finding:
                row.snapshot = retain_finding_snapshot(row, finding)
            present = finding is not None and finding.scan_id == scan.id
            if present:
                row.observation = "observed"
                row.observation_detail = ""
                row.verification_checked_at = None
            elif (
                row.observation_scan_id != scan.id
                and row.resolution_reason != "resource_removed"
            ):
                row.observation = "not_seen"
                row.observation_detail = (
                    "Not seen in latest scan. Resource deletion has not been verified."
                )
                row.verification_checked_at = None
            row.observation_scan_id = scan.id
            if (
                row.status == "resolved"
                and row.last_result == "PASS"
                and not row.resolution_reason
            ):
                row.resolution_reason = "check_passed"
        FindingTriage.objects.bulk_update(
            batch,
            [
                "snapshot",
                "observation",
                "observation_detail",
                "observation_scan_id",
                "verification_checked_at",
                "resolution_reason",
            ],
            batch_size=500,
        )
