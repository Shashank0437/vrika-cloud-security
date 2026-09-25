"""Finding-UID triage, scoped to a tenant and provider."""

from itertools import islice
from uuid import UUID

from api.db_utils import rls_transaction
from api.exceptions import ConflictException
from api.models import (
    Finding,
    FindingTriage,
    FindingTriageEvent,
    FindingTriageNote,
    MuteRule,
    Provider,
    Scan,
    StateChoices,
)
from api.rbac.permissions import get_providers, get_role
from api.triage_tracking import refresh_tracked_context, retain_finding_snapshot
from django.conf import settings
from django.db import transaction
from django.db.models import Count, Q
from django.db.models.functions import Coalesce
from django.utils import timezone
from rest_framework.exceptions import NotFound, PermissionDenied, ValidationError
from rest_framework_json_api.serializers import ListSerializer

MANUAL_STATUSES = frozenset(
    {"open", "under_review", "remediating", "risk_accepted", "false_positive"}
)
EXCEPTION_STATUSES = frozenset({"risk_accepted", "false_positive"})


class TriageSummaryListSerializer(ListSerializer):
    def to_representation(self, data):
        items = list(data.all() if hasattr(data, "all") else data)
        load_triage_summaries(items, self.context)
        return super().to_representation(items)


def visible_findings(request):
    role = get_role(request.user, request.tenant_id)
    findings = Finding.objects.filter(tenant_id=request.tenant_id)
    if not role.unlimited_visibility:
        findings = findings.filter(scan__provider__in=get_providers(role))
    return findings


def resolve_finding(request, identifier):
    findings = visible_findings(request)
    try:
        finding_id = UUID(identifier)
    except ValueError:
        finding_id = None
    if finding_id:
        finding = findings.filter(id=finding_id).select_related("scan").first()
        if finding:
            return finding
    matches = list(
        findings.filter(uid=identifier)
        .values_list("scan__provider_id", flat=True)
        .distinct()[:2]
    )
    if not matches:
        raise NotFound("Finding not found.")
    if len(matches) != 1:
        raise ValidationError("Use the finding snapshot ID for this UID.")
    return (
        findings.filter(uid=identifier).select_related("scan").order_by("-id").first()
    )


def _event(triage, kind, changes, actor=None, scan_id=None):
    return FindingTriageEvent.objects.create(
        tenant_id=triage.tenant_id,
        triage=triage,
        kind=kind,
        changes=changes,
        actor=actor,
        scan_id=scan_id,
    )


def _advance_result(triage, result, scan):
    """Never infer resolution from absence, or roll back a newer scan."""
    scanned_at = scan.started_at or scan.inserted_at
    if triage.last_scan_started_at is not None and (
        scanned_at,
        str(scan.id),
    ) <= (triage.last_scan_started_at, str(triage.last_scan_id)):
        return None
    old_status = triage.status
    if result == "PASS":
        triage.status = FindingTriage.Status.RESOLVED
        triage.resolution_reason = "check_passed"
    elif result == "FAIL" and (
        triage.last_result == "PASS" or triage.resolution_reason == "resource_removed"
    ):
        triage.status = FindingTriage.Status.REOPENED
        triage.resolution_reason = ""
    triage.last_result = result
    triage.last_scan_id = scan.id
    triage.last_scan_started_at = scanned_at
    triage.updated_at = timezone.now()
    return old_status


def _apply_result(triage, result, scan):
    old_reason = triage.resolution_reason
    if result == "FAIL":
        _seed_previous_pass(
            triage, _prior_passes(scan, [triage.finding_uid]).get(triage.finding_uid)
        )
    old_status = _advance_result(triage, result, scan)
    if old_status is None:
        return False
    triage.save(
        update_fields=[
            "status",
            "last_result",
            "last_scan_id",
            "last_scan_started_at",
            "resolution_reason",
            "updated_at",
        ]
    )
    if old_status != triage.status or old_reason != triage.resolution_reason:
        _event(
            triage,
            "scan",
            {
                "status": {"from": old_status, "to": triage.status},
                "resolution_reason": {
                    "from": old_reason,
                    "to": triage.resolution_reason,
                },
                "reason": "Scan returned PASS."
                if result == "PASS"
                else "Scan returned FAIL.",
            },
            scan_id=scan.id,
        )
    return True


def _prior_passes(scan, uids):
    scanned_at = scan.started_at or scan.inserted_at
    return {
        row["uid"]: (row["scan_time"], str(row["scan_id"]))
        for row in (
            Finding.all_objects.filter(
                tenant_id=scan.tenant_id,
                uid__in=uids,
                status="PASS",
                scan__provider_id=scan.provider_id,
                scan__state=StateChoices.COMPLETED,
            )
            .annotate(scan_time=Coalesce("scan__started_at", "scan__inserted_at"))
            .filter(
                Q(scan_time__lt=scanned_at)
                | Q(scan_time=scanned_at, scan_id__lt=scan.id)
            )
            .order_by("uid", "-scan_time", "-scan_id", "-id")
            .distinct("uid")
            .values("uid", "scan_time", "scan_id")
        )
    }


def _seed_previous_pass(triage, previous_pass):
    # A later FAIL task can run before an intermediate PASS task.
    if previous_pass and (
        triage.last_scan_started_at is None
        or previous_pass > (triage.last_scan_started_at, str(triage.last_scan_id))
    ):
        triage.last_result = "PASS"


def _mute(triage, finding, actor, reason):
    if len(triage.finding_uid) > 255:
        raise ValidationError("This finding UID exceeds the Mutelist rule limit.")
    if (
        Finding.all_objects.filter(tenant_id=triage.tenant_id, uid=triage.finding_uid)
        .exclude(scan__provider_id=triage.provider_id)
        .exists()
    ):
        raise ValidationError(
            "This UID cannot be safely muted with a provider-specific rule."
        )
    rule = MuteRule.objects.filter(
        tenant_id=triage.tenant_id,
        enabled=True,
        finding_uids__contains=[triage.finding_uid],
    ).first()
    if rule is None:
        from uuid import uuid4

        rule = MuteRule.objects.create(
            tenant_id=triage.tenant_id,
            name=f"Triage {uuid4()}",
            reason=reason,
            created_by=actor,
            finding_uids=[triage.finding_uid],
        )
    Finding.all_objects.filter(
        tenant_id=triage.tenant_id,
        id=finding.id,
        scan__provider_id=triage.provider_id,
        muted=False,
    ).update(muted=True, muted_at=timezone.now(), muted_reason=rule.reason)

    def reaggregate():
        from celery import chain
        from tasks.tasks import (
            mute_historical_findings_task,
            reaggregate_all_finding_group_summaries_task,
        )

        chain(
            mute_historical_findings_task.si(
                tenant_id=str(triage.tenant_id), mute_rule_id=str(rule.id)
            ),
            reaggregate_all_finding_group_summaries_task.si(
                tenant_id=str(triage.tenant_id)
            ),
        ).apply_async()

    transaction.on_commit(reaggregate)
    return str(rule.id)


def update_triage(request, finding, data, note_id=None, triage=None):
    role = get_role(request.user, request.tenant_id)
    if not role.manage_triage:
        raise PermissionDenied("Manage Triage permission is required.")
    tenant = request.tenant_id
    provider_id = finding.scan.provider_id if finding else triage.provider_id
    finding_uid = finding.uid if finding else triage.finding_uid
    with rls_transaction(tenant):
        # Serialize status/note writes and scan reconciliation for this provider.
        Provider.objects.select_for_update().get(id=provider_id, tenant_id=tenant)
        latest = (
            Finding.objects.filter(
                tenant_id=tenant,
                uid=finding_uid,
                scan__provider_id=provider_id,
                scan__state=StateChoices.COMPLETED,
            )
            .annotate(scan_time=Coalesce("scan__started_at", "scan__inserted_at"))
            .select_related("scan__provider")
            .prefetch_related("resources")
            .order_by("-scan_time", "-scan_id", "-id")
            .first()
        )
        if latest is None and triage is None:
            raise ValidationError(
                "Triage requires a completed scan containing this finding."
            )
        if latest is not None:
            triage, created = FindingTriage.objects.get_or_create(
                tenant_id=tenant,
                provider_id=provider_id,
                finding_uid=finding_uid,
                defaults={
                    "status": "resolved" if latest.status == "PASS" else "open",
                    "resolution_reason": "check_passed"
                    if latest.status == "PASS"
                    else "",
                    "last_result": latest.status,
                    "last_scan_id": latest.scan_id,
                    "last_scan_started_at": latest.scan.started_at
                    or latest.scan.inserted_at,
                },
            )
            if not created:
                _apply_result(triage, latest.status, latest.scan)
            triage.snapshot = retain_finding_snapshot(triage, latest)
            triage.save(update_fields=["snapshot"])
        else:
            triage.refresh_from_db()
        previous = data.get("previous_status")
        if previous is not None and previous != triage.status:
            raise ConflictException(
                "Triage changed; refresh the finding before saving."
            )
        new_status = data.get("status")
        if new_status is not None and new_status not in MANUAL_STATUSES:
            raise ValidationError("Resolved and Reopened are managed by scans.")
        if new_status is not None and new_status != triage.status:
            if triage.status == "resolved":
                raise ValidationError(
                    "Resolved findings are managed by subsequent scans."
                )
            changes = {"status": {"from": triage.status, "to": new_status}}
            if new_status in EXCEPTION_STATUSES:
                if latest is None:
                    raise ValidationError(
                        "A retained scan finding is required to create a mute rule."
                    )
                if not role.manage_triage_exceptions:
                    raise PermissionDenied(
                        "Manage Triage Exceptions permission is required."
                    )
                reason = str(data.get("reason") or "").strip()
                if data.get("confirm_mute") is not True or not 3 <= len(reason) <= 500:
                    raise ValidationError(
                        "Confirm muting and provide a reason of 3–500 characters."
                    )
                changes["reason"] = reason
                changes["mute_rule_id"] = _mute(triage, latest, request.user, reason)
            triage.status = new_status
            triage.save(update_fields=["status", "updated_at"])
            _event(triage, "status", changes, actor=request.user)
        if "note" in data:
            body = data["note"].strip()
            if len(body) > 500:
                raise ValidationError("Notes cannot exceed 500 characters.")
            note = FindingTriageNote.objects.filter(
                tenant_id=tenant, triage=triage
            ).first()
            if note_id is not None and (note is None or str(note.id) != str(note_id)):
                raise NotFound("Triage note not found.")
            old_body = note.body if note else ""
            if body != old_body:
                if not body:
                    note.delete()
                elif note:
                    note.body = body
                    note.updated_by = request.user
                    note.save(update_fields=["body", "updated_by", "updated_at"])
                else:
                    FindingTriageNote.objects.create(
                        tenant_id=tenant,
                        triage=triage,
                        body=body,
                        created_by=request.user,
                        updated_by=request.user,
                    )
                _event(
                    triage,
                    "note",
                    {"note": {"from": old_body, "to": body}},
                    actor=request.user,
                )
                triage.save(update_fields=["updated_at"])
        if latest is not None:
            from api.triage_tracking import latest_completed_scan

            current_scan = latest_completed_scan(tenant, provider_id)
            if current_scan:
                refresh_tracked_context(current_scan)
        return triage


def resolve_removed_resource(
    triage, scan, *, checked_at, detail, verification, actor=None
):
    """Record a removal decision under the caller's provider lock."""
    old_status, old_reason = triage.status, triage.resolution_reason
    triage.status = "resolved"
    triage.resolution_reason = "resource_removed"
    triage.observation = (
        "removal_confirmed" if actor is not None else "resource_removed"
    )
    triage.observation_detail = detail
    triage.verification_checked_at = checked_at
    triage.last_scan_id = scan.id
    triage.last_scan_started_at = scan.started_at or scan.inserted_at
    triage.save(
        update_fields=[
            "status",
            "resolution_reason",
            "observation",
            "observation_detail",
            "verification_checked_at",
            "last_scan_id",
            "last_scan_started_at",
            "updated_at",
        ]
    )
    _event(
        triage,
        "verification",
        {
            "status": {"from": old_status, "to": "resolved"},
            "resolution_reason": {"from": old_reason, "to": "resource_removed"},
            "reason": detail,
            "verification": {**verification, "checked_at": checked_at.isoformat()},
        },
        actor=actor,
        scan_id=scan.id,
    )
    return triage


def confirm_resource_removal(request, triage, data):
    from api.triage_tracking import latest_completed_scan

    role = get_role(request.user, request.tenant_id)
    if not role.manage_triage or not role.manage_triage_exceptions:
        raise PermissionDenied(
            "Manage Triage and Manage Triage Exceptions permissions are required to confirm removal."
        )
    evidence = data["evidence"].strip()
    if data["confirm_removed"] is not True or not 3 <= len(evidence) <= 500:
        raise ValidationError(
            "Confirm resource removal and provide evidence of 3-500 characters."
        )
    with rls_transaction(request.tenant_id):
        provider = Provider.objects.select_for_update().get(
            tenant_id=request.tenant_id, id=triage.provider_id
        )
        triage.refresh_from_db()
        scan = latest_completed_scan(request.tenant_id, provider.id)
        if (
            scan is None
            or triage.status == "resolved"
            or data["previous_status"] != triage.status
            or data["observation_scan_id"] != scan.id
            or triage.observation_scan_id != scan.id
            or str(data["finding_id"]) != triage.snapshot.get("finding_id")
        ):
            raise ConflictException(
                "Triage or scan evidence changed; refresh the finding before confirming removal."
            )
        if (
            scan.trigger not in Scan.LIVE_SCAN_TRIGGERS
            or any((scan.scanner_args or {}).values())
            or triage.observation not in {"not_seen", "verification_failed"}
            or Finding.objects.filter(
                tenant_id=request.tenant_id, scan_id=scan.id, uid=triage.finding_uid
            ).exists()
        ):
            raise ValidationError(
                "Removal confirmation requires a finding missing from the latest completed, full-scope scan."
            )
        resources = triage.snapshot.get("resources", [])
        if (
            triage.snapshot.get("provider_uid") != provider.uid
            or not resources
            or not all(resource.get("uid") for resource in resources)
        ):
            raise ValidationError(
                "Retained resource identities in the same provider are required to confirm removal."
            )
        return resolve_removed_resource(
            triage,
            scan,
            checked_at=timezone.now(),
            detail="Resource removal confirmed by an authorized reviewer; not automatically verified by the cloud API.",
            verification={
                "method": "reviewer_confirmation",
                "evidence": evidence,
                "provider_uid": provider.uid,
                "resource_uids": [resource["uid"] for resource in resources],
            },
            actor=request.user,
        )


def load_triage_summaries(items, context):
    """Batch enrichment shared by finding lists, includes and resource drill-downs."""
    if not settings.VRIKA_TRIAGE_ENABLED or not context.get("request"):
        return
    request = context["request"]
    ids = [
        str(item.get("finding_id")) if isinstance(item, dict) else str(item.id)
        for item in items
    ]
    cache = context.setdefault("_triage_summaries", {})
    ids = [item for item in ids if item not in cache]
    if not ids:
        return
    role = get_role(request.user, request.tenant_id)
    findings = list(
        visible_findings(request)
        .filter(id__in=ids)
        .values("id", "uid", "status", "scan__provider_id")
    )
    records = {
        (str(row.provider_id), row.finding_uid): row
        for row in FindingTriage.objects.filter(
            tenant_id=request.tenant_id,
            finding_uid__in={f["uid"] for f in findings},
            provider_id__in={f["scan__provider_id"] for f in findings},
        ).annotate(notes_count=Count("note"))
    }
    for finding in findings:
        triage = records.get((str(finding["scan__provider_id"]), finding["uid"]))
        cache[str(finding["id"])] = {
            "id": str(triage.id) if triage else None,
            "status": triage.status
            if triage
            else ("resolved" if finding["status"] == "PASS" else "open"),
            "notes_count": triage.notes_count if triage else 0,
            "can_edit": role.manage_triage,
            "can_manage_exceptions": role.manage_triage
            and role.manage_triage_exceptions,
            "finding_uid": finding["uid"],
            "resolution_reason": triage.resolution_reason if triage else "",
        }


def serialize_triage_summary(item, serializer):
    if not settings.VRIKA_TRIAGE_ENABLED:
        return None
    load_triage_summaries([item], serializer.context)
    finding_id = item.get("finding_id") if isinstance(item, dict) else item.id
    return serializer.context.get("_triage_summaries", {}).get(str(finding_id))


def reconcile_scan_triage(tenant_id, scan_id):
    if not settings.VRIKA_TRIAGE_ENABLED:
        return {"enabled": False}
    with rls_transaction(tenant_id):
        scan = Scan.all_objects.get(id=scan_id, tenant_id=tenant_id)
        if scan.state != StateChoices.COMPLETED:
            raise ValueError("Triage reconciliation requires a completed scan.")
        Provider.objects.select_for_update().get(
            id=scan.provider_id, tenant_id=tenant_id
        )
        findings = (
            Finding.all_objects.filter(
                tenant_id=tenant_id, scan_id=scan_id, status__in=["PASS", "FAIL"]
            )
            .order_by("uid", "-id")
            .distinct("uid")
            .values("uid", "status")
        )
        processed = 0
        iterator = findings.iterator(chunk_size=500)
        while batch := list(islice(iterator, 500)):
            uids = {finding["uid"] for finding in batch}
            existing = {
                row.finding_uid: row
                for row in FindingTriage.objects.filter(
                    tenant_id=tenant_id,
                    provider_id=scan.provider_id,
                    finding_uid__in=uids,
                )
            }
            previous_passes = _prior_passes(scan, uids)
            create, update, events = [], [], []
            for finding in batch:
                uid = finding["uid"]
                triage = existing.get(uid)
                is_new = triage is None
                if is_new:
                    triage = FindingTriage(
                        tenant_id=tenant_id,
                        provider_id=scan.provider_id,
                        finding_uid=uid,
                    )
                if finding["status"] == "FAIL":
                    _seed_previous_pass(triage, previous_passes.get(uid))
                old_reason = triage.resolution_reason
                old_status = _advance_result(triage, finding["status"], scan)
                if old_status is None:
                    continue
                (create if is_new else update).append(triage)
                processed += 1
                if (
                    old_status != triage.status
                    or old_reason != triage.resolution_reason
                ):
                    events.append(
                        FindingTriageEvent(
                            tenant_id=tenant_id,
                            triage=triage,
                            kind="scan",
                            changes={
                                "status": {"from": old_status, "to": triage.status},
                                "resolution_reason": {
                                    "from": old_reason,
                                    "to": triage.resolution_reason,
                                },
                                "reason": "Scan returned PASS."
                                if finding["status"] == "PASS"
                                else "Scan returned FAIL.",
                            },
                            scan_id=scan.id,
                        )
                    )
            FindingTriage.objects.bulk_create(create, batch_size=500)
            FindingTriage.objects.bulk_update(
                update,
                [
                    "status",
                    "last_result",
                    "last_scan_id",
                    "last_scan_started_at",
                    "resolution_reason",
                    "updated_at",
                ],
                batch_size=500,
            )
            FindingTriageEvent.objects.bulk_create(events, batch_size=500)
        refresh_tracked_context(scan)
        return {"enabled": True, "processed": processed}
