"""Triage API, isolation and scan lifecycle integration coverage."""

import json
from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

from api.db_router import MainRouter
from api.db_utils import rls_transaction
from api.models import (
    Finding,
    FindingTriage,
    FindingTriageEvent,
    FindingTriageNote,
    MuteRule,
    Provider,
    Role,
    Scan,
    Tenant,
    User,
    UserRoleRelationship,
)
from api.triage import reconcile_scan_triage
from django.db import connection
from django.test import TestCase, TransactionTestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient


@override_settings(VRIKA_TRIAGE_ENABLED=True)
class FindingTriageTests(TestCase):
    def setUp(self):
        self.admin_alias = patch.object(MainRouter, "admin_db", "default")
        self.admin_alias.start()
        self.addCleanup(self.admin_alias.stop)
        self.tenant = Tenant.objects.create(name="Triage tests")
        self.other_tenant = Tenant.objects.create(name="Other tenant")
        self.user = User.objects.create_user(
            email=f"{uuid4()}@example.com", password="test"
        )
        self.role = Role.objects.create(
            tenant=self.tenant,
            name="vrika_member",
            manage_triage=True,
            unlimited_visibility=True,
        )
        UserRoleRelationship.objects.create(
            tenant=self.tenant, user=self.user, role=self.role
        )
        self.provider = Provider.objects.create(
            tenant=self.tenant,
            provider="aws",
            uid="123456789012",
        )
        self.client = APIClient()
        self.client.force_authenticate(
            self.user, token={"tenant_id": str(self.tenant.id)}
        )
        self.now = timezone.now()
        self.finding = self.snapshot("FAIL", 0)

    def snapshot(
        self, result, offset, uid="stable-finding", provider=None, state="completed"
    ):
        provider = provider or self.provider
        scan = Scan.objects.create(
            tenant_id=provider.tenant_id,
            provider=provider,
            state=state,
            trigger="manual",
            started_at=self.now + timedelta(minutes=offset),
        )
        return Finding.objects.create(
            tenant_id=provider.tenant_id,
            scan=scan,
            uid=uid,
            status=result,
            severity="high",
            impact="high",
            check_id="test_check",
        )

    def url(self, finding=None):
        return f"/api/v1/findings/{(finding or self.finding).id}/triage"

    def write(self, attributes, url=None, resource_type="finding-triages"):
        url = url or self.url()
        identifier = (
            url.split("/")[-2] if url.endswith("/triage") else url.split("/")[-1]
        )
        return self.client.patch(
            url,
            data=json.dumps(
                {
                    "data": {
                        "type": resource_type,
                        "id": identifier,
                        "attributes": attributes,
                    }
                }
            ),
            content_type="application/vnd.api+json",
        )

    def record(self):
        return FindingTriage.objects.get(
            tenant=self.tenant, finding_uid=self.finding.uid
        )

    def test_member_status_note_and_history(self):
        response = self.write({"status": "under_review", "note": "Investigating"})
        self.assertEqual(response.status_code, 200, response.content)
        triage = self.record()
        self.assertEqual(triage.status, "under_review")
        notes = self.client.get(f"{self.url()}/notes")
        self.assertEqual(notes.status_code, 200, notes.content)
        self.assertEqual(notes.json()["data"][0]["attributes"]["body"], "Investigating")
        history = self.client.get(f"{self.url()}/history")
        self.assertEqual(history.status_code, 200, history.content)
        self.assertEqual(len(history.json()["data"]), 2)
        response = self.write({"note": ""})
        self.assertEqual(response.status_code, 200, response.content)
        self.assertFalse(FindingTriageNote.objects.exists())
        self.assertEqual(FindingTriageEvent.objects.filter(kind="note").count(), 2)

    def test_note_endpoint_edit_delete_and_validation(self):
        self.assertEqual(self.write({"note": "One"}).status_code, 200)
        note = FindingTriageNote.objects.get()
        url = f"/api/v1/finding-triages/{self.record().id}/notes/{note.id}"
        response = self.write({"body": "Two"}, url, "finding-triage-notes")
        self.assertEqual(response.status_code, 200, response.content)
        note.refresh_from_db()
        self.assertEqual(note.body, "Two")
        self.assertEqual(
            self.write({"body": " "}, url, "finding-triage-notes").status_code, 400
        )
        self.assertEqual(self.write({"note": "a" * 501}).status_code, 400)
        self.assertEqual(self.client.delete(url).status_code, 204)
        self.assertFalse(FindingTriageNote.objects.exists())

    def test_member_cannot_mute_and_write_rolls_back(self):
        response = self.write(
            {
                "status": "risk_accepted",
                "note": "Must not persist",
                "reason": "Accepted by member",
                "confirm_mute": True,
            }
        )
        self.assertEqual(response.status_code, 403, response.content)
        self.assertFalse(FindingTriage.objects.exists())
        self.assertFalse(MuteRule.objects.exists())

    def test_admin_exception_confirmation_atomic_mute_and_duplicate(self):
        self.role.manage_triage_exceptions = True
        self.role.save()
        self.assertEqual(self.write({"status": "risk_accepted"}).status_code, 400)
        self.assertFalse(FindingTriage.objects.exists())
        with self.captureOnCommitCallbacks(execute=False) as callbacks:
            response = self.write(
                {
                    "status": "risk_accepted",
                    "note": "Approved",
                    "confirm_mute": True,
                    "reason": "Approved temporary exception",
                }
            )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(len(callbacks), 1)
        self.finding.refresh_from_db()
        self.assertTrue(self.finding.muted)
        self.assertEqual(MuteRule.objects.count(), 1)
        self.assertEqual(self.write({"status": "risk_accepted"}).status_code, 200)
        self.assertEqual(MuteRule.objects.count(), 1)
        self.assertEqual(self.write({"status": "open"}).status_code, 200)
        self.assertTrue(MuteRule.objects.get().enabled)

    def test_read_only_can_read_but_not_write(self):
        self.write({"note": "Visible"})
        self.role.manage_triage = False
        self.role.save()
        self.assertEqual(self.client.get(f"{self.url()}/notes").status_code, 200)
        self.assertEqual(self.client.get(f"{self.url()}/history").status_code, 200)
        self.assertEqual(self.write({"status": "under_review"}).status_code, 403)

    def test_tenant_and_provider_isolation(self):
        provider = Provider.objects.create(
            tenant=self.other_tenant,
            provider="gcp",
            uid="other-project",
        )
        foreign = self.snapshot("FAIL", 1, provider=provider)
        self.assertEqual(
            self.write({"status": "under_review"}, self.url(foreign)).status_code, 404
        )
        self.role.unlimited_visibility = False
        self.role.save()
        self.assertEqual(self.write({"status": "under_review"}).status_code, 404)

    def test_collision_requires_snapshot_and_rejects_tenant_wide_mute(self):
        other = Provider.objects.create(
            tenant=self.tenant, provider="gcp", uid="project"
        )
        self.snapshot("FAIL", 1, provider=other)
        response = self.write(
            {"status": "under_review"}, f"/api/v1/findings/{self.finding.uid}/triage"
        )
        self.assertEqual(response.status_code, 400, response.content)
        self.assertEqual(self.write({"status": "under_review"}).status_code, 200)
        self.role.manage_triage_exceptions = True
        self.role.save()
        self.assertEqual(
            self.write(
                {
                    "status": "false_positive",
                    "confirm_mute": True,
                    "reason": "Confirmed",
                }
            ).status_code,
            400,
        )
        self.assertEqual(self.record().status, "under_review")

    def test_stale_update_and_automatic_status_rejected(self):
        self.write({"status": "under_review"})
        self.assertEqual(
            self.write({"status": "open", "previous_status": "open"}).status_code, 409
        )
        for status in ("resolved", "reopened", "invalid"):
            self.assertEqual(self.write({"status": status}).status_code, 400)
        self.assertEqual(
            self.write({"note": "valid", "unknown": True}).status_code, 400
        )

    def test_lifecycle_stable_uid_notes_and_repeat(self):
        self.write({"status": "remediating", "note": "Working"})
        passed = self.snapshot("PASS", 1)
        reconcile_scan_triage(self.tenant.id, passed.scan_id)
        self.assertEqual(self.record().status, "resolved")
        self.assertEqual(self.write({"status": "open"}).status_code, 400)
        failed = self.snapshot("FAIL", 2)
        reconcile_scan_triage(self.tenant.id, failed.scan_id)
        self.assertEqual(self.record().status, "reopened")
        count = FindingTriageEvent.objects.count()
        reconcile_scan_triage(self.tenant.id, failed.scan_id)
        reconcile_scan_triage(self.tenant.id, passed.scan_id)
        self.assertEqual(FindingTriageEvent.objects.count(), count)
        self.assertEqual(self.record().status, "reopened")
        self.assertEqual(FindingTriageNote.objects.get().body, "Working")

    def test_missing_partial_and_failed_scan_do_not_resolve(self):
        self.write({"status": "remediating"})
        missing = self.snapshot("PASS", 1, uid="different-finding")
        missing.scan.scanner_args = {"checks": ["test_check"]}
        missing.scan.save()
        reconcile_scan_triage(self.tenant.id, missing.scan_id)
        self.assertEqual(self.record().status, "remediating")
        failed = self.snapshot("PASS", 2, state="failed")
        with self.assertRaises(ValueError):
            reconcile_scan_triage(self.tenant.id, failed.scan_id)
        self.assertEqual(self.record().status, "remediating")

    def test_out_of_order_completion_observes_intermediate_pass(self):
        self.write({"status": "remediating"})
        passed = self.snapshot("PASS", 1)
        failed = self.snapshot("FAIL", 2)
        reconcile_scan_triage(self.tenant.id, failed.scan_id)
        self.assertEqual(self.record().status, "reopened")
        reconcile_scan_triage(self.tenant.id, passed.scan_id)
        self.assertEqual(self.record().status, "reopened")

    def test_summaries_for_list_and_detail(self):
        from types import SimpleNamespace

        from api.triage import load_triage_summaries, serialize_triage_summary

        self.write({"status": "under_review", "note": "Private note"})
        request = SimpleNamespace(user=self.user, tenant_id=self.tenant.id)
        serializer = SimpleNamespace(context={"request": request})
        load_triage_summaries([self.finding], serializer.context)
        summary = serialize_triage_summary(self.finding, serializer)
        self.assertEqual(summary["status"], "under_review")
        self.assertTrue(summary["can_edit"])
        self.assertFalse(summary["can_manage_exceptions"])
        self.assertEqual(summary["notes_count"], 1)
        self.assertNotIn("note", summary)
        response = self.client.get(f"/api/v1/findings/{self.finding.id}")
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(
            response.json()["data"]["attributes"]["triage"]["status"], "under_review"
        )

    def test_role_upgrade_changes_only_managed_permissions(self):
        from importlib import import_module

        from django.apps import apps

        custom = Role.objects.create(
            tenant=self.tenant, name="custom", manage_scans=True
        )
        admin = Role.objects.create(tenant=self.tenant, name="admin")
        self.role.manage_triage = False
        self.role.save()
        migration = import_module("api.migrations.0100_triage_managed_roles")
        migration.grant_managed_triage_permissions(apps, None)
        admin.refresh_from_db()
        custom.refresh_from_db()
        self.role.refresh_from_db()
        self.assertTrue(admin.manage_triage and admin.manage_triage_exceptions)
        self.assertTrue(self.role.manage_triage)
        self.assertFalse(self.role.manage_triage_exceptions)
        self.assertTrue(custom.manage_scans)
        self.assertFalse(custom.manage_triage or custom.manage_triage_exceptions)

    def test_readonly_note_history_scope_and_pagination(self):
        self.write({"note": "First"})
        self.write({"note": "Second"})
        triage = self.record()
        response = self.client.get(
            f"/api/v1/finding-triages/{triage.id}/history?page[size]=1"
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(len(response.json()["data"]), 1)
        self.assertIsNotNone(response.json()["links"]["next"])
        self.client.force_authenticate(
            self.user, token={"tenant_id": str(self.other_tenant.id)}
        )
        Role.objects.create(tenant=self.other_tenant, name="unused")
        for suffix in ("", "/notes", "/history"):
            self.assertIn(
                self.client.get(
                    f"/api/v1/finding-triages/{triage.id}{suffix}"
                ).status_code,
                (403, 404),
            )

    def test_batched_reconciliation_and_timestamp_ties(self):
        first = self.snapshot("PASS", 1, uid="tie")
        second = self.snapshot("FAIL", 1, uid="tie")
        reconcile_scan_triage(self.tenant.id, second.scan_id)
        reconcile_scan_triage(self.tenant.id, first.scan_id)
        self.assertEqual(
            FindingTriage.objects.get(finding_uid="tie").status, "reopened"
        )
        Finding.objects.bulk_create(
            [
                Finding(
                    tenant=self.tenant,
                    scan=self.finding.scan,
                    uid=f"batch-{i}",
                    status="FAIL",
                    severity="high",
                    impact="high",
                    check_id="test_check",
                )
                for i in range(501)
            ]
        )
        result = reconcile_scan_triage(self.tenant.id, self.finding.scan_id)
        self.assertEqual(result["processed"], 502)
        self.assertEqual(
            FindingTriage.objects.filter(finding_uid__startswith="batch-").count(), 501
        )

    def test_rls_policies_include_writes_and_hide_other_tenant(self):
        self.write({"note": "Private"})
        with connection.cursor() as cursor:
            cursor.execute("SET LOCAL ROLE test")
            try:
                with rls_transaction(self.other_tenant.id):
                    self.assertEqual(FindingTriage.objects.count(), 0)
                with rls_transaction(self.tenant.id):
                    self.assertEqual(FindingTriage.objects.count(), 1)
                    FindingTriage.objects.filter(id=self.record().id).update(
                        status="under_review"
                    )
            finally:
                cursor.execute("RESET ROLE")

    @override_settings(VRIKA_TRIAGE_ENABLED=False)
    def test_disabled_does_not_expose_routes_or_reconcile(self):
        self.assertEqual(self.write({"status": "under_review"}).status_code, 404)
        self.assertEqual(
            reconcile_scan_triage(self.tenant.id, self.finding.scan_id),
            {"enabled": False},
        )
        self.assertFalse(FindingTriage.objects.exists())


@override_settings(VRIKA_TRIAGE_ENABLED=True)
class ConcurrentTriageTests(TransactionTestCase):
    def test_concurrent_exception_writes_create_one_rule_and_one_history_event(self):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Barrier
        from types import SimpleNamespace

        from api.triage import update_triage
        from django.db import close_old_connections

        tenant = Tenant.objects.create(name="Concurrent")
        user = User.objects.create_user(email=f"{uuid4()}@example.com", password="test")
        role = Role.objects.create(
            tenant=tenant,
            name="admin",
            manage_triage=True,
            manage_triage_exceptions=True,
            unlimited_visibility=True,
        )
        UserRoleRelationship.objects.create(tenant=tenant, user=user, role=role)
        provider = Provider.objects.create(
            tenant=tenant, provider="aws", uid="123456789012"
        )
        scan = Scan.objects.create(
            tenant=tenant,
            provider=provider,
            state="completed",
            trigger="manual",
            started_at=timezone.now(),
        )
        finding = Finding.objects.create(
            tenant=tenant,
            scan=scan,
            uid="concurrent",
            status="FAIL",
            severity="high",
            impact="high",
            check_id="test_check",
        )
        barrier = Barrier(2)

        def write():
            close_old_connections()
            try:
                request = SimpleNamespace(
                    user=User.objects.get(id=user.id), tenant_id=tenant.id
                )
                snapshot = Finding.objects.select_related("scan").get(id=finding.id)
                barrier.wait(timeout=10)
                return update_triage(
                    request,
                    snapshot,
                    {
                        "status": "risk_accepted",
                        "confirm_mute": True,
                        "reason": "Approved exception",
                        "note": "Concurrent note",
                    },
                ).id
            finally:
                close_old_connections()

        with (
            patch.object(MainRouter, "admin_db", "default"),
            patch("api.triage.transaction.on_commit") as callback,
            ThreadPoolExecutor(max_workers=2) as executor,
        ):
            futures = [executor.submit(write) for _ in range(2)]
            ids = [future.result(timeout=20) for future in futures]
        self.assertEqual(ids[0], ids[1])
        self.assertEqual(FindingTriage.objects.count(), 1)
        self.assertEqual(MuteRule.objects.count(), 1)
        self.assertEqual(FindingTriageNote.objects.count(), 1)
        self.assertEqual(FindingTriageEvent.objects.filter(kind="status").count(), 1)
        self.assertEqual(callback.call_count, 1)
