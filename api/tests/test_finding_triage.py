"""Triage API, isolation and scan lifecycle integration coverage."""

import json
from datetime import timedelta
from unittest import TestCase as UnitTestCase
from unittest.mock import MagicMock, patch
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
    Resource,
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

    def configure_gcp_firewall(self):
        self.provider.provider = "gcp"
        self.provider.uid = "triage-test-project"
        self.provider.save()
        self.finding.check_id = "compute_firewall_rdp_access_from_the_internet_allowed"
        self.finding.check_metadata = {"checktitle": "Restrict public RDP"}
        self.finding.save()
        resource = Resource.objects.create(
            tenant=self.tenant,
            provider=self.provider,
            uid="1477183571312302287",
            name="default-allow-rdp",
            region="global",
            service="compute",
            type="Firewall",
        )
        self.finding.resources.add(
            resource, through_defaults={"tenant_id": self.tenant.id}
        )
        self.assertEqual(
            self.write(
                {"status": "remediating", "note": "Deleting public rule"}
            ).status_code,
            200,
        )

    def test_tracked_list_retains_missing_context_notes_and_history(self):
        self.configure_gcp_firewall()
        missing = self.snapshot("PASS", 1, uid="different-finding")
        reconcile_scan_triage(self.tenant.id, missing.scan_id)
        response = self.client.get("/api/v1/finding-triages/tracked")
        self.assertEqual(response.status_code, 200, response.content)
        rows = response.json()["data"]
        self.assertEqual(len(rows), 1)
        attrs = rows[0]["attributes"]
        self.assertEqual(attrs["status"], "remediating")
        self.assertEqual(attrs["observation"], "not_seen")
        self.assertEqual(attrs["snapshot"]["resources"][0]["name"], "default-allow-rdp")
        triage_id = self.record().id
        self.finding.delete()
        url = f"/api/v1/finding-triages/{triage_id}"
        self.assertEqual(self.write({"note": "Still retained"}, url).status_code, 200)
        self.assertEqual(self.client.get(f"{url}/history").status_code, 200)
        self.assertEqual(
            self.client.get(f"{url}/notes").json()["data"][0]["attributes"]["body"],
            "Still retained",
        )
        attrs = self.client.get("/api/v1/finding-triages/tracked").json()["data"][0][
            "attributes"
        ]
        self.assertEqual(attrs["snapshot"]["title"], "Restrict public RDP")

    def test_verified_removal_preserves_fail_and_reopens_on_return(self):
        from api.triage_removal import verify_missing_resources

        self.configure_gcp_firewall()
        missing = self.snapshot("PASS", 1, uid="different-finding")
        reconcile_scan_triage(self.tenant.id, missing.scan_id)
        with patch("api.triage_removal.list_gcp_firewalls", return_value={}):
            verify_missing_resources(self.tenant.id, missing.scan_id)
            verify_missing_resources(self.tenant.id, missing.scan_id)
        triage = self.record()
        self.assertEqual(triage.status, "resolved")
        self.assertEqual(triage.resolution_reason, "resource_removed")
        self.assertEqual(triage.last_result, "FAIL")
        self.assertEqual(triage.snapshot["result"], "FAIL")
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.status, "FAIL")
        self.assertEqual(
            FindingTriageEvent.objects.filter(kind="verification").count(), 1
        )
        self.assertEqual(FindingTriageNote.objects.get().body, "Deleting public rule")
        returned = self.snapshot("FAIL", 2)
        reconcile_scan_triage(self.tenant.id, returned.scan_id)
        self.assertEqual(self.record().status, "reopened")
        self.assertEqual(self.record().resolution_reason, "")

    def test_verification_errors_present_and_scoped_scans_do_not_close(self):
        from api.triage_removal import VerificationError, verify_missing_resources

        self.configure_gcp_firewall()
        missing = self.snapshot("PASS", 1, uid="different-finding")
        reconcile_scan_triage(self.tenant.id, missing.scan_id)
        with patch(
            "api.triage_removal.list_gcp_firewalls",
            side_effect=VerificationError("Cloud inventory could not be read."),
        ):
            verify_missing_resources(self.tenant.id, missing.scan_id)
        self.assertEqual(self.record().status, "remediating")
        self.assertEqual(self.record().observation, "verification_failed")
        with patch(
            "api.triage_removal.list_gcp_firewalls",
            return_value={"default-allow-rdp": "1477183571312302287"},
        ):
            verify_missing_resources(self.tenant.id, missing.scan_id)
        self.assertEqual(self.record().status, "remediating")
        self.assertEqual(self.record().observation, "not_seen")
        missing.scan.scanner_args = {"checks": ["unrelated_check"]}
        missing.scan.save()
        with patch("api.triage_removal.list_gcp_firewalls") as inventory:
            verify_missing_resources(self.tenant.id, missing.scan_id)
        inventory.assert_not_called()
        self.assertEqual(self.record().status, "remediating")

    def test_newer_scan_during_verification_blocks_stale_closure(self):
        from api.triage_removal import verify_missing_resources

        self.configure_gcp_firewall()
        missing = self.snapshot("PASS", 1, uid="different-finding")
        reconcile_scan_triage(self.tenant.id, missing.scan_id)

        def inventory(_provider):
            self.snapshot("FAIL", 2)
            return {}

        with patch("api.triage_removal.list_gcp_firewalls", side_effect=inventory):
            verify_missing_resources(self.tenant.id, missing.scan_id)
        self.assertEqual(self.record().status, "remediating")
        self.assertFalse(
            FindingTriageEvent.objects.filter(kind="verification").exists()
        )

    def test_tracked_filters_visibility_and_disabled_feature(self):
        self.configure_gcp_firewall()
        for query, expected in [
            ("filter[status]=remediating", 1),
            ("filter[status]=resolved", 0),
            ("filter[search]=default-allow-rdp", 1),
            ("filter[provider_id]=" + str(uuid4()), 0),
        ]:
            response = self.client.get("/api/v1/finding-triages/tracked?" + query)
            self.assertEqual(response.status_code, 200, response.content)
            self.assertEqual(len(response.json()["data"]), expected)
        self.assertEqual(
            self.client.get(
                "/api/v1/finding-triages/tracked?filter[status]=bogus"
            ).status_code,
            400,
        )
        self.role.unlimited_visibility = False
        self.role.save()
        self.assertEqual(
            self.client.get("/api/v1/finding-triages/tracked").json()["data"], []
        )
        with override_settings(VRIKA_TRIAGE_ENABLED=False):
            self.assertEqual(
                self.client.get("/api/v1/finding-triages/tracked").status_code, 404
            )

    def test_replacement_or_unknown_identity_is_not_closed(self):
        from api.triage_removal import verify_missing_resources

        self.configure_gcp_firewall()
        missing = self.snapshot("PASS", 1, uid="different-finding")
        reconcile_scan_triage(self.tenant.id, missing.scan_id)
        with patch(
            "api.triage_removal.list_gcp_firewalls",
            return_value={"default-allow-rdp": "99999"},
        ):
            verify_missing_resources(self.tenant.id, missing.scan_id)
        self.assertEqual(self.record().status, "remediating")
        self.provider.uid = "different-project"
        self.provider.save()
        with patch("api.triage_removal.list_gcp_firewalls") as inventory:
            verify_missing_resources(self.tenant.id, missing.scan_id)
        inventory.assert_not_called()
        self.assertEqual(self.record().status, "remediating")

    def test_backfill_legacy_context_and_out_of_order_results_after_removal(self):
        from api.triage_removal import verify_missing_resources
        from django.core.management import call_command

        self.configure_gcp_firewall()
        triage = self.record()
        triage.snapshot = {}
        triage.save()
        missing = self.snapshot("PASS", 2, uid="different-finding")
        call_command("backfill_triage_tracking", tenant_id=self.tenant.id, verbosity=0)
        self.assertEqual(self.record().snapshot["scan_id"], str(self.finding.scan_id))
        with patch("api.triage_removal.list_gcp_firewalls", return_value={}):
            verify_missing_resources(self.tenant.id, missing.scan_id)
        self.assertEqual(self.record().resolution_reason, "resource_removed")
        late_fail = self.snapshot("FAIL", 1)
        reconcile_scan_triage(self.tenant.id, late_fail.scan_id)
        self.assertEqual(self.record().status, "resolved")
        self.assertEqual(self.record().resolution_reason, "resource_removed")

    def test_backfill_applies_an_intermediate_pass_before_a_missing_scan(self):
        from django.core.management import call_command

        self.configure_gcp_firewall()
        self.snapshot("PASS", 1)
        self.snapshot("PASS", 2, uid="different-finding")
        call_command("backfill_triage_tracking", tenant_id=self.tenant.id, verbosity=0)
        self.assertEqual(self.record().status, "resolved")
        self.assertEqual(self.record().resolution_reason, "check_passed")

    def test_pass_preserves_manual_remediation_history_and_resolution_reason(self):
        self.write({"status": "remediating", "note": "Fixing configuration"})
        passed = self.snapshot("PASS", 1)
        reconcile_scan_triage(self.tenant.id, passed.scan_id)
        self.assertEqual(self.record().resolution_reason, "check_passed")
        changes = list(
            FindingTriageEvent.objects.filter(triage=self.record()).values_list(
                "changes", flat=True
            )
        )
        self.assertTrue(
            any(
                change.get("status") == {"from": "open", "to": "remediating"}
                for change in changes
            )
        )
        self.assertTrue(
            any(
                change.get("status") == {"from": "remediating", "to": "resolved"}
                for change in changes
            )
        )
        self.assertEqual(FindingTriageNote.objects.get().body, "Fixing configuration")

    def test_removal_then_pass_records_the_new_resolution_evidence(self):
        from api.triage_removal import verify_missing_resources

        self.configure_gcp_firewall()
        missing = self.snapshot("PASS", 1, uid="different-finding")
        reconcile_scan_triage(self.tenant.id, missing.scan_id)
        with patch("api.triage_removal.list_gcp_firewalls", return_value={}):
            verify_missing_resources(self.tenant.id, missing.scan_id)
        returned = self.snapshot("PASS", 2)
        reconcile_scan_triage(self.tenant.id, returned.scan_id)
        self.assertEqual(self.record().resolution_reason, "check_passed")
        event = FindingTriageEvent.objects.filter(
            triage=self.record(), scan_id=returned.scan_id
        ).get()
        self.assertEqual(
            event.changes["resolution_reason"],
            {
                "from": "resource_removed",
                "to": "check_passed",
            },
        )

    def test_task_queues_verification_only_when_enabled(self):
        from tasks.tasks import reconcile_finding_triage_task

        self.write({"status": "remediating"})
        with patch("tasks.tasks.verify_missing_triage_resources_task.delay") as verify:
            reconcile_finding_triage_task.run(
                str(self.tenant.id), str(self.finding.scan_id)
            )
            verify.assert_called_once_with(
                tenant_id=str(self.tenant.id), scan_id=str(self.finding.scan_id)
            )
            verify.reset_mock()
            with override_settings(VRIKA_TRIAGE_ENABLED=False):
                reconcile_finding_triage_task.run(
                    str(self.tenant.id), str(self.finding.scan_id)
                )
            verify.assert_not_called()

    def test_unsupported_provider_does_not_attempt_cloud_verification(self):
        from api.triage_removal import verify_missing_resources

        self.write({"status": "remediating"})
        missing = self.snapshot("PASS", 1, uid="different-finding")
        reconcile_scan_triage(self.tenant.id, missing.scan_id)
        with patch("api.triage_removal.list_gcp_firewalls") as inventory:
            verify_missing_resources(self.tenant.id, missing.scan_id)
        inventory.assert_not_called()
        self.assertEqual(self.record().status, "remediating")
        self.assertIn("not available", self.record().observation_detail)

    def test_resource_mapping_cleanup_does_not_erase_retained_identity(self):
        self.configure_gcp_firewall()
        Resource.objects.filter(tenant=self.tenant, uid="1477183571312302287").delete()
        missing = self.snapshot("PASS", 1, uid="different-finding")
        reconcile_scan_triage(self.tenant.id, missing.scan_id)
        self.assertEqual(self.write({"note": "Context retained"}).status_code, 200)
        self.assertEqual(
            self.record().snapshot["resources"][0]["uid"], "1477183571312302287"
        )

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

    def confirm_removal(self, triage=None, **overrides):
        triage = triage or self.record()
        attributes = {
            "previous_status": triage.status,
            "observation_scan_id": str(triage.observation_scan_id),
            "finding_id": triage.snapshot.get("finding_id"),
            "confirm_removed": True,
            "evidence": "Confirmed deletion in the cloud console; change request CHG-123.",
            **overrides,
        }
        return self.client.patch(
            f"/api/v1/finding-triages/{triage.id}/confirm-removal",
            data=json.dumps(
                {
                    "data": {
                        "type": "finding-triages",
                        "id": str(triage.id),
                        "attributes": attributes,
                    }
                }
            ),
            content_type="application/vnd.api+json",
        )

    def test_reviewer_removal_confirmation_works_for_every_provider(self):
        self.role.manage_triage_exceptions = True
        self.role.save()
        provider_uids = {
            "aws": "999999999999",
            "azure": str(uuid4()),
            "gcp": "review-project",
            "kubernetes": "review-cluster",
            "m365": "review.example.com",
            "github": "review-org",
            "mongodbatlas": "a" * 24,
            "iac": "https://example.com/review.git",
            "oraclecloud": "ocid1.tenancy.oc1..review123",
            "alibabacloud": "1" * 16,
            "cloudflare": "a" * 32,
            "openstack": "review-project",
            "image": "review-image:latest",
            "googleworkspace": "C12345678",
            "vercel": "team_" + "a" * 16,
            "okta": "review.okta.com",
        }
        for provider_type in Provider.ProviderChoices.values:
            with self.subTest(provider=provider_type):
                provider = Provider.objects.create(
                    tenant=self.tenant,
                    provider=provider_type,
                    uid=provider_uids[provider_type],
                )
                finding = self.snapshot(
                    "FAIL", 0, uid=f"issue-{provider_type}", provider=provider
                )
                resource = Resource.objects.create(
                    tenant=self.tenant,
                    provider=provider,
                    uid="resource-id",
                    name="Removed resource",
                    region="region",
                    service="any-service",
                    type="any-type",
                )
                finding.resources.add(
                    resource, through_defaults={"tenant_id": self.tenant.id}
                )
                self.assertEqual(
                    self.write(
                        {"status": "remediating", "note": "Working"}, self.url(finding)
                    ).status_code,
                    200,
                )
                missing = self.snapshot("PASS", 1, uid="other-issue", provider=provider)
                reconcile_scan_triage(self.tenant.id, missing.scan_id)
                triage = FindingTriage.objects.get(
                    provider=provider, finding_uid=finding.uid
                )
                with patch("api.triage_removal.list_gcp_firewalls") as cloud:
                    response = self.confirm_removal(triage)
                self.assertEqual(response.status_code, 200, response.content)
                cloud.assert_not_called()
                triage.refresh_from_db()
                self.assertEqual(triage.status, "resolved")
                self.assertEqual(triage.observation, "removal_confirmed")
                self.assertEqual(triage.last_result, "FAIL")
                finding.refresh_from_db()
                self.assertEqual(finding.status, "FAIL")
                event = triage.events.get(kind="verification")
                self.assertEqual(event.actor_id, self.user.id)
                self.assertEqual(
                    event.changes["verification"]["method"], "reviewer_confirmation"
                )
                self.assertIn("CHG-123", event.changes["verification"]["evidence"])
                self.assertEqual(triage.note.body, "Working")
                returned = self.snapshot("FAIL", 2, uid=finding.uid, provider=provider)
                reconcile_scan_triage(self.tenant.id, returned.scan_id)
                triage.refresh_from_db()
                self.assertEqual(triage.status, "reopened")

    def test_removal_confirmation_requires_permissions_evidence_and_consent(self):
        self.configure_gcp_firewall()
        missing = self.snapshot("PASS", 1, uid="different-finding")
        reconcile_scan_triage(self.tenant.id, missing.scan_id)
        self.assertEqual(self.confirm_removal().status_code, 403)
        self.role.manage_triage_exceptions = True
        self.role.save()
        for changes in (
            {"confirm_removed": False},
            {"evidence": " "},
            {"evidence": "x" * 501},
            {"status": "resolved"},
        ):
            self.assertEqual(self.confirm_removal(**changes).status_code, 400)
        self.assertEqual(self.record().status, "remediating")
        self.assertFalse(self.record().events.filter(kind="verification").exists())
        self.role.unlimited_visibility = False
        self.role.save()
        self.assertEqual(self.confirm_removal().status_code, 404)

    def test_removal_confirmation_rejects_observed_scoped_and_stale_findings(self):
        self.configure_gcp_firewall()
        self.role.manage_triage_exceptions = True
        self.role.save()
        self.assertEqual(self.confirm_removal().status_code, 400)
        missing = self.snapshot("PASS", 1, uid="different-finding")
        missing.scan.scanner_args = {"checks": ["unrelated"]}
        missing.scan.save()
        reconcile_scan_triage(self.tenant.id, missing.scan_id)
        self.assertEqual(self.confirm_removal().status_code, 400)
        missing.scan.scanner_args = {}
        missing.scan.save()
        self.assertEqual(self.confirm_removal(previous_status="open").status_code, 409)
        self.assertEqual(self.confirm_removal(finding_id=str(uuid4())).status_code, 409)
        self.assertEqual(
            self.confirm_removal(observation_scan_id=str(uuid4())).status_code, 409
        )
        self.assertEqual(self.confirm_removal().status_code, 200)
        self.assertEqual(self.confirm_removal().status_code, 409)
        self.assertEqual(self.record().events.filter(kind="verification").count(), 1)


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


class GcpRemovalInventoryTests(UnitTestCase):
    def inventory(self, pages, secret=None):
        from types import SimpleNamespace

        from api.triage_removal import list_gcp_firewalls

        provider = SimpleNamespace(
            uid="test-project",
            id="provider",
            tenant_id="tenant",
            secret=SimpleNamespace(
                secret=secret
                if secret is not None
                else {"service_account_key": {"type": "service_account"}}
            ),
        )
        client = MagicMock()
        client.firewalls.return_value.list.return_value.execute.side_effect = pages
        with (
            patch(
                "api.triage_removal.google.auth.load_credentials_from_dict",
                return_value=(MagicMock(), None),
            ),
            patch("api.triage_removal.AuthorizedHttp"),
            patch("api.triage_removal.build", return_value=client),
        ):
            result = list_gcp_firewalls(provider)
        client.close.assert_called_once()
        return result, client

    def test_reads_every_page_and_accepts_authoritative_empty_inventory(self):
        result, client = self.inventory(
            [
                {
                    "kind": "compute#firewallList",
                    "items": [{"name": "rule-one", "id": "123"}],
                    "nextPageToken": "page2",
                },
                {
                    "kind": "compute#firewallList",
                    "items": [{"name": "rule-two", "id": "456"}],
                },
            ]
        )
        self.assertEqual(result, {"rule-one": "123", "rule-two": "456"})
        self.assertEqual(
            client.firewalls.return_value.list.call_args_list[1].kwargs["pageToken"],
            "page2",
        )
        self.assertEqual(
            client.firewalls.return_value.list.call_args_list[0].kwargs["project"],
            "test-project",
        )
        result, _ = self.inventory([{"kind": "compute#firewallList"}])
        self.assertEqual(result, {})

    def test_does_not_accept_partial_error_or_malformed_inventory(self):
        from api.triage_removal import VerificationError
        from googleapiclient.errors import HttpError
        from httplib2 import Response

        for pages in [
            [{}],
            [{"kind": "compute#firewallList", "warning": "invalid-warning"}],
            [
                {
                    "kind": "compute#firewallList",
                    "error": {"message": "Partial response"},
                }
            ],
            [{"kind": "compute#firewallList", "items": [{"name": "rule-one"}]}],
            [{"kind": "compute#firewallList", "warning": {"code": "UNREACHABLE"}}],
            [
                {"kind": "compute#firewallList", "nextPageToken": "same"},
                {"kind": "compute#firewallList", "nextPageToken": "same"},
            ],
            [
                {"kind": "compute#firewallList", "nextPageToken": "page2"},
                HttpError(Response({"status": "403"}), b"Forbidden"),
            ],
            [TimeoutError("Timed out")],
            [HttpError(Response({"status": "404"}), b"Project not found")],
        ]:
            with self.subTest(pages=pages), self.assertRaises(VerificationError):
                self.inventory(pages)

    def test_never_falls_back_to_host_credentials(self):
        from api.triage_removal import VerificationError

        with (
            patch("google.auth.default") as default,
            self.assertRaises(VerificationError),
        ):
            self.inventory([], secret={})
        default.assert_not_called()
