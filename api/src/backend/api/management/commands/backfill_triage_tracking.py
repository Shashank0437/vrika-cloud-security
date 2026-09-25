from uuid import UUID

from api.db_utils import rls_transaction
from api.triage import reconcile_scan_triage
from api.triage_tracking import latest_completed_scan, tracked_triages
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Retain existing tracked findings before scan retention cleanup. Does not change scan results."

    def add_arguments(self, parser):
        parser.add_argument("--tenant-id", required=True, type=UUID)
        parser.add_argument(
            "--verify-removed",
            action="store_true",
            help="Queue read-only cloud verification after retaining context.",
        )

    def handle(self, *args, **options):
        if not settings.VRIKA_TRIAGE_ENABLED:
            raise CommandError("VRIKA_TRIAGE_ENABLED must be enabled.")
        tenant_id = options["tenant_id"]
        with rls_transaction(tenant_id):
            providers = list(
                tracked_triages()
                .filter(tenant_id=tenant_id, provider__is_deleted=False)
                .values_list("provider_id", flat=True)
                .distinct()
            )
        for provider_id in providers:
            with rls_transaction(tenant_id):
                scan = latest_completed_scan(tenant_id, provider_id)
            if scan is None:
                self.stderr.write(
                    f"Provider {provider_id}: no completed scan to backfill."
                )
                continue
            reconcile_scan_triage(tenant_id, scan.id)
            if options["verify_removed"]:
                from tasks.tasks import verify_missing_triage_resources_task

                verify_missing_triage_resources_task.delay(
                    tenant_id=str(tenant_id), scan_id=str(scan.id)
                )
            self.stdout.write(f"Retained tracked context for provider {provider_id}.")
