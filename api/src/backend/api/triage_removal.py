"""Read-only, fail-closed verification of missing GCP firewall resources."""

import logging
import re

import google.auth
import httplib2
from api.db_utils import rls_transaction
from api.models import FindingTriage, Provider, Scan, StateChoices
from api.triage import resolve_removed_resource
from api.triage_tracking import latest_completed_scan, tracked_triages
from django.conf import settings
from django.utils import timezone
from google.auth.exceptions import GoogleAuthError
from google_auth_httplib2 import AuthorizedHttp
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

logger = logging.getLogger(__name__)
FIREWALL_CHECKS = frozenset(
    {
        "compute_firewall_rdp_access_from_the_internet_allowed",
        "compute_firewall_ssh_access_from_the_internet_allowed",
    }
)


class VerificationError(Exception):
    """A safe explanation; never contains credentials or raw cloud responses."""


def list_gcp_firewalls(provider):
    """Only a complete, successful inventory is evidence of resource absence."""
    try:
        secret = provider.secret.secret
        if secret.get("service_account_key"):
            info = secret["service_account_key"]
        elif all(
            secret.get(key) for key in ("client_id", "client_secret", "refresh_token")
        ):
            info = {
                "type": "authorized_user",
                **{
                    key: secret[key]
                    for key in ("client_id", "client_secret", "refresh_token")
                },
            }
        else:
            raise VerificationError(
                "Connected GCP credentials are unavailable. Deletion was not verified."
            )
        credentials, _ = google.auth.load_credentials_from_dict(
            info, scopes=["https://www.googleapis.com/auth/compute.readonly"]
        )
        http = AuthorizedHttp(credentials, http=httplib2.Http(timeout=20))
        client = build("compute", "v1", http=http, cache_discovery=False)
        try:
            resource = client.firewalls()
            token = None
            tokens = set()
            inventory = {}
            while True:
                response = resource.list(
                    project=provider.uid, maxResults=500, pageToken=token
                ).execute(num_retries=1)
                if (
                    not isinstance(response, dict)
                    or response.get("kind") != "compute#firewallList"
                    or not isinstance(response.get("items", []), list)
                    or response.get("error")
                    or response.get("unreachables")
                    or (
                        response.get("warning") is not None
                        and (
                            not isinstance(response["warning"], dict)
                            or response["warning"].get("code") != "NO_RESULTS_ON_PAGE"
                        )
                    )
                ):
                    raise VerificationError(
                        "Cloud inventory response was incomplete. Deletion was not verified."
                    )
                for item in response.get("items", []):
                    if (
                        not isinstance(item, dict)
                        or not isinstance(item.get("name"), str)
                        or not re.fullmatch(
                            r"[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?", item["name"]
                        )
                        or not str(item.get("id", "")).isdigit()
                        or item["name"] in inventory
                    ):
                        raise VerificationError(
                            "Cloud inventory identity was incomplete. Deletion was not verified."
                        )
                    inventory[item["name"]] = str(item["id"])
                token = response.get("nextPageToken")
                if token is None or token == "":
                    return inventory
                if not isinstance(token, str) or token in tokens or len(tokens) >= 1000:
                    raise VerificationError(
                        "Cloud inventory pagination was incomplete. Deletion was not verified."
                    )
                tokens.add(token)
        finally:
            client.close()
    except Provider.secret.RelatedObjectDoesNotExist:
        raise VerificationError(
            "Connected GCP credentials are unavailable. Deletion was not verified."
        ) from None
    except (
        GoogleAuthError,
        HttpError,
        httplib2.HttpLib2Error,
        OSError,
        ValueError,
    ) as error:
        logger.warning(
            "GCP triage inventory verification failed tenant=%s provider=%s error_type=%s",
            provider.tenant_id,
            provider.id,
            type(error).__name__,
        )
        raise VerificationError(
            "Could not read complete GCP firewall inventory. Check provider access and connectivity; deletion was not verified."
        ) from None


def _supported_snapshot(provider, snapshot):
    resources = snapshot.get("resources", [])
    return (
        provider.provider == "gcp"
        and snapshot.get("provider_uid") == provider.uid
        and snapshot.get("check_id") in FIREWALL_CHECKS
        and len(resources) == 1
        and resources[0].get("service") == "compute"
        and str(resources[0].get("uid", "")).isdigit()
        and isinstance(resources[0].get("name"), str)
        and re.fullmatch(r"[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?", resources[0]["name"])
    )


def verify_missing_resources(tenant_id, scan_id):
    if not settings.VRIKA_TRIAGE_ENABLED:
        return {"enabled": False}
    with rls_transaction(tenant_id):
        scan = Scan.objects.get(tenant_id=tenant_id, id=scan_id)
        latest = latest_completed_scan(tenant_id, scan.provider_id)
        if (
            scan.state != StateChoices.COMPLETED
            or latest is None
            or latest.id != scan.id
        ):
            return {"skipped": "Scan is not the latest completed scan."}
        provider = Provider.objects.select_related("secret").get(
            tenant_id=tenant_id, id=scan.provider_id
        )
        candidates = list(
            tracked_triages()
            .filter(
                tenant_id=tenant_id,
                provider_id=provider.id,
                observation_scan_id=scan.id,
                observation__in=["not_seen", "verification_failed"],
            )
            .exclude(status="resolved")
            .values("id", "snapshot")
        )
    if not candidates:
        return {"verified": 0}
    full_scan = scan.trigger in Scan.LIVE_SCAN_TRIGGERS and not any(
        (scan.scanner_args or {}).values()
    )
    supported = [
        row for row in candidates if _supported_snapshot(provider, row["snapshot"])
    ]
    inventory, failure = None, None
    if full_scan and supported:
        try:
            inventory = list_gcp_firewalls(provider)
        except VerificationError as error:
            failure = str(error)
            logger.warning(
                "Triage deletion not verified tenant=%s provider=%s scan=%s: %s",
                tenant_id,
                provider.id,
                scan.id,
                failure,
            )
    checked_at = timezone.now()
    verified = 0
    with rls_transaction(tenant_id):
        current_provider = (
            Provider.objects.select_for_update()
            .filter(tenant_id=tenant_id, id=provider.id, is_deleted=False)
            .first()
        )
        if current_provider is None or (
            current_provider.uid != provider.uid
            or current_provider.provider != provider.provider
        ):
            return {"skipped": "Provider identity changed during verification."}
        latest = latest_completed_scan(tenant_id, provider.id)
        if (
            latest is None
            or latest.id != scan.id
            or latest.scanner_args != scan.scanner_args
            or latest.trigger != scan.trigger
        ):
            return {"skipped": "A newer completed scan superseded verification."}
        for candidate in candidates:
            row = FindingTriage.objects.get(tenant_id=tenant_id, id=candidate["id"])
            if (
                row.snapshot != candidate["snapshot"]
                or row.observation_scan_id != scan.id
                or row.status == "resolved"
                or row.observation not in {"not_seen", "verification_failed"}
            ):
                continue
            row.observation = "not_seen"
            row.verification_checked_at = None
            if not full_scan:
                row.observation_detail = "Not seen in latest scan. Scoped or imported scans do not trigger deletion verification."
            elif not _supported_snapshot(provider, row.snapshot):
                row.observation_detail = "Not seen in latest scan. Automatic deletion verification is not available for this resource identity."
            elif failure is not None:
                row.observation = "verification_failed"
                row.observation_detail = failure
                row.verification_checked_at = checked_at
            else:
                resource = row.snapshot["resources"][0]
                row.verification_checked_at = checked_at
                if (
                    resource["name"] in inventory
                    or str(resource["uid"]) in inventory.values()
                ):
                    row.observation_detail = "Not seen in latest scan, but the firewall identity or name is present in GCP. Review the scan scope and any replacement rule."
                else:
                    resolve_removed_resource(
                        row,
                        scan,
                        checked_at=checked_at,
                        detail="Resource removed: confirmed by a complete, successful GCP firewall inventory read.",
                        verification={
                            "method": "gcp_compute_firewalls_list",
                            "project": provider.uid,
                            "resource_uid": resource["uid"],
                            "resource_name": resource["name"],
                        },
                    )
                    verified += 1
                    continue
            row.save(
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
    return {"verified": verified}
