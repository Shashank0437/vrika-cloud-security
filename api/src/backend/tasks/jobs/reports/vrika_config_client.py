"""Fetch per-organization config from vrika-server's internal API (cached).

Cloud Security is a *consumer* of the central config that lives in vrika-server
(Option 2: owner + internal API). This client fetches an org's config for a
given Prowler tenant and caches it in the shared cache (valkey) so PDF/report
generation does not hit the network on every run.

All failures degrade gracefully to ``None`` so callers fall back to defaults.
"""

from __future__ import annotations

import base64
import binascii
import logging
import os

from django.core.cache import cache

logger = logging.getLogger(__name__)

_CACHE_PREFIX = "vrika-org-config:"
_CACHE_TTL_SECONDS = int(os.environ.get("VRIKA_CONFIG_CACHE_TTL", "300"))
_HTTP_TIMEOUT = float(os.environ.get("VRIKA_CONFIG_HTTP_TIMEOUT", "5"))

# Base URL of vrika-server's internal API, reachable over the shared Docker
# network (e.g. http://vrika-server-api:8000). Empty disables the feature.
_INTERNAL_BASE = os.environ.get("VRIKA_SERVER_INTERNAL_URL", "").strip().rstrip("/")
# Shared server-to-server secret (same value as vrika-server PROWLER_BRIDGE_SECRET).
_INTERNAL_SECRET = (
    os.environ.get("VRIKA_INTERNAL_CONFIG_SECRET")
    or os.environ.get("VRIKA_BRIDGE_SECRET")
    or os.environ.get("PROWLER_BRIDGE_SECRET")
    or ""
).strip()


def _cache_key(tenant_id: str) -> str:
    return f"{_CACHE_PREFIX}{tenant_id}"


def get_org_config(tenant_id: str | None) -> dict | None:
    """Return the org config dict for a tenant, or ``None`` when unavailable.

    Cached in valkey for ``_CACHE_TTL_SECONDS``. A cached empty dict ``{}`` is a
    valid "no custom config" answer and avoids repeated lookups.
    """
    if not tenant_id or not _INTERNAL_BASE or not _INTERNAL_SECRET:
        return None

    key = _cache_key(str(tenant_id))
    cached = cache.get(key)
    if cached is not None:
        return cached or None

    try:
        import requests  # local import: keep module import light

        resp = requests.get(
            f"{_INTERNAL_BASE}/internal/org-config",
            params={"prowler_tenant_id": str(tenant_id)},
            headers={"X-Vrika-Internal-Secret": _INTERNAL_SECRET},
            timeout=_HTTP_TIMEOUT,
        )
    except Exception:
        logger.warning("vrika-server internal config unreachable", exc_info=True)
        return None

    if resp.status_code != 200:
        logger.warning(
            "vrika-server internal config returned HTTP %s", resp.status_code
        )
        return None

    try:
        data = resp.json()
    except ValueError:
        logger.warning("vrika-server internal config returned non-JSON")
        return None

    if not isinstance(data, dict):
        data = {}
    # Cache even an empty result to avoid hammering the API for orgs with no config.
    cache.set(key, data, timeout=_CACHE_TTL_SECONDS)
    return data or None


def get_tenant_logo_from_config(tenant_id: str | None) -> tuple[bytes, str] | None:
    """Extract ``(image_bytes, content_type)`` from the org's branding config."""
    config = get_org_config(tenant_id)
    if not config:
        return None
    branding = config.get("branding")
    if not isinstance(branding, dict):
        return None
    logo_b64 = branding.get("logo_base64") or ""
    if not logo_b64:
        return None
    try:
        image_bytes = base64.b64decode(logo_b64, validate=True)
    except (ValueError, binascii.Error):
        logger.warning("Org branding logo for %s is not valid base64", tenant_id)
        return None
    if not image_bytes:
        return None
    content_type = branding.get("logo_content_type") or "image/png"
    return image_bytes, content_type
