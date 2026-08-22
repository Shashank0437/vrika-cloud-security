"""Vrika white-label branding for PDF reports."""

from __future__ import annotations

import base64
import binascii
import io
import logging
import os
from dataclasses import dataclass

from reportlab.lib import colors

logger = logging.getLogger(__name__)

_ASSETS_DIR = os.path.join(os.path.dirname(__file__), "../../assets/img")

COLOR_VRIKA_PURPLE = colors.HexColor("#684CB6")
COLOR_VRIKA_PURPLE_LIGHT = colors.HexColor("#8B7EC8")
COLOR_VRIKA_PURPLE_PALE = colors.HexColor("#F3F0FA")
COLOR_VRIKA_ORANGE = colors.HexColor("#F59E0B")
COLOR_VRIKA_PINK = colors.HexColor("#EC4899")
COLOR_VRIKA_BLUE = colors.HexColor("#3B82F6")

# ThreatScore section bar colors (match Compliance UI)
THREATSCORE_SECTION_CHART_COLORS: dict[str, str] = {
    "1. IAM": "#684CB6",
    "2. Attack Surface": "#F59E0B",
    "3. Logging and Monitoring": "#EC4899",
    "4. Encryption": "#3B82F6",
}

VRIKA_CHART_COLOR_HIGH = "#684CB6"
VRIKA_CHART_COLOR_MED_HIGH = "#8B7EC8"
VRIKA_CHART_COLOR_MED = "#C4B5FD"
VRIKA_CHART_COLOR_LOW = "#F59E0B"
VRIKA_CHART_COLOR_CRITICAL = "#EF4444"

DISPLAY_NAME_OVERRIDES: dict[str, str] = {
    "Prowler ThreatScore": "Vrika ThreatScore",
}

# Longer phrases first so nested "Prowler"/"prowler" tokens rewrite cleanly.
_REPORT_TEXT_REPLACEMENTS: tuple[tuple[str, str], ...] = (
    (
        "Prowler ThreatScore Compliance Framework",
        "Vrika ThreatScore Compliance Framework",
    ),
    ("Prowler ThreatScore", "Vrika ThreatScore"),
    ("ProwlerThreatScore", "VrikaThreatScore"),
    ("prowler_threatscore", "vrika_threatscore"),
)


@dataclass(frozen=True)
class PdfTheme:
    title_color: colors.Color
    h1_color: colors.Color
    h1_border_color: colors.Color
    h1_bg_color: colors.Color
    h2_color: colors.Color
    h2_border_color: colors.Color
    h2_bg_color: colors.Color
    h3_color: colors.Color
    info_label_color: colors.Color
    info_value_bg_color: colors.Color
    summary_header_color: colors.Color
    footer_right: str
    pdf_author: str
    pdf_creator: str
    pdf_keywords_suffix: str


def is_vrika_branding_enabled() -> bool:
    return os.environ.get("VRIKA_PDF_BRANDING", "").lower() in ("1", "true", "yes")


def get_assets_dir() -> str:
    return _ASSETS_DIR


def get_primary_logo_path() -> str:
    if is_vrika_branding_enabled():
        vrika_logo = os.path.join(_ASSETS_DIR, "vrika_logo.png")
        if os.path.exists(vrika_logo):
            return vrika_logo
    return os.path.join(_ASSETS_DIR, "prowler_logo.png")


def get_tenant_logo(tenant_id: str | None) -> tuple[bytes, str] | None:
    """Return ``(image_bytes, content_type)`` for a tenant's custom report logo.

    Reads the per-tenant ``TenantBranding`` row under RLS. Returns ``None`` when
    no tenant is given, no custom logo is set, or the stored data is unreadable
    so callers can fall back to the default product logo.
    """
    if not tenant_id:
        return None

    # Import lazily to avoid import cycles (models import this module's siblings).
    try:
        from api.db_utils import rls_transaction
        from api.models import TenantBranding
    except Exception:  # pragma: no cover - defensive, keeps report generation alive
        logger.exception("Unable to import branding dependencies")
        return None

    try:
        with rls_transaction(str(tenant_id)):
            branding = TenantBranding.objects.filter(tenant_id=tenant_id).first()
    except Exception:
        logger.exception("Failed to load tenant branding for %s", tenant_id)
        return None

    if branding is None or not branding.logo_base64:
        return None

    try:
        image_bytes = base64.b64decode(branding.logo_base64, validate=True)
    except (ValueError, binascii.Error):
        logger.warning("Stored tenant logo for %s is not valid base64", tenant_id)
        return None

    if not image_bytes:
        return None

    content_type = branding.logo_content_type or "image/png"
    return image_bytes, content_type


def resolve_report_logo(tenant_id: str | None):
    """Return a ReportLab-compatible logo source for a tenant.

    Resolution order:
      1. The org's custom logo from vrika-server's central config (internal API).
      2. A locally-stored ``TenantBranding`` logo (fallback if the internal API
         is unavailable or has no logo).
      3. The default product logo path.

    ReportLab's ``Image`` flowable accepts a filesystem path or a file-like
    object, so this returns either a ``BytesIO`` (custom logo) or a path.
    """
    # 1. Central config (single source of truth in vrika-server).
    try:
        from .vrika_config_client import get_tenant_logo_from_config

        config_logo = get_tenant_logo_from_config(tenant_id)
    except Exception:  # pragma: no cover - never let config lookup break reports
        logger.exception("Failed to fetch org logo from central config")
        config_logo = None
    if config_logo is not None:
        image_bytes, _content_type = config_logo
        return io.BytesIO(image_bytes)

    # 2. Local TenantBranding fallback.
    tenant_logo = get_tenant_logo(tenant_id)
    if tenant_logo is not None:
        image_bytes, _content_type = tenant_logo
        return io.BytesIO(image_bytes)

    # 3. Default product logo.
    return get_primary_logo_path()


def brand_report_text(text: str | None) -> str:
    """Rewrite Prowler ThreatScore strings to Vrika in user-facing PDF fields."""
    if text is None:
        return ""
    if not is_vrika_branding_enabled():
        return text
    branded = text
    for old, new in _REPORT_TEXT_REPLACEMENTS:
        branded = branded.replace(old, new)
    return branded


def get_branded_display_name(display_name: str) -> str:
    if not is_vrika_branding_enabled():
        return display_name
    return brand_report_text(DISPLAY_NAME_OVERRIDES.get(display_name, display_name))


def get_footer_right_text() -> str:
    return "VRIKA" if is_vrika_branding_enabled() else "Powered by Prowler"


def get_pdf_theme() -> PdfTheme:
    from .config import (
        COLOR_BG_BLUE,
        COLOR_BG_LIGHT_BLUE,
        COLOR_BLUE,
        COLOR_BORDER_GRAY,
        COLOR_HEADER_DARK,
        COLOR_LIGHT_BLUE,
        COLOR_LIGHTER_BLUE,
        COLOR_PROWLER_DARK_GREEN,
    )

    if not is_vrika_branding_enabled():
        return PdfTheme(
            title_color=COLOR_PROWLER_DARK_GREEN,
            h1_color=COLOR_BLUE,
            h1_border_color=COLOR_BLUE,
            h1_bg_color=COLOR_BG_BLUE,
            h2_color=COLOR_LIGHT_BLUE,
            h2_border_color=COLOR_BORDER_GRAY,
            h2_bg_color=COLOR_BG_LIGHT_BLUE,
            h3_color=COLOR_LIGHTER_BLUE,
            info_label_color=COLOR_BLUE,
            info_value_bg_color=COLOR_BG_BLUE,
            summary_header_color=COLOR_HEADER_DARK,
            footer_right="Powered by Prowler",
            pdf_author="Prowler",
            pdf_creator="Prowler Engineering Team",
            pdf_keywords_suffix="prowler",
        )

    return PdfTheme(
        title_color=COLOR_VRIKA_PURPLE,
        h1_color=COLOR_VRIKA_PURPLE,
        h1_border_color=COLOR_VRIKA_PURPLE,
        h1_bg_color=COLOR_VRIKA_PURPLE_PALE,
        h2_color=COLOR_VRIKA_PURPLE_LIGHT,
        h2_border_color=COLOR_VRIKA_PURPLE_LIGHT,
        h2_bg_color=COLOR_VRIKA_PURPLE_PALE,
        h3_color=COLOR_VRIKA_PURPLE,
        info_label_color=COLOR_VRIKA_PURPLE,
        info_value_bg_color=COLOR_VRIKA_PURPLE_PALE,
        summary_header_color=COLOR_VRIKA_PURPLE,
        footer_right="VRIKA",
        pdf_author="VRIKA",
        pdf_creator="VRIKA Cloud Security",
        pdf_keywords_suffix="vrika",
    )
