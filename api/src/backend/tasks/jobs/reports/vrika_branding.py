"""Vrika white-label branding for PDF reports."""

from __future__ import annotations

import os
from dataclasses import dataclass

from reportlab.lib import colors

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


def get_branded_display_name(display_name: str) -> str:
    if not is_vrika_branding_enabled():
        return display_name
    return DISPLAY_NAME_OVERRIDES.get(display_name, display_name)


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
