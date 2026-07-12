import os

import pytest
from tasks.jobs.reports import vrika_branding


@pytest.mark.parametrize("value", ["true", "1", "yes"])
def test_vrika_branding_enabled(value, monkeypatch):
    monkeypatch.setenv("VRIKA_PDF_BRANDING", value)
    assert vrika_branding.is_vrika_branding_enabled() is True


def test_vrika_branding_disabled(monkeypatch):
    monkeypatch.delenv("VRIKA_PDF_BRANDING", raising=False)
    assert vrika_branding.is_vrika_branding_enabled() is False


def test_branded_display_name_when_enabled(monkeypatch):
    monkeypatch.setenv("VRIKA_PDF_BRANDING", "true")
    assert (
        vrika_branding.get_branded_display_name("Prowler ThreatScore")
        == "Vrika ThreatScore"
    )


def test_primary_logo_prefers_vrika_asset(monkeypatch):
    monkeypatch.setenv("VRIKA_PDF_BRANDING", "true")
    path = vrika_branding.get_primary_logo_path()
    assert path.endswith("vrika_logo.png")
    assert os.path.exists(path)
