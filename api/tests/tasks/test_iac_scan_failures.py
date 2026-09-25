"""IaC import failures must never become successful scans or terminate a worker."""

import json
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from api.iac_provider import ApiIacProvider
from api.models import StateChoices
from api.utils import return_prowler_provider
from prowler.providers.iac.iac_provider import IacProvider
from tasks.jobs import scan as scan_jobs


def finding(severity="HIGH"):
    return {
        "ID": "AVD-AWS-0001",
        "Title": "Test configuration",
        "Description": "Synthetic finding",
        "Status": "FAIL",
        "Severity": severity,
    }


@pytest.fixture
def provider():
    # No repository access, subprocesses, or credentials in these tests.
    obj = ApiIacProvider.__new__(ApiIacProvider)
    obj.region = "main"
    obj._temp_clone_dir = None
    obj.scan_path = "."
    obj.scanners = ["misconfig"]
    obj.exclude_path = []
    return obj


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("CRITICAL", "critical"),
        ("HIGH", "high"),
        (" medium ", "medium"),
        ("LOW", "low"),
        ("INFO", "informational"),
        ("INFORMATIONAL", "informational"),
    ],
)
def test_normalizes_severity_without_changing_raw_evidence(provider, raw, expected):
    source = finding(raw)
    with patch.object(IacProvider, "run_scan", return_value=iter([])):
        list(provider.run_scan(".", [], []))
    report = provider._process_finding(source, "main.tf", "terraform")
    assert report.check_metadata.Severity.value == expected
    assert report.resource["Severity"] == raw
    assert source["Severity"] == raw
    provider.raise_for_import_errors()


@pytest.mark.parametrize("severity", ["UNKNOWN", "", None, 12])
def test_unsupported_severity_retains_valid_results_but_fails_scan(provider, severity):
    def output(self, *args):
        yield [
            self._process_finding(finding(severity), "bad.tf", "terraform"),
            self._process_finding(finding(), "good.tf", "terraform"),
        ]

    with patch.object(IacProvider, "run_scan", output):
        reports = provider.run()
    assert len(reports) == 1
    assert reports[0].resource_name == "good.tf"
    with pytest.raises(ValueError, match="unsupported severity") as error:
        provider.raise_for_import_errors()
    assert repr(severity) in str(error.value)
    assert "AVD-AWS-0001" in str(error.value)


def test_sdk_exit_becomes_normal_failure(provider):
    with patch.object(IacProvider, "run_scan", side_effect=SystemExit(1)):
        with pytest.raises(RuntimeError, match="exited"):
            provider.run()
    # The SDK scan wrapper can swallow ordinary exceptions; failure remains detectable.
    with pytest.raises(ValueError, match="exited"):
        provider.raise_for_import_errors()


def test_real_trivy_parser_preserves_partial_findings(provider):
    output = {
        "Results": [
            {
                "Target": "main.tf",
                "Type": "terraform",
                "Misconfigurations": [finding("UNKNOWN"), finding("INFO")],
            }
        ]
    }
    with patch(
        "prowler.providers.iac.iac_provider.subprocess.run",
        return_value=SimpleNamespace(
            stdout=json.dumps(output), stderr="", returncode=0
        ),
    ):
        reports = provider.run()
    assert len(reports) == 1
    assert reports[0].check_metadata.Severity.value == "informational"
    assert reports[0].resource["Severity"] == "INFO"
    with pytest.raises(ValueError, match="UNKNOWN"):
        provider.raise_for_import_errors()


def test_unexpected_provider_error_is_not_swallowed(provider):
    with patch.object(IacProvider, "run_scan", side_effect=ValueError("bad output")):
        with pytest.raises(ValueError, match="bad output"):
            provider.run()
    with pytest.raises(ValueError, match="bad output"):
        provider.raise_for_import_errors()


def test_api_selects_adapter():
    assert return_prowler_provider(SimpleNamespace(provider="iac")) is ApiIacProvider


@pytest.mark.parametrize(
    "phase", ["initialization", "iteration", "partial_import", "success", "aws_success"]
)
def test_failed_scan_persists_failed_state_not_100_percent(phase):
    instance = SimpleNamespace(
        state=StateChoices.AVAILABLE,
        progress=0,
        scanner_args={},
    )
    cloud = SimpleNamespace(
        provider="aws" if phase == "aws_success" else "iac", save=MagicMock()
    )
    sdk = MagicMock()
    saved = []
    with (
        patch.object(
            scan_jobs, "rls_transaction", side_effect=lambda *a, **k: nullcontext()
        ),
        patch.object(scan_jobs.Provider, "objects") as providers,
        patch.object(scan_jobs.Scan, "objects") as scans,
        patch.object(scan_jobs.Processor, "objects") as processors,
        patch.object(scan_jobs.MuteRule, "objects") as rules,
        patch.object(
            scan_jobs, "initialize_prowler_provider", return_value=sdk
        ) as init,
        patch.object(scan_jobs, "ProwlerScan") as runner,
        patch.object(scan_jobs, "_process_finding_micro_batch") as process,
        patch.object(
            scan_jobs,
            "_save_scan_instance",
            side_effect=lambda s, *a: saved.append((s.state, s.progress)),
        ),
        patch.object(scan_jobs, "ResourceScanSummary") as summaries,
        patch.object(scan_jobs, "ScanTaskSerializer"),
        patch(
            "django.db.backends.base.base.BaseDatabaseWrapper.ensure_connection",
            side_effect=AssertionError("Tests must not access a database"),
        ),
    ):
        providers.get.return_value = cloud
        scans.get.return_value = instance
        processors.get.side_effect = scan_jobs.Processor.DoesNotExist
        rules.filter.return_value.values_list.return_value = []
        if phase == "initialization":
            init.side_effect = SystemExit(1)
        elif phase == "iteration":
            runner.return_value.scan.side_effect = SystemExit(1)
        elif phase == "partial_import":
            runner.return_value.scan.return_value = [(100, [object()])]
            sdk.raise_for_import_errors.side_effect = ValueError(
                "unsupported severity UNKNOWN"
            )
        else:
            runner.return_value.scan.return_value = [(100, [])]
            scan_jobs.perform_prowler_scan("tenant", "scan", "provider")
            assert instance.state == StateChoices.COMPLETED
            assert saved[-1] == (StateChoices.COMPLETED, 100)
            assert all(progress < 100 for _, progress in saved[:-1])
            if phase == "aws_success":
                sdk.raise_for_import_errors.assert_not_called()
            return
        with pytest.raises((RuntimeError, ValueError)):
            scan_jobs.perform_prowler_scan("tenant", "scan", "provider")
        assert instance.state == StateChoices.FAILED
        assert instance.progress < 100
        assert instance.completed_at is not None
        assert saved[-1][0] == StateChoices.FAILED
        assert all(progress < 100 for _, progress in saved)
        summaries.objects.bulk_create.assert_not_called()
        if phase == "partial_import":
            process.assert_called_once()
