"""Report/email ordering tests; all database, broker and mail access is mocked."""

import base64
import inspect
import json
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from celery.canvas import _chain
from tasks import tasks
from tasks.jobs import report

TENANT = "11111111-1111-4111-8111-111111111111"
SCAN = "22222222-2222-4222-8222-222222222222"
PROVIDER = "33333333-3333-4333-8333-333333333333"
PDF = b"%PDF-1.4\nreport content\n%%EOF\n"


@pytest.fixture(autouse=True)
def no_database_access():
    with patch(
        "django.db.backends.base.base.BaseDatabaseWrapper.ensure_connection",
        side_effect=AssertionError("These tests must not access a database"),
    ):
        yield


@pytest.fixture
def database():
    with (
        patch.object(
            tasks, "rls_transaction", side_effect=lambda *a, **kw: nullcontext()
        ),
        patch.object(
            report, "rls_transaction", side_effect=lambda *a, **kw: nullcontext()
        ),
        patch.object(tasks.Scan, "objects") as scans,
        patch.object(tasks.Provider, "objects") as providers,
    ):
        scans.filter.return_value.exists.return_value = True
        scans.get.return_value.provider_id = PROVIDER
        providers.get.return_value.uid = "project-test"
        providers.get.return_value.provider = "gcp"
        yield scans, providers


def _branches(canvas):
    yield canvas
    for child in getattr(canvas, "tasks", ()):
        yield from _branches(child)


def test_scheduled_email_is_chained_after_reports_not_dispatched_independently(
    database,
):
    with (
        patch.object(_chain, "apply_async", autospec=True) as dispatch,
        patch.object(tasks, "can_provider_run_attack_paths_scan", return_value=False),
        patch.object(tasks.share_vrika_scan_email_task, "apply_async") as standalone,
    ):
        tasks._perform_scan_complete_tasks(TENANT, SCAN, PROVIDER)

    standalone.assert_not_called()
    pipeline = dispatch.call_args_list[-1].args[0]
    assert pipeline.tasks[0].task == tasks.perform_scan_summary_task.name
    report_branch = next(
        item
        for item in _branches(pipeline)
        if isinstance(item, _chain)
        and item.tasks[0].task == tasks.generate_compliance_reports_task.name
    )
    assert report_branch.tasks[1].task == "scan-scheduled-report-email"
    assert not report_branch.tasks[1].immutable
    assert report_branch.tasks[1].kwargs == {
        "tenant_id": TENANT,
        "scan_id": SCAN,
        "provider_id": PROVIDER,
    }


@pytest.mark.parametrize("scheduled", [True, False])
def test_only_scheduled_scans_email_after_success(database, scheduled):
    scans, _ = database
    scans.filter.return_value.exists.return_value = scheduled
    with patch.object(report, "share_vrika_scan_email_job") as send:
        send.return_value = {"status": "accepted"}
        result = inspect.unwrap(tasks.send_scheduled_scan_report_task.run)(
            {"vrika_executive": {"upload": False, "path": "/reports"}},
            tenant_id=TENANT,
            scan_id=SCAN,
            provider_id=PROVIDER,
        )
    assert send.call_count == int(scheduled)
    assert result["status"] == ("accepted" if scheduled else "skipped")


@pytest.mark.parametrize(
    "results",
    [
        {},
        {"vrika_executive": {"upload": False, "path": ""}},
        {"vrika_executive": {"error": "render failed", "path": ""}},
        {
            "vrika_executive": {"path": "/reports"},
            "threatscore": {"error": "score failed", "path": ""},
        },
    ],
)
def test_failed_or_missing_report_results_block_scheduled_email(database, results):
    with patch.object(report, "share_vrika_scan_email_job") as send:
        with pytest.raises(RuntimeError, match="report"):
            inspect.unwrap(tasks.send_scheduled_scan_report_task.run)(
                results, tenant_id=TENANT, scan_id=SCAN, provider_id=PROVIDER
            )
    send.assert_not_called()


@pytest.fixture
def report_paths(tmp_path):
    prefix = str(tmp_path / "scan")
    with patch.object(report, "_vrika_report_path_prefix", return_value=prefix):
        yield (
            Path(f"{prefix}_executive_report.pdf"),
            Path(f"{prefix}_full_report.pdf"),
        )


@pytest.mark.parametrize("failed_variant", ["executive", "full"])
def test_pdf_generation_failure_prevents_email(database, report_paths, failed_variant):
    def executive(**kwargs):
        if failed_variant == "executive":
            raise RuntimeError("render failed")
        Path(kwargs["output_path"]).write_bytes(PDF)

    with (
        patch(
            "tasks.jobs.reports.vrika_scan.generate_vrika_executive_report",
            side_effect=executive,
        ),
        patch(
            "tasks.jobs.reports.vrika_scan.generate_vrika_full_report",
            side_effect=RuntimeError("render failed"),
        ),
        patch.object(report, "_notify_vrika_scan_completed") as send,
    ):
        with pytest.raises(RuntimeError, match="render failed"):
            report.share_vrika_scan_email_job(TENANT, SCAN, PROVIDER)
    send.assert_not_called()


@pytest.mark.parametrize("provider", ["aws", "azure", "gcp"])
def test_successful_generation_precedes_email(database, report_paths, provider):
    _, providers = database
    providers.get.return_value.provider = provider
    events = []

    def generate(**kwargs):
        path = Path(kwargs["output_path"])
        path.write_bytes(PDF)
        events.append(path.name)

    def notify(**kwargs):
        assert kwargs["provider_type"] == provider
        assert Path(kwargs["executive_pdf_path"]).read_bytes() == PDF
        assert Path(kwargs["full_pdf_path"]).read_bytes() == PDF
        events.append("email")

    with (
        patch(
            "tasks.jobs.reports.vrika_scan.generate_vrika_executive_report",
            side_effect=generate,
        ),
        patch(
            "tasks.jobs.reports.vrika_scan.generate_vrika_full_report",
            side_effect=generate,
        ),
        patch.object(report, "_notify_vrika_scan_completed", side_effect=notify),
    ):
        assert report.share_vrika_scan_email_job(TENANT, SCAN, PROVIDER) == {
            "status": "accepted"
        }
    assert events == ["scan_executive_report.pdf", "scan_full_report.pdf", "email"]


@pytest.mark.parametrize(
    "invalid_content", [None, b"", b"%PDF-1.4\nunfinished", b"not a PDF"]
)
@pytest.mark.parametrize("variant", ["executive", "full"])
def test_missing_or_incomplete_attachment_blocks_notification(
    report_paths, invalid_content, variant
):
    for path in report_paths:
        path.write_bytes(PDF)
    path = report_paths[0 if variant == "executive" else 1]
    if invalid_content is None:
        path.unlink()
    else:
        path.write_bytes(invalid_content)
    with patch("urllib.request.urlopen") as send:
        with pytest.raises((OSError, ValueError)):
            report._notify_vrika_scan_completed(
                TENANT,
                SCAN,
                PROVIDER,
                "gcp",
                "project-test",
                str(report_paths[0]),
                str(report_paths[1]),
            )
    send.assert_not_called()


@pytest.mark.parametrize("server_status", ["accepted", "skipped"])
def test_notification_requires_server_acceptance(database, report_paths, server_status):
    for path in report_paths:
        path.write_bytes(PDF)
    response = Mock()
    response.getcode.return_value = 202
    response.read.return_value = json.dumps({"status": server_status}).encode()
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    with (
        patch("api.models.ScanSummary.objects") as summaries,
        patch("urllib.request.urlopen", return_value=response) as send,
    ):
        summaries.filter.return_value.aggregate.return_value = {
            "passed": 1,
            "failed": 1,
            "total": 2,
        }
        summaries.filter.return_value.values.return_value.annotate.return_value = []
        if server_status == "accepted":
            report._notify_vrika_scan_completed(
                TENANT,
                SCAN,
                PROVIDER,
                "gcp",
                "project-test",
                str(report_paths[0]),
                str(report_paths[1]),
            )
            payload = json.loads(send.call_args.args[0].data)
            assert base64.b64decode(payload["executive_pdf_base64"]) == PDF
            assert base64.b64decode(payload["full_pdf_base64"]) == PDF
        else:
            with pytest.raises(RuntimeError, match="accept"):
                report._notify_vrika_scan_completed(
                    TENANT,
                    SCAN,
                    PROVIDER,
                    "gcp",
                    "project-test",
                    str(report_paths[0]),
                    str(report_paths[1]),
                )


def test_notification_error_is_not_reported_as_sent(database, report_paths):
    for path in report_paths:
        path.write_bytes(PDF)
    with patch.object(
        report, "_notify_vrika_scan_completed", side_effect=OSError("network down")
    ):
        with pytest.raises(OSError, match="network down"):
            report.share_vrika_scan_email_job(TENANT, SCAN, PROVIDER)


def test_existing_reports_are_reused(database, report_paths):
    for path in report_paths:
        path.write_bytes(PDF)
    with (
        patch(
            "tasks.jobs.reports.vrika_scan.generate_vrika_executive_report"
        ) as executive,
        patch("tasks.jobs.reports.vrika_scan.generate_vrika_full_report") as full,
        patch.object(report, "_notify_vrika_scan_completed") as notify,
    ):
        result = report.share_vrika_scan_email_job(TENANT, SCAN, PROVIDER)
    assert result == {"status": "accepted"}
    executive.assert_not_called()
    full.assert_not_called()
    notify.assert_called_once()


def test_summary_lookup_error_blocks_notification(database, report_paths):
    for path in report_paths:
        path.write_bytes(PDF)
    with (
        patch("api.models.ScanSummary.objects") as summaries,
        patch("urllib.request.urlopen") as send,
    ):
        summaries.filter.side_effect = RuntimeError("summary lookup failed")
        with pytest.raises(RuntimeError, match="summary lookup failed"):
            report._notify_vrika_scan_completed(
                TENANT,
                SCAN,
                PROVIDER,
                "gcp",
                "project-test",
                str(report_paths[0]),
                str(report_paths[1]),
            )
    send.assert_not_called()


def test_provider_lookup_error_blocks_email(database, report_paths):
    _, providers = database
    providers.get.side_effect = RuntimeError("provider lookup failed")
    with patch.object(report, "_notify_vrika_scan_completed") as send:
        with pytest.raises(RuntimeError, match="provider lookup failed"):
            report.share_vrika_scan_email_job(TENANT, SCAN, PROVIDER)
    send.assert_not_called()
