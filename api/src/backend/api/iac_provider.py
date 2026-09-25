"""API-safe adapter for the CLI-oriented IaC SDK provider."""

import logging
from collections.abc import Generator

from prowler.lib.check.models import CheckReportIAC, Severity
from prowler.providers.iac.iac_provider import IacProvider

logger = logging.getLogger(__name__)


class ApiIacProvider(IacProvider):
    def _record_import_error(self, message: str) -> None:
        self._import_error_count += 1
        if len(self._import_errors) < 20:
            self._import_errors.append(message)
        logger.error("IaC import: %s", message)

    def _process_finding(
        self, finding: dict, file_path: str, type: str
    ) -> CheckReportIAC | None:
        raw_severity = finding.get("Severity")
        severity = raw_severity.strip().lower() if isinstance(raw_severity, str) else ""
        if severity == "info":
            severity = "informational"
        identifier = (
            finding.get("ID") or finding.get("VulnerabilityID") or finding.get("RuleID")
        )
        if severity not in {item.value for item in Severity}:
            self._record_import_error(
                f"{identifier!r} in {file_path!r}: unsupported severity {raw_severity!r}"
            )
            return None

        try:
            report = super()._process_finding(
                {**finding, "Severity": severity}, file_path, type
            )
        except SystemExit as error:
            self._record_import_error(
                f"{identifier!r} in {file_path!r}: SDK report conversion exited "
                f"with code {error.code!r}; see worker validation log"
            )
            return None
        # Keep the scanner's evidence unchanged; normalize only the metadata.
        report.resource = finding
        return report

    def run_scan(
        self, directory: str, scanners: list[str], exclude_path: list[str]
    ) -> Generator[list[CheckReportIAC], None, None]:
        self._import_error_count = 0
        self._import_errors: list[str] = []
        try:
            for batch in super().run_scan(directory, scanners, exclude_path):
                valid = [report for report in batch if report is not None]
                if valid:
                    yield valid
        except SystemExit as error:
            message = f"IaC scanner exited with code {error.code!r}; see worker log"
            self._record_import_error(message)
            raise RuntimeError(message) from error
        except Exception as error:
            self._record_import_error(f"IaC scanner failed: {error}")
            raise

    def raise_for_import_errors(self) -> None:
        # The SDK Scan.scan wrapper can swallow ordinary provider exceptions.
        # Check this after consuming its output, before marking the scan successful.
        if self._import_error_count:
            raise ValueError(
                f"IaC import incomplete: {self._import_error_count} error(s). "
                + "; ".join(self._import_errors)
            )
