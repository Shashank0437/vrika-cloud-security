import unittest
from types import SimpleNamespace
from unittest.mock import patch

from api.compliance import build_scan_kwargs


class ScanComplianceSelectionTests(unittest.TestCase):
    def setUp(self):
        self.frameworks = {
            "dpdpa_cloud_security_1.0": SimpleNamespace(
                requirements=[
                    SimpleNamespace(checks={"aws": ["audit", "encrypt"]}),
                    SimpleNamespace(checks={"aws": ["audit"]}),
                    SimpleNamespace(checks={"aws": []}),
                ]
            ),
            "cis": SimpleNamespace(
                requirements=[SimpleNamespace(checks={"aws": ["access"]})]
            ),
        }
        loader = patch(
            "api.compliance.get_prowler_provider_compliance",
            return_value=self.frameworks,
        )
        self.loader = loader.start()
        self.addCleanup(loader.stop)
        legacy = patch("api.compliance.Compliance.get_bulk", return_value={})
        legacy.start()
        self.addCleanup(legacy.stop)
        inventory = patch(
            "api.compliance.CheckMetadata.get_bulk",
            return_value={
                check: SimpleNamespace(
                    CheckAliases=[], Severity=None, Categories=[], ResourceGroup=None
                )
                for check in ("access", "audit", "encrypt")
            },
        )
        inventory.start()
        self.addCleanup(inventory.stop)

    def test_universal_framework_resolves_to_unique_provider_checks(self):
        args = {"compliances": ["dpdpa_cloud_security_1.0"]}
        self.assertEqual(
            build_scan_kwargs("aws", args), {"checks": ["audit", "encrypt"]}
        )
        self.assertEqual(args, {"compliances": ["dpdpa_cloud_security_1.0"]})
        self.loader.assert_called_once_with("aws")

    def test_mixed_frameworks_use_union(self):
        self.assertEqual(
            build_scan_kwargs("aws", {"compliances": list(self.frameworks)}),
            {"checks": ["access", "audit", "encrypt"]},
        )

    def test_explicit_checks_preserve_sdk_precedence(self):
        self.assertEqual(
            build_scan_kwargs(
                "aws",
                {"compliances": list(self.frameworks), "checks": ["stored"]},
                ["override"],
            ),
            {"checks": ["override"]},
        )
        self.assertEqual(
            build_scan_kwargs(
                "aws", {"compliances": list(self.frameworks), "checks": ["stored"]}
            ),
            {"checks": ["stored"]},
        )

    def test_unknown_framework_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unknown compliance framework"):
            build_scan_kwargs("aws", {"compliances": ["unknown"]})

    def test_empty_mapping_never_falls_back_to_full_scan(self):
        with self.assertRaisesRegex(ValueError, "no automated checks"):
            build_scan_kwargs("azure", {"compliances": list(self.frameworks)})

    def test_retired_checks_are_excluded_like_sdk_compliance_selection(self):
        self.frameworks["cis"].requirements[0].checks["aws"].append("retired")
        self.assertEqual(
            build_scan_kwargs("aws", {"compliances": ["cis"]}),
            {"checks": ["access"]},
        )

    def test_all_compliance_keeps_default_scan_behavior(self):
        self.assertEqual(build_scan_kwargs("aws", {}), {})
        self.assertEqual(build_scan_kwargs("aws", None), {})
        self.assertEqual(build_scan_kwargs("aws", {"compliances": []}), {})
        self.loader.assert_not_called()


class SDKScanComplianceSelectionTests(unittest.TestCase):
    def test_dpdpa_can_initialize_scans_for_each_supported_provider(self):
        from api.compliance import get_prowler_provider_compliance
        from prowler.lib.scan.scan import Scan

        for provider in ("aws", "azure", "gcp"):
            with self.subTest(provider=provider):
                framework = get_prowler_provider_compliance(provider)[
                    "dpdpa_cloud_security_1.0"
                ]
                expected = {
                    check
                    for requirement in framework.requirements
                    for check in requirement.checks.get(provider, [])
                }
                kwargs = build_scan_kwargs(
                    provider, {"compliances": ["dpdpa_cloud_security_1.0"]}
                )
                scan = Scan(provider=SimpleNamespace(type=provider), **kwargs)
                self.assertTrue(expected)
                self.assertEqual(set(scan.checks_to_execute), expected)

    def test_legacy_framework_selection_is_unchanged(self):
        from prowler.lib.check.compliance_models import Compliance
        from prowler.lib.scan.scan import Scan

        for provider in ("aws", "azure", "gcp"):
            with self.subTest(provider=provider):
                selected = list(Compliance.get_bulk(provider))
                self.assertTrue(selected)
                original = Scan(
                    provider=SimpleNamespace(type=provider), compliances=selected
                )
                adapted = Scan(
                    provider=SimpleNamespace(type=provider),
                    **build_scan_kwargs(provider, {"compliances": selected}),
                )
                self.assertEqual(adapted.checks_to_execute, original.checks_to_execute)


if __name__ == "__main__":
    unittest.main()
