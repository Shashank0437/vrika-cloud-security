import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from install_compliance import install_catalog, validate_catalog


class ValidateCatalogTests(unittest.TestCase):
    def test_bundled_baseline_has_explicit_scope_and_provider_mappings(self):
        source = Path(__file__).parent / "compliance" / "dpdpa_cloud_security_1.0.json"
        catalog = json.loads(source.read_text())
        self.assertEqual(catalog["framework"], "DPDPA-Cloud-Security-Baseline")
        self.assertIn("not the complete Act or Rules", catalog["description"])
        self.assertEqual(len(catalog["requirements"]), 24)
        references = set()
        for requirement in catalog["requirements"]:
            self.assertEqual(set(requirement["checks"]), {"aws", "azure", "gcp"})
            self.assertTrue(requirement["attributes"]["EvidenceLimitations"])
            self.assertTrue(requirement["attributes"]["Applicability"])
            self.assertTrue(requirement["attributes"]["Commencement"])
            references.update(requirement["attributes"]["SourceClauses"])
            coverage = requirement["attributes"]["Coverage"]
            self.assertIn(coverage, {"Partial", "Manual"})
            if coverage == "Manual":
                self.assertFalse(any(requirement["checks"].values()))
        self.assertTrue(
            {
                "Rule 6(1)(a)",
                "Rule 6(1)(b)",
                "Rule 6(1)(c)",
                "Rule 6(1)(d)",
                "Rule 6(1)(e)",
                "Rule 6(1)(f)",
                "Rule 6(1)(g)",
                "Rule 7(1)",
                "Rule 7(2)",
                "Rule 8(1)",
                "Rule 8(2)",
                "Rule 8(3)",
                "Rule 13(1)",
                "Rule 13(2)",
                "Rule 13(3)",
                "Rule 13(4)",
                "Rule 15",
                "First Schedule Part B 7",
                "Second Schedule (f)",
            }.issubset(references)
        )

    def test_duplicate_requirement_ids_are_rejected(self):
        catalog = {"requirements": [{"id": "8(5)"}, {"id": "8(5)"}]}
        with self.assertRaisesRegex(ValueError, "unique"):
            validate_catalog(catalog, Path("unused"))

    def test_unknown_check_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            sdk_root = Path(directory)
            (sdk_root / "providers/aws/services").mkdir(parents=True)
            catalog = {"requirements": [{"id": "8(5)", "checks": {"aws": ["unknown"]}}]}
            with self.assertRaisesRegex(ValueError, "Unknown check"):
                validate_catalog(catalog, sdk_root)

    def test_empty_requirement_id_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "nonempty"):
            validate_catalog({"requirements": [{"id": " "}]}, Path("unused"))

    def test_unknown_provider_is_rejected(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            self.assertRaisesRegex(ValueError, "Unknown provider"),
        ):
            validate_catalog(
                {"requirements": [{"id": "control", "checks": {"unknown": []}}]},
                Path(directory),
            )

    def test_metadata_check_id_must_match(self):
        with tempfile.TemporaryDirectory() as directory:
            sdk_root = Path(directory)
            metadata = (
                sdk_root / "providers/aws/services/iam/example/example.metadata.json"
            )
            metadata.parent.mkdir(parents=True)
            metadata.write_text(json.dumps({"CheckID": "different"}))
            catalog = {
                "requirements": [{"id": "control", "checks": {"aws": ["example"]}}]
            }
            with self.assertRaisesRegex(ValueError, "CheckID mismatch"):
                validate_catalog(catalog, sdk_root)
            metadata.write_text(json.dumps({"CheckID": "example"}))
            validate_catalog(catalog, sdk_root)
            catalog["requirements"][0]["checks"]["aws"].append("example")
            with self.assertRaisesRegex(ValueError, "Duplicate checks"):
                validate_catalog(catalog, sdk_root)

    def test_manual_requirement_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            sdk_root = Path(directory)
            (sdk_root / "providers/aws/services").mkdir(parents=True)
            catalog = {"requirements": [{"id": "5", "checks": {"aws": []}}]}
            validate_catalog(catalog, sdk_root)


@unittest.skipUnless(
    importlib.util.find_spec("prowler"), "Prowler SDK is not installed"
)
class SDKCatalogTests(unittest.TestCase):
    def test_catalog_schema_checks_and_repeat_installation(self):
        from prowler.lib.check.compliance_models import (
            load_compliance_framework_universal,
        )

        source = Path(__file__).parent / "compliance" / "dpdpa_cloud_security_1.0.json"
        sdk_root = Path(importlib.util.find_spec("prowler").origin).parent
        framework = load_compliance_framework_universal(str(source))
        self.assertIsNotNone(framework)
        self.assertEqual(framework.get_providers(), ["aws", "azure", "gcp"])
        self.assertEqual(len(framework.requirements), 24)
        validate_catalog(json.loads(source.read_text()), sdk_root)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "providers").symlink_to(
                sdk_root / "providers", target_is_directory=True
            )
            (target / "compliance").mkdir()
            installed = install_catalog(source, target)
            self.assertEqual(installed.read_bytes(), source.read_bytes())
            self.assertEqual(install_catalog(source, target), installed)
            installed.write_text("{}")
            with self.assertRaisesRegex(ValueError, "Refusing to replace"):
                install_catalog(source, target)


if __name__ == "__main__":
    unittest.main()
