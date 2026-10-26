"""Validate and install the bundled compliance catalog into the Prowler SDK."""

import importlib.util
import json
import shutil
from pathlib import Path


def validate_catalog(catalog: dict, sdk_root: Path) -> None:
    requirements = catalog["requirements"]
    requirement_ids = [requirement["id"] for requirement in requirements]
    if (
        not requirement_ids
        or any(not requirement_id.strip() for requirement_id in requirement_ids)
        or len(requirement_ids) != len(set(requirement_ids))
    ):
        raise ValueError("Compliance requirement IDs must be nonempty and unique")
    for requirement in requirements:
        for provider, checks in requirement.get("checks", {}).items():
            services = sdk_root / "providers" / provider / "services"
            if not services.is_dir():
                raise ValueError(f"Unknown provider: {provider}")
            if len(checks) != len(set(checks)):
                raise ValueError(f"Duplicate checks: {requirement['id']}/{provider}")
            for check_id in checks:
                matches = list(services.glob(f"*/{check_id}/{check_id}.metadata.json"))
                if len(matches) != 1:
                    raise ValueError(f"Unknown check: {provider}/{check_id}")
                metadata = json.loads(matches[0].read_text())
                if metadata.get("CheckID") != check_id:
                    raise ValueError(f"CheckID mismatch: {provider}/{check_id}")


def install_catalog(source: Path, sdk_root: Path) -> Path:
    from prowler.lib.check.compliance_models import load_compliance_framework_universal

    catalog = json.loads(source.read_text())
    validate_catalog(catalog, sdk_root)
    framework = load_compliance_framework_universal(str(source))
    if framework is None:
        raise ValueError(f"Invalid compliance framework: {source.name}")
    destination = sdk_root / "compliance" / source.name
    if destination.exists() and destination.read_bytes() != source.read_bytes():
        raise ValueError(f"Refusing to replace an existing framework: {source.name}")
    if not destination.exists():
        shutil.copyfile(source, destination)
    return destination


if __name__ == "__main__":
    from prowler.lib.check.compliance_models import (
        get_bulk_compliance_frameworks_universal,
    )

    spec = importlib.util.find_spec("prowler")
    if spec is None or spec.origin is None:
        raise RuntimeError("Cannot locate the installed Prowler SDK")
    source = (
        Path(__file__).resolve().parent / "compliance" / "dpdpa_cloud_security_1.0.json"
    )
    destination = install_catalog(source, Path(spec.origin).parent)
    for provider in ("aws", "azure", "gcp"):
        frameworks = get_bulk_compliance_frameworks_universal(provider)
        if destination.stem not in frameworks:
            raise RuntimeError(f"Framework not discovered for {provider}")
    print(f"Installed compliance framework: {destination.name}")
