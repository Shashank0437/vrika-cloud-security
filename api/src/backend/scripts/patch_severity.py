"""Add an unrated category to the locked SDK during the reproducible image build."""

import ast
import importlib.util
from pathlib import Path


def patch_severity(source: str) -> str:
    tree = ast.parse(source)
    severity = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "Severity"
    )
    for node in severity.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "unknown"
            for target in node.targets
        ):
            if (
                not isinstance(node.value, ast.Constant)
                or node.value.value != "unknown"
            ):
                raise ValueError("SDK unknown severity has an unexpected definition")
            return source
    lines = source.splitlines(keepends=True)
    lines.insert(severity.end_lineno, '    unknown = "unknown"\n')
    result = "".join(lines)
    ast.parse(result)
    return result


if __name__ == "__main__":
    spec = importlib.util.find_spec("prowler.lib.check.models")
    if spec is None or spec.origin is None:
        raise RuntimeError("Cannot locate locked SDK severity model")
    path = Path(spec.origin)
    original = path.read_text()
    updated = patch_severity(original)
    if updated != original:
        path.write_text(updated)
    print("SDK Unknown / Unrated severity support verified")
