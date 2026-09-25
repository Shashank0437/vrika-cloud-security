import pytest
from scripts.patch_severity import patch_severity


def test_sdk_enum_patch_is_additive_and_idempotent():
    source = 'class Severity(str, Enum):\n    high = "high"\n    informational = "informational"\n'
    updated = patch_severity(source)
    assert updated == source + '    unknown = "unknown"\n'
    assert patch_severity(updated) == updated


def test_conflicting_sdk_category_is_not_silently_accepted():
    with pytest.raises(ValueError, match="unexpected definition"):
        patch_severity('class Severity(str, Enum):\n    unknown = "low"\n')
