import pytest
from info_shield.validators.hetu_validator import HetuValidator

@pytest.mark.parametrize("value,expected", [
    ("131052-308T", True),   # valid HETU
    ("131052-308X", False),  # wrong checksum
    ("991352-308T", False),  # invalid date
])
def test_hetu_validator(value, expected):
    v = HetuValidator()
    res = v.validate(value)
    assert res.ok == expected
