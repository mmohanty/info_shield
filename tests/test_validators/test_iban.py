import pytest
from info_shield.validators.iban_validator import IbanValidator

@pytest.mark.parametrize("value,expected", [
    ("GB82 WEST 1234 5698 7654 32", True),
    ("DE89370400440532013000", True),
    ("GB00 TEST 1234 5698 7654 32", False),  # checksum fails
])
def test_iban_validator(value, expected):
    v = IbanValidator()
    res = v.validate(value)
    assert res.ok == expected
