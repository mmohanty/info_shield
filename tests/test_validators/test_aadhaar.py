import pytest
from info_shield.validators.aadhaar_validator import AadhaarValidator

@pytest.mark.parametrize("value,expected", [
    ("79927398713", False),         # invalid
    ("123412341234", True),        # invalid checksum
    ("868997802613", True),         # valid Aadhaar (synthetic example with Verhoeff)
])
def test_aadhaar_validator(value, expected):
    v = AadhaarValidator()
    res = v.validate(value)
    assert res.ok == expected
