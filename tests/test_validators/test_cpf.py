import pytest
from info_shield.validators.cpf_validator import CpfValidator

@pytest.mark.parametrize("value,expected", [
    ("529.982.247-25", True),   # valid CPF
    ("52998224725", True),      # valid no formatting
    ("11111111111", False),     # invalid repeated digits
    ("12345678900", False),     # invalid checksum
])
def test_cpf_validator(value, expected):
    v = CpfValidator()
    res = v.validate(value)
    assert res.ok == expected
