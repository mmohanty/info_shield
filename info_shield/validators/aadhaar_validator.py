# info_shield/validators/aadhaar_validator.py
from .base import BaseValidator, ValidationResult

# Aadhaar uses Verhoeff algorithm for checksum
VERHOEFF_D = [
    [0,1,2,3,4,5,6,7,8,9],
    [1,2,3,4,0,6,7,8,9,5],
    [2,3,4,0,1,7,8,9,5,6],
    [3,4,0,1,2,8,9,5,6,7],
    [4,0,1,2,3,9,5,6,7,8],
    [5,9,8,7,6,0,4,3,2,1],
    [6,5,9,8,7,1,0,4,3,2],
    [7,6,5,9,8,2,1,0,4,3],
    [8,7,6,5,9,3,2,1,0,4],
    [9,8,7,6,5,4,3,2,1,0]
]
VERHOEFF_P = [
    [0,1,2,3,4,5,6,7,8,9],
    [1,5,7,6,2,8,3,0,9,4],
    [5,8,0,3,7,9,6,1,4,2],
    [8,9,1,6,0,4,3,5,2,7],
    [9,4,5,3,1,2,6,8,7,0],
    [4,2,8,6,5,7,9,3,0,1],
    [2,7,9,3,8,0,4,6,1,5],
    [7,0,4,6,9,1,3,2,5,8]
]

def verhoeff_validate(number: str) -> bool:
    c = 0
    for i, item in enumerate(reversed(number)):
        c = VERHOEFF_D[c][VERHOEFF_P[i % 8][int(item)]]
    return c == 0

class AadhaarValidator(BaseValidator):
    name = "aadhaar_validator"
    def validate(self, value: str, context: dict = None) -> ValidationResult:
        digits = "".join([d for d in value if d.isdigit()])
        if len(digits) != 12:
            return ValidationResult(False, "Invalid length", 0.0)
        if not verhoeff_validate(digits):
            return ValidationResult(False, "Checksum failed", 0.0)
        return ValidationResult(True, "Valid Aadhaar", 1.0)
