from .base import BaseValidator, ValidationResult

class CpfValidator(BaseValidator):
    name = "cpf_validator"
    def validate(self, value: str, context: dict = None) -> ValidationResult:
        digits = [int(d) for d in value if d.isdigit()]
        if len(digits) != 11:
            return ValidationResult(False,  "Invalid length", 0.0)

        if len(set(digits)) == 1:
            return ValidationResult(False, "All digits same", 0.0)

        # Check digits calculation
        for i in range(9, 11):
            s = sum(digits[j] * ((i + 1) - j) for j in range(0, i))
            check = ((s * 10) % 11) % 10
            if digits[i] != check:
                return ValidationResult(False, "Checksum failed", 0.0)

        return ValidationResult(True, "Valid CPF", 1.0)
