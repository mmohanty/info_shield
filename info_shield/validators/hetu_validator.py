from datetime import datetime
from .base import BaseValidator, ValidationResult

CHECK_CHARS = "0123456789ABCDEFHJKLMNPRSTUVWXY"

class HetuValidator(BaseValidator):
    name = "hetu_validator"
    def validate(self, value: str, context: dict = None) -> ValidationResult:
        try:
            birth = value[:6]
            century = value[6]
            individual = value[7:10]
            check = value[10]

            # Map century
            if century == "+":
                year_prefix = "18"
            elif century == "-":
                year_prefix = "19"
            elif century.upper() == "A":
                year_prefix = "20"
            else:
                return ValidationResult(False, "Invalid century marker", 0.0)

            birth_date = year_prefix + birth[4:6]
            full_date = year_prefix + birth[4:6]
            try:
                datetime.strptime(birth + year_prefix, "%d%m%Y")
            except ValueError:
                return ValidationResult(False, "Invalid date", 0.0)

            # Validate checksum
            base = birth + individual
            idx = int(base) % 31
            expected = CHECK_CHARS[idx]
            if check.upper() != expected:
                return ValidationResult(False, "Checksum failed", 0.0)

            return ValidationResult(True, "Valid HETU", 1.0)
        except Exception as e:
            return ValidationResult(False, str(e), 0.0)
