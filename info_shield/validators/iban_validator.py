from .base import BaseValidator, ValidationResult

class IbanValidator(BaseValidator):
    name = "iban_validator"
    def validate(self, value: str, context: dict = None) -> ValidationResult:
        iban = value.replace(" ", "").upper()
        if len(iban) < 15 or len(iban) > 34:
            return ValidationResult(False, "Invalid length",0.0)

        rearranged = iban[4:] + iban[:4]
        digits = ""
        for ch in rearranged:
            if ch.isdigit():
                digits += ch
            else:
                digits += str(ord(ch) - 55)
        if int(digits) % 97 != 1:
            return ValidationResult(False,  "Checksum failed", 0.0)
        return ValidationResult(True, "Valid IBAN", 1.0)
