from typing import Dict, Any

from .base import BaseValidator, ValidationResult
import regex as re

class LuhnValidator(BaseValidator):
    name = "luhn"
    def validate(self, value: str, *, context: Dict[str, Any]) -> ValidationResult:
        digits = re.sub(r"\D+", "", value)
        if len(digits) < 12:  # keep conservative
            return ValidationResult(False, "too_short_for_luhn")
        s = 0; alt = False
        for d in reversed(digits):
            n = ord(d) - 48
            if alt: n = n * 2; n = n - 9 if n > 9 else n
            s += n; alt = not alt
        ok = (s % 10 == 0)
        return ValidationResult(ok, None if ok else "luhn_failed", score=1.0 if ok else 0.0)