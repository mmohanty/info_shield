from __future__ import annotations
import re, base64, json
from typing import Any, Dict
from .base import BaseValidator, ValidationResult

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

class JwtStructureValidator(BaseValidator):
    name = "jwt_struct"
    _b64url_re = re.compile(r"^[A-Za-z0-9_\-]+$")
    def validate(self, value: str, *, context: Dict[str, Any]) -> ValidationResult:
        parts = value.split(".")
        if len(parts) != 3:
            return ValidationResult(False, "not_three_parts")
        for i, p in enumerate(parts):
            if not self._b64url_re.match(p):
                return ValidationResult(False, f"bad_b64url[{i}]")
            # Optional: try decoding header/payload to be stricter
            try:
                pad = "=" * (-len(p) % 4)
                base64.urlsafe_b64decode(p + pad)
            except Exception:
                return ValidationResult(False, f"b64_decode_failed[{i}]")
        return ValidationResult(True, score=0.8)

class EmailDomainAllowlistValidator(BaseValidator):
    name = "email_domain_allowlist"
    def __init__(self, allow: list[str] | None = None):
        self.allow = {d.lower() for d in (allow or [])}
    def validate(self, value: str, *, context: Dict[str, Any]) -> ValidationResult:
        m = re.search(r"@([^>\s]+)$", value)
        if not m:
            return ValidationResult(False, "no_domain")
        domain = m.group(1).lower()
        if self.allow and domain not in self.allow:
            return ValidationResult(False, f"domain_not_allowed:{domain}")
        return ValidationResult(True)

class PasswordEntropyValidator(BaseValidator):
    name = "password_entropy"
    def validate(self, value: str, *, context: Dict[str, Any]):
        # context may include 'match_span' and 'pattern_def'
        # value argument here should be the captured password (or full mr.value)
        # return object with .ok (bool), .score (float), .reason (str)
        passw = value
        score = self._simple_entropy(passw)
        ok = (len(passw) >= 8 and score >= 3.0)  # tune thresholds
        return ValidationResult(ok=ok, score=score, reason=None if ok else "low_entropy")
    def _simple_entropy(self, s: str) -> float:
        import math, collections
        if not s:
            return 0.0
        counts = collections.Counter(s)
        probs = [c / len(s) for c in counts.values()]
        return -sum(p * math.log2(p) for p in probs)


#Aadhaar Verhoeff (OPTIONAL): add if you need strict Aadhaar checksum
# from .verhoeff import verhoeff_valid
# class AadhaarVerhoeffValidator(BaseValidator):
#     name = "aadhaar_verhoeff"
#     def validate(self, value: str, *, context: Dict[str, Any]) -> ValidationResult:
#         digits = re.sub(r"\D+","", value)
#         ok = len(digits) == 12 and verhoeff_valid(digits)
#         return ValidationResult(ok, None if ok else "verhoeff_failed", score=1.0 if ok else 0.0)
