from __future__ import annotations
import base64
import regex as re
from typing import Any, Dict
from .base import BaseValidator, ValidationResult


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






#Aadhaar Verhoeff (OPTIONAL): add if you need strict Aadhaar checksum
# from .verhoeff import verhoeff_valid
# class AadhaarVerhoeffValidator(BaseValidator):
#     name = "aadhaar_verhoeff"
#     def validate(self, value: str, *, context: Dict[str, Any]) -> ValidationResult:
#         digits = re.sub(r"\D+","", value)
#         ok = len(digits) == 12 and verhoeff_valid(digits)
#         return ValidationResult(ok, None if ok else "verhoeff_failed", score=1.0 if ok else 0.0)
