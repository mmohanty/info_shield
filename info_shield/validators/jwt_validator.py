import base64
import json
from .base import BaseValidator, ValidationResult

def _b64decode(segment: str):
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)

class JwtValidator(BaseValidator):
    name = "jwt_struct_2"
    def validate(self, value: str, context: dict = None) -> ValidationResult:
        try:
            parts = value.split(".")
            if len(parts) != 3:
                return ValidationResult(False, "Invalid JWT structure", 0.0)
            header = json.loads(_b64decode(parts[0]))
            payload = json.loads(_b64decode(parts[1]))
            # don't verify signature here
            if "alg" not in header:
                return ValidationResult(False, "Missing alg in header", 0.5)
            return ValidationResult(True, "Valid JWT structure", 0.9)
        except Exception as e:
            return ValidationResult(False, f"Invalid JWT: {e}", 0.0)
