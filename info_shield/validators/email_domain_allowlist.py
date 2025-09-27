from typing import Dict, Any

from .base import BaseValidator, ValidationResult

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