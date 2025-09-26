from __future__ import annotations
from typing import Dict, Iterable
from .base import BaseValidator
from .builtin import LuhnValidator, JwtStructureValidator, EmailDomainAllowlistValidator, PasswordEntropyValidator

class ValidatorRegistry:
    def __init__(self):
        self._by_name: Dict[str, BaseValidator] = {}

    def register(self, validator: BaseValidator):
        self._by_name[validator.name] = validator

    def bulk(self, validators: Iterable[BaseValidator]):
        for v in validators: self.register(v)

    def get(self, name: str) -> BaseValidator | None:
        return self._by_name.get(name)

    @staticmethod
    def load_builtin() -> "ValidatorRegistry":
        reg = ValidatorRegistry()
        reg.bulk([
            LuhnValidator(),
            JwtStructureValidator(),
            PasswordEntropyValidator(),
            EmailDomainAllowlistValidator(allow=[]),  # empty allowlist by default
        ])
        return reg
