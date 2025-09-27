from __future__ import annotations
from typing import Dict, Iterable

from .aadhaar_validator import AadhaarValidator
from .base import BaseValidator
from .builtin import JwtStructureValidator
from .cpf_validator import CpfValidator
from .email_domain_allowlist import EmailDomainAllowlistValidator
from .hetu_validator import HetuValidator
from .iban_validator import IbanValidator
from .luhn_validator import LuhnValidator
from .password_entropy import PasswordEntropyValidator


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
            CpfValidator(),
            HetuValidator(),
            AadhaarValidator(),
            IbanValidator(),
            EmailDomainAllowlistValidator(allow=[]),  # empty allowlist by default
        ])
        return reg
