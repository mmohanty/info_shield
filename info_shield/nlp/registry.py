from __future__ import annotations
from typing import Dict, Iterable, List
from info_shield.model import BaseNlpRule

class NlpRuleRegistry:
    def __init__(self):
        self._rules: Dict[str, BaseNlpRule] = {}

    def register(self, rule: BaseNlpRule) -> None:
        self._rules[rule.name] = rule

    def bulk_register(self, rules: Iterable[BaseNlpRule]) -> None:
        for r in rules:
            self.register(r)

    def list_all(self) -> List[BaseNlpRule]:
        return list(self._rules.values())

    def get(self, name: str) -> BaseNlpRule | None:
        return self._rules.get(name)

    @staticmethod
    def load_builtin() -> "NlpRuleRegistry":
        from .spacy_rules import get_rules as spacy_builtin
        from .jailbreak_rules import get_rules as jailbreak_builtin
        reg = NlpRuleRegistry()
        reg.bulk_register(spacy_builtin())
        reg.bulk_register(jailbreak_builtin())
        return reg
