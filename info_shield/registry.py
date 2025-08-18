from __future__ import annotations
from typing import Dict, Iterable, List
from .model import PatternDef, BaseNlpRule

class PatternRegistry:
    def __init__(self):
        self._by_name: Dict[str, PatternDef] = {}
        self._by_category: Dict[str, Dict[str, PatternDef]] = {}

    def register(self, p: PatternDef) -> None:
        self._by_name[p.name] = p
        self._by_category.setdefault(p.category, {})[p.name] = p

    def bulk_register(self, items: Iterable[PatternDef]) -> None:
        for p in items:
            self.register(p)

    def list_all(self) -> List[PatternDef]:
        return list(self._by_name.values())

    @staticmethod
    def load_builtin() -> "PatternRegistry":
        from .patterns.builtin_pii import get_patterns as pii
        from .patterns.builtin_financial import get_patterns as fin
        from .patterns.builtin_secrets import get_patterns as sec
        from .patterns.builtin_network import get_patterns as net
        from .patterns.builtin_safety import get_patterns as safety
        from .patterns.builtin_exact import get_patterns as exact

        reg = PatternRegistry()
        reg.bulk_register(pii())
        reg.bulk_register(fin())
        reg.bulk_register(sec())
        reg.bulk_register(net())
        reg.bulk_register(safety())
        reg.bulk_register(exact())
        return reg

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
        from .nlp.spacy_rules import get_rules as spacy_builtin
        from .nlp.jailbreak_rules import get_rules as jailbreak_builtin
        reg = NlpRuleRegistry()
        reg.bulk_register(spacy_builtin())
        reg.bulk_register(jailbreak_builtin())
        return reg