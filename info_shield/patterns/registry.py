from __future__ import annotations
from typing import Dict, Iterable, List
from info_shield.model import PatternDef

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
        from ..patterns.builtin_pii import get_patterns as pii
        from ..patterns.builtin_financial import get_patterns as fin
        from ..patterns.builtin_secrets import get_patterns as sec
        from ..patterns.builtin_network import get_patterns as net
        from ..patterns.builtin_safety import get_patterns as safety
        from ..patterns.builtin_exact import get_patterns as exact
       # from ..patterns.builtin_composites import get_composites as composite

        reg = PatternRegistry()
        reg.bulk_register(pii())
        reg.bulk_register(fin())
        reg.bulk_register(sec())
        reg.bulk_register(net())
        reg.bulk_register(safety())
        reg.bulk_register(exact())
        #reg.bulk_register(composite())
        return reg
