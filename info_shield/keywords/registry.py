from __future__ import annotations
from typing import Dict, Iterable, List, Optional
from info_shield.model import KeywordDef

class KeywordRegistry:
    def __init__(self):
        self._by_name: Dict[str, KeywordDef] = {}

    def register(self, k: KeywordDef) -> None:
        self._by_name[k.name] = k

    def bulk_register(self, defs: Iterable[KeywordDef]) -> None:
        for k in defs:
            self.register(k)

    def get(self, name: str) -> Optional[KeywordDef]:
        return self._by_name.get(name)

    def list_all(self) -> List[KeywordDef]:
        return list(self._by_name.values())

    def names(self) -> List[str]:
        return list(self._by_name.keys())

    @staticmethod
    def load_builtin() -> "KeywordRegistry":
        from .builtin_packs import get_keyword_packs
        reg = KeywordRegistry()
        reg.bulk_register(get_keyword_packs())
        # Optional: load extra packs from env/json here if you like
        return reg
