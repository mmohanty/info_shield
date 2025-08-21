from __future__ import annotations
from typing import Dict, Iterable, List, Optional, Any
from .base import Preprocessor, PreprocessResult
from .builtins import StripZeroWidth, NormalizeWhitespace, ToLower, Deaccent

class PreprocessorRegistry:
    def __init__(self):
        self._by_name: Dict[str, Preprocessor] = {}

    def register(self, p: Preprocessor):
        self._by_name[p.name] = p

    def bulk_register(self, items: Iterable[Preprocessor]):
        for p in items:
            self.register(p)

    def get(self, name: str) -> Preprocessor | None:
        return self._by_name.get(name)

    def resolve_chain(self, names: Iterable[str]) -> List[Preprocessor]:
        res: List[Preprocessor] = []
        for n in names:
            p = self.get(n)
            if p:
                res.append(p)
        return res

    @staticmethod
    def load_builtin() -> "PreprocessorRegistry":
        reg = PreprocessorRegistry()
        reg.bulk_register([
            StripZeroWidth(),
            NormalizeWhitespace(),
            ToLower(),
            Deaccent(),
        ])
        return reg

def apply_chain(text: str, chain: Iterable[Preprocessor], *, context: Optional[Dict[str, Any]] = None) -> PreprocessResult:
    # initial identity map: each processed char maps to its original index
    idx_map = list(range(len(text)))
    res = PreprocessResult(text=text, index_map=idx_map)
    for p in chain:
        res = p.apply(res.text, res.index_map, context=context)
    return res
