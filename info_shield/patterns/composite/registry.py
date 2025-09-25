from __future__ import annotations
from info_shield.patterns.composite.builtin_composites import get_composites
class CompositeRegistry:
    def __init__(self): self._defs=[]
    def bulk_register(self, items): self._defs.extend(items)
    def list_all(self): return list(self._defs)
    @staticmethod
    def load_builtin():
        reg = CompositeRegistry()
        reg.bulk_register(get_composites())
        return reg