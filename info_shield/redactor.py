from __future__ import annotations
from typing import List
from .model import PatternDef, partial_mask, MatchResult
from .config import DEFAULT_REDACTION


class Redactor:
    def __init__(self, patterns: List[PatternDef]):
        self._pmap = {p.name: p for p in patterns}

    @staticmethod
    def _merge_overlaps(matches: List[MatchResult]) -> List[MatchResult]:
        if not matches:
            return []
        merged: List[MatchResult] = []
        for m in sorted(matches, key=lambda r: (r.start, r.end)):
            if not merged or m.start > merged[-1].end:
                merged.append(m)
            else:
                last = merged[-1]
                if m.end > last.end:
                    last.end = m.end  # type: ignore
                sev_rank = {"critical": 3, "high": 2, "medium": 1, "low": 0}
                if sev_rank.get(m.severity, 0) > sev_rank.get(last.severity, 0):
                    last.pattern = m.pattern  # type: ignore
                    last.severity = m.severity  # type: ignore
        return merged

    def apply(self, text: str, matches: List[MatchResult]) -> str:
        merged = self._merge_overlaps(matches)
        redacted = list(text)
        for m in reversed(merged):
            pdef = self._pmap.get(m.pattern)
            token: str
            if pdef and pdef.redact:
                token = pdef.redact
            elif pdef and pdef.partial_mask:
                token = partial_mask(m.value)

            else:
                token = DEFAULT_REDACTION
            redacted[m.start:m.end] = token
        return "".join(redacted)