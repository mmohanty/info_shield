from __future__ import annotations
from typing import Dict, Iterable, List, Optional, Pattern, Tuple
import re
from .model import PatternDef, MatchResult, BaseNlpRule
from .config import MAX_FINDINGS_PER_PATTERN

class GuardrailScanner:
    """Scans text using a mix of regex patterns and NLP rules."""

    def __init__(self, regex_patterns: Iterable[PatternDef], nlp_rules: Iterable[BaseNlpRule] | None = None, max_findings_per_pattern: int = MAX_FINDINGS_PER_PATTERN):
        self.pattern_defs: List[PatternDef] = list(regex_patterns)
        self.compiled: Dict[str, Pattern[str]] = {p.name: p.compile() for p in self.pattern_defs}
        self.nlp_rules: List[BaseNlpRule] = list(nlp_rules) if nlp_rules else []
        self.max_findings_per_pattern = max(1, int(max_findings_per_pattern))

    @staticmethod
    def _line_col(text: str, index: int) -> Tuple[int, int]:
        line = text.count("\n", 0, index) + 1
        last_nl = text.rfind("\n", 0, index)
        col = index - (last_nl + 1)
        return line, col + 1

    @staticmethod
    def _preview(text: str, start: int, end: int, window: int = 24) -> str:
        left = max(0, start - window)
        right = min(len(text), end + window)
        return text[left:start] + "⟦" + text[start:end] + "⟧" + text[end:right]

    def _scan_regex(self, text: str) -> List[MatchResult]:
        results: List[MatchResult] = []
        for pdef in self.pattern_defs:
            regex = self.compiled[pdef.name]
            count = 0
            for m in regex.finditer(text):
                value = m.group(1) if m.lastindex else m.group(0)
                valid: Optional[bool] = None
                if pdef.validators:
                    valid = all(v(value) for v in pdef.validators)
                    if valid is False:
                        continue
                line, col = self._line_col(text, m.start())
                results.append(
                    MatchResult(
                        pattern=pdef.name,
                        category=pdef.category,
                        severity=pdef.severity,
                        value=value,
                        start=m.start(),
                        end=m.end(),
                        line=line,
                        col=col,
                        preview=self._preview(text, m.start(), m.end()),
                        valid=valid,
                    )
                )
                count += 1
                if count >= self.max_findings_per_pattern:
                    break
        return results

    def _scan_nlp(self, text: str) -> List[MatchResult]:
        results: List[MatchResult] = []
        for rule in self.nlp_rules:
            results.extend(rule.find(text))
        return results

    def scan_text(self, text: str) -> List[MatchResult]:
        results = self._scan_regex(text)
        results += self._scan_nlp(text)
        severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        results.sort(key=lambda r: (severity_rank.get(r.severity, 9), r.start))
        return results