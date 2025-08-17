from __future__ import annotations
from typing import List
import re
from ..model import BaseNlpRule, MatchResult

class PromptInjectionHeuristicsRule(BaseNlpRule):
    """Heuristic jailbreak/prompt-injection detector (no spaCy needed)."""
    name = "prompt_injection_heuristics"
    description = "Heuristic detection of jailbreak / prompt-injection phrases"
    category = "Safety"
    severity = "high"

    PHRASES = [
        r"ignore\s+(?:all\s+)?previous\s+instructions",
        r"system\s*prompt",
        r"developer\s*instructions?",
        r"you\s+are\s+no\s+longer\s+bound\s+by",
        r"bypass\s+(?:the\s+)?rules?",
        r"disregard\s+(?:the\s+)?policies",
        r"jailbreak",
        r"act\s+as\s+an?\s+unrestricted",
        r"output\s+the\s+raw\s+prompt",
    ]

    def __init__(self, window: int = 180):
        self.window = window
        union_source = "|".join(f"(?:{p})" for p in self.PHRASES)
        self._union = re.compile(union_source, re.IGNORECASE)

    def find(self, text: str) -> List[MatchResult]:
        hits = [m for m in self._union.finditer(text)]
        out: List[MatchResult] = []
        for i, m in enumerate(hits):
            start, end = m.start(), m.end()
            # cluster nearby hits to boost severity
            cluster = 1
            j = i + 1
            while j < len(hits) and hits[j].start() - start <= self.window:
                cluster += 1
                j += 1
            sev = "critical" if cluster >= 3 else ("high" if cluster == 2 else self.severity)
            line = text.count("\n", 0, start) + 1
            col = start - (text.rfind("\n", 0, start) + 1) + 1
            preview = text[max(0, start-24):start] + "⟦" + text[start:end] + "⟧" + text[end:min(len(text), end+24)]
            out.append(MatchResult(
                pattern=self.name, category=self.category, severity=sev,
                value=text[start:end], start=start, end=end,
                line=line, col=col, preview=preview, valid=None,
            ))
        return out

def get_rules() -> List[BaseNlpRule]:
    return [PromptInjectionHeuristicsRule()]
