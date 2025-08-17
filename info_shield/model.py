from __future__ import annotations
from dataclasses import dataclass
from typing import Callable, Optional, Pattern, Tuple, List
import re
from .config import PARTIAL_MASK_CHAR, PARTIAL_MASK_KEEP_LAST

Validator = Callable[[str], bool]


def partial_mask(s: str, keep_last: int = PARTIAL_MASK_KEEP_LAST, mask_char: str = PARTIAL_MASK_CHAR) -> str:
    if keep_last <= 0:
        return mask_char * len(s)
    alnum_indices = [i for i, ch in enumerate(s) if ch.isalnum()]
    to_mask = max(0, len(alnum_indices) - keep_last)
    masked = list(s)
    for idx in alnum_indices[:to_mask]:
        masked[idx] = mask_char
    return "".join(masked)


@dataclass
class PatternDef:
    name: str
    description: str
    category: str
    severity: str  # low | medium | high | critical
    regex: str
    flags: int = re.MULTILINE
    validators: Tuple[Validator, ...] = ()
    redact: Optional[str] = None
    partial_mask: bool = False

    def compile(self) -> Pattern[str]:
        return re.compile(self.regex, self.flags)


@dataclass
class MatchResult:
    pattern: str
    category: str
    severity: str
    value: str
    start: int
    end: int
    line: int
    col: int
    preview: str
    valid: Optional[bool] = None


# ---- NLP Rule Protocol ----
class BaseNlpRule:
    """Interface for NLP rules (spaCy-backed)."""
    name: str
    description: str
    category: str
    severity: str

    def find(self, text: str) -> List[MatchResult]:
        raise NotImplementedError