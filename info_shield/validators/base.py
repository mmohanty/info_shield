from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, Optional

@dataclass
class ValidationResult:
    ok: bool
    reason: Optional[str] = None
    score: Optional[float] = None   # 0..1, confidence if you want

class BaseValidator:
    """
    Implement .validate(value, *, context) -> ValidationResult
    value: the matched string
    context: dict with extras (full_text, pattern_def, match_span, request options, etc.)
    """
    name: str = "base"

    def validate(self, value: str, *, context: Dict[str, Any]) -> ValidationResult:
        raise NotImplementedError
