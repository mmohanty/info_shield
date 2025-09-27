from typing import Dict, Any

from .base import BaseValidator, ValidationResult

class PasswordEntropyValidator(BaseValidator):
    name = "password_entropy"
    def validate(self, value: str, *, context: Dict[str, Any]):
        # context may include 'match_span' and 'pattern_def'
        # value argument here should be the captured password (or full mr.value)
        # return object with .ok (bool), .score (float), .reason (str)
        passw = value
        score = self._simple_entropy(passw)
        ok = (len(passw) >= 8 and score >= 3.0)  # tune thresholds
        return ValidationResult(ok=ok, score=score, reason=None if ok else "low_entropy")
    def _simple_entropy(self, s: str) -> float:
        import math, collections
        if not s:
            return 0.0
        counts = collections.Counter(s)
        probs = [c / len(s) for c in counts.values()]
        return -sum(p * math.log2(p) for p in probs)