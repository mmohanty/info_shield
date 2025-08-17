from __future__ import annotations
from typing import List
from ..model import PatternDef

def get_patterns() -> List[PatternDef]:
    return [
        PatternDef(
            name="email",
            description="Email address",
            category="PII",
            severity="medium",
            regex=r"(?ix)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,24}\b",
            partial_mask=True,
        ),
        PatternDef(
            name="india_aadhaar",
            description="India Aadhaar number (12 digits, may contain separators)",
            category="PII",
            severity="high",
            regex=r"(?x)(?<!\d)(?:\d[ -]?){11}\d(?!\d)",
            partial_mask=True,
        ),
        PatternDef(
            name="india_pan",
            description="India PAN (e.g., ABCDE1234F)",
            category="PII",
            severity="high",
            regex=r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
            partial_mask=True,
        ),
        PatternDef(
            name="phone_general",
            description="Phone number (international, heuristic)",
            category="PII",
            severity="medium",
            regex=r"(?x)(?:\+\d{1,3}[ \-]?)?(?:\(\d{2,4}\)[ \-]?)?(?:\d[ \-]?){7,12}\d",
            partial_mask=True,
        ),
    ]