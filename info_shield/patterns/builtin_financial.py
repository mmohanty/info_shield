from __future__ import annotations
from typing import List
from ..model import PatternDef


def get_patterns() -> List[PatternDef]:
    return [
        PatternDef(
            name="cc_number",
            description="Credit/Debit card number (Luhn)",
            category="Financial",
            severity="critical",
            regex=r"(?x)(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)",
            validators=["luhn"],
            partial_mask=True,
        ),
        PatternDef(
            name="iban",
            description="IBAN (International Bank Account Number)",
            category="Financial",
            severity="high",
            regex=r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b",
            partial_mask=True,
        ),
    ]