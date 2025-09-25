# info_shield/patterns/builtin_composites.py
import re
from info_shield.model import CompositePatternDef, SubPattern

def get_composites():
    return [
        CompositePatternDef(
            name="wmk_internal_and_donotshare",
            category="Watermark",
            severity="low",
            op="AND",
            parts=[
                SubPattern(name="A", regex=re.escape("internal only"), flags=re.IGNORECASE,
                           preprocessors=["strip_zero_width","normalize_whitespace","lower"], confidence=0.7),
                SubPattern(name="B", regex=re.escape("do not share"), flags=re.IGNORECASE,
                           preprocessors=["strip_zero_width","normalize_whitespace","lower"], confidence=0.7),
            ],
            redact="[WATERMARK]"
        ),
        CompositePatternDef(
            name="secret_or_jwt",
            category="Secrets",
            severity="high",
            boolean_expr="A || B",
            parts=[
                SubPattern(name="A", regex=re.escape("BEGIN PRIVATE KEY"), flags=re.IGNORECASE, confidence=0.95),
                SubPattern(name="B", regex=r"\b[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b", confidence=0.8),
            ],
            validators=["jwt_struct"],  # optional: validate if B was the one that matched
            redact="[SECRET]"
        ),
        CompositePatternDef(
            name="policy_and_procedure_but_not_demo",
            category="Policy",
            severity="medium",
            boolean_expr="A && B && !C",
            parts=[
                SubPattern(name="A", regex=re.escape("policy")),
                SubPattern(name="B", regex=re.escape("procedure")),
                SubPattern(name="C", regex=re.escape("demo-only"), negate=False),
            ],
        )
    ]
