# info_shield/patterns/builtin_composites.py
import regex as re
from info_shield.model import CompositePatternDef, SubPattern

# username regex (captures user token)
USERNAME_RE = r"""
(?mx)                                # multiline, verbose
\b(?:username|user|login)\b          # key
\s*[:=]\s*                           # separator
(?P<username>[A-Za-z0-9._-]{1,64})  # username token (safe chars)
\b
"""

# password regex (captures password token; allow many symbols)
PASSWORD_RE = r"""
(?mx)
\b(?:password|pass|pwd|pw)\b         # key
\s*[:=]\s*                           # separator
(?P<password>[^,\s'"]{4,128})        # value (no spaces, common delimiter based)
"""

def get_composites():
    return [
        CompositePatternDef(
            name="wmk_internal_and_donotshare",
            category="Watermark",
            severity="low",
            op="AND",
            parts=[
                SubPattern(name="A", regexes=[re.escape("internal only")], flags=re.IGNORECASE,
                           preprocessors=["strip_zero_width","normalize_whitespace","lower"], confidence=0.7),
                SubPattern(name="B", regexes=[re.escape("do not share")], flags=re.IGNORECASE,
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
                SubPattern(name="A", regexes=[re.escape("BEGIN PRIVATE KEY")], flags=re.IGNORECASE, confidence=0.95),
                SubPattern(name="B", regexes=[r"\b[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b"], confidence=0.8),
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
                SubPattern(name="A", regexes=[re.escape("policy")]),
                SubPattern(name="B", regexes=[re.escape("procedure")]),
                SubPattern(name="C", regexes=[re.escape("demo-only")], negate=False),
            ],
        ),
        CompositePatternDef(
            name="credentials_pair",
            category="Secrets",
            severity="critical",
            boolean_expr="A && B",  # both must be present
            proximity=200,  # max distance in chars
            parts=[
                SubPattern(
                    name="A",
                    regexes=[USERNAME_RE],
                    flags=re.IGNORECASE | re.VERBOSE,
                    preprocessors=["strip_zero_width", "normalize_whitespace"],
                    confidence=0.7,
                ),
                SubPattern(
                    name="B",
                    regexes=[PASSWORD_RE],
                    flags=re.IGNORECASE | re.VERBOSE,
                    preprocessors=["strip_zero_width", "normalize_whitespace"],
                    confidence=0.9,
                ),
            ],
            # Optional: redact the union span
            redact="[REDACTED_CREDENTIALS]",
            validators=["password_entropy"]  # optional, described below
        )
    ]
