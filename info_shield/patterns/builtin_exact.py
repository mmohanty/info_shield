from __future__ import annotations
from typing import List, Iterable
import json, os
import regex as re
from ..model import PatternDef

# Default phrases (you can replace with your watermark strings)
DEFAULT_WATERMARKS_CASE_INSENSITIVE = [
    "ConfidentialWatermark",
    "InternalOnly"
]

DEFAULT_WATERMARKS_CASE_SENSITIVE = [
    "CONFIDENTIAL - INTERNAL",
]

def _patterns_from_list(
    phrases: Iterable[str],
    *,
    name_prefix: str,
    category: str = "Exact",
    severity: str = "medium",
    case_sensitive: bool = False,
    whole_word: bool = False,
) -> List[PatternDef]:
    flags = re.MULTILINE if case_sensitive else (re.MULTILINE | re.IGNORECASE)
    word = r"\b" if whole_word else ""
    out: List[PatternDef] = []
    for i, phrase in enumerate(phrases):
        esc = re.escape(phrase)
        regex = rf"{word}{esc}{word}"
        out.append(PatternDef(
            name=f"{name_prefix}_{i+1}",
            description=f'Exact match: "{phrase}"',
            category=category,
            severity=severity,
            regex=regex,
            flags=flags,
            # redaction token can be customized; partial masking usually not useful here
            redact="[WATERMARK]",
        ))
    return out

def _load_json_phrases(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict) and "phrases" in data:
        return [str(x) for x in data["phrases"]]
    if isinstance(data, list):
        return [str(x) for x in data]
    raise ValueError("Unsupported JSON format for exact-match phrases")

def get_patterns() -> List[PatternDef]:
    """
    Build a set of exact-match patterns from:
      1) Built-in defaults
      2) Optional JSON files pointed to by env vars:
         - GR_EXACT_WATERMARKS_CI_JSON  (case-insensitive)
         - GR_EXACT_WATERMARKS_CS_JSON  (case-sensitive)
    """
    ci = list(DEFAULT_WATERMARKS_CASE_INSENSITIVE)
    cs = list(DEFAULT_WATERMARKS_CASE_SENSITIVE)

    ci_json = os.getenv("GR_EXACT_WATERMARKS_CI_JSON")
    cs_json = os.getenv("GR_EXACT_WATERMARKS_CS_JSON")

    if ci_json and os.path.exists(ci_json):
        try:
            ci.extend(_load_json_phrases(ci_json))
        except Exception:
            pass  # ignore bad file, keep defaults

    if cs_json and os.path.exists(cs_json):
        try:
            cs.extend(_load_json_phrases(cs_json))
        except Exception:
            pass

    patterns: List[PatternDef] = []
    patterns += _patterns_from_list(
        ci,
        name_prefix="watermark_ci",
        case_sensitive=False,
        whole_word=False,      # flip to True if you only want whole-word matches
        category="Watermark",
        severity="low",
    )
    patterns += _patterns_from_list(
        cs,
        name_prefix="watermark_cs",
        case_sensitive=True,
        whole_word=False,
        category="Watermark",
        severity="low",
    )
    return patterns
