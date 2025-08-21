from __future__ import annotations
try:
    from fastapi import FastAPI, Body, HTTPException
    from pydantic import BaseModel, Field
except Exception as e:  # pragma: no cover
    raise SystemExit("FastAPI not installed. Run: pip install fastapi uvicorn pydantic")
import base64
from typing import List, Optional
from ..registry import PatternRegistry, NlpRuleRegistry
from ..scanner import GuardrailScanner
from ..redactor import Redactor
from ..model import MatchResult
from typing import List, Optional, Dict, Any
from info_shield.preprocess.registry import PreprocessorRegistry
from info_shield.validators.registry import ValidatorRegistry
from info_shield.keywords.builtin_packs import get_keyword_packs

class ScanOptions(BaseModel):
    redact: bool = False
    scan_all: bool = False
    include_regex: Optional[List[str]] = None
    include_nlp: Optional[List[str]] = None
    # NEW: arbitrary metadata, e.g. {"filename": "...", "mime_type": "...", "size": 12345}
    file_meta: Optional[Dict[str, Any]] = None

class ScanTextRequest(BaseModel):
    text: str
    options: Optional[ScanOptions] = None

class ScanBase64Request(BaseModel):
    filename: Optional[str] = None
    content_base64: str = Field(...)
    options: Optional[ScanOptions] = None


# ---------------- Response Models ----------------

class MatchModel(BaseModel):
    rule_name: str
    match_text: str
    start: int
    end: int
    type: Optional[str] = None       # maps from scanner "category"
    severity: Optional[str] = None   # maps from scanner "severity"
    metadata: Optional[Dict[str, Any]] = None  # line, col, preview, valid

class UsedRulesModel(BaseModel):
    regex: List[str]
    nlp: List[str]

class CountsModel(BaseModel):
    total_matches: int

class ScanResponse(BaseModel):
    filename: Optional[str] = None
    matches: List[MatchModel]
    redacted_text: Optional[str] = None
    counts: CountsModel
    used_rules: UsedRulesModel

app = FastAPI(title="Regex Guardrail Service", version="1.0.0")


# Load registries once (you can reload on demand if you hot-add rules)
_PATTERN_REG = PatternRegistry.load_builtin()
_NLP_REG = NlpRuleRegistry.load_builtin()


def _select_rules(opts: Optional[ScanOptions]):
    """
    Rule selection used by both endpoints:
      - If scan_all=True => ALL regex + ALL NLP.
      - Else if options missing or no include_* provided => ALL regex + ALL NLP (friendly default).
      - Else => filter to includes.
    """
    if (opts is None) or opts.scan_all or (not (opts.include_regex or opts.include_nlp)):
        return _all_regex(), _all_nlp()

    regex_defs = [p for p in _all_regex() if p.name in set(opts.include_regex or [])]
    keyword_defs = get_keyword_packs()
    nlp_rules = [r for r in _all_nlp() if r.name in set(opts.include_nlp or [])]
    return regex_defs, nlp_rules, keyword_defs

def _all_regex():
    # central place if you later add dynamic packs or feature flags
    return _PATTERN_REG.list_all()

def _all_nlp():
    # NlpRuleRegistry.load_builtin() already handles optional spaCy
    try:
        return _NLP_REG.list_all()
    except Exception:
        return []


def _scan_and_optionally_redact(text: str, regex_defs,
                                nlp_rules, redact: bool,
                                *,
                                preprocessors=None,
                                preproc_registry=None,
                                validator_registry=None,
                                keyword_defs=None,
                                preprocess_context: Optional[Dict[str, Any]] = None):
    preproc_registry = preproc_registry or PreprocessorRegistry.load_builtin()
    validator_registry = validator_registry or ValidatorRegistry.load_builtin()
    scanner = GuardrailScanner(pattern_defs=regex_defs,
        nlp_rules=nlp_rules,
        keyword_defs=keyword_defs or [],            # NEW
        preprocessors=preprocessors or [],
        preproc_registry=preproc_registry,
        validators=validator_registry,)
    match_objs = [m.__dict__ for m in scanner.scan_text(text, preprocess_context=preprocess_context)]
    valid_for_redaction = [m for m in match_objs if getattr(m, "valid", True)]
    redacted_text = None
    if redact:
        redacted_text = Redactor(regex_defs).apply(text, [MatchResult(**m) for m in match_objs])
    return match_objs, redacted_text


# --- helper mapper (put near your other helpers) ---
def to_match_model(m: Dict[str, Any]) -> MatchModel:
    """Map scanner dict -> MatchModel."""
    return MatchModel(
        rule_name = m.get("pattern") or m.get("rule") or m.get("name") or "unknown",
        match_text = m.get("value") or m.get("match") or "",
        start = int(m.get("start", 0)),
        end = int(m.get("end", 0)),
        type = m.get("category"),
        severity = m.get("severity"),
        metadata = {
            k: v for k, v in m.items()
            if k in ("line", "col", "preview", "valid", "confidence", "source")
        }
    )

@app.post("/scan", response_model=ScanResponse)
def scan_text_endpoint(payload: ScanTextRequest = Body(...)):
    regex_defs, nlp_rules, keyword_defs  = _select_rules(payload.options)
    redact = bool(payload.options.redact) if payload.options else False
    matches_dicts, redacted = _scan_and_optionally_redact(
        payload.text,
        regex_defs,
        nlp_rules,
        redact,
        preprocessors=payload.options.preprocessors if payload.options else None,
        keyword_defs=keyword_defs)
    return ScanResponse(
        matches=[to_match_model(m) for m in matches_dicts],
        redacted_text=redacted,
        counts=CountsModel(total_matches=len(matches_dicts)),
        used_rules=UsedRulesModel(
            regex=[p.name for p in regex_defs],
            nlp=[r.name for r in nlp_rules],
        ),
    )

@app.post("/scan/base64", response_model=ScanResponse)
def scan_b64_endpoint(payload: ScanBase64Request = Body(...)):
    try:
        raw = base64.b64decode(payload.content_base64)
        text = raw.decode("utf-8", errors="replace")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid base64 or non-UTF8 content: {e}")

    regex_defs, nlp_rules, keyword_defs = _select_rules(payload.options)
    redact = bool(payload.options.redact) if payload.options else False
    matches_dicts, redacted = _scan_and_optionally_redact(
        text,
        regex_defs,
        nlp_rules,
        redact,
        preprocessors=payload.options.preprocessors if payload.options else None,
        keyword_defs=keyword_defs)

    return ScanResponse(
        filename=payload.filename,
        matches=[to_match_model(m) for m in matches_dicts],
        redacted_text=redacted,
        counts=CountsModel(total_matches=len(matches_dicts)),
        used_rules=UsedRulesModel(
            regex=[p.name for p in regex_defs],
            nlp=[r.name for r in nlp_rules],
        ),
    )