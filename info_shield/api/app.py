from __future__ import annotations
try:
    from fastapi import FastAPI, Body
    from pydantic import BaseModel, Field
except Exception as e:  # pragma: no cover
    raise SystemExit("FastAPI not installed. Run: pip install fastapi uvicorn pydantic")
import base64
from typing import List, Optional
from ..registry import PatternRegistry, NlpRuleRegistry
from ..scanner import GuardrailScanner
from ..redactor import Redactor
from ..model import MatchResult

class ScanOptions(BaseModel):
    redact: bool = False
    include_regex: Optional[List[str]] = None
    include_nlp: Optional[List[str]] = None

class ScanTextRequest(BaseModel):
    text: str
    options: Optional[ScanOptions] = None

class ScanBase64Request(BaseModel):
    filename: Optional[str] = None
    content_base64: str = Field(...)
    options: Optional[ScanOptions] = None

class ScanResponse(BaseModel):
    matches: List[dict]
    redacted_text: Optional[str] = None

app = FastAPI(title="Regex Guardrail Service", version="1.0.0")


# Load registries once (you can reload on demand if you hot-add rules)
_PATTERN_REG = PatternRegistry.load_builtin()
_NLP_REG = NlpRuleRegistry.load_builtin()


def _select_rules(opts: Optional[ScanOptions]):
    """
    Rule selection logic shared by /scan and /scan-document:
      - If scan_all=True -> ALL regex + ALL NLP
      - Else, if no include lists are supplied at all -> ALL regex (+ NLP if installed)
      - Else, filter by include lists
    """
    if not opts or opts.scan_all or (
        not opts.include_regex and not opts.include_nlp
    ):
        regex_defs = _pattern_reg_all()
        nlp_rules = _nlp_reg_all()
        return regex_defs, nlp_rules

    regex_defs = (
        [p for p in _pattern_reg_all() if p.name in set(opts.include_regex or [])]
        if (opts.include_regex is not None)
        else []
    )
    nlp_rules = (
        [r for r in _nlp_reg_all() if r.name in set(opts.include_nlp or [])]
        if (opts.include_nlp is not None)
        else []
    )
    return regex_defs, nlp_rules

def _pattern_reg_all():
    # central place if you later add dynamic packs or feature flags
    return _PATTERN_REG.list_all()

def _nlp_reg_all():
    # NlpRuleRegistry.load_builtin() already handles optional spaCy
    try:
        return _NLP_REG.list_all()
    except Exception:
        return []


@app.post("/scan", response_model=ScanResponse)
def scan_text_endpoint(payload: ScanTextRequest = Body(...)):
    regex_defs, nlp_rules = _select_rules(payload.options)
    scanner = GuardrailScanner(regex_defs, nlp_rules)
    matches = [m.__dict__ for m in scanner.scan_text(payload.text)]
    redacted = None
    if payload.options and payload.options.redact:
        redacted = Redactor(regex_defs).apply(payload.text, [MatchResult(**m) for m in matches])
    return ScanResponse(matches=matches, redacted_text=redacted)

@app.post("/scan/base64", response_model=ScanResponse)
def scan_b64_endpoint(payload: ScanBase64Request = Body(...)):
    raw = base64.b64decode(payload.content_base64)
    text = raw.decode("utf-8", errors="replace")

    regex_defs, nlp_rules = _select_rules(payload.options)
    scanner = GuardrailScanner(regex_defs, nlp_rules)
    matches = [m.__dict__ for m in scanner.scan_text(text)]
    redacted = None
    if payload.options and payload.options.redact:
        redacted = Redactor(regex_defs).apply(text, [MatchResult(**m) for m in matches])
    return ScanResponse(matches=matches, redacted_text=redacted)