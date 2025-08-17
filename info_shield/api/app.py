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

app = FastAPI(title="Regex Guardrail Service", version="3.0.0")
_reg = PatternRegistry.load_builtin()
_nlp = NlpRuleRegistry.load_builtin()


def _select_regex(include: Optional[List[str]]):
    pats = _reg.list_all()
    if include:
        s = set(include)
        pats = [p for p in pats if p.name in s]
    return pats

def _select_nlp(include: Optional[List[str]]):
    rules = _nlp.list_all()
    if include:
        s = set(include)
        rules = [r for r in rules if r.name in s]
    return rules

@app.post("/scan", response_model=ScanResponse)
def scan_text_endpoint(payload: ScanTextRequest = Body(...)):
    regex = _select_regex(payload.options.include_regex if payload.options else None)
    nlp_rules = _select_nlp(payload.options.include_nlp if payload.options else None)
    scanner = GuardrailScanner(regex, nlp_rules)
    matches = [m.__dict__ for m in scanner.scan_text(payload.text)]
    redacted = None
    if payload.options and payload.options.redact:
        redacted = Redactor(regex).apply(payload.text, [MatchResult(**m) for m in matches])
    return ScanResponse(matches=matches, redacted_text=redacted)

@app.post("/scan/base64", response_model=ScanResponse)
def scan_b64_endpoint(payload: ScanBase64Request = Body(...)):
    raw = base64.b64decode(payload.content_base64)
    text = raw.decode("utf-8", errors="replace")
    regex = _select_regex(payload.options.include_regex if payload.options else None)
    nlp_rules = _select_nlp(payload.options.include_nlp if payload.options else None)
    scanner = GuardrailScanner(regex, nlp_rules)
    matches = [m.__dict__ for m in scanner.scan_text(text)]
    redacted = None
    if payload.options and payload.options.redact:
        redacted = Redactor(regex).apply(text, [MatchResult(**m) for m in matches])
    return ScanResponse(matches=matches, redacted_text=redacted)