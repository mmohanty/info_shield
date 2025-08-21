# tests/test_keywords.py
from info_shield.model import KeywordDef
from info_shield.scanner import GuardrailScanner

def test_keyword_pack_matches():
    kws = [
        KeywordDef(
            name="kpack",
            phrases=["ConfidentialWatermark", "Internal Only"],
            case_sensitive=False,
            whole_word=False,
            preprocessors=["strip_zero_width", "normalize_whitespace", "lower"],
            category="Watermark",
            severity="low",
        )
    ]
    s = GuardrailScanner(pattern_defs=[], nlp_rules=[], keyword_defs=kws, preprocessors=[])
    text = "This is C\u200Bon\u200BfidentialWatermark and Internal   Only."
    hits = s.scan_text(text)
    assert hits, "Expected keyword matches"
    names = {h.pattern for h in hits}
    assert "kpack" in names
