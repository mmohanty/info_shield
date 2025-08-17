from info_shield.scanner import GuardrailScanner
from info_shield.registry import PatternRegistry


def test_end_to_end(sample_text):
    patterns = PatternRegistry.load_builtin().list_all()
    scanner = GuardrailScanner(patterns)
    matches = scanner.scan_text(sample_text)
    kinds = {m.pattern for m in matches}
    assert {"email", "india_pan", "india_aadhaar", "cc_number", "phone_general", "jwt"}.issubset(kinds)