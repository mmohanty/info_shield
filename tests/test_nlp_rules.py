import pytest

spacy = pytest.importorskip("spacy", reason="spaCy not installed")
from info_shield.registry import NlpRuleRegistry, PatternRegistry
from info_shield.scanner import GuardrailScanner


def test_person_name_rule():
    nlpreg = NlpRuleRegistry.load_builtin()
    preg = PatternRegistry.load_builtin()
    scanner = GuardrailScanner(preg.list_all(), nlpreg.list_all())
    text = "John Doe emailed from john@example.com in New York."
    matches = scanner.scan_text(text)
    assert any(m.pattern == "person_name_ner" and "John" in m.value for m in matches)
