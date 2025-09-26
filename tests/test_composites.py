# tests/test_composites.py
from info_shield.patterns.composite.builtin_composites import get_composites
from info_shield.patterns.composite.registry import CompositeRegistry
from info_shield.scanner import GuardrailScanner
from info_shield.validators.registry import ValidatorRegistry


def test_and_composite_matches():
    text = "This is internal only. Please do not share outside."
    scanner = GuardrailScanner(pattern_defs=[], composite_defs=get_composites())
    hits = scanner.scan_text(text)
    names = {h.pattern for h in hits}
    assert "wmk_internal_and_donotshare" in names

def test_and_composite_fails_if_missing():
    text = "This is internal only."
    scanner = GuardrailScanner(pattern_defs=[], composite_defs=get_composites())
    hits = scanner.scan_text(text)
    assert not any(h.pattern == "wmk_internal_and_donotshare" for h in hits)

def test_credentials_composite_matches():
    text = "username=alice\npassword=P@ssw0rd123\n"
    scanner = GuardrailScanner(pattern_defs=[],
                               composite_defs=get_composites(),
                               preprocessors=[],
                               validators=ValidatorRegistry.load_builtin())
    hits = scanner.scan_text(text)
    assert any(h.pattern == "credentials_pair" for h in hits)

