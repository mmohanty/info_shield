import os
import sys
import types
import pytest

# Import shim: prefer regex_guardrail; if missing, alias info_shield as regex_guardrail
try:
    import regex_guardrail as rg  # type: ignore
except Exception:  # pragma: no cover
    rg = None
    try:
        import info_shield as is_pkg  # type: ignore
        rg = is_pkg
        sys.modules["regex_guardrail"] = is_pkg  # alias for imports in tests
    except Exception as e:
        pytest.skip("Neither regex_guardrail nor info_shield importable", allow_module_level=True)

from regex_guardrail.registry import PatternRegistry, NlpRuleRegistry
from regex_guardrail.scanner import GuardrailScanner

@pytest.fixture(scope="session")
def pattern_registry():
    return PatternRegistry.load_builtin()

@pytest.fixture(scope="session")
def nlp_registry():
    try:
        return NlpRuleRegistry.load_builtin()
    except Exception:
        pytest.skip("spaCy not installed; skipping NLP tests", allow_module_level=False)

@pytest.fixture()
def scanner(pattern_registry):
    return GuardrailScanner(pattern_registry.list_all(), [])

@pytest.fixture()
def sample_text():
    return (
        "Contact John Doe at john.doe@example.com or +91-98765 43210."
        "PAN: ABCDE1234F, Aadhaar: 1234 5678 9123."
        "Card: 4111-1111-1111-1111. IP: 192.168.1.5"
        "JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc.def"
    )