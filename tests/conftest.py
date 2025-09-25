import sys
import pytest

from info_shield.preprocess.registry import PreprocessorRegistry
from info_shield.validators.registry import ValidatorRegistry


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

from info_shield.nlp.registry import NlpRuleRegistry
from info_shield.patterns.registry import PatternRegistry
from info_shield.scanner import GuardrailScanner

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
def scanner(pattern_registry,
            preprocessors=None,
            preproc_registry=None,
            validators=None):
    preproc_registry = preproc_registry or PreprocessorRegistry.load_builtin()
    validator_registry = validators or ValidatorRegistry.load_builtin()
    return GuardrailScanner(pattern_registry.list_all(), [],
                            preprocessors=preprocessors or [],
                            preproc_registry=preproc_registry,
                            validators=validator_registry)

@pytest.fixture()
def sample_text():
    return (
        "Contact John Doe at john.doe@example.com or +91-98765 43210."
        "PAN: ABCDE1234F, Aadhaar: 1234 5678 9123."
        "Card: 4111-1111-1111-1111. IP: 192.168.1.5"
        "JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc.def"
    )