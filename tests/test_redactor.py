from regex_guardrail.redactor import Redactor


def test_redaction_partial_mask(scanner):
    text = "email john@example.com here"
    matches = scanner.scan_text(text)
    email_matches = [m for m in matches if m.pattern == "email"]
    redacted = Redactor(scanner.pattern_defs).apply(text, email_matches)
    assert "example.com" in redacted
    assert "john@" not in redacted  # local-part masked


def test_redaction_full_tokens(scanner):
    text = "jwt eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.x.y present"
    matches = scanner.scan_text(text)
    jwt_matches = [m for m in matches if m.pattern == "jwt"]
    redacted = Redactor(scanner.pattern_defs).apply(text, jwt_matches)
    assert "[JWT]" in redacted