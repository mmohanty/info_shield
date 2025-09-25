def test_email_detection(scanner):
    text = "reach me at a.b+test@example.co.in today"
    matches = [m for m in scanner.scan_text(text) if m.pattern == "email"]
    assert any("example.co.in" in m.value for m in matches)


def test_india_pan_detection(scanner):
    text = "PAN ABCDE1234F is present"
    pans = [m.value for m in scanner.scan_text(text) if m.pattern == "india_pan"]
    assert "ABCDE1234F" in pans


def test_aadhaar_detection(scanner):
    text = "Aadhaar 1234 5678 9123 is here"
    hits = [m.value for m in scanner.scan_text(text) if m.pattern == "india_aadhaar"]
    assert any("1234" in v for v in hits)


def test_ipv4_detection(scanner):
    text = "local ip 10.0.0.1 and public 8.8.8.8"
    ips = [m.value for m in scanner.scan_text(text) if m.pattern == "ipv4"]
    assert {"10.0.0.1", "8.8.8.8"}.issubset(set(ips))


def test_credit_card_luhn_valid(scanner):
    text = "Visa 4111 1111 1111 1111 should match"
    cc = [m.value for m in scanner.scan_text(text) if m.pattern == "cc_number"]
    assert any("4111" in v for v in cc)


def test_credit_card_luhn_invalid(scanner):
    text = "Bad 4111 1111 1111 1112 should NOT match"
    cc = [m.value for m in scanner.scan_text(text) if m.pattern == "cc_number"]
    assert cc == []
