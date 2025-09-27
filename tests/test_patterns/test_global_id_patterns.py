import pytest
from info_shield.patterns.global_id_patterns import PATTERN_DEFS
from info_shield.scanner import GuardrailScanner
from info_shield.model import MatchResult

# Build scanner with all patterns
scanner = GuardrailScanner(pattern_defs=PATTERN_DEFS)

test_cases = {
    # --- National IDs ---
    "argentina_dni": [
        ["My DNI is 12345678", True],
        ["DNI: 98765432", True],
    ],
    "australia_tfn": [
        ["TFN: 123456789", True],
        ["Tax File Number 123456782", True],
    ],
    "belgium_national_register": [
        ["Register ID 85012312345", True],
        ["85.01.23-123.45", True],
    ],
    "brazil_cpf": [
        ["CPF: 529.982.247-25", True],
        ["52998224725", True],
    ],
    "canada_sin": [
        ["SIN: 123 456 789", True],
        ["SIN 987-654-321", True],
    ],
    "china_passport": [
        ["Passport: E12345678", True],
        ["Passport G12345678", True],
    ],
    "china_resident_id": [
        ["ID: 11010519491231002X", True],
        ["320311770706001", True],
    ],
    "colombia_cdc": [
        ["CDC: 1234567890", True],
        ["CDC-9876543210", True],
    ],
    "france_tin": [
        ["TIN: 1234567890123", True],
        ["TIN 1987654321098", True],
    ],
    "finland_hetu": [
        ["131052-308T", True],
        ["010101-123N", True],
    ],
    "hongkong_id": [
        ["ID: A123456(7)", True],
        ["Z765432(1)", True],
    ],
    "india_aadhaar": [
        ["868997802613", True],
        ["1234 5678 9012", True],
    ],
    "india_pan": [
        ["ABCDE1234F", True],
        ["ABCDE1234D", True],
    ],
    "ireland_ppsn": [
        ["1234567A", True],
        ["8765432T", True],
    ],
    "italy_fiscal_code": [
        ["RSSMRA85T10A562S", True],
        ["BNCLRD65M01F205Z", True],
    ],
    "japan_my_number": [
        ["123456789012", True],
        ["987654321098", True],
    ],
    "korea_passport": [
        ["M12345678", True],
        ["S23456789", True],
    ],
    "korea_rrn": [
        ["900101-1234567", True],
        ["800101-3456789", True],
    ],
    "korea_alien_registration_number": [
        ["900101-5234567", True],
        ["850101-6456789", True],
    ],
    "mexico_curp": [
        ["GODE561231GR8MNK07", True],
        ["LOPR850101HMNRRN09", True],
    ],
    "netherlands_bsn": [
        ["123456782", True],
        ["987654321", True],
    ],
    "norway_ni": [
        ["01020312345", True],
        ["15039012345", True],
    ],
    "poland_id": [
        ["44051401359", True],
        ["02070803628", True],
    ],
    "singapore_nric": [
        ["S1234567D", True],
        ["T7654321J", True],
    ],
    "southafrica_id": [
        ["8001015009087", True],
        ["7501015800083", True],
    ],
    "spain_dni": [
        ["12345678Z", True],
        ["87654321X", True],
    ],
    "spain_ssn": [
        ["A1234567B", True],
        ["B7654321C", True],
    ],
    "sweden_id": [
        ["19900101-1234", True],
        ["20000101-5678", True],
    ],
    "switzerland_ssn": [
        ["7569217076985", True],
        ["7561234567897", True],
    ],
    "taiwan_id": [
        ["A123456789", True],
        ["B234567890", True],
    ],
    "thailand_id": [
        ["1-2345-67890-12-3", True],
        ["9-8765-43210-98-7", True],
    ],
    "turkey_id": [
        ["10000000146", True],
        ["12345678946", True],
    ],
    "uk_nino": [
        ["QQ123456C", True],
        ["AB123456D", True],
    ],
    "us_itin": [
        ["912-34-5678", True],
        ["987-65-4321", True],
    ],
    "us_ssn": [
        ["123-45-6789", True],
        ["321-54-9876", True],
    ],
    "venezuela_cdi": [
        ["V12345678", True],
        ["E98765432", True],
    ],

    # --- Financial Identifiers ---
    "financial_account_number_generic": [
        ["1234567890123456", True],
        ["9876543210987654", True],
    ],
    "iban": [
        ["GB82WEST12345698765432", True],
        ["DE89370400440532013000", True],
        ["FR1420041010050500013M02606", True],
    ],
    "credit_card_number": [
        ["4111111111111111", True],
        ["5500000000000004", True],
        ["340000000000009", True],
    ],
    "us_ein": [
        ["12-3456789", True],
        ["98-7654321", True],
    ],

    # --- Tokens, Keys & Secrets ---
    "jwt_token": [
        ["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature", True],
        ["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiam9obiJ9.signature", True],
    ],
    "oauth_client_secret_like": [
        ["abcdefABCDEF1234567890abcdefABCDEF", True],
        ["abcd1234abcd1234abcd1234abcd1234", True],
    ],
    "auth_token_generic": [
        ["Authorization=abcdef123456", True],
        ["Authorization: Bearer abcdefghijklmnop", True],
    ],
    "azure_auth_token": [
        ["eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", True],
        ["eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJleHAiOjEyMzQ1fQ.signature", True],
    ],
    "gcp_service_account_key": [
        ["-----BEGIN PRIVATE KEY-----\nMIIEv...\n-----END PRIVATE KEY-----", True],
        ["-----BEGIN PRIVATE KEY-----\nABCDEF...\n-----END PRIVATE KEY-----", True],
    ],
    "aws_access_key_1": [
        ["AKIAIOSFODNN7EXAMPLE", True],  # 20 chars, valid
        ["AKIA1234567890EXAMPLE", False],  # 20 chars, valid
        ["ASIA1234567890TEMP", False],  # 18 chars, invalid
        ["ASIA1234567890TEMPP1", True],  # 20 chars, valid
        ["akia1234567890example", False],  # lowercase, invalid

    ],
    "encryption_key_like": [
        ["0123456789abcdef0123456789abcdef", True],
        ["abcdefabcdefabcdefabcdefabcdefabcd", True],
    ],
    "ssl_certificate_pem": [
        ["-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----", True],
        ["-----BEGIN CERTIFICATE-----\nABC...\n-----END CERTIFICATE-----", True],
    ],
    "storage_signed_url": [
        ["https://example.com/file?X-Amz-Credential=abc&X-Amz-Signature=xyz", True],
        ["https://bucket.s3.amazonaws.com/file?X-Amz-Signature=12345", True],
    ],
    "storage_signed_policy_document": [
        ["policy=abc&Signature=xyz", True],
        ["Credential=abc&Signature=123", True],
        ["foo=bar&Signature=xyz", False]
    ],

    # --- Web Security Tokens ---
    "xsrf_token": [
        ["XSRF-TOKEN=abcd1234", True],
        ["xsrf_token=xyz98765", True],
        ["XSRFToken=1234abcd", True],
    ],
    "password_field_like": [
        ["password=Secret123", True],
        ["Password = My$ecret123!", True],
        ["pwd=topsecret", True],
        ["password_hint=Secret123", False]
    ],
    "oauth_client_secret_header": [
        ["client_secret=abcdef1234567890", True],
        ["client_secret : zyxwv987654321", True],
        ["client_secret=abc", False]
    ],
    "xsrf_token_cookie": [
        ["XSRF-TOKEN=abcd1234", True],
        ["Set-Cookie: XSRF-TOKEN=xyz9876abcd; Path=/", True],
    ],
}


@pytest.mark.parametrize("pattern,cases", test_cases.items())
def test_patterns_match(pattern, cases):
    for text, should_match in cases:
        matches = scanner.scan_text(text)
        found = any(m.pattern == pattern for m in matches)
        assert found == should_match, f"Failed for {pattern} with text: {text}"
