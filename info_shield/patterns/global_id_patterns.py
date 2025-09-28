# info_shield/patterns/global_id_patterns.py
import regex as re
from typing import List
from info_shield.model import PatternDef

# validators can be implemented in info_shield/validators/
# Example: cpf_validator, luhn_validator, iban_validator, aadhaar_validator, ssn_validator
# Each must implement validate(value: str, context: dict) -> ValidationResult

IGNORECASE = re.IGNORECASE

PATTERN_DEFS: List[PatternDef] = [
    # ---------------------------
    # National / government IDs
    # ---------------------------
    PatternDef(
        name="argentina_dni",
        regexes=[r"\b\d{7,8}\b"],  # 7–8 digits
        category="PII",
        severity="high",
        flags=0,
        description="Argentina DNI number (Documento Nacional de Identidad)",
    ),
    PatternDef(
        name="australia_tfn",
        regexes=[r"\b\d{8,9}\b"],
        category="PII",
        severity="high",
        flags=0,
        description="Australia Tax File Number (TFN)",
    ),
    PatternDef(
        name="belgium_national_register",
        regexes=[r"\b\d{11}\b", r"\b\d{2}\.\d{2}\.\d{2}-\d{3}\.\d{2}\b"],
        category="PII",
        severity="high",
        flags=0,
        description="Belgium National Register number (11 digits)",
    ),
    PatternDef(
        name="brazil_cpf",
        regexes=[r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b"],
        category="PII",
        severity="high",
        flags=0,
        description="Brazil CPF number (Cadastro de Pessoas Físicas)",
        validators=["cpf_validator"],
    ),
    PatternDef(
        name="canada_sin",
        regexes=[r"\b\d{3}\s?\d{3}\s?\d{3}\b", r"\b\d{3}[- ]?\d{3}[- ]?\d{3}\b"],
        category="PII",
        severity="high",
        flags=0,
        description="Canada Social Insurance Number (SIN)",
        validators=["luhn-validator"],  # SIN uses Luhn
    ),
    PatternDef(
        name="china_passport",
        regexes=[r"\b([EeKkGg]\d{8}|[A-Z]\d{7})\b"],
        category="PII",
        severity="high",
        flags=IGNORECASE,
        description="China Passport number (E, K, G prefix or similar)",
    ),
    PatternDef(
        name="china_resident_id",
        regexes=[
            r"\b\d{6}(19|20)?\d{2}\d{2}\d{2}\d{3}[0-9Xx]\b",
            r"\b\d{6}(?:\d{8}|\d{6})\d{3}[\dXx]?\b"
        ],
        category="PII",
        severity="high",
        flags=0,
        description="China Resident Identity Card number",
    ),
    PatternDef(
        name="colombia_cdc",
        regexes=[r"\b\d{6,10}\b"],  # CDC numbers can be 6–10 digits
        category="PII",
        severity="high",
        flags=0,
        description="Colombia CDC number (approximation)"
    ),
    PatternDef(
        name="finland_hetu",
        regexes=[r"\b\d{6}[-+A]\d{3}[0-9A-Y]\b"],
        category="PII",
        severity="high",
        flags=re.IGNORECASE,
        description="Finland National Identity Code (HETU)",
        validators=["hetu_validator"],  # validate date and checksum
    ),
    PatternDef(
        name="france_tin",
        regexes=[r"\b\d{13}\b"],  # NIR (may be 13 digits + key)
        category="PII",
        severity="high",
        flags=0,
        description="France Tax Identification Number (NIR, 13 digits, may include key)"
    ),
    PatternDef(
        name="hongkong_id",
        regexes=[
            r"[A-Z]{1,2}\d{6}\([0-9A]\)"
        ],
        category="PII",
        severity="high",
        flags=IGNORECASE,
        description="Hong Kong Identity Card (HKID)",
    ),
    PatternDef(
        name="india_aadhaar",
        regexes=[r"\b\d{4}\s?\d{4}\s?\d{4}\b"],
        category="PII",
        severity="critical",
        flags=0,
        description="India Aadhaar number (12-digit)",
        validators=["aadhaar_validator"],
    ),
    PatternDef(
        name="india_pan",
        regexes=[r"\b[A-Z]{5}\d{4}[A-Z]\b"],
        category="PII",
        severity="high",
        flags=IGNORECASE,
        description="India Permanent Account Number (PAN)",
    ),
    PatternDef(
        name="ireland_ppsn",
        regexes=[r"^\d{7}[A-Z]{1,2}$"],
        category="PII",
        severity="high",
        flags=re.IGNORECASE,
        description="Ireland Personal Public Service Number (PPSN)"
    ),
    PatternDef(
        name="italy_fiscal_code",
        regexes=[r"^[A-Z0-9]{16}$"],
        category="PII",
        severity="high",
        flags=re.IGNORECASE,
        description="Italy Fiscal Code (Codice Fiscale, 16 alphanumeric chars)"
    ),
    PatternDef(
        name="japan_my_number",
        regexes=[r"^\d{12}$"],
        category="PII",
        severity="high",
        description="Japan Individual Number (My Number, 12 digits)"
    ),
    PatternDef(
        name="korea_passport",
        regexes=[r"^[A-Z]\d{8}$"],
        category="PII",
        severity="high",
        flags=re.IGNORECASE,
        description="Korea Passport Number (1 letter + 8 digits)"
    ),
    PatternDef(
        name="korea_rrn",
        regexes=[r"\b\d{6}-\d{7}\b", r"\b\d{13}\b"],
        category="PII",
        severity="critical",
        flags=0,
        description="Korea Resident Registration Number (RRN)",
    ),
    PatternDef(
        name="korea_alien_registration_number",
        regexes=[r"\b\d{6}-[5678]\d{6}\b"],
        category="PII",
        severity="critical",
        flags=0,
        description="Korea Alien Registration Number (ARN)",
    ),
    PatternDef(
        name="mexico_curp",
        regexes=[r"^[A-Z]{4}\d{6}[A-Z0-9]{8}$"],
        category="PII",
        severity="high",
        flags=re.IGNORECASE,
        description="Mexico CURP (18-character unique population registry code)"
    ),
    PatternDef(
        name="netherlands_bsn",
        regexes=[r"^\d{9}$"],
        category="PII",
        severity="high",
        description="Netherlands BSN (9 digits, 11-proef checksum applies)"
    ),
    PatternDef(
        name="norway_ni",
        regexes=[r"^\d{11}$"],
        category="PII",
        severity="high",
        description="Norway National Identity Number (11 digits, DDMMYY + individual + checksum)"
    ),
    PatternDef(
        name="poland_id",
        regexes=[r"^\d{11}$"],
        category="PII",
        severity="high",
        description="Poland PESEL (11 digits, includes birthdate and checksum)"
    ),
    PatternDef(
        name="singapore_nric",
        regexes=[r"^[STFG]\d{7}[A-Z]$"],
        category="PII",
        severity="high",
        flags=re.IGNORECASE,
        description="Singapore NRIC/FIN (1 letter prefix, 7 digits, 1 letter checksum)"
    ),
    PatternDef(
        name="southafrica_id",
        regexes=[r"^\d{13}$"],
        category="PII",
        severity="high",
        description="South Africa ID number (13 digits, YYMMDD + sequence + checksum)"
    ),
    PatternDef(
        name="spain_dni",
        regexes=[r"^\d{8}[A-Z]$"],
        category="PII",
        severity="high",
        flags=re.IGNORECASE,
        description="Spain DNI (8 digits + 1 letter)"
    ),
    PatternDef(
        name="spain_ssn",
        regexes=[r"(?<![A-Za-z0-9])[A-Z]\d{7}[A-Z](?![A-Za-z0-9])"],  # possible patterns vary
        category="PII",
        severity="high",
        flags=IGNORECASE,
        description="Spain Social Security Number"
    ),
    PatternDef(
        name="sweden_id",
        regexes=[
            r"^\d{12}$",  # YYYYMMDDXXXX
            r"^\d{6}-\d{4}$",  # YYMMDD-XXXX
            r"(?<![0-9])\d{8}-\d{4}(?![0-9])",  # YYYYMMDD-XXXX
        ],
        category="PII",
        severity="high",
        description="Sweden National ID (personnummer, 12 digits or YYMMDD-XXXX)"
    ),
    PatternDef(
        name="switzerland_ssn",
        regexes=[r"^\d{13}$"],
        category="PII",
        severity="high",
        description="Switzerland AHV/AVS number (13 digits, often formatted with dots)"
    ),
    PatternDef(
        name="taiwan_id",
        regexes=[r"^[A-Z][12]\d{8}$"],
        category="PII",
        severity="high",
        flags=re.IGNORECASE,
        description="Taiwan National ID (1 letter + 1 gender digit [1/2] + 8 digits)"
    ),
    PatternDef(
        name="thailand_id",
        regexes=[
            r"^\d-\d{4}-\d{5}-\d{2}-\d$",  # hyphenated form
            r"^\d{13}$"  # compact 13-digit form
        ],
        category="PII",
        severity="high",
        description="Thailand National ID (13 digits, written with or without hyphens)"
    ),
    PatternDef(
        name="turkey_id",
        regexes=[r"^[1-9]\d{10}$"],
        category="PII",
        severity="high",
        description="Turkey National ID (11 digits, does not start with 0)"
    ),
    PatternDef(
        name="uk_nino",
        regexes=[
            r"^(?!BG)(?!GB)(?!KN)(?!NK)(?!NT)(?!TN)(?!ZZ)[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]$",
            r"^QQ\d{6}[A-D]$"  # special/test NINO
        ],
        category="PII",
        severity="high",
        flags=re.IGNORECASE,
        description="UK National Insurance Number (2 letters, 6 digits, optional suffix A-D; includes QQ test numbers)"
    ),
    PatternDef(
        name="us_ein",
        regexes=[
            r"(?<!\d)\d{2}-\d{7}(?!\d)"
        ],
        category="Financial",
        severity="high",
        flags=0,
        description="US Employer Identification Number (EIN)"
    ),
    PatternDef(
        name="us_itin",
        regexes=[
            r"(?<!\d)9\d{2}-\d{2}-\d{4}(?!\d)"
        ],
        category="PII",
        severity="high",
        description="US Individual Taxpayer Identification Number (ITIN)"
    ),
    PatternDef(
        name="us_ssn",
        regexes=[
            r"(?<!\d)(?!000|666|9\d{2})\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}(?!\d)"
        ],
        category="PII",
        severity="high",
        description="US Social Security Number (SSN)"
    ),
    PatternDef(
        name="venezuela_cdi",
        regexes=[
            r"\b[Vv]?\d{8,10}\b",  # allow V + 8–10 digits
            r"\b[VE]\d{7,8}\b"
        ],
        category="PII",
        severity="high",
        flags=re.IGNORECASE,
        description="Venezuela CDI number"
    ),
    # ... continue the same for other countries ...

    # ---------------------------
    # Financial identifiers
    # ---------------------------
    PatternDef(
        name="iban",
        regexes=[r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b"],
        category="Financial",
        severity="high",
        flags=IGNORECASE,
        description="International Bank Account Number (IBAN)",
        validators=["iban_validator"],
    ),
    PatternDef(
        name="credit_card_number",
        regexes=[
            r"\b(?:4[0-9]{12}(?:[0-9]{3})?"  # Visa
            r"|5[1-5][0-9]{14}"  # MasterCard
            r"|3[47][0-9]{13}"  # Amex
            r"|6(?:011|5[0-9]{2})[0-9]{12})\b"  # Discover
        ],
        category="Financial",
        severity="critical",
        flags=0,
        description="Credit card number (Visa, MasterCard, Amex, Discover)",
        validators=["luhn-validator"],
    ),
    PatternDef(
        name="financial_account_number_generic",
        regexes=[r"(?<!\d)\d{8,20}(?!\d)"],
        category="Financial",
        severity="high",
        flags=0,
        description="Generic financial account number (8–20 digits)"
    ),

    # ---------------------------
    # Secrets / Keys / Tokens
    # ---------------------------
    PatternDef(
        name="auth_token_generic",
        regexes=[
            r"(?i)\b(?:token|authorization|auth)[=\s:]{1,3}[A-Za-z0-9\-\._~\+/]{6,}(?:=*)"
        ],
        category="Secrets",
        severity="critical",
        description="Generic auth/authorization token",
    ),
    PatternDef(
        name="aws_access_key_1",
        regexes=[
            r"^(AKIA|ASIA)[0-9A-Z]{16}$"
        ],
        category="Secrets",
        severity="critical",
        flags=0,
        description="AWS Access Key ID",
    ),
    PatternDef(
        name="azure_auth_token",
        regexes=[
            r"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9[.-_A-Za-z0-9]{50,}"
            r"\b[A-Za-z0-9-_]{20,}\.[A-Za-z0-9-_]{20,}\.[A-Za-z0-9-_]{10,}\b|\beyJ[A-Za-z0-9-_]{30,}\b"
        ],
        category="Secrets",
        severity="critical",
        description="Azure Active Directory JWT access token (RS256)",
    ),
    PatternDef(
        name="encryption_key_like",
        regexes=[r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{32,}(?![0-9A-Fa-f])"],
        category="Secrets",
        severity="critical",
        description="Hexadecimal encryption key (128-bit or longer)",
        flags=0,
    ),
    PatternDef(
        name="gcp_service_account_key",
        regexes=[
            r"-----BEGIN PRIVATE KEY-----[\s\S]+?-----END PRIVATE KEY-----",  # any length
            r"\"type\"\s*:\s*\"service_account\""
        ],
        category="Secrets",
        severity="critical",
        description="Google Cloud Service Account key (PEM or JSON)",
        flags=re.MULTILINE,
    ),
    PatternDef(
        name="jwt_token",
        regexes=[
            r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b",
            r"\beyJ[0-9A-Za-z_-]+\.[0-9A-Za-z_-]+\.[0-9A-Za-z_-]+\b"
        ],
        category="Secrets",
        severity="critical",
        flags=IGNORECASE,
        description="JSON Web Token (JWT)",
        validators=["jwt_validator"],  # optional: decode header/payload
    ),
    PatternDef(
        name="oauth_client_secret_like",
        regexes=[r"(?<![A-Za-z0-9])[A-Za-z0-9\-_\.\+]{32,}(?![A-Za-z0-9])"],
        category="Secrets",
        severity="critical",
        flags=0,
        description="OAuth client secret heuristic (>=32 chars, safe charset)"
    ),
    PatternDef(
        name="oauth_client_secret_header",
        regexes=[
            "(?i)client_secret\s*=\s*[A-Za-z0-9_\-]{8,}",
            r"(?i)\bclient_secret\s*[:=]\s*[A-Za-z0-9_\-]{6,}"
        ],
        category="Secrets",
        severity="critical",
        flags=0,
        description="OAuth client secret Header"
    ),
    PatternDef(
        name="password_field_like",
        regexes=[
            r"(?i)\bpassword\s*=\s*[^&\s]{4,}",
            r"(?i)\b(pass(word)?|pwd)\s*=\s*[^&\s]{4,}"
        ],
        category="Secrets",
        severity="critical",
        flags=0,
        description="Password Like Field"
    ),
    PatternDef(
        name="ssl_certificate_pem",
        regexes=[
            r"-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----"
        ],
        category="Secrets",
        severity="critical",
        description="X.509 SSL/TLS certificate in PEM format",
        flags=re.MULTILINE,
    ),
    PatternDef(
        name="storage_signed_url",
        regexes=[
            r"https?://[^\s]+\?(?=.*(?:X-Amz-Credential|X-Amz-Signature|X-Amz-Algorithm|X-Goog-Expires|Expires|ExpiresIn))"
            r"[^\s]+"
        ],
        category="Secrets",
        severity="high",
        description="Signed cloud storage URL (AWS/GCP/Azure pre-signed URLs)",
        flags=re.IGNORECASE,
    ),
    PatternDef(
        name="storage_signed_policy_document",
        regexes=[
            r"policy=.*?Signature=.*",
            r"(?i)(policy|credential)=[^&\s]+&signature=[^&\s]+"
        ],
        category="Secrets",
        severity="high",
        description="Signed storage policy document string",
        flags=re.IGNORECASE,
    ),
    PatternDef(
        name="xsrf_token",
        regexes=[
            r"XSRF-TOKEN=[A-Za-z0-9\-_]{8,}",
            r"csrf_token[:=]\s*[A-Za-z0-9\-_]{8,}",
            r"(?i)xsrf[\-_]?token\s*=\s*[A-Za-z0-9_\-]{8,}"
        ],
        category="Secrets",
        severity="high",
        description="Cross-Site Request Forgery (XSRF/CSRF) token",
        flags=re.IGNORECASE,
    ),
    PatternDef(
        name="xsrf_token_cookie",
        regexes=[
            r"XSRF-TOKEN=[A-Za-z0-9\-_]{8,}",
            r"csrf_token[:=]\s*[A-Za-z0-9\-_]{8,}",
            r"(?i)xsrf[\-_]?token\s*=\s*[A-Za-z0-9_\-]{8,}"
        ],
        category="Secrets",
        severity="high",
        description="Cross-Site Request Forgery (XSRF/CSRF) tokens in cookie",
        flags=re.IGNORECASE,
    )

]


def get_patterns() -> List[PatternDef]:
    return PATTERN_DEFS
