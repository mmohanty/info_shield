import os

MAX_FINDINGS_PER_PATTERN = int(os.getenv("GR_MAX_FINDINGS_PER_PATTERN", "200"))
DEFAULT_REDACTION = os.getenv("GR_DEFAULT_REDACTION", "[REDACTED]")
PARTIAL_MASK_CHAR = os.getenv("GR_PARTIAL_MASK_CHAR", "*")
PARTIAL_MASK_KEEP_LAST = int(os.getenv("GR_PARTIAL_MASK_KEEP_LAST", "4"))

# GUI storage location for user rule sets
USER_RULE_DIR = os.getenv("GR_USER_RULE_DIR", os.path.expanduser("~/.regex_guardrail/users"))

# NLP
SPACY_MODEL = os.getenv("GR_SPACY_MODEL", "en_core_web_sm")