from info_shield.model import KeywordDef

def get_keyword_packs():
    return [
        KeywordDef(
            name="security_blocklist_ci",
            phrases=[
                "do not share", "internal only", "company proprietary",
                "subject to nda", "export controlled information"
            ],
            category="Keyword",
            severity="low",
            case_sensitive=False,
            whole_word=False,
            # strip ZW, collapse spaces, lowercase for robustness:
            preprocessors=["strip_zero_width", "normalize_whitespace", "lower"],
        ),
        KeywordDef(
            name="risky_software_terms_cs",
            phrases=["debug build", "unsafe_mode", "god_mode"],
            category="Keyword",
            severity="medium",
            case_sensitive=True,  # must match exactly
            whole_word=False,
            preprocessors=[],     # raw text only
        ),
    ]
