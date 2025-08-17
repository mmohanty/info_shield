from __future__ import annotations
from typing import List
from ..model import PatternDef

def get_patterns() -> List[PatternDef]:
    return [
        PatternDef(
            name="aws_access_key_id",
            description="AWS Access Key ID",
            category="Secrets",
            severity="critical",
            regex=r"\bAKIA[0-9A-Z]{16}\b",
            redact="[AWS_ACCESS_KEY_ID]",
        ),
        PatternDef(
            name="aws_secret_access_key_like",
            description="Possible AWS secret key (heuristic)",
            category="Secrets",
            severity="critical",
            regex=r"(?i)(?:aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*)([A-Za-z0-9/+=]{40})",
            redact="[AWS_SECRET_ACCESS_KEY]",
        ),
        PatternDef(
            name="jwt",
            description="JWT token",
            category="Secrets",
            severity="high",
            regex=r"\beyJ[0-9A-Za-z_-]+\.[0-9A-Za-z_-]+\.[0-9A-Za-z_-]+\b",
            redact="[JWT]",
        ),
    ]