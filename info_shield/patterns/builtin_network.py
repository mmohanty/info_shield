from __future__ import annotations
from typing import List
from ..model import PatternDef

def get_patterns() -> List[PatternDef]:
    return [
        PatternDef(
            name="ipv4",
            description="IPv4 address",
            category="Network",
            severity="low",
            regexes=[r"(?x)\b(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"],
        ),
    ]