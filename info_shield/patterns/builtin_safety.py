from __future__ import annotations
from typing import List
from ..model import PatternDef

def get_patterns() -> List[PatternDef]:
    return [
        PatternDef(
            name="jailbreak_ignore_instructions",
            description="Phrases like 'ignore all previous instructions'",
            category="Safety",
            severity="high",
            regex=r"(?i)\bignore\s+(?:all\s+)?previous\s+instructions\b",
        ),
        PatternDef(
            name="jailbreak_system_prompt",
            description="Mentions of 'system prompt' or 'developer instructions'",
            category="Safety",
            severity="medium",
            regex=r"(?i)\b(system\s*prompt|developer\s*instructions?)\b",
        ),
        PatternDef(
            name="jailbreak_roleplay_bypass",
            description="Roleplay/pretend to be X to bypass safety",
            category="Safety",
            severity="medium",
            regex=r"(?i)\b(?:pretend|role[-\s]?play)\s+to\s+be\b",
        ),
        PatternDef(
            name="jailbreak_disregard_policies",
            description="Ask to disregard rules/safety/policies",
            category="Safety",
            severity="high",
            regex=r"(?i)\b(disregard|bypass|circumvent)\s+(?:the\s+)?(?:rules?|safety|guardrails?|policy|policies)\b",
        ),
    ]
