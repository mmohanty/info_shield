from __future__ import annotations
from typing import List
from .engine import SpaCyEngine
from ..model import BaseNlpRule, MatchResult
from ..config import SPACY_MODEL

class PersonNameNerRule(BaseNlpRule):
    name = "person_name_ner"
    description = "Detect PERSON entities via spaCy NER"
    category = "PII"
    severity = "medium"

    def __init__(self, model: str = SPACY_MODEL):
        self.engine = SpaCyEngine(model)

    def find(self, text: str) -> List[MatchResult]:
        nlp = self.engine.load()
        doc = nlp(text)
        out: List[MatchResult] = []
        for ent in doc.ents:
            if ent.label_ == "PERSON":
                start, end = ent.start_char, ent.end_char
                line = text.count("\n", 0, start) + 1
                col = start - (text.rfind("\n", 0, start) + 1)
                preview = text[max(0, start-24):start] + "[" + text[start:end] + "]" + text[end:min(len(text), end+24)]
                out.append(MatchResult(
                    pattern=self.name,
                    category=self.category,
                    severity=self.severity,
                    value=ent.text,
                    start=start,
                    end=end,
                    line=line,
                    col=col+1,
                    preview=preview,
                    valid=None,
                ))
        return out

# You can add more spaCy rules here, e.g., medical terms using PhraseMatcher, custom patterns, etc.

def get_rules() -> List[BaseNlpRule]:
    return [PersonNameNerRule()]