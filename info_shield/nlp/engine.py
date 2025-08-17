from __future__ import annotations
from typing import Any

class SpaCyEngine:
    """Lazy spaCy loader so the base package has no hard dependency.

    Usage:
        nlp = SpaCyEngine("en_core_web_sm").load()
        doc = nlp(text)
    """

    def __init__(self, model_name: str = "en_core_web_sm"):
        self.model_name = model_name
        self._nlp = None

    def load(self):
        if self._nlp is None:
            try:
                import spacy  # type: ignore
            except Exception as e:  # pragma: no cover
                raise RuntimeError("spaCy not installed. Run: pip install spacy && python -m spacy download en_core_web_sm") from e
            self._nlp = spacy.load(self.model_name)
        return self._nlp