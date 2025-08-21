from __future__ import annotations
from typing import List
import unicodedata
from .base import Preprocessor, PreprocessResult

class StripZeroWidth(Preprocessor):
    """Remove ZERO WIDTH characters & control separators often used to evade regex."""
    name = "strip_zero_width"
    ZW = {0x200B, 0x200C, 0x200D, 0xFEFF}
    def apply(self, text: str, index_map: List[int], *, context =None) -> PreprocessResult:
        out_chars: List[str] = []
        out_map: List[int] = []
        for i, ch in enumerate(text):
            if ord(ch) in self.ZW:
                continue
            out_chars.append(ch)
            out_map.append(index_map[i])
        return PreprocessResult("".join(out_chars), out_map)

class NormalizeWhitespace(Preprocessor):
    """Collapse runs of whitespace to a single space."""
    name = "normalize_whitespace"
    def apply(self, text: str, index_map: List[int], *, context=None) -> PreprocessResult:
        out_chars: List[str] = []
        out_map: List[int] = []
        i = 0
        n = len(text)
        while i < n:
            ch = text[i]
            if ch.isspace():
                # write one space
                out_chars.append(" ")
                out_map.append(index_map[i])
                # skip following whitespace
                i += 1
                while i < n and text[i].isspace():
                    i += 1
                continue
            out_chars.append(ch)
            out_map.append(index_map[i])
            i += 1
        return PreprocessResult("".join(out_chars), out_map)

class ToLower(Preprocessor):
    """Lowercase entire text (use when your exact/regex are case-insensitive)."""
    name = "lower"
    def apply(self, text: str, index_map: List[int], *, context=None) -> PreprocessResult:
        # 1:1 mapping; just replace chars
        return PreprocessResult(text.lower(), index_map[:])

class Deaccent(Preprocessor):
    name = "deaccent"
    def apply(self, text: str, index_map: List[int], *, context=None) -> PreprocessResult:
        out_chars: List[str] = []
        out_map: List[int] = []
        for i, ch in enumerate(text):
            nk = unicodedata.normalize("NFKD", ch)
            for sub in nk:
                if unicodedata.combining(sub):
                    # drop combining mark (no output char)
                    continue
                out_chars.append(sub)
                out_map.append(index_map[i])  # map all emitted chars to original index i
        return PreprocessResult("".join(out_chars), out_map)

