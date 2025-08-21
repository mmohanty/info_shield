from __future__ import annotations
from typing import Dict, Iterable, List, Optional, Pattern, Tuple, Any
import re
from .model import PatternDef, MatchResult, BaseNlpRule, KeywordDef
from .config import MAX_FINDINGS_PER_PATTERN
from .preprocess.registry import apply_chain, PreprocessorRegistry


class GuardrailScanner:
    """Scans text using a mix of regex patterns and NLP rules."""

    def __init__(self,
                 pattern_defs: Iterable[PatternDef],
                 nlp_rules: Iterable[BaseNlpRule] | None = None,
                 max_findings_per_pattern: int = MAX_FINDINGS_PER_PATTERN,
                 keyword_defs: Optional[List[KeywordDef]] = None,
                 preprocessors: Optional[List[str]] = None,
                 preproc_registry: Optional[PreprocessorRegistry] = None,
                 validators=None,
                 ):
        self.pattern_defs: List[PatternDef] = list(pattern_defs)
        self.keyword_defs = keyword_defs or []
        self.compiled: Dict[str, Pattern[str]] = {p.name: p.compile() for p in self.pattern_defs}
        self.nlp_rules: List[BaseNlpRule] = list(nlp_rules) if nlp_rules else []
        self.max_findings_per_pattern = max(1, int(max_findings_per_pattern))
        self.preproc_registry = preproc_registry or PreprocessorRegistry.load_builtin()
        self.default_preproc_chain = preprocessors or []
        self.validators = validators# ordered list of names
        self._defs_by_name = {p.name: p for p in self.pattern_defs}

    @staticmethod
    def _line_col(text: str, index: int) -> Tuple[int, int]:
        line = text.count("\n", 0, index) + 1
        last_nl = text.rfind("\n", 0, index)
        col = index - (last_nl + 1)
        return line, col + 1

    @staticmethod
    def _preview(text: str, start: int, end: int, window: int = 24) -> str:
        left = max(0, start - window)
        right = min(len(text), end + window)
        return text[left:start] + "[" + text[start:end] + "]" + text[end:right]

    def _resolve_chain_names(self, override: Optional[List[str]]) -> Tuple[str, ...]:
        # None -> inherit default; [] -> explicitly none; list -> that list
        if override is None:
            return tuple(self.default_preproc_chain)
        return tuple(override)

    def _get_preprocessed(self, text: str, cache: Dict[Tuple[str, ...], Tuple[str, List[int]]],
                          chain_names: Tuple[str, ...], *, context=None):
        if chain_names not in cache:
            if chain_names:
                chain = self.preproc_registry.resolve_chain(chain_names)
                pre = apply_chain(text, chain, context=context)
                cache[chain_names] = (pre.text, pre.index_map)
            else:
                cache[chain_names] = (text, list(range(len(text))))
        return cache[chain_names]

    def _scan_regex(self, text: str, *, context=None) -> List[MatchResult]:
        results: List[MatchResult] = []
        cache: Dict[Tuple[str, ...], Tuple[str, List[int]]] = {}
        for pdef in self.pattern_defs:

            chain_names = self._resolve_chain_names(pdef.preprocessors)
            ptext, pmap = self._get_preprocessed(text, cache, chain_names)

            regex = self.compiled[pdef.name]
            count = 0
            for m in regex.finditer(ptext):
                value = m.group(1) if m.lastindex else m.group(0)
                # if pdef.validators:
                #     valid = all(v(value) for v in pdef.validators)
                #     if valid is False:
                #         continue
                line, col = self._line_col(ptext, m.start())
                mr = MatchResult(
                    pattern=pdef.name,
                    category=pdef.category,
                    severity=pdef.severity,
                    value=value,
                    start=m.start(),
                    end=m.end(),
                    line=line,
                    col=col,
                    preview=self._preview(text, m.start(), m.end()),
                    valid=None,
                )
                if self.validators is not None:
                    mr = self._validate_match(mr, ptext)
                else:
                    mr.valid = True  # default when no validators are present

                if mr.valid:  # <-- only add valid matches
                    results.append(mr)
                    count += 1
                    if count >= self.max_findings_per_pattern:
                        break
        return results

    # if you implemented validators earlier:
    def _validate_match(self, mr: MatchResult, full_text: str) -> MatchResult:
        pdef = self._defs_by_name.get(mr.pattern)
        if not pdef or not getattr(pdef, "validators", None):
            mr.valid = True
            return mr
        ctx = {"full_text": full_text, "pattern_def": pdef, "match_span": (mr.start, mr.end)}
        for vname in pdef.validators:
            v = self.validators.get(vname) if hasattr(self.validators, "get") else None
            if not v:
                continue
            res = v.validate(mr.value, context=ctx)
            if not res.ok:
                mr.valid = False
                mr.validation_reason = res.reason or vname
                return mr
        mr.valid = True
        return mr

    def _scan_keywords(self, text: str, *, context=None) -> List[MatchResult]:  # NEW
        """
        Build a single alternation regex per KeywordDef (escaping phrases),
        apply per-pattern preprocessors, map spans back, emit MatchResult.
        """
        results: List[MatchResult] = []
        cache: Dict[Tuple[str, ...], Tuple[str, List[int]]] = {}

        for kdef in self.keyword_defs:
            if not kdef.phrases:
                continue
            chain_names = self._resolve_chain_names(kdef.preprocessors)
            ptext, pmap = self._get_preprocessed(text, cache, chain_names)

            # Compile alternation of escaped phrases
            parts = []
            for ph in kdef.phrases:
                esc = re.escape(ph)
                if kdef.whole_word:
                    esc = rf"\b{esc}\b"
                parts.append(f"(?:{esc})")
            flags = re.MULTILINE | (0 if kdef.case_sensitive else re.IGNORECASE)
            union = re.compile("|".join(parts), flags)

            count = 0
            for m in union.finditer(ptext):
                pstart, pend = m.start(), m.end()
                start = pmap[pstart]
                end = pmap[pend - 1] + 1
                value = text[start:end]
                mr = MatchResult(
                    pattern=kdef.name,  # name of the keyword pack
                    category=kdef.category,
                    severity=kdef.severity,
                    value=value,
                    start=start,
                    end=end,
                    line=text.count("\n", 0, start) + 1,
                    col=start - (text.rfind("\n", 0, start) + 1) + 1,
                    preview=text[max(0, start - 24):start] + "⟦" + value + "⟧" + text[end:end + 24],
                    valid=None
                )
                if self.validators is not None:
                    mr = self._validate_match(mr, ptext)
                else:
                    mr.valid = True  # default when no validators are present

                if mr.valid:  # <-- only add valid matches
                    results.append(mr)
                    count += 1
                    if count >= self.max_findings_per_pattern:
                        break

        return results

    def _scan_nlp(self, text: str) -> List[MatchResult]:
        results: List[MatchResult] = []
        for rule in self.nlp_rules:
            results.extend(rule.find(text))
        return results

    def scan_text(self, text: str, *, preprocess_context: Optional[Dict[str, Any]] = None) -> List[MatchResult]:
        results = self._scan_regex(text, context=preprocess_context)
        results += self._scan_keywords(text, context=preprocess_context)
        results += self._scan_nlp(text)
        severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        results.sort(key=lambda r: (severity_rank.get(r.severity, 9), r.start))
        return results