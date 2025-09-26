# scanner.py
import re
import unicodedata
from typing import Dict, List, Pattern, Tuple, Callable, Optional

import spacy

from info_shield.model import (
    PatternDef,
    KeywordDef,
    CompositePatternDef,
    BaseNlpRule,
    MatchResult,
)
from info_shield.preprocess.registry import PreprocessorRegistry

_PREPROC_REG = PreprocessorRegistry()

# ============================================================
# Scanner
# ============================================================
class GuardrailScanner:
    _nlp: Optional[spacy.language.Language] = None  # <-- declare here
    def __init__(
        self,
        pattern_defs: List[PatternDef] = None,
        keyword_defs: List[KeywordDef] = None,
        composite_defs: List[CompositePatternDef] = None,
        nlp_rules: List[BaseNlpRule] = None,
        validators: Dict[str, object] = None,
    ):
        self.pattern_defs = pattern_defs or []
        self.keyword_defs = keyword_defs or []
        self.composite_defs = composite_defs or []
        self.nlp_rules = nlp_rules or []
        self.validators = validators or {}

        self.max_findings_per_pattern = 50

        # compile regex upfront
        self.compiled: Dict[str, Pattern[str]] = {}
        for p in self.pattern_defs:
            if isinstance(p, PatternDef):
                self.compiled[p.name] = p.compile()

        # unified rule lookup
        self._defs_by_name = {
            **{p.name: p for p in self.pattern_defs},
            **{k.name: k for k in self.keyword_defs},
            **{c.name: c for c in self.composite_defs},
            **{r.name: r for r in self.nlp_rules},
        }

    # ============================================================
    # Public entrypoint
    # ============================================================
    def scan_text(self, text: str, *, context=None) -> List[MatchResult]:
        results: List[MatchResult] = []
        severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}

        for rule in (
            self.pattern_defs + self.keyword_defs + self.composite_defs + self.nlp_rules
        ):
            results.extend(self._scan_rule(rule, text, context))

        results.sort(key=lambda r: (severity_rank.get(r.severity, 9), r.start))
        return results

    # ============================================================
    # Rule dispatcher
    # ============================================================
    def _scan_rule(self, rule, text: str, context=None) -> List[MatchResult]:
        # Composite rules: handled separately
        if isinstance(rule, CompositePatternDef):
            matches = self._scan_composites(rule, text, None, text, context)

            # ✅ Validators are applied only at composite level
            if self.validators and getattr(rule, "validators", None):
                validated = []
                for mr in matches:
                    mr = self._validate_match(mr, text)
                    if mr.valid:
                        validated.append(mr)
                matches = validated

            return matches

        # Normal PatternDef / KeywordDef / NLP rule
        preprocessors = getattr(rule, "preprocessors", []) or []
        chain = _PREPROC_REG.resolve_chain(preprocessors)
        ptext, pmap = self._get_preprocessed(text, {}, chain, context=context)

        if isinstance(rule, PatternDef):
            matches = self._scan_regex(rule, ptext, pmap, text)
        elif isinstance(rule, KeywordDef):
            matches = self._scan_keywords(rule, ptext, pmap, text)
        elif isinstance(rule, BaseNlpRule):
            matches = self._scan_nlp(rule, ptext, pmap, text, context)
        else:
            matches = []

        # ✅ Validators only for non-composites
        if self.validators and getattr(rule, "validators", None):
            validated = []
            for mr in matches:
                mr = self._validate_match(mr, text)
                if mr.valid:
                    validated.append(mr)
            matches = validated

        return matches

    # ============================================================
    # Regex scanning
    # ============================================================
    def _scan_regex(self, rule: PatternDef, ptext, pmap, raw_text) -> List[MatchResult]:
        rx = self.compiled.get(rule.name) or rule.compile()
        self.compiled[rule.name] = rx

        results = []
        for count, m in enumerate(rx.finditer(ptext), 1):
            start = pmap[m.start()]
            end = pmap[m.end() - 1] + 1
            value = raw_text[start:end]
            results.append(
                MatchResult(
                    pattern=rule.name,
                    category=rule.category,
                    severity=rule.severity,
                    value=value,
                    start=start,
                    end=end,
                    valid=True,
                )
            )
            if count >= self.max_findings_per_pattern:
                break
        return results

    # ============================================================
    # Keyword scanning
    # ============================================================
    def _scan_keywords(self, rule, ptext, pmap, raw_text) -> List[MatchResult]:
        results = []
        search_text = ptext if not rule.case_sensitive else raw_text
        phrases = rule.phrases or []

        for phrase in phrases:
            idx = (
                search_text.lower().find(phrase.lower())
                if not rule.case_sensitive
                else search_text.find(phrase)
            )
            while idx != -1:
                start = pmap[idx]
                end = pmap[idx + len(phrase) - 1] + 1
                value = raw_text[start:end]
                results.append(
                    MatchResult(
                        pattern=rule.name,
                        category=rule.category,
                        severity=rule.severity,
                        value=value,
                        start=start,
                        end=end,
                        valid=True,
                    )
                )
                idx = search_text.find(phrase, idx + 1)
        return results

    # ============================================================
    # Composite scanning
    # ============================================================
    def _scan_composites(
        self, rule, ptext, pmap, raw_text, context=None
    ) -> List[MatchResult]:
        results: List[MatchResult] = []
        preproc_cache: Dict[Tuple[str, ...], Tuple[str, List[int]]] = {}

        sub_hits: Dict[str, List[Tuple[int, int]]] = {}
        truth: Dict[str, bool] = {}
        confs: Dict[str, float] = {}

        for part in rule.parts:
            chain = _PREPROC_REG.resolve_chain(
                part.preprocessors if part.preprocessors is not None else rule.preprocessors
            )
            psub_text, pmap_sub = self._get_preprocessed(
                raw_text, preproc_cache, chain, context=context
            )

            rx = re.compile(part.regex, part.flags or 0)
            hits = []
            for count, m in enumerate(rx.finditer(psub_text), 1):
                start = pmap_sub[m.start()]
                end = pmap_sub[m.end() - 1] + 1
                hits.append((start, end))
                if count >= self.max_findings_per_pattern:
                    break

            ok = len(hits) >= part.min_count
            if part.negate:
                ok = not ok
                hits = [] if ok else hits

            sub_hits[part.name] = hits
            truth[part.name] = ok
            confs[part.name] = part.confidence

        if rule.boolean_expr:
            overall_ok = self._eval_boolean(rule.boolean_expr, truth)
        else:
            overall_ok = all(truth.values()) if rule.op == "AND" else any(truth.values())

        if not overall_ok:
            return []

        contributing = []
        for part in rule.parts:
            if not part.negate and truth.get(part.name, False):
                contributing.extend(sub_hits.get(part.name, []))

        if not contributing:
            return []

        start = min(s for s, _ in contributing)
        end = max(e for _, e in contributing)
        value = raw_text[start:end]

        avg_conf = (
            sum(confs[p.name] for p in rule.parts if not p.negate and truth.get(p.name, False))
            / max(1, sum(1 for p in rule.parts if not p.negate and truth.get(p.name, False)))
        )
        likelihood = (
            "MostLikely" if avg_conf >= 0.9 else "Likely" if avg_conf >= 0.6 else "Possible"
        )

        mr = MatchResult(
            pattern=rule.name,
            category=rule.category,
            severity=rule.severity,
            value=value,
            start=start,
            end=end,
            line=raw_text.count("\n", 0, start) + 1,
            col=start - (raw_text.rfind("\n", 0, start) + 1),
            preview=raw_text[max(0, start - 24):start]
            + "⟦"
            + value
            + "⟧"
            + raw_text[end : end + 24],
            valid=True,
        )
        mr.likelihood = likelihood
        results.append(mr)
        return results

    # ============================================================
    # NLP scanning
    # ============================================================
    def _scan_nlp(self, rule, ptext, pmap, raw_text, context=None) -> List[MatchResult]:
        results: List[MatchResult] = []
        if not hasattr(self, "_nlp") or self._nlp is None:
            return results

        doc = self._nlp(raw_text)
        for span in rule.find(doc):
            start, end = span.start_char, span.end_char
            value = raw_text[start:end]
            mr = MatchResult(
                pattern=rule.name,
                category=getattr(rule, "category", "NLP"),
                severity=getattr(rule, "severity", "medium"),
                value=value,
                start=start,
                end=end,
                line=raw_text.count("\n", 0, start) + 1,
                col=start - (raw_text.rfind("\n", 0, start) + 1),
                preview=raw_text[max(0, start - 24):start]
                + "⟦"
                + value
                + "⟧"
                + raw_text[end : end + 24],
                valid=True,
            )
            results.append(mr)
        return results

    # ============================================================
    # Validators
    # ============================================================
    def _validate_match(self, mr: MatchResult, full_text: str) -> MatchResult:
        rule = self._defs_by_name.get(mr.pattern)
        if not rule or not getattr(rule, "validators", None):
            mr.valid = True
            return mr

        for vname in rule.validators:
            validator = self.validators.get(vname)
            if not validator:
                continue
            res = validator.validate(mr.value, {"text": full_text, "match": mr})
            if not res.ok:
                mr.valid = False
                mr.validation_reason = res.reason or vname
                return mr
        mr.valid = True
        return mr

    # ============================================================
    # Helpers
    # ============================================================
    def _get_preprocessed(self, text: str, cache, chain, context=None):
        if not chain:
            return text, list(range(len(text)))

        key = tuple(p.name for p in chain)
        if key in cache:
            return cache[key]

        out = text
        for p in chain:
            out = p.apply(out)

        # naive mapping (assumes transformations don’t alter length except for deletions)
        mapping = list(range(len(text)))[: len(out)]
        cache[key] = (out, mapping)
        return out, mapping

    def _eval_boolean(self, expr: str, truth: Dict[str, bool]) -> bool:
        local_vars = {k: truth.get(k, False) for k in truth}
        try:
            return eval(expr, {}, local_vars)
        except Exception:
            return False
