from __future__ import annotations
import argparse
import base64
import json
from .registry import PatternRegistry, NlpRuleRegistry
from .scanner import GuardrailScanner
from .redactor import Redactor


def _build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Regex/NLP Guardrail CLI")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--scan-text", dest="text")
    g.add_argument("--scan-file", dest="file")
    g.add_argument("--scan-base64", dest="b64")
    p.add_argument("--include-regex", nargs="*", help="Regex pattern names to include (default: all)")
    p.add_argument("--include-nlp", nargs="*", help="NLP rule names to include (default: all)")
    p.add_argument("--redact", action="store_true")
    p.add_argument("--format", choices=["json", "text"], default="text")
    return p


def main() -> int:
    args = _build_argparser().parse_args()
    reg = PatternRegistry.load_builtin()
    nlpreg = NlpRuleRegistry.load_builtin()
    regex = reg.list_all() if not args.include_regex else [p for p in reg.list_all() if p.name in set(args.include_regex)]
    nlp_rules = nlpreg.list_all() if not args.include_nlp else [r for r in nlpreg.list_all() if r.name in set(args.include_nlp)]

    if args.text:
        text = args.text
    elif args.file:
        with open(args.file, "rb") as f:
            raw = f.read()
        text = raw.decode("utf-8", errors="replace")
    else:
        raw = base64.b64decode(args.b64)
        text = raw.decode("utf-8", errors="replace")

    scanner = GuardrailScanner(regex, nlp_rules)
    matches = scanner.scan_text(text)

    if args.format == "json":
        out = {
            "findings": [m.__dict__ for m in matches],
            "counts": {},
        }
        for m in matches:
            out["counts"].setdefault(m.pattern, 0)
            out["counts"][m.pattern] += 1
        if args.redact:
            out["redacted_text"] = Redactor(regex).apply(text, matches)
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        for m in matches:
            print(f"[{m.severity.upper()}] {m.pattern} @ line {m.line}, col {m.col}: {m.preview}")
        if args.redact:
            print("\n--- Redacted ---\n")
            print(Redactor(regex).apply(text, matches))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())