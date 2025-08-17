# 🛡️ InfoShield

**InfoShield** is a modular **guardrail service** that detects and redacts sensitive information such as **PII, financial data, secrets, and jailbreak prompts** using **regex patterns** and optional **NLP (spaCy)** rules.
It supports **CLI, REST API (FastAPI), and GUI (PyQt5)**.

---

## ✨ Features

* 🔍 **Regex-based detection**: email, phone, Aadhaar, PAN, credit card (Luhn validated), IPv4, JWT, AWS keys, and more.
* 🤖 **NLP support (spaCy)**: detect person names, prompt injections, jailbreak heuristics.
* 🛠️ **Extensible**: easily add new regex patterns or NLP rules.
* 🖥️ **Multiple interfaces**:

  * **CLI** for scripting and automation
  * **REST API** with FastAPI
  * **GUI** (PyQt5) to pick rules per user
* 🔒 **Redaction**: configurable masking for detected entities.

---

## 🚀 Quick Start

### 1. Install

```bash
git clone https://github.com/your-org/info_shield.git
cd info_shield
python -m venv .venv && source .venv/bin/activate
pip install -e ".[api,gui,nlp]"
```

### 2. CLI

```bash
python -m info_shield.cli \
  --scan-text "Email a@b.com PAN ABCDE1234F 4111111111111111" \
  --redact --format json
```

### 3. GUI

```bash
python -m info_shield.gui.app
```

### 4. API

```bash
uvicorn info_shield.api.app:app --reload --port 8080
```

➡️ Open [http://127.0.0.1:8080/docs](http://127.0.0.1:8080/docs) for Swagger UI.

### 5. Tests

```bash
pytest -q
pytest -q tests/test_jailbreak.py
```

---

## 🧠 NLP (optional)

Enable spaCy rules:

```bash
pip install spacy
python -m spacy download en_core_web_sm
```

Now you can include NLP rules:

```bash
python -m info_shield.cli \
  --scan-text "John Doe met Alice" \
  --include person_name_ner
```

---

## 🔧 Add New Rules

### ➕ Regex Pattern

1. Create file: `info_shield/patterns/my_company.py`
2. Define `get_patterns()`:

```python
from info_shield.model import PatternDef

def get_patterns():
    return [
        PatternDef(
            name="employee_id",
            regex=r"EMP[0-9]{5}",
            category="PII",
            description="Employee ID"
        )
    ]
```

3. Register in `PatternRegistry.load_builtin()` or dynamically import.

### ➕ NLP Rule

1. Add new class in `info_shield/nlp/spacy_rules.py`:

```python
from info_shield.model import BaseNlpRule

class LocationRule(BaseNlpRule):
    name = "location_ner"
    def apply(self, doc):
        return [ent for ent in doc.ents if ent.label_ == "GPE"]
```

2. Register in `NlpRuleRegistry.load_builtin()`.

---

## 📦 Project Layout

```
info_shield/
│── api/        # FastAPI endpoints
│── cli.py      # CLI entrypoint
│── gui/        # PyQt5 GUI
│── patterns/   # Regex rules
│── nlp/        # NLP rules (spaCy)
│── tests/      # Pytest cases
pyproject.toml
README.md
```

---

## 🧪 Example API Request

```http
POST /scan
Content-Type: application/json

{
  "text": "My email is john@example.com and PAN is ABCDE1234F.",
  "options": {
    "redact": true,
    "include_regex": ["email", "india_pan"]
  }
}
```

Response:

```json
{
  "matches": [
    {"type": "email", "value": "john@example.com", "redacted": "j***@example.com"},
    {"type": "india_pan", "value": "ABCDE1234F", "redacted": "A*******F"}
  ]
}
```

---

## 🧩 Roadmap

* [ ] Add policy-based rule sets (HIPAA, PCI, GDPR presets)
* [ ] Add PDF/Doc ingestion
* [ ] Add vectorized semantic jailbreak detection

---

## 📜 License

MIT License © 2025
