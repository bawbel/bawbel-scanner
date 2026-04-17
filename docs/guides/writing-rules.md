# Writing Detection Rules

Three rule types are supported. Use the simplest one that works.

---

## Choosing a Rule Type

| Type | Use when | File |
|---|---|---|
| Pattern (regex) | Simple text matching | `scanner/engines/pattern.py` |
| YARA | Multi-string, binary, complex logic | `scanner/rules/yara/ave_rules.yar` |
| Semgrep | Structural patterns, AST matching | `scanner/rules/semgrep/ave_rules.yaml` |

**Start with pattern rules.** Add YARA or Semgrep only if regex is insufficient.

---

## Pattern Rules

Add to `PATTERN_RULES` in `scanner/engines/pattern.py`:

```python
{
    "rule_id":     "bawbel-your-rule",       # kebab-case, unique forever
    "ave_id":      "AVE-2026-NNNNN",         # or None
    "title":       "Brief title (max 80)",
    "description": "Full description of what this detects.",
    "severity":    Severity.HIGH,
    "cvss_ai":     8.0,
    "owasp":       ["ASI01"],
    "patterns": [
        r"your\s+regex\s+here",              # re.IGNORECASE applied
        r"alternative\s+pattern",
    ],
},
```

**Tips:**
- Use `\s+` not spaces — content may have irregular whitespace
- One finding per rule per file — first matching pattern wins
- Test each pattern: `python3 -c "import re; print(re.search(r'pattern', 'test', re.I))"`

---

## YARA Rules

Add to `scanner/rules/yara/ave_rules.yar`:

```yara
rule AVE_PascalCase_Description
{
    meta:
        ave_id       = "AVE-2026-NNNNN"
        attack_class = "Attack Class Name"
        severity     = "HIGH"
        cvss_ai      = "8.0"
        description  = "One sentence description."
        owasp        = "ASI01, ASI07"

    strings:
        $s1 = "exact string" nocase
        $s2 = /regex pattern/ nocase

    condition:
        any of ($s*)
}
```

Test: `yara scanner/rules/yara/ave_rules.yar tests/fixtures/skills/malicious/malicious_skill.md`

---

## Semgrep Rules

Add to `scanner/rules/semgrep/ave_rules.yaml`:

```yaml
rules:
  - id: ave-your-rule-name
    patterns:
      - pattern-regex: '(?i)your pattern here'
    message: >
      [HIGH] Title. Full description of the finding.
    languages: [generic]
    severity: ERROR
    metadata:
      ave_id: AVE-2026-NNNNN
      attack_class: "Attack Class Name"
      cvss_ai_score: 8.0
      owasp_mapping: [ASI01, ASI07]
```

Test: `semgrep --config scanner/rules/semgrep/ave_rules.yaml <file>`

---

## Required: Test Fixtures

Every rule needs two fixtures:

```bash
# Positive — must trigger the rule
echo "# Skill\n[triggering content]" > tests/fixtures/skills/malicious/ave_NNNNN_trigger.md

# Negative — must NOT trigger (false positive check)
echo "# Skill\n[innocent similar content]" > tests/fixtures/skills/clean/ave_NNNNN_clean.md
```

And a pytest test in `tests/test_scanner.py`:

```python
def test_detects_your_rule(self, tmp_path):
    path = write_skill(tmp_path, "s.md", "# Skill\n[triggering content]\n")
    result = scan(path)
    assert "bawbel-your-rule" in [f.rule_id for f in result.findings]

def test_your_rule_no_false_positive(self, tmp_path):
    path = write_skill(tmp_path, "s.md", "# Skill\n[innocent content]\n")
    result = scan(path)
    assert "bawbel-your-rule" not in [f.rule_id for f in result.findings]
```

---

## Full Guide

See `.claude/skills/add-detection-rule.md` for the complete step-by-step process
including AVE record lookup, commit conventions, and verification checklist.
