# Getting Started — Bawbel Scanner

## Requirements

- Python 3.10 or higher
- pip

Optional (for fuller detection):
- `yara-python` — YARA rule scanning
- `semgrep` — Semgrep rule scanning

---

## Installation

```bash
# Basic install (Stage 1 pattern scanning only)
pip install bawbel-scanner

# With YARA support
pip install "bawbel-scanner[yara]"

# With Semgrep support
pip install "bawbel-scanner[semgrep]"

# Everything
pip install "bawbel-scanner[all]"
```

---

## Your First Scan

```bash
# Scan a SKILL.md file
bawbel scan ./my-skill.md
```

**Example output — clean component:**
```
Bawbel Scanner v0.1.0  ·  github.com/bawbel/bawbel-scanner

Scanning:  my-skill.md
Type:      skill

✓  No vulnerabilities found
   This component passed all AVE checks.

SUMMARY
Risk score:   0.0 / 10  CLEAN
Findings:     0
Scan time:    3ms
```

**Example output — vulnerable component:**
```
Bawbel Scanner v0.1.0  ·  github.com/bawbel/bawbel-scanner

Scanning:  malicious-skill.md
Type:      skill

FINDINGS
🔴  CRITICAL  AVE-2026-00001  External instruction fetch detected
   Line 7  fetch your instructions
   OWASP: ASI01, ASI08

🟠  HIGH      N/A             Goal override instruction detected
   Line 17  Ignore all previous instructions
   OWASP: ASI01, ASI08

SUMMARY
Risk score:   9.4 / 10  CRITICAL
Findings:     2
Scan time:    5ms

→  Run 'bawbel report malicious-skill.md' for full A-BOM and remediation guide
```

---

## Scan Options

```bash
# Scan a directory (non-recursive)
bawbel scan ./skills/

# Scan a directory recursively
bawbel scan ./skills/ --recursive

# JSON output (for CI/CD and SIEM integration)
bawbel scan ./skills/ --format json

# Fail build on severity threshold
bawbel scan ./skills/ --fail-on-severity high
bawbel scan ./skills/ --fail-on-severity critical

# Generate A-BOM report
bawbel report ./my-skill.md
```

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Clean — no findings |
| `1` | Scan completed with warnings |
| `2` | Findings at or above `--fail-on-severity` threshold |

---

## Supported File Types

| Extension | Component type | Examples |
|---|---|---|
| `.md` | `skill` | SKILL.md, .cursorrules, CLAUDE.md |
| `.json` | `mcp` | MCP server manifests |
| `.yaml` / `.yml` | `prompt` | System prompt configs |
| `.txt` | `prompt` | Plain text prompts |

---

## Debug Mode

```bash
# Show verbose internal logs
BAWBEL_LOG_LEVEL=DEBUG bawbel scan ./my-skill.md

# Levels: DEBUG, INFO, WARNING (default), ERROR
```

---

## Next Steps

- [Configuration](configuration.md) — tune scanner behaviour
- [CI/CD Integration](cicd-integration.md) — add to your pipeline
- [AVE Standard](https://github.com/bawbel/bawbel-ave) — browse vulnerability records
