# Bawbel Scanner — Project Context

## What this is
Bawbel Scanner is an open-source CLI tool that scans agentic AI components
(SKILL.md files, MCP server manifests, system prompts, plugins) for security
vulnerabilities mapped to the AVE standard.

## Architecture
```
cli.py                     ← Click CLI entry point
scanner/
  scanner.py               ← Core scan() function — this is the main engine
  rules/
    yara/ave_rules.yar     ← YARA detection rules
    semgrep/ave_rules.yaml ← Semgrep detection rules
```

## Key conventions
- All findings must have: rule_id, title, severity, cvss_ai, engine
- AVE IDs are optional (assigned by PiranhaDB on publication)
- Severity enum: CRITICAL > HIGH > MEDIUM > LOW > INFO
- scan() must never raise — always return ScanResult (with error field if needed)
- New detection engines go in scanner/scanner.py as run_X_scan() functions
- New rules go in scanner/rules/yara/ or scanner/rules/semgrep/

## Detection stages
1. Pattern matching — regex, no deps, always runs
2. YARA — requires yara-python, graceful fallback if missing
3. Semgrep — requires semgrep CLI, graceful fallback if missing

## Running locally
```bash
pip install click rich
python cli.py scan ./path/to/skill.md
python cli.py scan ./skills/ --recursive --format json
```

## Running with Docker
```bash
docker build -t bawbel/scanner .
docker run --rm -v $(pwd)/skills:/scan:ro bawbel/scanner scan /scan --recursive
```

## Running tests
```bash
python cli.py scan tests/malicious_skill.md
# Expected: 2 findings, CRITICAL 9.4
```

## AVE Standard
github.com/bawbel/bawbel-ave — the vulnerability database this scanner queries.
Every rule in this scanner should reference an AVE record (ave_id field).

## Do not
- Add external API calls to scan() without a fallback
- Change the ScanResult or Finding dataclass field names (breaking change)
- Hardcode API keys anywhere
- Raise exceptions from scan() — catch and return ScanResult(error=...)