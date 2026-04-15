<div align="center">

# Bawbel Scanner

**The open-source CLI scanner for agentic AI components**

[![License](https://img.shields.io/badge/License-Apache_2.0-teal.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://python.org)
[![PyPI](https://img.shields.io/badge/PyPI-bawbel--scanner-teal.svg)](https://pypi.org/project/bawbel-scanner)
[![AVE Standard](https://img.shields.io/badge/AVE-Standard-green.svg)](https://github.com/bawbel/bawbel-ave)
[![Contributions Welcome](https://img.shields.io/badge/Contributions-Welcome-brightgreen.svg)](CONTRIBUTING.md)

[Documentation](https://bawbel.io/docs) · [AVE Standard](https://github.com/bawbel/bawbel-ave) · [bawbel.io](https://bawbel.io)

</div>

---

## What is Bawbel Scanner?

Bawbel Scanner is a free, open-source CLI tool that scans **agentic AI components** for security vulnerabilities before they reach production.

It detects threats in:
- **SKILL.md files** — Claude Code, Cursor, Codex, Windsurf
- **MCP server manifests** — any MCP-compatible agent
- **System prompts** — LLM deployment instructions
- **Agent plugins** — Copilot, AgentForce, Bedrock
- **A2A protocol configs** — agent-to-agent handlers

Findings are matched against the **[AVE database](https://github.com/bawbel/bawbel-ave)** — the open standard for agentic vulnerability enumeration.

---

## Quick Start

```bash
pip install bawbel-scanner
bawbel scan ./my-skill.md
```

**Example output:**
```
Bawbel Scanner v0.1.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Scanning: my-skill.md
Component type: skill

FINDINGS
────────
[CRITICAL 9.4]  AVE-2026-00001  Metamorphic Payload
                External config fetch detected — skill fetches
                instructions from https://rentry.co/config at runtime

SUMMARY
───────
Risk score:     9.4 / 10  CRITICAL
Findings:       1
Scan time:      0.3s

→ Run 'bawbel report my-skill.md' for full A-BOM and remediation guide
```

---

## Installation

**Requirements:** Python 3.10+

```bash
# Using pip
pip install bawbel-scanner

# Using uv (recommended)
uv pip install bawbel-scanner
```

---

## Usage

### Scan a single component
```bash
bawbel scan ./my-skill.md
bawbel scan ./mcp-server.json
bawbel scan ./system-prompt.txt
```

### Scan a directory recursively
```bash
bawbel scan ./skills/ --recursive
```

### Output formats
```bash
bawbel scan ./my-skill.md --format text      # default
bawbel scan ./my-skill.md --format json
bawbel scan ./my-skill.md --format markdown
bawbel scan ./my-skill.md --format sarif     # for GitHub Code Scanning
```

### Generate a full A-BOM report
```bash
bawbel report ./my-skill.md
```

### CI/CD — fail build on findings
```bash
bawbel scan ./skills/ --fail-on-severity critical
bawbel scan ./skills/ --fail-on-severity high
```

### Exit codes
| Code | Meaning |
|---|---|
| `0` | Clean — no findings |
| `1` | Warnings found |
| `2` | Critical or high findings found |

---

## Detection Engines

Bawbel Scanner uses three detection stages:

| Stage | Engine | What it detects |
|---|---|---|
| **1 — Static** | YARA + Semgrep + Gitleaks | Hardcoded secrets, suspicious patterns, known malicious signatures |
| **2 — Semantic** | LLM analysis via LiteLLM | Prompt injection, goal hijack, shadow permissions |
| **3 — Behavioral** | Sandbox + eBPF | Runtime network egress, file access, syscall anomalies |

Stage 1 runs locally with no API key. Stages 2 and 3 require configuration.

---

## CI/CD Integrations

| Platform | Integration |
|---|---|
| GitHub Actions | [bawbel/bawbel-integrations](https://github.com/bawbel/bawbel-integrations) |
| GitLab CI | [bawbel/bawbel-integrations](https://github.com/bawbel/bawbel-integrations) |
| Jenkins | [bawbel/bawbel-integrations](https://github.com/bawbel/bawbel-integrations) |
| CircleCI | [bawbel/bawbel-integrations](https://github.com/bawbel/bawbel-integrations) |
| Bitbucket | [bawbel/bawbel-integrations](https://github.com/bawbel/bawbel-integrations) |
| Pre-commit | [bawbel/bawbel-integrations](https://github.com/bawbel/bawbel-integrations) |

---

## AVE Standard

Every finding is mapped to an **AVE record** — the open standard for agentic vulnerability enumeration.

```json
{
  "ave_id": "AVE-2026-00001",
  "attack_class": "Metamorphic Payload",
  "cvss_ai_score": 9.4,
  "owasp_mapping": ["ASI01", "ASI08"]
}
```

[→ Browse all AVE records](https://github.com/bawbel/bawbel-ave/tree/main/records)

---

## Configuration

Create a `bawbel.yml` in your project root:

```yaml
# bawbel.yml
version: "1"

scan:
  component_types:
    - skill
    - mcp
    - prompt
  fail_on_severity: high
  recursive: true

llm:
  enabled: false         # set true to enable Stage 2 semantic analysis
  provider: anthropic    # anthropic | openai | bedrock | vertex
  model: claude-sonnet-4-20250514

output:
  format: sarif
  file: bawbel-results.sarif
```

---

## Roadmap

| Version | Features |
|---|---|
| `v0.1.0` | Static analysis — YARA + Semgrep + Gitleaks |
| `v0.2.0` | LLM semantic analysis — Stage 2 |
| `v0.3.0` | A-BOM generator — CycloneDX output |
| `v0.4.0` | MCP server scanning |
| `v1.0.0` | Behavioral sandbox — Stage 3 |

---

## Contributing

Contributions welcome — detection rules, new component type support, bug fixes, and documentation.

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## Related Projects

| Project | Description |
|---|---|
| [bawbel-ave](https://github.com/bawbel/bawbel-ave) | AVE standard — the vulnerability database this scanner queries |
| [bawbel-integrations](https://github.com/bawbel/bawbel-integrations) | CI/CD integrations for all major pipeline platforms |
| [bawbel.io](https://bawbel.io) | Web scanner, verified registry, and enterprise platform |

---

## License

Apache License 2.0 — see [LICENSE](LICENSE)

---

<div align="center">
Built by <a href="https://bawbel.io">Bawbel</a> · <a href="https://twitter.com/bawbel_io">@bawbel_io</a> · <a href="https://linkedin.com/company/bawbel">LinkedIn</a>
</div>
