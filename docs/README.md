# Bawbel Scanner — Documentation

## What is this?

Bawbel Scanner is an open-source CLI tool that scans agentic AI components
(SKILL.md files, MCP server manifests, system prompts, plugins) for security
vulnerabilities mapped to the [AVE standard](https://github.com/bawbel/bawbel-ave).

---

## Documentation Index

### Guides — for developers and users

| Document | Description |
|---|---|
| [Getting Started](guides/getting-started.md) | Install, run your first scan, understand output |
| [Configuration](guides/configuration.md) | Environment variables, config options |
| [CI/CD Integration](guides/cicd-integration.md) | GitHub Actions, GitLab, Jenkins, CircleCI |
| [Docker](guides/docker.md) | Running via Docker and Docker Compose |
| [Writing Rules](guides/writing-rules.md) | Add YARA and Semgrep detection rules |
| [Adding an Engine](guides/adding-engine.md) | Add a new detection stage |

### API Reference — for contributors

| Document | Description |
|---|---|
| [scan()](api/scan.md) | Main public API |
| [Finding](api/finding.md) | Finding dataclass |
| [ScanResult](api/scan-result.md) | ScanResult dataclass |
| [Engines](api/engines.md) | Engine interface contract |
| [Utils](api/utils.md) | Utility classes reference |
| [Messages](api/messages.md) | Error codes and log messages |

### Decisions — why things are the way they are

| Document | Description |
|---|---|
| [ADR-001: Engine separation](decisions/adr-001-engine-separation.md) | Why each engine is a separate file |
| [ADR-002: OOP utils](decisions/adr-002-oop-utils.md) | Why utils uses classes with function aliases |
| [ADR-003: Error codes](decisions/adr-003-error-codes.md) | Why errors use E-codes not raw messages |
| [ADR-004: No exceptions from scan()](decisions/adr-004-no-exceptions.md) | Why scan() never raises |

---

## Quick Reference

```bash
# Install
pip install bawbel-scanner

# Scan a file
bawbel scan ./my-skill.md

# Scan a directory
bawbel scan ./skills/ --recursive

# Fail CI on high severity
bawbel scan ./skills/ --fail-on-severity high

# JSON output for SIEM
bawbel scan ./skills/ --format json

# Enable debug logging
BAWBEL_LOG_LEVEL=DEBUG bawbel scan ./my-skill.md
```

---

## AVE Standard

Every finding maps to an AVE record.
Browse records: [github.com/bawbel/bawbel-ave](https://github.com/bawbel/bawbel-ave)
