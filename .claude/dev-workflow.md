# Local Development Workflow — Claude Code Context

This file is for Claude Code sessions only.
Full developer documentation is in docs/ — do not duplicate it here.

## Quick orientation for a new Claude Code session

```bash
source .venv/bin/activate                                    # always first
python cli.py scan tests/fixtures/skills/malicious/malicious_skill.md
# Expected: 2 findings, CRITICAL 9.4 — if this fails, stop
python -m pytest tests/ -q                                   # must be 125/125
```

## Where things live

| Task | Go to |
|---|---|
| First-time setup | `docs/guides/getting-started.md` |
| Configuration options | `docs/guides/configuration.md` |
| Docker usage | `docs/guides/docker.md` |
| CI/CD integration | `docs/guides/cicd-integration.md` |
| Adding a rule | `docs/guides/writing-rules.md` |
| Adding an engine | `docs/guides/adding-engine.md` |
| scan() API | `docs/api/scan.md` |
| Utils classes | `docs/api/utils.md` |
| All dev commands | `.claude/commands.md` |

## Common Claude Code tasks

### Fix a failing test
```bash
python -m pytest tests/test_scanner.py::ClassName::test_name -v
```

### Check a specific engine
```bash
BAWBEL_LOG_LEVEL=DEBUG python cli.py scan tests/fixtures/skills/malicious/malicious_skill.md
```

### Run security checks
```bash
bandit -r scanner/ cli.py config/ -f screen   # must be 0 issues
pip-audit -r requirements.txt                 # must be 0 CVEs
```

### Update progress log
```bash
python scripts/update_log.py -m "describe what you did"
```

## Before committing anything

```bash
python -m pytest tests/ -q                                # 125/125
python cli.py scan tests/fixtures/skills/malicious/malicious_skill.md  # 2 findings
bandit -r scanner/ cli.py config/ -f screen               # 0 issues
```
