# API Reference — scan()

## Overview

`scan()` is the single public entry point for all scanning operations.

```python
from scanner.scanner import scan

result = scan("/path/to/skill.md")
```

---

## Signature

```python
def scan(file_path: str) -> ScanResult:
```

---

## Parameters

| Parameter | Type | Description |
|---|---|---|
| `file_path` | `str` | Path to the component file to scan |

Any string is accepted — the function validates and resolves the path internally.
Relative paths, absolute paths, and paths with `~` are all handled.

---

## Return Value

Always returns a `ScanResult`. **Never raises.**

See [ScanResult](scan-result.md) for full field reference.

```python
result = scan("/path/to/skill.md")

# Check outcome
if result.is_clean:
    print("No vulnerabilities found")
elif result.has_error:
    print(f"Scan failed: {result.error}")
else:
    print(f"Found {len(result.findings)} vulnerabilities")
    print(f"Risk score: {result.risk_score:.1f} / 10")
    print(f"Max severity: {result.max_severity.value}")
```

---

## Scan Pipeline

`scan()` runs these steps in order:

```
1. resolve_path()          Validate and resolve the file path
2. is_safe_path()          Check symlink, existence, size
3. detect component type   From file extension
4. read_file_safe()        UTF-8 with errors="ignore"
5. run_pattern_scan()      Regex engine (always runs)
6. run_yara_scan()         YARA engine (if yara-python installed)
7. run_semgrep_scan()      Semgrep engine (if semgrep installed)
8. _deduplicate()          Keep highest severity per rule_id
9. sort by severity        Highest first
```

---

## Error Handling

All errors are captured in `ScanResult.error`. The error string uses
stable error codes from `E001`–`E020`.

```python
result = scan("/nonexistent/skill.md")
print(result.error)     # "E003: File not found: skill.md"
print(result.is_clean)  # False — error present
print(result.findings)  # []
```

Common error codes:

| Code | Meaning |
|---|---|
| `E001` | Invalid file path |
| `E003` | File not found |
| `E005` | Symlink rejected |
| `E006` | File too large |
| `E008` | Could not read file |

---

## Exit Codes (CLI)

When used via the CLI with `--fail-on-severity`:

| Exit code | Meaning |
|---|---|
| `0` | Clean — no findings |
| `1` | Findings below threshold |
| `2` | Findings at or above threshold |

---

## Thread Safety

`scan()` is stateless and thread-safe. Each call creates fresh state.
Safe to call concurrently from multiple threads or processes.

---

## Example: Batch scanning

```python
from pathlib import Path
from scanner.scanner import scan

skills_dir = Path("./skills")
results = [scan(str(p)) for p in skills_dir.glob("*.md")]

# Filter critical findings
critical = [r for r in results if r.max_severity and r.max_severity.value == "CRITICAL"]
print(f"{len(critical)} critical files out of {len(results)} scanned")
```
