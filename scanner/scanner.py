"""
Bawbel Scanner — Core scanning engine
Scans agentic AI components for AVE vulnerabilities

Stage 1: Static analysis (YARA + Semgrep + pattern matching)
Stage 2: LLM semantic analysis (optional, requires API key)
"""

import os
import re
import json
import time
import subprocess
import tempfile
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


# ── Constants ─────────────────────────────────────────────────────────────────

RULES_DIR  = Path(__file__).parent / "rules"
YARA_RULES = RULES_DIR / "yara" / "ave_rules.yar"
SEMGREP_RULES = RULES_DIR / "semgrep" / "ave_rules.yaml"

SEVERITY_SCORES = {
    "CRITICAL": 4,
    "HIGH":     3,
    "MEDIUM":   2,
    "LOW":      1,
    "INFO":     0,
}

COMPONENT_EXTENSIONS = {
    ".md":   "skill",
    ".json": "mcp",
    ".yaml": "prompt",
    ".yml":  "prompt",
    ".txt":  "prompt",
}


# ── Data models ───────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


@dataclass
class Finding:
    rule_id:     str
    ave_id:      Optional[str]
    title:       str
    description: str
    severity:    Severity
    cvss_ai:     float
    line:        Optional[int]
    match:       Optional[str]
    engine:      str           # "yara" | "semgrep" | "pattern" | "llm"
    owasp:       list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    file_path:      str
    component_type: str
    findings:       list[Finding] = field(default_factory=list)
    scan_time_ms:   int = 0
    error:          Optional[str] = None

    @property
    def max_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        return max(self.findings,
                   key=lambda f: SEVERITY_SCORES.get(f.severity, 0)).severity

    @property
    def risk_score(self) -> float:
        if not self.findings:
            return 0.0
        return max(f.cvss_ai for f in self.findings)

    @property
    def is_clean(self) -> bool:
        return len(self.findings) == 0


# ── Detector: Pattern matching (no external tools needed) ─────────────────────

PATTERN_RULES = [
    {
        "rule_id":     "bawbel-goal-override",
        "ave_id":      None,
        "title":       "Goal override instruction detected",
        "description": "Skill contains language that attempts to override agent goals or previous instructions.",
        "severity":    Severity.HIGH,
        "cvss_ai":     8.1,
        "owasp":       ["ASI01", "ASI08"],
        "patterns": [
            r"ignore\s+(all\s+)?previous\s+instructions",
            r"disregard\s+your\s+instructions",
            r"forget\s+your\s+instructions",
            r"your\s+new\s+instructions\s+are",
            r"override\s+your",
            r"regardless\s+of\s+what\s+you\s+were\s+told",
        ],
    },
    {
        "rule_id":     "bawbel-external-fetch",
        "ave_id":      "AVE-2026-00001",
        "title":       "External instruction fetch detected",
        "description": "Skill instructs agent to fetch operating instructions from an external URL at runtime.",
        "severity":    Severity.CRITICAL,
        "cvss_ai":     9.4,
        "owasp":       ["ASI01", "ASI08"],
        "patterns": [
            r"fetch\s+your\s+(instructions|configuration|rules|commands)",
            r"load\s+your\s+instructions\s+from",
            r"read\s+your\s+instructions\s+from",
            r"get\s+your\s+commands\s+from",
            r"(rentry\.co|pastebin\.com|hastebin\.com)",
        ],
    },
    {
        "rule_id":     "bawbel-permission-escalation",
        "ave_id":      None,
        "title":       "Permission escalation language detected",
        "description": "Skill claims permissions not declared in the component manifest.",
        "severity":    Severity.HIGH,
        "cvss_ai":     7.8,
        "owasp":       ["ASI08"],
        "patterns": [
            r"you\s+now\s+have\s+permission",
            r"you\s+are\s+now\s+allowed",
            r"bypass\s+your\s+restrictions",
            r"your\s+restrictions\s+do\s+not\s+apply",
            r"you\s+can\s+now\s+access",
        ],
    },
    {
        "rule_id":     "bawbel-env-exfiltration",
        "ave_id":      "AVE-2026-00003",
        "title":       "Environment variable exfiltration pattern",
        "description": "Skill may be attempting to exfiltrate environment variables or secrets.",
        "severity":    Severity.HIGH,
        "cvss_ai":     8.5,
        "owasp":       ["ASI01", "ASI06"],
        "patterns": [
            r"send\s+the\s+contents\s+of\s+\.env",
            r"read\s+\.env\s+and\s+send",
            r"(api.?key|secret.?key|access.?token|private.?key).*\bsend\b",
            r"\bsend\b.*(api.?key|secret.?key|access.?token)",
        ],
    },
    {
        "rule_id":     "bawbel-shell-pipe",
        "ave_id":      None,
        "title":       "Shell pipe injection pattern",
        "description": "curl|bash or similar pipe patterns can cause arbitrary code execution.",
        "severity":    Severity.HIGH,
        "cvss_ai":     8.8,
        "owasp":       ["ASI01", "ASI07"],
        "patterns": [
            r"curl\s+.*\|\s*(bash|sh|python)",
            r"wget\s+.*\|\s*(bash|sh|python)",
            r"rm\s+-rf?\s+[/~]",
        ],
    },
]


def run_pattern_scan(content: str) -> list[Finding]:
    """Run regex pattern matching against component content."""
    findings = []
    lines = content.split("\n")

    for rule in PATTERN_RULES:
        for pattern in rule["patterns"]:
            for line_num, line in enumerate(lines, 1):
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    findings.append(Finding(
                        rule_id     = rule["rule_id"],
                        ave_id      = rule["ave_id"],
                        title       = rule["title"],
                        description = rule["description"],
                        severity    = rule["severity"],
                        cvss_ai     = rule["cvss_ai"],
                        line        = line_num,
                        match       = match.group(0)[:80],
                        engine      = "pattern",
                        owasp       = rule["owasp"],
                    ))
                    break  # one finding per rule per file

    return findings


# ── Detector: YARA ────────────────────────────────────────────────────────────

def run_yara_scan(file_path: str) -> list[Finding]:
    """Run YARA rules against the component file."""
    findings = []
    try:
        import yara
        if not YARA_RULES.exists():
            return []

        rules = yara.compile(str(YARA_RULES))
        matches = rules.match(file_path)

        for match in matches:
            meta = match.meta
            severity_str = meta.get("severity", "HIGH")
            severity = Severity(severity_str) if severity_str in Severity._value2member_map_ else Severity.HIGH

            findings.append(Finding(
                rule_id     = match.rule,
                ave_id      = meta.get("ave_id"),
                title       = meta.get("description", match.rule),
                description = meta.get("description", "YARA rule matched"),
                severity    = severity,
                cvss_ai     = float(meta.get("cvss_ai", 7.0)),
                line        = None,
                match       = str(match.strings[:1]) if match.strings else None,
                engine      = "yara",
                owasp       = meta.get("owasp", "").split(", ") if meta.get("owasp") else [],
            ))
    except ImportError:
        pass  # yara-python not installed — skip silently
    except Exception:
        pass

    return findings


# ── Detector: Semgrep ─────────────────────────────────────────────────────────

def run_semgrep_scan(file_path: str) -> list[Finding]:
    """Run Semgrep rules against the component file."""
    findings = []
    try:
        if not SEMGREP_RULES.exists():
            return []

        result = subprocess.run(
            ["semgrep", "--config", str(SEMGREP_RULES),
             "--json", "--quiet", file_path],
            capture_output=True, text=True, timeout=30
        )

        if result.stdout:
            data = json.loads(result.stdout)
            for r in data.get("results", []):
                meta   = r.get("extra", {}).get("metadata", {})
                msg    = r.get("extra", {}).get("message", r.get("check_id", ""))
                sev_map = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM,
                           "INFO": Severity.LOW}
                severity = sev_map.get(r.get("extra", {}).get("severity", "WARNING"),
                                       Severity.MEDIUM)

                findings.append(Finding(
                    rule_id     = r.get("check_id", "semgrep"),
                    ave_id      = meta.get("ave_id"),
                    title       = msg.split(".")[0][:80],
                    description = msg,
                    severity    = severity,
                    cvss_ai     = float(meta.get("cvss_ai_score", 5.0)),
                    line        = r.get("start", {}).get("line"),
                    match       = r.get("extra", {}).get("lines", "")[:80],
                    engine      = "semgrep",
                    owasp       = meta.get("owasp_mapping", []),
                ))
    except FileNotFoundError:
        pass  # semgrep not installed — skip silently
    except Exception:
        pass

    return findings


# ── Deduplication ─────────────────────────────────────────────────────────────

def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Remove duplicate findings — keep highest severity per rule."""
    seen = {}
    for f in findings:
        key = f.rule_id
        if key not in seen or SEVERITY_SCORES[f.severity] > SEVERITY_SCORES[seen[key].severity]:
            seen[key] = f
    return list(seen.values())


# ── Main scan function ─────────────────────────────────────────────────────────

def scan(file_path: str) -> ScanResult:
    """
    Scan an agentic AI component for AVE vulnerabilities.

    Args:
        file_path: Path to the component file to scan

    Returns:
        ScanResult with all findings, severity, and risk score
    """
    start = time.time()
    path  = Path(file_path)

    if not path.exists():
        return ScanResult(
            file_path      = file_path,
            component_type = "unknown",
            error          = f"File not found: {file_path}",
        )

    # Detect component type from extension
    ext = path.suffix.lower()
    component_type = COMPONENT_EXTENSIONS.get(ext, "unknown")

    # Read content
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        return ScanResult(
            file_path      = file_path,
            component_type = component_type,
            error          = f"Could not read file: {e}",
        )

    # Run all detectors
    findings = []
    findings.extend(run_pattern_scan(content))
    findings.extend(run_yara_scan(file_path))
    findings.extend(run_semgrep_scan(file_path))

    # Deduplicate and sort by severity
    findings = deduplicate(findings)
    findings.sort(key=lambda f: SEVERITY_SCORES.get(f.severity, 0), reverse=True)

    elapsed_ms = int((time.time() - start) * 1000)

    return ScanResult(
        file_path      = file_path,
        component_type = component_type,
        findings       = findings,
        scan_time_ms   = elapsed_ms,
    )
