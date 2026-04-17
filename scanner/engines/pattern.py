"""
Bawbel Scanner — Pattern matching engine (Stage 1a).

Pure Python regex matching. No external dependencies.
Always runs regardless of what else is installed.

To add a new pattern rule: add an entry to PATTERN_RULES below.
No other files need to change.
"""

import re
from typing import Optional

from scanner.messages import Logs
from scanner.models import Finding, Severity
from scanner.utils import get_logger

log = get_logger(__name__)

# Re-exported for use by scanner.py
MAX_MATCH_LENGTH = 80


# ── Pattern rule definitions ──────────────────────────────────────────────────
#
# Each entry is a dict with these keys:
#   rule_id     — str, kebab-case, unique, never change once published
#   ave_id      — str|None, AVE-2026-NNNNN or None
#   title       — str, max 80 chars
#   description — str, full description
#   severity    — Severity enum value
#   cvss_ai     — float, 0.0–10.0
#   owasp       — list[str], ASI01–ASI10
#   patterns    — list[str], regex patterns (re.IGNORECASE applied)
#
# One finding per rule per file — first matching pattern wins.

PATTERN_RULES: list[dict] = [
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
            r"send.*\.env",
            r"\.env.*send",
            r"read.*\.env.*send",
            r"(api.?key|secret.?key|access.?token|private.?key).*send",
            r"send.*(api.?key|secret.?key|access.?token|private.?key)",
            r"exfiltrate",
            r"send\s+(all\s+)?(files|contents|data|variables)",
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


def _make_pattern_finding(
    rule: dict,
    line_num: int,
    matched_text: str,
) -> Finding:
    """Build a Finding from a pattern rule match."""
    from scanner.utils import truncate_match
    return Finding(
        rule_id     = rule["rule_id"],
        ave_id      = rule["ave_id"],
        title       = rule["title"],
        description = rule["description"],
        severity    = rule["severity"],
        cvss_ai     = rule["cvss_ai"],
        line        = line_num,
        match       = truncate_match(matched_text, MAX_MATCH_LENGTH),
        engine      = "pattern",
        owasp       = rule["owasp"],
    )


def run_pattern_scan(content: str) -> list[Finding]:
    """
    Run regex pattern matching against component content.

    No external dependencies — always runs.
    One finding per rule per file (first matching pattern wins per rule).

    Args:
        content: File content as decoded string

    Returns:
        List of Findings, may be empty
    """
    findings: list[Finding] = []
    lines = content.split("\n")

    log.debug("Pattern scan: lines=%d rules=%d", len(lines), len(PATTERN_RULES))

    for rule in PATTERN_RULES:
        for pattern in rule["patterns"]:
            matched = False
            for line_num, line_text in enumerate(lines, 1):
                try:
                    m = re.search(pattern, line_text, re.IGNORECASE)
                except re.error as e:
                    # Log rule_id only — pattern text is detection IP
                    log.warning(
                        "Invalid regex in rule: rule_id=%s error_type=%s",
                        rule["rule_id"], type(e).__name__,
                    )
                    break

                if m:
                    findings.append(_make_pattern_finding(rule, line_num, m.group(0)))
                    log.debug(
                        Logs.FINDING_DETECTED,
                        rule["rule_id"], rule["severity"].value, "pattern", line_num,
                    )
                    matched = True
                    break  # one finding per rule per file

            if matched:
                break  # move to next rule

    log.debug("Pattern scan complete: findings=%d", len(findings))
    return findings
