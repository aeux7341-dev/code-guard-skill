#!/usr/bin/env python3
"""
High-Risk Code Guard - Static Security & Financial Safety Scanner
Scans source files for hardcoded secrets, SQL/command injection vectors,
unsafe DOM sinks, and floating-point financial calculations.

Usage:
    python3 scripts/audit_scanner.py <file_or_directory>
"""

import os
import re
import sys
from pathlib import Path
from typing import List, Tuple

RULES: List[Tuple[str, str, str, re.Pattern]] = [
    (
        "SEC-001",
        "CRITICAL",
        "Potential hardcoded secret, API key, or private token",
        re.compile(
            r"""(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|jwt[_-]?secret|private[_-]?key|password)\s*[:=]\s*['"][A-Za-z0-9_\-/.+=]{12,}['"]"""
        ),
    ),
    (
        "SEC-002",
        "CRITICAL",
        "Potential SQL Injection via string interpolation or concatenation",
        re.compile(
            r"""(?i)(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+.*(\$\{|\+\s*[a-zA-Z0-9_.]|\.\s*\$[a-zA-Z0-9_]+|f['"].*\{)"""
        ),
    ),
    (
        "SEC-003",
        "HIGH",
        "Unsafe command execution or eval() usage",
        re.compile(
            r"""\b(eval|exec|child_process\.exec|os\.system|shell_exec|passthru)\s*\("""
        ),
    ),
    (
        "SEC-004",
        "HIGH",
        "Potential XSS sink (dangerouslySetInnerHTML or unescaped innerHTML)",
        re.compile(r"""(dangerouslySetInnerHTML|\.innerHTML\s*=)"""),
    ),
    (
        "FIN-001",
        "HIGH",
        "Floating-point parseFloat/float used on financial variable (price/amount/balance)",
        re.compile(
            r"""(?i)(price|amount|balance|total|saldo|harga|fee)\s*[:=].*\b(parseFloat|float\s*\()"""
        ),
    ),
    (
        "PRIV-001",
        "MEDIUM",
        "Sensitive credential or token potentially written to console/application logs",
        re.compile(
            r"""(?i)(console\.(log|info|debug|error)|logger\.(info|debug|error)|print\s*\().*\b(password|token|secret|authorization|credit_card|cvv)\b"""
        ),
    ),
]

IGNORED_DIRS = {".git", "node_modules", "vendor", "dist", "build", "__pycache__", ".next"}
SUPPORTED_EXTENSIONS = {".js", ".ts", ".jsx", ".tsx", ".py", ".php", ".sql", ".go", ".rb"}


def scan_file(filepath: Path) -> List[Tuple[int, str, str, str, str]]:
    findings = []
    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return findings

    for line_num, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("//", "#", "/*", "*")):
            continue
        for rule_id, severity, message, pattern in RULES:
            if pattern.search(line):
                findings.append((line_num, rule_id, severity, message, stripped[:120]))
    return findings


def scan_target(target_path: Path) -> int:
    total_findings = 0
    files_to_scan: List[Path] = []

    if target_path.is_file():
        files_to_scan.append(target_path)
    else:
        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
            for file in files:
                p = Path(root) / file
                if p.suffix.lower() in SUPPORTED_EXTENSIONS:
                    files_to_scan.append(p)

    for file_path in sorted(files_to_scan):
        findings = scan_file(file_path)
        for line_num, rule_id, severity, message, snippet in findings:
            total_findings += 1
            print(f"[{severity}] {rule_id} | {file_path}:{line_num}")
            print(f"  Reason : {message}")
            print(f"  Snippet: {snippet}\n")

    if total_findings == 0:
        print("OK: No high-risk patterns detected.")
        return 0

    print(f"FAILED: Detected {total_findings} potential high-risk issue(s).")
    return 1


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 scripts/audit_scanner.py <file_or_directory>")
        sys.exit(2)

    target = Path(sys.argv[1])
    if not target.exists():
        print(f"Error: Path '{target}' does not exist.")
        sys.exit(2)

    sys.exit(scan_target(target))