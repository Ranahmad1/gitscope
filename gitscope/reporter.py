"""
reporter.py — Output formatters for gitscope scan results.

Supports:
  - Pretty terminal output (ANSI colors, tables, score gauge)
  - JSON output for CI/CD integration and tooling
  - Plain text output (no ANSI codes, for pipe-friendly use)

Author: ranahmad1
License: MIT
"""

import json
import sys
from datetime import datetime, timezone
from typing import TextIO

from gitscope.scanner import ScanResult, Finding

# ---------------------------------------------------------------------------
# ANSI color helpers
# ---------------------------------------------------------------------------

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
GREEN = "\033[92m"
WHITE = "\033[97m"
MAGENTA = "\033[95m"
BLUE = "\033[94m"
DARK_RED = "\033[31m"


def _supports_color(stream: TextIO) -> bool:
    """Return True if the output stream supports ANSI color codes."""
    if not hasattr(stream, "isatty"):
        return False
    if not stream.isatty():
        return False
    if sys.platform == "win32":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            return True
        except Exception:
            return False
    return True


def _severity_color(severity: str, use_color: bool) -> str:
    if not use_color:
        return ""
    mapping = {
        "critical": RED + BOLD,
        "high": YELLOW + BOLD,
        "medium": CYAN,
        "low": DIM + WHITE,
    }
    return mapping.get(severity, "")


def _score_color(score: int, use_color: bool) -> str:
    if not use_color:
        return ""
    if score >= 80:
        return GREEN + BOLD
    elif score >= 60:
        return YELLOW + BOLD
    elif score >= 40:
        return YELLOW
    else:
        return RED + BOLD


def _severity_badge(severity: str, use_color: bool) -> str:
    labels = {
        "critical": "CRITICAL",
        "high": "HIGH    ",
        "medium": "MEDIUM  ",
        "low": "LOW     ",
    }
    label = labels.get(severity, severity.upper().ljust(8))
    col = _severity_color(severity, use_color)
    reset = RESET if use_color else ""
    return f"{col}[{label}]{reset}"


def _score_bar(score: int, width: int = 30, use_color: bool = True) -> str:
    """Draw a visual progress bar for the security score."""
    filled = int((score / 100) * width)
    empty = width - filled
    bar = "█" * filled + "░" * empty
    col = _score_color(score, use_color)
    reset = RESET if use_color else ""
    return f"{col}{bar}{reset}"


def _section_header(title: str, use_color: bool) -> str:
    line = "─" * 70
    bold = BOLD if use_color else ""
    reset = RESET if use_color else ""
    return f"\n{bold}{line}{reset}\n{bold}  {title}{reset}\n{bold}{line}{reset}"


# ---------------------------------------------------------------------------
# Terminal reporter
# ---------------------------------------------------------------------------

def render_terminal(result: ScanResult, stream: TextIO = sys.stdout, no_color: bool = False) -> None:
    """Render a human-readable terminal report."""
    use_color = _supports_color(stream) and not no_color
    bold = BOLD if use_color else ""
    dim = DIM if use_color else ""
    reset = RESET if use_color else ""
    cyan = CYAN if use_color else ""
    green = GREEN if use_color else ""
    magenta = MAGENTA if use_color else ""

    stream.write("\n")
    stream.write(f"{bold}{'━' * 70}{reset}\n")
    stream.write(f"{bold}  gitscope — Git Repository Security Hygiene Auditor{reset}\n")
    stream.write(f"{bold}{'━' * 70}{reset}\n")
    stream.write(f"  Repository : {cyan}{result.repo_path}{reset}\n")
    stream.write(f"  Scanned at : {dim}{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}{reset}\n")
    stream.write(f"  Files      : {result.files_scanned}\n")
    stream.write(f"  Commits    : {result.commits_scanned}\n")
    stream.write(f"  Findings   : {len(result.findings)}")

    if result.findings:
        parts = []
        if result.critical_count:
            col = RED + BOLD if use_color else ""
            parts.append(f"{col}{result.critical_count} critical{reset}")
        if result.high_count:
            col = YELLOW + BOLD if use_color else ""
            parts.append(f"{col}{result.high_count} high{reset}")
        if result.medium_count:
            parts.append(f"{result.medium_count} medium")
        if result.low_count:
            parts.append(f"{dim}{result.low_count} low{reset}")
        stream.write(f"  ({', '.join(parts)})")
    stream.write("\n")

    score_col = _score_color(result.score, use_color)
    stream.write(f"\n  Security Score: {score_col}{result.score}/100{reset}\n")
    stream.write(f"  {_score_bar(result.score, use_color=use_color)}  {score_col}{result.score}%{reset}\n")

    grade_map = [
        (90, "A — Excellent"),
        (80, "B — Good"),
        (60, "C — Needs attention"),
        (40, "D — Poor"),
        (0,  "F — Critical issues"),
    ]
    grade = next((g for threshold, g in grade_map if result.score >= threshold), "F — Critical issues")
    stream.write(f"  Grade: {score_col}{grade}{reset}\n")

    if not result.findings:
        stream.write(f"\n  {green}✔ No security issues found. Repository looks clean!{reset}\n\n")
        _write_errors(result, stream, use_color)
        return

    for severity in ("critical", "high", "medium", "low"):
        findings = [f for f in result.sorted_findings() if f.severity == severity]
        if not findings:
            continue

        stream.write(_section_header(
            f"{severity.upper()} ({len(findings)} finding{'s' if len(findings) != 1 else ''})",
            use_color
        ))
        stream.write("\n")

        for i, finding in enumerate(findings, start=1):
            badge = _severity_badge(finding.severity, use_color)
            stream.write(f"  {i:3}. {badge}  {bold}{finding.name}{reset}\n")

            if finding.file_path:
                loc = finding.file_path
                if finding.line_number:
                    loc += f":{finding.line_number}"
                stream.write(f"       {dim}File: {loc}{reset}\n")

            if finding.commit_hash:
                stream.write(f"       {dim}Commit: {finding.commit_hash}{reset}\n")

            if finding.matched_text:
                stream.write(f"       {dim}Match: {finding.matched_text}{reset}\n")

            stream.write(f"       {magenta}What: {reset}{finding.description}\n")
            stream.write(f"       {green}Fix : {reset}{finding.remediation}\n")
            stream.write("\n")

    _write_errors(result, stream, use_color)

    stream.write(f"{bold}{'━' * 70}{reset}\n")
    stream.write(f"  Run with --json for machine-readable output.\n")
    stream.write(f"  Run with --no-history to skip commit history scan.\n")
    stream.write(f"{bold}{'━' * 70}{reset}\n\n")


def _write_errors(result: ScanResult, stream: TextIO, use_color: bool) -> None:
    if result.errors:
        yellow = YELLOW if use_color else ""
        reset = RESET if use_color else ""
        stream.write(f"\n  {yellow}Warnings / Errors:{reset}\n")
        for err in result.errors:
            stream.write(f"  • {err}\n")
        stream.write("\n")


# ---------------------------------------------------------------------------
# JSON reporter
# ---------------------------------------------------------------------------

def render_json(result: ScanResult, stream: TextIO = sys.stdout, pretty: bool = True) -> None:
    """Render machine-readable JSON output."""
    data = {
        "gitscope_version": "1.0.0",
        "scan_timestamp": datetime.now(timezone.utc).isoformat() + "Z",
        "repository": result.repo_path,
        "summary": {
            "files_scanned": result.files_scanned,
            "commits_scanned": result.commits_scanned,
            "total_findings": len(result.findings),
            "critical": result.critical_count,
            "high": result.high_count,
            "medium": result.medium_count,
            "low": result.low_count,
            "score": result.score,
        },
        "findings": [
            {
                "category": f.category,
                "name": f.name,
                "severity": f.severity,
                "description": f.description,
                "remediation": f.remediation,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "commit_hash": f.commit_hash,
                "matched_text": f.matched_text,
            }
            for f in result.sorted_findings()
        ],
        "errors": result.errors,
    }
    indent = 2 if pretty else None
    json.dump(data, stream, indent=indent, ensure_ascii=False)
    stream.write("\n")


# ---------------------------------------------------------------------------
# Plain text reporter (no color, for logs / file output)
# ---------------------------------------------------------------------------

def render_plain(result: ScanResult, stream: TextIO = sys.stdout) -> None:
    """Render a plain-text report with no ANSI codes."""
    render_terminal(result, stream=stream, no_color=True)
