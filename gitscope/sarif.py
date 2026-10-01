"""
sarif.py — SARIF 2.1.0 output for gitscope.

SARIF (Static Analysis Results Interchange Format) is the format GitHub Code
Scanning ingests, so a gitscope scan can show up directly in a repository's
Security tab:

    gitscope --sarif --output gitscope.sarif
    # then upload with github/codeql-action/upload-sarif

Author: ranahmad1
License: MIT
"""

import hashlib
import json
import re
import sys
from typing import Dict, List, TextIO

from gitscope import __version__
from gitscope.scanner import Finding, ScanResult

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
INFORMATION_URI = "https://github.com/Ranahmad1/gitscope"

# SARIF result levels
_LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}

# GitHub uses `security-severity` (CVSS-like, 0.0-10.0) to bucket alerts into
# Critical / High / Medium / Low in the Security tab.
_SECURITY_SEVERITY = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
}

# GitHub requires every result to have a location. Findings that are not tied
# to a file (e.g. some history or config findings) fall back to the repo root.
_FALLBACK_URI = "."


def _slug(text: str, default: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or default


def _rule_id(finding: Finding) -> str:
    """Build a stable rule id such as 'gitscope/secret/aws-access-key-id'."""
    return f"gitscope/{_slug(finding.category, 'general')}/{_slug(finding.name, 'unknown')}"


def _normalize_uri(path: str) -> str:
    """SARIF artifact URIs are forward-slash, repo-relative paths."""
    uri = path.replace("\\", "/")
    uri = re.sub(r"^(\./)+", "", uri).lstrip("/")
    return uri or _FALLBACK_URI


def _fingerprint(rule_id: str, finding: Finding) -> str:
    """Stable fingerprint so GitHub can de-duplicate alerts across runs."""
    raw = "|".join(
        [
            rule_id,
            finding.file_path or "",
            str(finding.line_number or ""),
            finding.commit_hash or "",
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _build_rules(findings: List[Finding]) -> List[Dict]:
    """One SARIF rule per distinct rule id, in first-seen order."""
    rules: Dict[str, Dict] = {}
    for finding in findings:
        rule_id = _rule_id(finding)
        if rule_id in rules:
            continue
        rules[rule_id] = {
            "id": rule_id,
            "name": re.sub(r"[^A-Za-z0-9]+", "", finding.name.title()) or "Finding",
            "shortDescription": {"text": finding.name},
            "fullDescription": {"text": finding.description},
            "help": {
                "text": finding.remediation,
                "markdown": f"**Remediation:** {finding.remediation}",
            },
            "defaultConfiguration": {"level": _LEVELS.get(finding.severity, "warning")},
            "properties": {
                "tags": ["security", finding.category],
                "security-severity": _SECURITY_SEVERITY.get(finding.severity, "5.5"),
            },
        }
    return list(rules.values())


def _build_result(finding: Finding) -> Dict:
    rule_id = _rule_id(finding)

    message = finding.description
    if finding.commit_hash:
        message += f" (found in commit {finding.commit_hash})"

    physical_location: Dict = {
        "artifactLocation": {"uri": _normalize_uri(finding.file_path or _FALLBACK_URI)}
    }
    if finding.line_number:
        physical_location["region"] = {"startLine": int(finding.line_number)}

    properties: Dict = {"severity": finding.severity}
    if finding.commit_hash:
        properties["commit"] = finding.commit_hash
    if finding.matched_text:
        # gitscope already masks matched secrets; never emit raw values.
        properties["matchedText"] = finding.matched_text

    return {
        "ruleId": rule_id,
        "level": _LEVELS.get(finding.severity, "warning"),
        "message": {"text": message},
        "locations": [{"physicalLocation": physical_location}],
        "partialFingerprints": {"gitscopeFindingHash/v1": _fingerprint(rule_id, finding)},
        "properties": properties,
    }


def build_sarif(result: ScanResult) -> Dict:
    """Convert a ScanResult into a SARIF 2.1.0 document (as a dict)."""
    findings = result.sorted_findings()
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "gitscope",
                        "version": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": _build_rules(findings),
                    }
                },
                "results": [_build_result(f) for f in findings],
                "invocations": [
                    {
                        "executionSuccessful": not result.errors,
                        "toolExecutionNotifications": [
                            {"level": "warning", "message": {"text": err}}
                            for err in result.errors
                        ],
                    }
                ],
                "properties": {
                    "repository": result.repo_path,
                    "filesScanned": result.files_scanned,
                    "commitsScanned": result.commits_scanned,
                    "securityScore": result.score,
                },
            }
        ],
    }


def render_sarif(result: ScanResult, stream: TextIO = sys.stdout, pretty: bool = True) -> None:
    """Write a SARIF 2.1.0 report to *stream*."""
    json.dump(build_sarif(result), stream, indent=2 if pretty else None, ensure_ascii=False)
    stream.write("\n")
