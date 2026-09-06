"""
test_reporter.py — Tests for gitscope's report rendering module.

Author: ranahmad1
License: MIT
"""

import io
import json

import pytest

from gitscope.scanner import ScanResult, Finding
from gitscope.reporter import render_terminal, render_json, render_plain


def _make_result(findings=None):
    result = ScanResult(repo_path="/fake/repo")
    result.files_scanned = 10
    result.commits_scanned = 5
    for f in (findings or []):
        result.add_finding(f)
    return result


def _make_finding(severity="high", category="secret"):
    return Finding(
        category=category,
        name="Test Secret",
        severity=severity,
        description="A test secret was found.",
        remediation="Remove the secret and rotate it.",
        file_path="src/config.py",
        line_number=42,
        matched_text="sk_live_****",
    )


class TestRenderTerminal:
    def test_no_findings_shows_clean_message(self):
        result = _make_result()
        buf = io.StringIO()
        render_terminal(result, stream=buf, no_color=True)
        output = buf.getvalue()
        assert "No security issues" in output or "clean" in output.lower()

    def test_findings_appear_in_output(self):
        result = _make_result([_make_finding("critical")])
        buf = io.StringIO()
        render_terminal(result, stream=buf, no_color=True)
        output = buf.getvalue()
        assert "Test Secret" in output
        assert "CRITICAL" in output

    def test_score_appears_in_output(self):
        result = _make_result()
        buf = io.StringIO()
        render_terminal(result, stream=buf, no_color=True)
        assert "100/100" in buf.getvalue() or "Score" in buf.getvalue()

    def test_multiple_severities_all_shown(self):
        findings = [
            _make_finding("critical"),
            _make_finding("high"),
            _make_finding("medium"),
            _make_finding("low"),
        ]
        result = _make_result(findings)
        buf = io.StringIO()
        render_terminal(result, stream=buf, no_color=True)
        output = buf.getvalue()
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            assert sev in output

    def test_file_path_shown(self):
        result = _make_result([_make_finding()])
        buf = io.StringIO()
        render_terminal(result, stream=buf, no_color=True)
        assert "src/config.py" in buf.getvalue()

    def test_remediation_shown(self):
        result = _make_result([_make_finding()])
        buf = io.StringIO()
        render_terminal(result, stream=buf, no_color=True)
        assert "Remove the secret" in buf.getvalue()

    def test_repo_path_shown(self):
        result = _make_result()
        buf = io.StringIO()
        render_terminal(result, stream=buf, no_color=True)
        assert "/fake/repo" in buf.getvalue()

    def test_errors_shown(self):
        result = _make_result()
        result.errors.append("Could not read some_file.py")
        buf = io.StringIO()
        render_terminal(result, stream=buf, no_color=True)
        assert "Could not read some_file.py" in buf.getvalue()


class TestRenderJson:
    def test_valid_json_output(self):
        result = _make_result([_make_finding()])
        buf = io.StringIO()
        render_json(result, stream=buf)
        data = json.loads(buf.getvalue())
        assert "findings" in data
        assert "summary" in data

    def test_json_summary_fields(self):
        result = _make_result([_make_finding("critical"), _make_finding("low")])
        buf = io.StringIO()
        render_json(result, stream=buf)
        data = json.loads(buf.getvalue())
        summary = data["summary"]
        assert summary["total_findings"] == 2
        assert summary["critical"] == 1
        assert summary["low"] == 1
        assert "score" in summary

    def test_json_findings_structure(self):
        result = _make_result([_make_finding()])
        buf = io.StringIO()
        render_json(result, stream=buf)
        data = json.loads(buf.getvalue())
        finding = data["findings"][0]
        for key in ("category", "name", "severity", "description", "remediation"):
            assert key in finding

    def test_json_no_findings_empty_list(self):
        result = _make_result()
        buf = io.StringIO()
        render_json(result, stream=buf)
        data = json.loads(buf.getvalue())
        assert data["findings"] == []

    def test_json_version_present(self):
        result = _make_result()
        buf = io.StringIO()
        render_json(result, stream=buf)
        data = json.loads(buf.getvalue())
        assert "gitscope_version" in data

    def test_json_repository_field(self):
        result = _make_result()
        buf = io.StringIO()
        render_json(result, stream=buf)
        data = json.loads(buf.getvalue())
        assert data["repository"] == "/fake/repo"

    def test_json_findings_sorted_by_severity(self):
        findings = [
            _make_finding("low"),
            _make_finding("critical"),
            _make_finding("medium"),
        ]
        result = _make_result(findings)
        buf = io.StringIO()
        render_json(result, stream=buf)
        data = json.loads(buf.getvalue())
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        ranks = [severity_order[f["severity"]] for f in data["findings"]]
        assert ranks == sorted(ranks)

    def test_json_scan_timestamp_present(self):
        result = _make_result()
        buf = io.StringIO()
        render_json(result, stream=buf)
        data = json.loads(buf.getvalue())
        assert "scan_timestamp" in data
        assert data["scan_timestamp"].endswith("Z")


class TestRenderPlain:
    def test_plain_output_has_no_ansi(self):
        result = _make_result([_make_finding("critical")])
        buf = io.StringIO()
        render_plain(result, stream=buf)
        output = buf.getvalue()
        assert "\033[" not in output

    def test_plain_output_has_findings(self):
        result = _make_result([_make_finding("high")])
        buf = io.StringIO()
        render_plain(result, stream=buf)
        assert "Test Secret" in buf.getvalue()
