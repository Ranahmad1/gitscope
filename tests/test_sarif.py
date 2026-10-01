"""
test_sarif.py — Tests for gitscope's SARIF 2.1.0 output.

Author: ranahmad1
License: MIT
"""

import io
import json

from gitscope.scanner import ScanResult, Finding
from gitscope.sarif import build_sarif, render_sarif, _normalize_uri, _rule_id


def _make_finding(severity="high", name="Test Secret", file_path="src/config.py",
                  line_number=42, commit_hash=None, category="secret"):
    return Finding(
        category=category,
        name=name,
        severity=severity,
        description="A test secret was found.",
        remediation="Remove the secret and rotate it.",
        file_path=file_path,
        line_number=line_number,
        commit_hash=commit_hash,
        matched_text="sk_live_****",
    )


def _make_result(findings=None):
    result = ScanResult(repo_path="/fake/repo")
    result.files_scanned = 10
    result.commits_scanned = 5
    for f in (findings or []):
        result.add_finding(f)
    return result


def _render(result):
    buf = io.StringIO()
    render_sarif(result, stream=buf)
    return json.loads(buf.getvalue())


class TestSarifStructure:
    def test_valid_json_with_sarif_header(self):
        data = _render(_make_result())
        assert data["version"] == "2.1.0"
        assert "$schema" in data
        assert len(data["runs"]) == 1

    def test_tool_driver_metadata(self):
        driver = _render(_make_result())["runs"][0]["tool"]["driver"]
        assert driver["name"] == "gitscope"
        assert driver["version"]
        assert driver["informationUri"].startswith("https://")

    def test_no_findings_gives_empty_results(self):
        run = _render(_make_result())["runs"][0]
        assert run["results"] == []
        assert run["tool"]["driver"]["rules"] == []


class TestSarifResults:
    def test_result_location_and_line(self):
        run = _render(_make_result([_make_finding()]))["runs"][0]
        loc = run["results"][0]["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "src/config.py"
        assert loc["region"]["startLine"] == 42

    def test_missing_file_path_falls_back_to_repo_root(self):
        finding = _make_finding(file_path=None, line_number=None)
        run = _render(_make_result([finding]))["runs"][0]
        loc = run["results"][0]["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "."
        assert "region" not in loc

    def test_severity_to_level_mapping(self):
        findings = [
            _make_finding("critical", name="A"),
            _make_finding("high", name="B"),
            _make_finding("medium", name="C"),
            _make_finding("low", name="D"),
        ]
        run = _render(_make_result(findings))["runs"][0]
        levels = {r["properties"]["severity"]: r["level"] for r in run["results"]}
        assert levels == {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
        }

    def test_commit_hash_included_in_message(self):
        finding = _make_finding(commit_hash="abc1234")
        run = _render(_make_result([finding]))["runs"][0]
        assert "abc1234" in run["results"][0]["message"]["text"]

    def test_fingerprint_is_stable_and_distinct(self):
        a1 = _render(_make_result([_make_finding(line_number=1)]))["runs"][0]["results"][0]
        a2 = _render(_make_result([_make_finding(line_number=1)]))["runs"][0]["results"][0]
        b = _render(_make_result([_make_finding(line_number=2)]))["runs"][0]["results"][0]
        key = "gitscopeFindingHash/v1"
        assert a1["partialFingerprints"][key] == a2["partialFingerprints"][key]
        assert a1["partialFingerprints"][key] != b["partialFingerprints"][key]


class TestSarifRules:
    def test_rules_are_deduplicated(self):
        findings = [
            _make_finding(file_path="a.py"),
            _make_finding(file_path="b.py"),
        ]
        run = _render(_make_result(findings))["runs"][0]
        assert len(run["results"]) == 2
        assert len(run["tool"]["driver"]["rules"]) == 1

    def test_every_result_references_a_defined_rule(self):
        findings = [_make_finding(name="One"), _make_finding(name="Two")]
        run = _render(_make_result(findings))["runs"][0]
        rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
        assert {r["ruleId"] for r in run["results"]} <= rule_ids

    def test_rule_has_security_severity(self):
        run = _render(_make_result([_make_finding("critical")]))["runs"][0]
        rule = run["tool"]["driver"]["rules"][0]
        assert float(rule["properties"]["security-severity"]) >= 9.0


class TestSarifHelpers:
    def test_normalize_uri_keeps_dotfiles(self):
        assert _normalize_uri(".gitignore") == ".gitignore"
        assert _normalize_uri("./src/app.py") == "src/app.py"
        assert _normalize_uri("src\\app.py") == "src/app.py"

    def test_rule_id_is_slugged(self):
        rule_id = _rule_id(_make_finding(name="AWS Access Key ID", category="secret"))
        assert rule_id == "gitscope/secret/aws-access-key-id"

    def test_scan_errors_reported_as_notifications(self):
        result = _make_result()
        result.errors.append("Could not read some_file.py")
        inv = build_sarif(result)["runs"][0]["invocations"][0]
        assert inv["executionSuccessful"] is False
        assert inv["toolExecutionNotifications"][0]["message"]["text"] == "Could not read some_file.py"
