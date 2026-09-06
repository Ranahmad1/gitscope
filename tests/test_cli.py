"""
test_cli.py — Tests for gitscope's command-line interface.

Author: ranahmad1
License: MIT
"""

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from gitscope.cli import main, build_parser, should_fail, filter_findings
from gitscope.scanner import ScanResult, Finding


# ---------------------------------------------------------------------------
# Parser tests
# ---------------------------------------------------------------------------

class TestBuildParser:
    def test_default_path_is_dot(self):
        parser = build_parser()
        args = parser.parse_args([])
        assert args.path == "."

    def test_custom_path_parsed(self):
        parser = build_parser()
        args = parser.parse_args(["/some/repo"])
        assert args.path == "/some/repo"

    def test_json_flag(self):
        parser = build_parser()
        args = parser.parse_args(["--json"])
        assert args.json is True

    def test_no_history_flag(self):
        parser = build_parser()
        args = parser.parse_args(["--no-history"])
        assert args.no_history is True

    def test_depth_flag(self):
        parser = build_parser()
        args = parser.parse_args(["--depth", "100"])
        assert args.depth == 100

    def test_min_severity_flag(self):
        parser = build_parser()
        args = parser.parse_args(["--min-severity", "high"])
        assert args.min_severity == "high"

    def test_fail_on_flag(self):
        parser = build_parser()
        args = parser.parse_args(["--fail-on", "critical"])
        assert args.fail_on == "critical"

    def test_json_and_plain_mutually_exclusive(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--json", "--plain"])


# ---------------------------------------------------------------------------
# should_fail tests
# ---------------------------------------------------------------------------

class TestShouldFail:
    def _result_with(self, severity):
        result = ScanResult(repo_path="/fake")
        result.add_finding(Finding(
            category="secret", name="X", severity=severity,
            description="d", remediation="r"
        ))
        return result

    def test_fail_on_never_always_false(self):
        result = self._result_with("critical")
        assert should_fail(result, "never") is False

    def test_critical_finding_fails_on_critical(self):
        result = self._result_with("critical")
        assert should_fail(result, "critical") is True

    def test_high_finding_fails_on_medium(self):
        result = self._result_with("high")
        assert should_fail(result, "medium") is True

    def test_low_finding_does_not_fail_on_high(self):
        result = self._result_with("low")
        assert should_fail(result, "high") is False

    def test_no_findings_does_not_fail(self):
        result = ScanResult(repo_path="/fake")
        assert should_fail(result, "low") is False


# ---------------------------------------------------------------------------
# filter_findings tests
# ---------------------------------------------------------------------------

class TestFilterFindings:
    def _make(self, severities):
        result = ScanResult(repo_path="/fake")
        for sev in severities:
            result.add_finding(Finding(
                category="secret", name="X", severity=sev,
                description="d", remediation="r"
            ))
        return result

    def test_filter_low_keeps_all(self):
        result = self._make(["low", "medium", "high", "critical"])
        filter_findings(result, "low")
        assert len(result.findings) == 4

    def test_filter_high_removes_medium_low(self):
        result = self._make(["low", "medium", "high", "critical"])
        filter_findings(result, "high")
        severities = {f.severity for f in result.findings}
        assert "low" not in severities
        assert "medium" not in severities
        assert "high" in severities
        assert "critical" in severities

    def test_filter_critical_keeps_only_critical(self):
        result = self._make(["low", "medium", "high", "critical"])
        filter_findings(result, "critical")
        assert all(f.severity == "critical" for f in result.findings)

    def test_filter_on_empty_result(self):
        result = ScanResult(repo_path="/fake")
        filter_findings(result, "high")
        assert result.findings == []


# ---------------------------------------------------------------------------
# main() integration tests
# ---------------------------------------------------------------------------

@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=str(tmp_path), check=True, capture_output=True
    )
    subprocess.run(
        ["git", "config", "user.name", "Test User"],
        cwd=str(tmp_path), check=True, capture_output=True
    )
    return tmp_path


@pytest.fixture
def clean_repo(git_repo: Path) -> Path:
    readme = git_repo / "README.md"
    readme.write_text("# Test\n")
    gitignore = git_repo / ".gitignore"
    gitignore.write_text(".env\n*.pem\n*.key\nnode_modules\n__pycache__\n*.pyc\n*.log\n*.sqlite\n*.db\n.DS_Store\n")
    subprocess.run(["git", "add", "."], cwd=str(git_repo), check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=str(git_repo), check=True, capture_output=True)
    return git_repo


class TestMainCLI:
    def test_nonexistent_path_exits_2(self):
        exit_code = main(["/absolutely/does/not/exist"])
        assert exit_code == 2

    def test_non_git_directory_exits_2(self, tmp_path: Path):
        exit_code = main([str(tmp_path)])
        assert exit_code == 2

    def test_clean_repo_exits_0(self, clean_repo: Path):
        exit_code = main([str(clean_repo), "--no-history", "--fail-on", "never"])
        assert exit_code == 0

    def test_json_output_valid(self, clean_repo: Path, capsys):
        exit_code = main([str(clean_repo), "--json", "--no-history"])
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "findings" in data
        assert "summary" in data

    def test_plain_output_no_ansi(self, clean_repo: Path, capsys):
        main([str(clean_repo), "--plain", "--no-history"])
        captured = capsys.readouterr()
        assert "\033[" not in captured.out

    def test_fail_on_never_exits_0_even_with_secrets(self, git_repo: Path):
        secret_file = git_repo / "config.py"
        # Plaintext pattern that triggers scanner but not GitHub secret scanner
        secret_file.write_text('JWT_SECRET = "example_jwt_signing_key_for_test_only_9876"\n')
        exit_code = main([str(git_repo), "--no-history", "--fail-on", "never"])
        assert exit_code == 0

    def test_dirty_repo_exits_1_by_default(self, git_repo: Path):
        secret_file = git_repo / "config.py"
        secret_file.write_text('DB_URL = "postgres://user:pass@localhost/db"\n')
        subprocess.run(["git", "add", "."], cwd=str(git_repo), capture_output=True)
        subprocess.run(["git", "commit", "-m", "add config"], cwd=str(git_repo), capture_output=True)
        exit_code = main([str(git_repo), "--no-history"])
        assert exit_code == 1

    def test_version_flag(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            main(["--version"])
        assert exc_info.value.code == 0
        captured = capsys.readouterr()
        assert "gitscope" in captured.out
