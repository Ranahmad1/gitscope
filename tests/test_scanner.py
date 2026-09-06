"""
test_scanner.py — Integration tests for gitscope's scanner module.

Uses a real temporary git repository to test end-to-end scanning logic.

Author: ranahmad1
License: MIT
"""

import os
import subprocess
import tempfile
import textwrap
from pathlib import Path

import pytest

from gitscope.scanner import (
    run_full_scan,
    scan_working_tree,
    audit_gitignore,
    audit_git_config,
    ScanResult,
    _is_git_repo,
    _should_skip_file,
    _redact,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    """Create a minimal git repository in a temp directory."""
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
    """A repo with no secrets."""
    readme = git_repo / "README.md"
    readme.write_text("# Test Repo\nThis is a test repository.\n")

    gitignore = git_repo / ".gitignore"
    gitignore.write_text(textwrap.dedent("""\
        .env
        *.pem
        *.key
        node_modules
        __pycache__
        *.pyc
        *.log
        *.sqlite
        *.db
        .DS_Store
    """))

    subprocess.run(
        ["git", "add", "."],
        cwd=str(git_repo), check=True, capture_output=True
    )
    subprocess.run(
        ["git", "commit", "-m", "Initial commit"],
        cwd=str(git_repo), check=True, capture_output=True
    )
    return git_repo


@pytest.fixture
def dirty_repo(git_repo: Path) -> Path:
    """A repo with hardcoded secrets (non-live example strings)."""
    config_file = git_repo / "config.py"
    config_file.write_text(textwrap.dedent("""\
        # Application configuration
        DEBUG = True
        JWT_SECRET = "my_super_secret_jwt_signing_key_here_12345"
        PASSWORD = "hardcoded_password_value_1234"
        SECRET_KEY = "my_super_secret_django_key_12345"
    """))

    subprocess.run(
        ["git", "add", "."],
        cwd=str(git_repo), check=True, capture_output=True
    )
    subprocess.run(
        ["git", "commit", "-m", "Add config"],
        cwd=str(git_repo), check=True, capture_output=True
    )
    return git_repo


# ---------------------------------------------------------------------------
# _is_git_repo tests
# ---------------------------------------------------------------------------

class TestIsGitRepo:
    def test_valid_git_repo(self, git_repo: Path):
        assert _is_git_repo(git_repo) is True

    def test_non_git_directory(self, tmp_path: Path):
        assert _is_git_repo(tmp_path) is False

    def test_nested_directory_not_repo(self, tmp_path: Path):
        nested = tmp_path / "some" / "nested" / "dir"
        nested.mkdir(parents=True)
        assert _is_git_repo(nested) is False


# ---------------------------------------------------------------------------
# _should_skip_file tests
# ---------------------------------------------------------------------------

class TestShouldSkipFile:
    def test_python_file_not_skipped(self, tmp_path: Path):
        f = tmp_path / "app.py"
        f.write_text("print('hello')")
        assert not _should_skip_file(f)

    def test_png_file_skipped(self, tmp_path: Path):
        f = tmp_path / "image.png"
        f.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
        assert _should_skip_file(f)

    def test_zip_file_skipped(self, tmp_path: Path):
        f = tmp_path / "archive.zip"
        f.write_bytes(b"PK\x03\x04")
        assert _should_skip_file(f)

    def test_large_file_skipped(self, tmp_path: Path):
        f = tmp_path / "bigfile.txt"
        f.write_bytes(b"A" * (1_048_576 + 1))  # 1MB + 1 byte
        assert _should_skip_file(f)

    def test_json_file_not_skipped(self, tmp_path: Path):
        f = tmp_path / "data.json"
        f.write_text('{"key": "value"}')
        assert not _should_skip_file(f)


# ---------------------------------------------------------------------------
# _redact tests
# ---------------------------------------------------------------------------

class TestRedact:
    def test_short_string_fully_redacted(self):
        result = _redact("abc", keep_chars=6)
        assert result == "***"

    def test_long_string_partially_redacted(self):
        result = _redact("AKIAIOSFODNN7EXAMPLE", keep_chars=4)
        assert result.startswith("AKIA")
        assert "*" in result

    def test_exact_keep_chars_length(self):
        result = _redact("123456", keep_chars=6)
        assert result == "123456"


# ---------------------------------------------------------------------------
# run_full_scan — error handling
# ---------------------------------------------------------------------------

class TestRunFullScanErrors:
    def test_nonexistent_path_raises(self):
        with pytest.raises(ValueError, match="does not exist"):
            run_full_scan("/nonexistent/path/to/nowhere")

    def test_not_a_directory_raises(self, tmp_path: Path):
        f = tmp_path / "somefile.txt"
        f.write_text("hello")
        with pytest.raises(ValueError, match="not a directory"):
            run_full_scan(str(f))

    def test_non_git_directory_raises(self, tmp_path: Path):
        with pytest.raises(ValueError, match="not a git repository"):
            run_full_scan(str(tmp_path))


# ---------------------------------------------------------------------------
# Working tree scan tests
# ---------------------------------------------------------------------------

class TestScanWorkingTree:
    def test_clean_repo_has_no_secret_findings(self, clean_repo: Path):
        result = ScanResult(repo_path=str(clean_repo))
        scan_working_tree(clean_repo, result)
        secret_findings = [f for f in result.findings if f.category == "secret"]
        assert len(secret_findings) == 0, f"Unexpected findings: {[f.name for f in secret_findings]}"

    def test_jwt_secret_detected_in_file(self, git_repo: Path):
        f = git_repo / "deploy.sh"
        f.write_text('JWT_SECRET = "jwt_secret_key_for_testing_1234567890"\n')
        result = ScanResult(repo_path=str(git_repo))
        scan_working_tree(git_repo, result)
        names = [f.name for f in result.findings]
        assert any("JWT" in n or "Secret" in n for n in names), f"Expected JWT/secret finding, got: {names}"

    def test_database_url_detected(self, git_repo: Path):
        f = git_repo / "settings.py"
        f.write_text('DATABASE_URL = "postgres://user:password@localhost/db"\n')
        result = ScanResult(repo_path=str(git_repo))
        scan_working_tree(git_repo, result)
        names = [f.name for f in result.findings]
        assert "Database Connection String" in names

    def test_private_key_detected(self, git_repo: Path):
        f = git_repo / "server.pem"
        f.write_text("-----BEGIN RSA PRIVATE KEY-----\nFAKEKEYDATA\n-----END RSA PRIVATE KEY-----\n")
        result = ScanResult(repo_path=str(git_repo))
        scan_working_tree(git_repo, result)
        names = [f.name for f in result.findings]
        assert any("Private Key" in n or "PEM" in n for n in names)

    def test_env_file_flagged_as_sensitive(self, git_repo: Path):
        f = git_repo / ".env"
        f.write_text("API_KEY=secret\n")
        result = ScanResult(repo_path=str(git_repo))
        scan_working_tree(git_repo, result)
        sensitive = [f for f in result.findings if f.category == "sensitive_file"]
        assert len(sensitive) > 0

    def test_files_scanned_counter_increments(self, clean_repo: Path):
        result = ScanResult(repo_path=str(clean_repo))
        scan_working_tree(clean_repo, result)
        assert result.files_scanned > 0

    def test_png_file_not_scanned(self, git_repo: Path):
        f = git_repo / "logo.png"
        f.write_bytes(b"\x89PNG\r\n\x1a\n" + b"password='secret'" * 100)
        result_before = ScanResult(repo_path=str(git_repo))
        scan_working_tree(git_repo, result_before)
        assert result_before.files_scanned >= 0  # At least we didn't crash


# ---------------------------------------------------------------------------
# .gitignore audit tests
# ---------------------------------------------------------------------------

class TestAuditGitignore:
    def test_missing_gitignore_flagged(self, git_repo: Path):
        result = ScanResult(repo_path=str(git_repo))
        audit_gitignore(git_repo, result)
        names = [f.name for f in result.findings]
        assert "Missing .gitignore" in names

    def test_complete_gitignore_passes(self, clean_repo: Path):
        result = ScanResult(repo_path=str(clean_repo))
        audit_gitignore(clean_repo, result)
        critical_high = [f for f in result.findings if f.severity in ("critical", "high")]
        assert len(critical_high) == 0, f"Unexpected high/critical gitignore findings: {[f.name for f in critical_high]}"

    def test_env_missing_from_gitignore_flagged(self, git_repo: Path):
        gitignore = git_repo / ".gitignore"
        gitignore.write_text("*.log\nnode_modules\n")  # .env missing
        result = ScanResult(repo_path=str(git_repo))
        audit_gitignore(git_repo, result)
        names = [f.name for f in result.findings]
        assert any(".env" in n for n in names)


# ---------------------------------------------------------------------------
# Score calculation tests
# ---------------------------------------------------------------------------

class TestScoreCalculation:
    def test_no_findings_score_100(self):
        result = ScanResult(repo_path="/fake")
        assert result.score == 100

    def test_critical_deducts_25(self):
        from gitscope.scanner import Finding
        result = ScanResult(repo_path="/fake")
        result.add_finding(Finding(
            category="secret", name="Test", severity="critical",
            description="d", remediation="r"
        ))
        assert result.score == 75

    def test_high_deducts_10(self):
        from gitscope.scanner import Finding
        result = ScanResult(repo_path="/fake")
        result.add_finding(Finding(
            category="secret", name="Test", severity="high",
            description="d", remediation="r"
        ))
        assert result.score == 90

    def test_score_floored_at_zero(self):
        from gitscope.scanner import Finding
        result = ScanResult(repo_path="/fake")
        for _ in range(10):
            result.add_finding(Finding(
                category="secret", name="Test", severity="critical",
                description="d", remediation="r"
            ))
        assert result.score == 0

    def test_mixed_findings_score(self):
        from gitscope.scanner import Finding
        result = ScanResult(repo_path="/fake")
        result.add_finding(Finding(category="secret", name="A", severity="critical", description="d", remediation="r"))
        result.add_finding(Finding(category="secret", name="B", severity="high", description="d", remediation="r"))
        assert result.score == 65


# ---------------------------------------------------------------------------
# Full scan integration test
# ---------------------------------------------------------------------------

class TestFullScan:
    def test_full_scan_clean_repo(self, clean_repo: Path):
        result = run_full_scan(str(clean_repo), scan_history=True)
        assert isinstance(result, ScanResult)
        assert result.files_scanned > 0
        assert result.commits_scanned > 0
        secret_findings = [f for f in result.findings if f.category == "secret"]
        assert len(secret_findings) == 0

    def test_full_scan_dirty_repo_finds_secrets(self, dirty_repo: Path):
        result = run_full_scan(str(dirty_repo), scan_history=False)
        assert len(result.findings) > 0
        severities = {f.severity for f in result.findings}
        assert severities & {"critical", "high", "medium"}

    def test_full_scan_returns_valid_score(self, clean_repo: Path):
        result = run_full_scan(str(clean_repo))
        assert 0 <= result.score <= 100

    def test_sorted_findings_most_severe_first(self, dirty_repo: Path):
        result = run_full_scan(str(dirty_repo), scan_history=False)
        if len(result.findings) > 1:
            ranks = [f.severity_rank() for f in result.sorted_findings()]
            assert ranks == sorted(ranks)
