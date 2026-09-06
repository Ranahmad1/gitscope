"""
scanner.py — Core scanning engine for gitscope.

Performs:
  1. Working-tree file scan for hardcoded secrets
  2. Git commit history scan (HEAD~N commits)
  3. Sensitive file detection
  4. .gitignore hygiene audit
  5. Git config hygiene checks

Author: ranahmad1
License: MIT
"""

import os
import re
import subprocess
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from gitscope.patterns import (
    SECRET_PATTERNS,
    SENSITIVE_FILENAMES,
    RECOMMENDED_GITIGNORE_PATTERNS,
    BINARY_EXTENSIONS,
    SKIP_EXTENSIONS,
)

logger = logging.getLogger("gitscope")

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# Max file size to scan in bytes (1 MB)
MAX_FILE_SIZE = 1_048_576

# Max number of commits to inspect in history scan
DEFAULT_COMMIT_DEPTH = 50


@dataclass
class Finding:
    """Represents a single security finding."""

    category: str           # "secret", "sensitive_file", "gitignore", "git_config", "history"
    name: str               # Short name of the rule that triggered
    severity: str           # "critical", "high", "medium", "low"
    description: str        # What was found
    remediation: str        # How to fix it
    file_path: Optional[str] = None   # Relative path in repository
    line_number: Optional[int] = None # Line number in file (if applicable)
    commit_hash: Optional[str] = None # Commit SHA (for history findings)
    matched_text: Optional[str] = None  # Redacted preview of matched content

    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 99)


@dataclass
class ScanResult:
    """Aggregated result of a full repository scan."""

    repo_path: str
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    commits_scanned: int = 0
    errors: List[str] = field(default_factory=list)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "medium")

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "low")

    @property
    def score(self) -> int:
        """
        Security score out of 100.
        Deductions: critical=-25, high=-10, medium=-5, low=-1
        Floored at 0.
        """
        deductions = (
            self.critical_count * 25
            + self.high_count * 10
            + self.medium_count * 5
            + self.low_count * 1
        )
        return max(0, 100 - deductions)

    def sorted_findings(self) -> List[Finding]:
        return sorted(self.findings, key=lambda f: f.severity_rank())


def _is_git_repo(path: Path) -> bool:
    """Return True if the given path is inside a git repository."""
    git_dir = path / ".git"
    return git_dir.exists() and git_dir.is_dir()


def _get_tracked_files(repo_path: Path) -> List[Path]:
    """Return all files tracked by git in the repository."""
    try:
        result = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            logger.warning("git ls-files failed: %s", result.stderr.strip())
            return []
        files = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if line:
                files.append(repo_path / line)
        return files
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        logger.error("Failed to list git files: %s", exc)
        return []


def _get_all_files(repo_path: Path) -> List[Path]:
    """
    Recursively yield all non-hidden files in the repo,
    skipping .git directory and common build/dependency dirs.
    """
    SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv",
                 "dist", "build", ".tox", ".eggs", "*.egg-info"}
    files = []
    for root, dirs, filenames in os.walk(repo_path):
        dirs[:] = [
            d for d in dirs
            if d not in SKIP_DIRS and not d.startswith(".")
        ]
        for fname in filenames:
            files.append(Path(root) / fname)
    return files


def _should_skip_file(file_path: Path) -> bool:
    """Return True if this file should not be scanned for secrets."""
    suffix = file_path.suffix.lower()
    if suffix in BINARY_EXTENSIONS:
        return True
    name_lower = file_path.name.lower()
    for skip_ext in SKIP_EXTENSIONS:
        if name_lower.endswith(skip_ext):
            return True
    try:
        if file_path.stat().st_size > MAX_FILE_SIZE:
            logger.debug("Skipping large file: %s", file_path)
            return True
    except OSError:
        return True
    return False


def _redact(match: str, keep_chars: int = 6) -> str:
    """Redact most of a matched secret, keeping only the first few chars."""
    if len(match) < keep_chars:
        return "*" * len(match)
    return match[:keep_chars] + "*" * (len(match) - keep_chars)


def _scan_content_for_secrets(
    content: str,
    file_path: str,
    result: ScanResult,
    commit_hash: Optional[str] = None,
) -> None:
    """Scan raw text content line-by-line for secret patterns."""
    lines = content.splitlines()
    for lineno, line in enumerate(lines, start=1):
        for pattern_def in SECRET_PATTERNS:
            match = pattern_def["regex"].search(line)
            if match:
                matched_text = _redact(match.group(0))
                finding = Finding(
                    category="history" if commit_hash else "secret",
                    name=pattern_def["name"],
                    severity=pattern_def["severity"],
                    description=pattern_def["description"],
                    remediation=pattern_def["remediation"],
                    file_path=file_path,
                    line_number=lineno if not commit_hash else None,
                    commit_hash=commit_hash,
                    matched_text=matched_text,
                )
                result.add_finding(finding)
                break


def scan_working_tree(repo_path: Path, result: ScanResult) -> None:
    """
    Stage 1: Scan all working-tree files for:
      - Hardcoded secrets / credentials
      - Sensitive file names
    """
    logger.info("Scanning working tree: %s", repo_path)

    try:
        tracked = _get_tracked_files(repo_path)
        all_files = tracked if tracked else _get_all_files(repo_path)
    except Exception as exc:
        result.errors.append(f"File enumeration error: {exc}")
        all_files = _get_all_files(repo_path)

    for file_path in all_files:
        if not file_path.is_file():
            continue

        rel_path = str(file_path.relative_to(repo_path))

        for sf in SENSITIVE_FILENAMES:
            if sf["pattern"].match(file_path.name.lower()) or sf["pattern"].match(file_path.name):
                result.add_finding(Finding(
                    category="sensitive_file",
                    name=sf["name"],
                    severity=sf["severity"],
                    description=sf["description"],
                    remediation=sf["remediation"],
                    file_path=rel_path,
                ))

        if _should_skip_file(file_path):
            continue

        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            result.errors.append(f"Cannot read {rel_path}: {exc}")
            continue

        _scan_content_for_secrets(content, rel_path, result)
        result.files_scanned += 1


def scan_git_history(
    repo_path: Path,
    result: ScanResult,
    depth: int = DEFAULT_COMMIT_DEPTH,
) -> None:
    """
    Stage 2: Inspect recent git commit history for accidentally
    committed secrets (even if they were later deleted from working tree).
    """
    logger.info("Scanning git history (last %d commits)", depth)

    try:
        log_result = subprocess.run(
            ["git", "log", f"--max-count={depth}", "--pretty=format:%H %s"],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            timeout=60,
        )
        if log_result.returncode != 0:
            result.errors.append("Could not read git log.")
            return

        commits = []
        for line in log_result.stdout.splitlines():
            parts = line.split(" ", 1)
            if parts:
                commits.append(parts[0])

    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        result.errors.append(f"git log failed: {exc}")
        return

    seen_findings: set = set()

    for commit_hash in commits:
        try:
            diff_result = subprocess.run(
                ["git", "show", "--stat", "--patch", "--unified=0", commit_hash],
                cwd=str(repo_path),
                capture_output=True,
                text=True,
                timeout=30,
            )
            if diff_result.returncode != 0:
                continue

            diff_text = diff_result.stdout
            current_file = "<unknown>"

            for line in diff_text.splitlines():
                if line.startswith("diff --git"):
                    parts = line.split(" b/", 1)
                    current_file = parts[1] if len(parts) > 1 else "<unknown>"

                if line.startswith("+") and not line.startswith("+++"):
                    stripped = line[1:]
                    for pattern_def in SECRET_PATTERNS:
                        match = pattern_def["regex"].search(stripped)
                        if match:
                            dedup_key = (commit_hash[:8], pattern_def["name"], current_file)
                            if dedup_key in seen_findings:
                                break
                            seen_findings.add(dedup_key)
                            result.add_finding(Finding(
                                category="history",
                                name=pattern_def["name"],
                                severity=pattern_def["severity"],
                                description=(
                                    f"{pattern_def['description']} "
                                    f"Found in commit history (may no longer be in working tree)."
                                ),
                                remediation=(
                                    f"{pattern_def['remediation']} "
                                    "Also consider running `git filter-repo` or BFG Repo Cleaner "
                                    "to purge the secret from history entirely."
                                ),
                                file_path=current_file,
                                commit_hash=commit_hash[:8],
                                matched_text=_redact(match.group(0)),
                            ))
                            break

        except (subprocess.TimeoutExpired, Exception) as exc:
            logger.debug("Error processing commit %s: %s", commit_hash[:8], exc)
            continue

    result.commits_scanned = len(commits)


def audit_gitignore(repo_path: Path, result: ScanResult) -> None:
    """Stage 3: Audit .gitignore for missing recommended patterns."""
    logger.info("Auditing .gitignore")
    gitignore_path = repo_path / ".gitignore"

    if not gitignore_path.exists():
        result.add_finding(Finding(
            category="gitignore",
            name="Missing .gitignore",
            severity="medium",
            description="No .gitignore file found. Sensitive files may be accidentally committed.",
            remediation=(
                "Create a .gitignore file. Use gitignore.io or GitHub's templates "
                "for your tech stack."
            ),
            file_path=".gitignore",
        ))
        return

    try:
        gitignore_content = gitignore_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        result.errors.append("Cannot read .gitignore")
        return

    for rec in RECOMMENDED_GITIGNORE_PATTERNS:
        raw = rec["pattern"]
        regex_str = re.escape(raw).replace(r"\*", r".*")
        found = bool(re.search(regex_str, gitignore_content, re.IGNORECASE | re.MULTILINE))
        if not found:
            result.add_finding(Finding(
                category="gitignore",
                name=f"Missing gitignore rule: {rec['pattern']}",
                severity=rec["severity"],
                description=f".gitignore is missing a rule for: {rec['description']}",
                remediation=f"Add '{rec['pattern']}' to .gitignore.",
                file_path=".gitignore",
            ))


def audit_git_config(repo_path: Path, result: ScanResult) -> None:
    """Stage 4: Check git configuration for hygiene issues."""
    logger.info("Auditing git config")
    git_config_path = repo_path / ".git" / "config"

    if not git_config_path.exists():
        return

    try:
        config_content = git_config_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return

    cred_patterns = [
        re.compile(r"(?i)password\s*=\s*.+"),
        re.compile(r"(?i)token\s*=\s*.+"),
        re.compile(r"https://[^:]+:[^@]+@"),
    ]
    for pat in cred_patterns:
        if pat.search(config_content):
            result.add_finding(Finding(
                category="git_config",
                name="Credentials in git config",
                severity="high",
                description="Credentials may be embedded in .git/config (e.g., in remote URLs).",
                remediation=(
                    "Remove credentials from remote URLs. Use SSH or a credential manager. "
                    "Run: git remote set-url origin git@github.com:user/repo.git"
                ),
                file_path=".git/config",
            ))
            break

    if re.search(r"helper\s*=\s*store", config_content):
        result.add_finding(Finding(
            category="git_config",
            name="git credential.helper=store (plaintext)",
            severity="medium",
            description=(
                "git credential helper is set to 'store', which saves credentials "
                "in plaintext on disk (~/.git-credentials)."
            ),
            remediation=(
                "Use 'git config --global credential.helper osxkeychain' (macOS), "
                "'manager' (Windows), or 'libsecret' (Linux) instead."
            ),
            file_path=".git/config",
        ))


def run_full_scan(
    repo_path: str,
    scan_history: bool = True,
    commit_depth: int = DEFAULT_COMMIT_DEPTH,
) -> ScanResult:
    """
    Entry point: run all scan stages and return a ScanResult.

    Args:
        repo_path:     Path to the git repository root.
        scan_history:  If True, also scan git commit history.
        commit_depth:  How many commits to inspect in history scan.

    Returns:
        ScanResult with all findings.

    Raises:
        ValueError: If the path is not a valid git repository.
    """
    path = Path(repo_path).resolve()

    if not path.exists():
        raise ValueError(f"Path does not exist: {path}")

    if not path.is_dir():
        raise ValueError(f"Path is not a directory: {path}")

    if not _is_git_repo(path):
        raise ValueError(
            f"'{path}' is not a git repository. "
            "Run 'git init' first or point gitscope at a directory with a .git folder."
        )

    result = ScanResult(repo_path=str(path))

    scan_working_tree(path, result)

    if scan_history:
        scan_git_history(path, result, depth=commit_depth)

    audit_gitignore(path, result)
    audit_git_config(path, result)

    logger.info(
        "Scan complete. %d findings (%d critical, %d high, %d medium, %d low). Score: %d/100",
        len(result.findings),
        result.critical_count,
        result.high_count,
        result.medium_count,
        result.low_count,
        result.score,
    )

    return result
