# gitscope 🔍

**Git Repository Security Hygiene Auditor**

A lightweight, zero-dependency CLI tool that scans your local Git repositories for hardcoded secrets, credential leaks, sensitive files, and security misconfigurations — including secrets buried in commit history.

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  gitscope — Git Repository Security Hygiene Auditor
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Repository : /home/dev/myproject
  Scanned at : 2026-09-06 10:30:00 UTC
  Files      : 47
  Commits    : 50
  Findings   : 3  (1 critical, 2 high)

  Security Score: 55/100
  ████████████████░░░░░░░░░░░░░░  55%
  Grade: C — Needs attention

──────────────────────────────────────────────────────────────────────
  CRITICAL (1 finding)
──────────────────────────────────────────────────────────────────────
    1. [CRITICAL]  AWS Access Key ID
       File: src/deploy.sh:14
       Match: AKIAIO**************
       What: AWS Access Key ID detected. Provides API access to AWS services.
       Fix : Rotate the key immediately in AWS IAM, then remove it from code.
```

---

## Why gitscope?

Most secret scanning tools — [truffleHog](https://github.com/trufflesecurity/trufflehog), [gitleaks](https://github.com/gitleaks/gitleaks), [detect-secrets](https://github.com/Yelp/detect-secrets) — are powerful but require Docker, external binaries, or complex configuration to get started.

**gitscope is different:**

| Feature | gitscope | truffleHog | gitleaks | detect-secrets |
|---|---|---|---|---|
| Zero external dependencies | ✅ | ❌ (Docker/binary) | ❌ (binary) | Partial |
| Pure Python stdlib | ✅ | ❌ | ❌ | Partial |
| Works fully offline | ✅ | ❌ | ✅ | ✅ |
| .gitignore hygiene audit | ✅ | ❌ | ❌ | ❌ |
| Security score + grade | ✅ | ❌ | ❌ | ❌ |
| JSON output for CI/CD | ✅ | ✅ | ✅ | ✅ |
| Remediation guidance | ✅ | ❌ | ❌ | ❌ |
| `pip install` only | ✅ | ❌ | ❌ | ✅ |

**gitscope is the tool you reach for when you want a fast, no-setup security gut-check on any Python-capable machine.**

---

## Features

- **Secret Detection** — 21 pattern categories covering AWS, GitHub, Stripe, Google, Slack, Twilio, SendGrid, JWT, database URLs, private keys, bearer tokens, and generic credentials
- **Git History Scanning** — Inspects the last N commits for secrets deleted from working tree but still present in history
- **Sensitive File Detection** — Flags `.env`, `.pem`, `.key`, private keys, keystores, service account JSONs, and other files that should never be committed
- **.gitignore Hygiene Audit** — Checks your `.gitignore` for missing rules that protect common sensitive patterns
- **Git Config Checks** — Detects credentials embedded in remote URLs or plaintext credential storage
- **Security Score** — Produces a 0–100 score with letter grade (A–F) based on severity-weighted findings
- **CI/CD Integration** — JSON output mode and configurable exit codes for pipeline integration
- **Remediation Guidance** — Every finding includes specific, actionable fix instructions

---

## Installation

**Requirements:** Python 3.8+, Git installed and on PATH. No other dependencies.

### From PyPI (recommended)

```bash
pip install gitscope
```

### From source

```bash
git clone https://github.com/Ranahmad1/gitscope.git
cd gitscope
pip install -e .
```

### Verify installation

```bash
gitscope --version
```

---

## Quick Start

```bash
# Scan the current directory (must be a git repo)
gitscope

# Scan a specific repository
gitscope /path/to/your/repo

# Fast scan — skip commit history
gitscope --no-history

# JSON output for CI/CD or tooling
gitscope --json

# Only show high/critical findings
gitscope --min-severity high

# Save JSON report to file
gitscope --json --output report.json
```

---

## Usage

```
usage: gitscope [PATH] [OPTIONS]

positional arguments:
  PATH                  Path to the git repository (default: current directory)

options:
  --version             Show version and exit
  --json                Output results as JSON
  --plain               Output plain text (no ANSI colors)
  --no-color            Disable ANSI colors in terminal output
  --no-history          Skip git commit history scan
  --depth N             Number of commits to inspect (default: 50)
  --min-severity LEVEL  Minimum severity to report: low|medium|high|critical (default: low)
  --output FILE         Write report to FILE instead of stdout
  --verbose             Enable debug logging
  --fail-on LEVEL       Exit with code 1 if findings at this level exist (default: medium)
                        Values: low | medium | high | critical | never
  -h, --help            Show help message
```

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | Clean — no findings at or above `--fail-on` threshold |
| `1` | Findings found at or above `--fail-on` threshold |
| `2` | Scan error (invalid path, not a git repo, etc.) |

---

## What gitscope detects

### Secrets & Credentials (21 pattern categories)

| Category | Examples |
|---|---|
| AWS credentials | AWS access key IDs, secret access keys |
| GitHub tokens | `ghp_`, `gho_`, `ghs_`, `ghr_` personal access tokens |
| Stripe keys | Live and test secret/publishable keys |
| Google credentials | API keys, OAuth client secrets |
| Slack tokens | Bot tokens, webhook URLs |
| Twilio | Account SID, Auth Token |
| SendGrid | API keys |
| Database URLs | `postgres://`, `mysql://`, `mongodb://`, `redis://` with embedded credentials |
| Private keys | RSA, EC, DSA, OpenSSH PEM headers |
| JWT secrets | JWT signing secret assignments |
| Hardcoded passwords | `password = '...'` assignments |
| Bearer tokens | `Authorization: Bearer <token>` in code |
| Generic API keys | `api_key = '...'` style assignments |
| NPM tokens | `.npmrc` auth token entries |
| Firebase URLs | Firebase database URL references |

### Sensitive Files (15 file types)

`.env`, `.env.*`, `.pem`, `.key`, `id_rsa`, `id_ed25519`, `*credentials*.json`, `*secrets*.yml`, `.pfx`, `.p12`, `*.jks`, `database.yml`, `wp-config.php`, `*.sqlite`, `.htpasswd`, `service_account*.json`

### .gitignore Hygiene (10 recommended rules)

Missing rules for: `.env`, `*.pem`, `*.key`, `node_modules`, `*.log`, `*.sqlite`, `*.db`, `__pycache__`, `*.pyc`, `.DS_Store`

### Git Config Issues

- Credentials embedded in remote URLs
- Plaintext credential storage (`credential.helper=store`)

---

## Security Score

| Grade | Score | Meaning |
|---|---|---|
| A | 90–100 | Excellent — minimal issues |
| B | 80–89 | Good — minor recommendations |
| C | 60–79 | Needs attention — some risks |
| D | 40–59 | Poor — significant issues |
| F | 0–39 | Critical issues — immediate action needed |

**Score deductions:** Critical −25 · High −10 · Medium −5 · Low −1

---

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/security.yml
name: Security Audit

on: [push, pull_request]

jobs:
  gitscope:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 50

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.x'

      - name: Install gitscope
        run: pip install gitscope

      - name: Run security scan
        run: gitscope --json --output gitscope-report.json --fail-on high

      - name: Upload security report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: gitscope-report
          path: gitscope-report.json
```

### GitLab CI

```yaml
gitscope:
  image: python:3.12-slim
  script:
    - pip install gitscope
    - gitscope --json --output report.json --fail-on high
  artifacts:
    when: always
    paths:
      - report.json
```

### Pre-commit Hook

```bash
#!/bin/sh
# .git/hooks/pre-commit
gitscope --no-history --min-severity high --fail-on high
```

### JSON Output Example

```json
{
  "gitscope_version": "1.0.0",
  "scan_timestamp": "2026-09-06T10:30:00Z",
  "repository": "/home/dev/myproject",
  "summary": {
    "files_scanned": 47,
    "commits_scanned": 50,
    "total_findings": 3,
    "critical": 1,
    "high": 2,
    "medium": 0,
    "low": 0,
    "score": 55
  },
  "findings": [
    {
      "category": "secret",
      "name": "AWS Access Key ID",
      "severity": "critical",
      "description": "AWS Access Key ID detected.",
      "remediation": "Rotate the key immediately in AWS IAM...",
      "file_path": "src/deploy.sh",
      "line_number": 14,
      "commit_hash": null,
      "matched_text": "AKIAIO**************"
    }
  ],
  "errors": []
}
```

---

## Real-World Use Cases

**Before open-sourcing a project** — Verify you haven't left credentials in the codebase or its history.

**In your CI/CD pipeline** — Catch credential commits before they reach your main branch.

**During code review** — Run on a PR branch to verify no secrets were introduced.

**Security auditing** — Audit inherited or third-party codebases before integrating them.

**Developer onboarding** — Help new team members understand what should and shouldn't be committed.

---

## Architecture

```
gitscope/
├── gitscope/
│   ├── __init__.py      Version and package metadata
│   ├── patterns.py      All detection patterns (secrets, files, gitignore rules)
│   ├── scanner.py       Core scanning engine (4 scan stages)
│   ├── reporter.py      Output formatters (terminal, JSON, plain)
│   └── cli.py           Argument parsing and CLI entry point
└── tests/
    ├── test_patterns.py Pattern unit tests
    ├── test_scanner.py  Scanner integration tests (real temp git repos)
    ├── test_reporter.py Reporter output tests
    └── test_cli.py      CLI behavior tests
```

**Design principles:**
- Zero runtime dependencies — only Python standard library
- Readable, commented code — easy to extend with new patterns
- Works fully offline — no network calls during scanning
- Secrets are redacted in output — first 6 chars + asterisks
- Deduplication in history scan — same secret in multiple commits reported once per file

---

## Limitations

gitscope is a **static pattern-matching tool**, not a full SAST solution:

- May miss heavily obfuscated secrets
- May produce false positives in test files containing example credential strings
- Does not perform network validation (e.g., checking if a key is active)
- History scanning covers the most recent N commits (configurable with `--depth`)

For production-grade scanning at scale, consider combining gitscope with [gitleaks](https://github.com/gitleaks/gitleaks) or [truffleHog](https://github.com/trufflesecurity/trufflehog).

---

## Development

```bash
git clone https://github.com/Ranahmad1/gitscope.git
cd gitscope
pip install -e ".[dev]"

python -m pytest                                             # all 103 tests
python -m pytest --cov=gitscope --cov-report=term-missing   # with coverage
python -m pytest tests/test_patterns.py -v                  # pattern tests only
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on adding new patterns or features.

---

## Roadmap

- [ ] Pre-commit hook installer (`gitscope install-hook`)
- [ ] `.gitscope.toml` configuration file (custom patterns, ignores)
- [ ] Allowlist comments (`# gitscope: ignore`) for false-positive suppression
- [ ] SARIF output for GitHub Code Scanning
- [ ] HTML report output
- [ ] Glob-based file exclusions (`--exclude-path`)

---

## Troubleshooting

**`not a git repository`** — Point gitscope at a directory containing a `.git` folder, or run `git init` first.

**`git: command not found`** — Install git: https://git-scm.com/downloads

**Too many false positives** — Use `--min-severity high` or `--no-history` to narrow scope.

**Scan is slow** — Use `--depth 20` or `--no-history` to limit scanning.

**Nothing found but I know there's a secret** — Run `--verbose` for debug output. Binary files and files over 1MB are skipped.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Author

**ranahmad1** — Full Stack Engineer & CS student from Pakistan
GitHub: [@Ranahmad1](https://github.com/Ranahmad1)
Portfolio: [ranahmad1.github.io/rana-ahmad-portfolio](https://ranahmad1.github.io/rana-ahmad-portfolio/)

---

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add patterns, fix bugs, or improve documentation.

## Security

If you find a security issue in gitscope itself, please see [SECURITY.md](SECURITY.md) for responsible disclosure guidelines.
