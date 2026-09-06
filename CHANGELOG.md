# Changelog

All notable changes to gitscope will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] — 2026-09-06

### Added

**Core scanning engine**
- Working-tree file scan for hardcoded secrets using 21 pattern categories
- Git commit history scan (configurable depth, default 50 commits)
- Sensitive filename detection (15 file type categories)
- `.gitignore` hygiene audit (10 recommended rule checks)
- Git config credential check (embedded URLs, plaintext credential helper)

**Secret pattern coverage**
- AWS Access Key ID and Secret Access Key
- GitHub Personal Access Tokens (new `ghp_`, `gho_`, `ghs_`, `ghr_` format)
- Stripe live, test, and publishable keys
- Google API Keys and OAuth client secrets
- Slack bot tokens and Incoming Webhook URLs
- Twilio Account SID and Auth Token
- SendGrid API Keys
- Database connection strings with embedded credentials (PostgreSQL, MySQL, MongoDB, Redis)
- PEM private key headers (RSA, EC, DSA, OpenSSH)
- JWT signing secrets
- Hardcoded password assignments
- Hardcoded Bearer tokens
- Generic API key/secret/token assignments
- NPM auth tokens
- Firebase database URLs
- SSH private key filename references

**Output formats**
- Terminal output with ANSI colors, severity badges, score gauge, and grade
- JSON output for CI/CD and tooling integration
- Plain text output (no ANSI codes)
- File output via `--output`

**CLI features**
- Configurable commit depth (`--depth`)
- Minimum severity filter (`--min-severity`)
- Configurable fail threshold (`--fail-on`)
- History scan toggle (`--no-history`)
- Verbose debug logging (`--verbose`)

**Security score**
- 0–100 score with severity-weighted deductions
- Letter grade (A–F)

**Testing**
- 103 unit and integration tests across 4 test modules
- Tests use real temporary git repositories for integration coverage

**Documentation**
- Full README with usage examples, CI/CD integration, architecture overview
- CONTRIBUTING.md with pattern contribution guide
- SECURITY.md with responsible disclosure policy
- THIRD_PARTY_NOTICES.md
- GitHub Actions CI workflow
- GitHub issue templates (bug report, feature request, new pattern)

---

## Upcoming

### [1.1.0] — Planned

- Pre-commit hook installer (`gitscope install-hook`)
- `.gitscope.toml` configuration file for custom patterns and ignores
- Allowlist comments (`# gitscope: ignore`) for false-positive suppression
- SARIF output format for GitHub Code Scanning

### [1.2.0] — Planned

- HTML report output
- Glob-based file path exclusions (`--exclude-path`)
- Pattern severity customization via config
