# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 1.x | ✅ Active |

---

## Reporting a Vulnerability

If you discover a security vulnerability in gitscope itself, please **do not open a public GitHub issue**. Doing so may expose the vulnerability to malicious actors before a fix is available.

### How to report

Send a private report via one of these channels:

1. **GitHub Security Advisories** (preferred): [github.com/Ranahmad1/gitscope/security/advisories/new](https://github.com/Ranahmad1/gitscope/security/advisories/new)
2. **Email**: ahmadaslam0904@gmail.com — Subject: `[gitscope] Security Vulnerability`

### What to include

- A clear description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fix (optional but appreciated)

### Response timeline

- **Acknowledgment**: within 48 hours
- **Initial assessment**: within 5 business days
- **Fix and disclosure**: we aim to release a patch within 30 days for critical/high issues

---

## Scope

**In scope for gitscope security reports:**

- Vulnerabilities that allow an attacker to execute arbitrary code when gitscope scans a crafted repository
- Path traversal issues that allow scanning outside the target repository
- Regex denial-of-service (ReDoS) via crafted file content
- Information disclosure beyond what gitscope intentionally reports

**Out of scope:**

- Findings that gitscope correctly reports (expected behavior)
- Issues in the underlying Python runtime or git binary
- Feature requests (please use the [feature request template](.github/ISSUE_TEMPLATE/feature_request.md))

---

## Important notes on gitscope's design

gitscope is a **defensive, read-only** tool. It:
- Never modifies files or git history
- Never makes network requests during scanning
- Never stores or transmits data
- Redacts matched secrets in output (shows only first 6 characters + asterisks)
- Runs entirely locally on your machine

gitscope is not designed to and does not provide any capability for offensive security operations.
