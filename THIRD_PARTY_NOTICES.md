# Third-Party Notices

gitscope is an original work by ranahmad1, built entirely using the Python standard library.
It has **no runtime dependencies** on third-party packages.

---

## Inspiration and Research

The following open-source projects were researched during the design of gitscope's detection patterns.
**No code was copied from any of these projects.** They informed the categories of secrets worth detecting
and the general approach to pattern-based scanning.

### truffleHog
- Repository: https://github.com/trufflesecurity/trufflehog
- License: GNU Affero General Public License v3.0 (AGPL-3.0)
- Use: Informed the categories of credentials worth detecting (AWS, GitHub, Stripe, etc.)
- Code copied: None

### gitleaks
- Repository: https://github.com/gitleaks/gitleaks
- License: MIT License
- Use: Reference for the general concept of git history scanning for secrets
- Code copied: None

### detect-secrets
- Repository: https://github.com/Yelp/detect-secrets
- License: Apache License 2.0
- Use: Reference for the concept of severity scoring and CI/CD integration patterns
- Code copied: None

---

## Development Dependencies

The following packages are used only during development and testing. They are **not** bundled with or required by gitscope at runtime.

### pytest
- Repository: https://github.com/pytest-dev/pytest
- License: MIT License
- Use: Test runner for the gitscope test suite

### pytest-cov
- Repository: https://github.com/pytest-dev/pytest-cov
- License: MIT License
- Use: Code coverage reporting during development

---

## Standards Referenced

The following publicly available security resources were referenced when writing detection patterns and remediation advice:

- AWS IAM Best Practices: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
- GitHub Token Formats: https://docs.github.com/en/authentication
- OWASP: Hardcoded Credentials: https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_credentials
- gitignore.io (community-maintained .gitignore templates): https://www.toptal.com/developers/gitignore

---

All patterns, source code, documentation, and tooling in this repository were written from scratch by ranahmad1.
