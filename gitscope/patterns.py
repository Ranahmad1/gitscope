"""
patterns.py — Secret and sensitive data detection patterns for gitscope.

Each pattern entry is a dict with:
  - name:        Human-readable label shown in the report
  - regex:       Compiled regular expression to match against file content
  - severity:    "critical", "high", "medium", or "low"
  - description: Explanation of what was found
  - remediation: Actionable advice for fixing the issue

Author: ranahmad1
License: MIT
"""

import re

# ---------------------------------------------------------------------------
# Secret / credential patterns
# ---------------------------------------------------------------------------

SECRET_PATTERNS = [
    {
        "name": "AWS Access Key ID",
        "regex": re.compile(r"(?i)AKIA[0-9A-Z]{16}"),
        "severity": "critical",
        "description": "AWS Access Key ID detected. These credentials provide API access to AWS services.",
        "remediation": "Rotate the key immediately in AWS IAM, then remove it from code. Use environment variables or AWS Secrets Manager.",
    },
    {
        "name": "AWS Secret Access Key",
        "regex": re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"),
        "severity": "critical",
        "description": "AWS Secret Access Key detected.",
        "remediation": "Rotate immediately. Never store AWS credentials in source code.",
    },
    {
        "name": "Generic API Key",
        "regex": re.compile(
            r"(?i)(?:api[_\-]?key|apikey|api[_\-]?secret)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-]{20,})['\"]?"
        ),
        "severity": "high",
        "description": "Generic API key or secret assignment detected.",
        "remediation": "Move the key to a .env file (excluded from git) or a secrets manager.",
    },
    {
        "name": "GitHub Personal Access Token",
        "regex": re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,255}"),
        "severity": "critical",
        "description": "GitHub Personal Access Token detected.",
        "remediation": "Revoke this token on GitHub immediately. Use GitHub Actions secrets for CI workflows.",
    },
    {
        "name": "Slack Bot/Webhook Token",
        "regex": re.compile(r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}"),
        "severity": "high",
        "description": "Slack API token detected.",
        "remediation": "Regenerate the token in the Slack API dashboard. Never commit Slack tokens.",
    },
    {
        "name": "Slack Incoming Webhook URL",
        "regex": re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+"),
        "severity": "high",
        "description": "Slack Incoming Webhook URL detected. Anyone with this URL can post to your Slack channel.",
        "remediation": "Rotate the webhook in Slack App settings. Store in environment variables.",
    },
    {
        "name": "Stripe Secret Key",
        "regex": re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
        "severity": "critical",
        "description": "Stripe live secret key detected. This grants full API access to your Stripe account.",
        "remediation": "Roll the key in the Stripe Dashboard immediately.",
    },
    {
        "name": "Stripe Publishable/Test Key",
        "regex": re.compile(r"(?:pk_live|pk_test|sk_test)_[0-9a-zA-Z]{24,}"),
        "severity": "medium",
        "description": "Stripe publishable or test key detected.",
        "remediation": "While test keys are less critical, avoid committing any payment keys.",
    },
    {
        "name": "Google API Key",
        "regex": re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
        "severity": "high",
        "description": "Google API Key detected.",
        "remediation": "Restrict the key in Google Cloud Console and rotate it. Use environment variables.",
    },
    {
        "name": "Google OAuth Client Secret",
        "regex": re.compile(r"(?i)google.{0,30}['\"][0-9a-zA-Z_\-]{24}['\"]"),
        "severity": "high",
        "description": "Possible Google OAuth secret detected.",
        "remediation": "Revoke in Google Cloud Console > Credentials.",
    },
    {
        "name": "Generic Password Assignment",
        "regex": re.compile(
            r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,})['\"]"
        ),
        "severity": "high",
        "description": "Hardcoded password detected in source code.",
        "remediation": "Use environment variables or a secrets manager. Never hardcode passwords.",
    },
    {
        "name": "Database Connection String",
        "regex": re.compile(
            r"(?i)(?:postgres|mysql|mongodb|sqlserver|redis)://[a-zA-Z0-9_%+\-]+:[^@\s]{3,}@[^\s]+"
        ),
        "severity": "critical",
        "description": "Database connection string with credentials detected.",
        "remediation": "Remove the connection string. Use DATABASE_URL environment variable.",
    },
    {
        "name": "Private Key Header",
        "regex": re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
        ),
        "severity": "critical",
        "description": "Private key (RSA/EC/DSA/OpenSSH) detected in source code.",
        "remediation": "Remove this key immediately. Generate a new key pair. Never commit private keys.",
    },
    {
        "name": "JWT Secret / Token",
        "regex": re.compile(
            r"(?i)jwt[_\-]?secret\s*[=:]\s*['\"]?([a-zA-Z0-9_\-]{16,})['\"]?"
        ),
        "severity": "high",
        "description": "JWT signing secret detected. This allows forging authentication tokens.",
        "remediation": "Move to an environment variable. Rotate immediately if exposed.",
    },
    {
        "name": "SendGrid API Key",
        "regex": re.compile(r"SG\.[a-zA-Z0-9_\-]{22,}\.[a-zA-Z0-9_\-]{43,}"),
        "severity": "high",
        "description": "SendGrid API Key detected.",
        "remediation": "Revoke in the SendGrid console and use an environment variable.",
    },
    {
        "name": "Twilio Account SID / Auth Token",
        "regex": re.compile(r"AC[a-f0-9]{32}|SK[a-f0-9]{32}"),
        "severity": "high",
        "description": "Twilio Account SID or Auth Token detected.",
        "remediation": "Regenerate in the Twilio console. Store in environment variables.",
    },
    {
        "name": "Firebase Config / URL",
        "regex": re.compile(r"https://[a-z0-9\-]+\.firebaseio\.com"),
        "severity": "medium",
        "description": "Firebase database URL detected.",
        "remediation": "Ensure Firestore rules are locked down. Avoid exposing admin credentials.",
    },
    {
        "name": "NPM Auth Token",
        "regex": re.compile(r"//registry\.npmjs\.org/:_authToken\s*=\s*[a-zA-Z0-9_\-]+"),
        "severity": "high",
        "description": "NPM authentication token detected.",
        "remediation": "Revoke at npmjs.com and use CI environment secrets.",
    },
    {
        "name": "SSH Private Key Path",
        "regex": re.compile(r"(?i)id_rsa|id_ed25519|id_ecdsa"),
        "severity": "medium",
        "description": "Reference to SSH private key file detected.",
        "remediation": "Ensure private key files are in .gitignore and never committed.",
    },
    {
        "name": "Hardcoded Bearer Token",
        "regex": re.compile(r"(?i)Authorization:\s*Bearer\s+[a-zA-Z0-9_\-\.]{20,}"),
        "severity": "high",
        "description": "Hardcoded Authorization Bearer token found.",
        "remediation": "Move to environment variables. Never commit auth headers with real tokens.",
    },
    {
        "name": "Generic Secret Variable",
        "regex": re.compile(
            r"(?i)(?:secret|token|access_token|auth_token)\s*[=:]\s*['\"]([a-zA-Z0-9_\-]{16,})['\"]"
        ),
        "severity": "medium",
        "description": "Generic secret or token variable assignment detected.",
        "remediation": "Verify this is not a real credential. If so, move to environment variables.",
    },
]

# ---------------------------------------------------------------------------
# Files that should never be committed
# ---------------------------------------------------------------------------

SENSITIVE_FILENAMES = [
    {"pattern": re.compile(r"^\.env$"), "name": ".env file", "severity": "critical",
     "description": "Environment file with credentials should never be committed.",
     "remediation": "Add '.env' to .gitignore. Use .env.example for templates."},
    {"pattern": re.compile(r"^\.env\.\w+$"), "name": ".env variant", "severity": "high",
     "description": "Environment file variant detected.",
     "remediation": "Ensure all .env.* files except .env.example are in .gitignore."},
    {"pattern": re.compile(r".*\.pem$"), "name": "PEM certificate/key file", "severity": "critical",
     "description": "PEM file (certificate or key) detected.",
     "remediation": "Remove from repository. Add *.pem to .gitignore."},
    {"pattern": re.compile(r".*\.key$"), "name": "Private key file (.key)", "severity": "critical",
     "description": "Private key file detected.",
     "remediation": "Remove from repository. Add *.key to .gitignore."},
    {"pattern": re.compile(r".*id_rsa.*"), "name": "SSH RSA private key", "severity": "critical",
     "description": "SSH RSA private key file detected.",
     "remediation": "Remove immediately. Add to .gitignore."},
    {"pattern": re.compile(r".*id_ed25519(?!\.pub).*"), "name": "SSH Ed25519 private key", "severity": "critical",
     "description": "SSH Ed25519 private key file detected.",
     "remediation": "Remove immediately. Add to .gitignore."},
    {"pattern": re.compile(r".*credentials.*\.(json|yaml|yml)$"), "name": "Credentials config file",
     "severity": "high",
     "description": "File named 'credentials' in JSON/YAML format detected.",
     "remediation": "Add to .gitignore. Use service-specific secrets management."},
    {"pattern": re.compile(r".*secrets?\.(json|yaml|yml|toml|ini|cfg|conf)$"), "name": "Secrets config file",
     "severity": "high",
     "description": "File named 'secret(s)' in config format detected.",
     "remediation": "Add to .gitignore. Reference secrets via environment variables."},
    {"pattern": re.compile(r".*\.pfx$|.*\.p12$"), "name": "PKCS12 certificate", "severity": "critical",
     "description": "PKCS12 certificate bundle detected.",
     "remediation": "Remove from repository. Store in a secrets manager."},
    {"pattern": re.compile(r".*keystore\.(jks|p12)$"), "name": "Java keystore", "severity": "critical",
     "description": "Java keystore file detected.",
     "remediation": "Remove from repository. Keep keystores out of version control."},
    {"pattern": re.compile(r".*database\.ya?ml$"), "name": "Database config (Rails-style)", "severity": "high",
     "description": "database.yml detected — may contain database credentials.",
     "remediation": "Ensure credentials are templated and actual values are in .gitignore."},
    {"pattern": re.compile(r"wp-config\.php$"), "name": "WordPress config", "severity": "high",
     "description": "wp-config.php with database credentials detected.",
     "remediation": "Add wp-config.php to .gitignore. Use environment-based configuration."},
    {"pattern": re.compile(r".*\.sqlite$|.*\.sqlite3$|.*\.db$"), "name": "SQLite database file",
     "severity": "medium",
     "description": "Database file detected in repository.",
     "remediation": "Add *.sqlite, *.db to .gitignore. Never commit database files."},
    {"pattern": re.compile(r".*htpasswd$|.*\.htpasswd$"), "name": "htpasswd file", "severity": "high",
     "description": "Apache/Nginx password file detected.",
     "remediation": "Remove from repository. Add .htpasswd to .gitignore."},
    {"pattern": re.compile(r".*service[_\-]?account.*\.json$"), "name": "Service account JSON",
     "severity": "critical",
     "description": "Google/Cloud service account JSON detected.",
     "remediation": "Remove immediately. Use Workload Identity or environment variables."},
]

# ---------------------------------------------------------------------------
# .gitignore hygiene: patterns that should appear in .gitignore
# ---------------------------------------------------------------------------

RECOMMENDED_GITIGNORE_PATTERNS = [
    {"pattern": ".env", "description": ".env files (contain credentials)", "severity": "high"},
    {"pattern": "*.pem", "description": "PEM certificate/key files", "severity": "high"},
    {"pattern": "*.key", "description": "Private key files", "severity": "medium"},
    {"pattern": "node_modules", "description": "Node.js dependencies directory", "severity": "low"},
    {"pattern": "*.log", "description": "Log files (may contain sensitive data)", "severity": "low"},
    {"pattern": "*.sqlite", "description": "SQLite database files", "severity": "medium"},
    {"pattern": "*.db", "description": "Database files", "severity": "medium"},
    {"pattern": "__pycache__", "description": "Python bytecode cache", "severity": "low"},
    {"pattern": "*.pyc", "description": "Python compiled files", "severity": "low"},
    {"pattern": ".DS_Store", "description": "macOS metadata files", "severity": "low"},
]

# ---------------------------------------------------------------------------
# Binary / non-text file extensions to skip during scanning
# ---------------------------------------------------------------------------

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".mp3", ".mp4", ".avi", ".mov", ".wav",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".bin",
    ".pdf", ".docx", ".xlsx", ".pptx",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".pyc", ".pyo", ".class",
    ".lock",
}

# Extensions always skipped even if not binary (minified, generated)
SKIP_EXTENSIONS = {
    ".min.js", ".min.css", ".map",
}
