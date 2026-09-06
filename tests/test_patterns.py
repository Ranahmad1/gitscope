"""
test_patterns.py — Unit tests for secret detection patterns.

Tests that each pattern correctly identifies its target credential type
and does NOT produce excessive false positives on safe content.

Author: ranahmad1
License: MIT
"""

import pytest
import re

from gitscope.patterns import SECRET_PATTERNS, SENSITIVE_FILENAMES, RECOMMENDED_GITIGNORE_PATTERNS


class TestSecretPatterns:
    """Tests that SECRET_PATTERNS match real secrets."""

    def _find_pattern(self, name: str):
        for p in SECRET_PATTERNS:
            if p["name"] == name:
                return p
        raise KeyError(f"Pattern '{name}' not found in SECRET_PATTERNS")

    def test_aws_access_key_id_detected(self):
        pattern = self._find_pattern("AWS Access Key ID")
        # Use a string that matches AKIA + 16 uppercase chars/digits
        assert pattern["regex"].search("AKIAIOSFODNN7EXAM" + "PLE")
        assert pattern["regex"].search("AWS_ACCESS_KEY=AKIAI" + "OSFODNN7EXAMPLE1")

    def test_aws_access_key_id_too_short_not_detected(self):
        pattern = self._find_pattern("AWS Access Key ID")
        assert not pattern["regex"].search("AKIA12345")

    def test_github_pat_detected(self):
        pattern = self._find_pattern("GitHub Personal Access Token")
        sample = "ghp_" + "a" * 36
        assert pattern["regex"].search(sample)

    def test_github_pat_old_format_not_matched(self):
        pattern = self._find_pattern("GitHub Personal Access Token")
        assert not pattern["regex"].search("abc123def456abc123def456abc123def456abcd")

    def test_slack_bot_token_detected(self):
        pattern = self._find_pattern("Slack Bot/Webhook Token")
        # Construct token from parts to avoid secret scanner
        tok = "xoxb-" + "1234567890123" + "-" + "1234567890123" + "-" + "abcdefghijklmnop12345678"
        assert pattern["regex"].search(tok)

    def test_stripe_live_key_detected(self):
        pattern = self._find_pattern("Stripe Secret Key")
        # Construct from parts
        key = "sk_live_" + "51HExampleKeyHere1234567890abcdef"
        assert pattern["regex"].search(key)

    def test_google_api_key_detected(self):
        pattern = self._find_pattern("Google API Key")
        # AIza + 35 chars
        key = "AIzaSyD-9tSrke72I6e48h8-" + "xxxxxxxxxxxxxxxx"
        assert pattern["regex"].search(key)

    def test_private_key_header_detected(self):
        pattern = self._find_pattern("Private Key Header")
        assert pattern["regex"].search("-----BEGIN RSA PRIVATE KEY-----")
        assert pattern["regex"].search("-----BEGIN PRIVATE KEY-----")
        assert pattern["regex"].search("-----BEGIN OPENSSH PRIVATE KEY-----")

    def test_hardcoded_password_detected(self):
        pattern = self._find_pattern("Generic Password Assignment")
        assert pattern["regex"].search("password = 'MyS3cur3Pass!'")
        assert pattern["regex"].search('pwd: "secret123"')

    def test_database_connection_string_detected(self):
        pattern = self._find_pattern("Database Connection String")
        assert pattern["regex"].search("postgres://user:password@localhost:5432/mydb")
        assert pattern["regex"].search("mysql://admin:hunter2@db.example.com/prod")
        assert pattern["regex"].search("mongodb://root:pass123@mongo:27017/app")

    def test_generic_api_key_detected(self):
        pattern = self._find_pattern("Generic API Key")
        assert pattern["regex"].search("API_KEY = 'abcdef1234567890abcdef'")
        assert pattern["regex"].search("apikey: 'xyz123secretvalue9876'")

    def test_jwt_secret_detected(self):
        pattern = self._find_pattern("JWT Secret / Token")
        assert pattern["regex"].search("JWT_SECRET = 'my_super_secret_key_here'")

    def test_sendgrid_key_detected(self):
        pattern = self._find_pattern("SendGrid API Key")
        # SG. + 22+ chars + . + 43+ chars
        key = "SG." + "a" * 22 + "." + "b" * 43
        assert pattern["regex"].search(key)

    def test_all_patterns_have_required_fields(self):
        required_fields = {"name", "regex", "severity", "description", "remediation"}
        for pattern in SECRET_PATTERNS:
            missing = required_fields - set(pattern.keys())
            assert not missing, f"Pattern '{pattern.get('name', '?')}' missing fields: {missing}"

    def test_all_severity_values_valid(self):
        valid = {"critical", "high", "medium", "low"}
        for pattern in SECRET_PATTERNS:
            assert pattern["severity"] in valid, (
                f"Pattern '{pattern['name']}' has invalid severity '{pattern['severity']}'"
            )

    def test_all_patterns_are_compiled_regex(self):
        for pattern in SECRET_PATTERNS:
            assert hasattr(pattern["regex"], "search"), (
                f"Pattern '{pattern['name']}' regex is not compiled"
            )


class TestSensitiveFilenames:
    """Tests for SENSITIVE_FILENAMES patterns."""

    def _match(self, filename: str):
        return [
            sf for sf in SENSITIVE_FILENAMES
            if sf["pattern"].match(filename.lower()) or sf["pattern"].match(filename)
        ]

    def test_env_file_detected(self):
        matches = self._match(".env")
        assert any(sf["name"] == ".env file" for sf in matches)

    def test_env_variant_detected(self):
        matches = self._match(".env.production")
        assert len(matches) > 0

    def test_pem_file_detected(self):
        matches = self._match("server.pem")
        assert len(matches) > 0

    def test_private_key_file_detected(self):
        matches = self._match("private.key")
        assert len(matches) > 0

    def test_ssh_key_detected(self):
        matches = self._match("id_rsa")
        assert len(matches) > 0

    def test_service_account_json_detected(self):
        matches = self._match("service_account.json")
        assert len(matches) > 0

    def test_regular_files_not_detected(self):
        safe_files = ["main.py", "README.md", "index.html", "app.js", "styles.css", "config.json"]
        for fname in safe_files:
            matches = self._match(fname)
            assert not matches, f"False positive: {fname} matched {[m['name'] for m in matches]}"

    def test_all_sensitive_filenames_have_required_fields(self):
        required = {"pattern", "name", "severity", "description", "remediation"}
        for sf in SENSITIVE_FILENAMES:
            missing = required - set(sf.keys())
            assert not missing, f"Sensitive filename rule '{sf.get('name', '?')}' missing: {missing}"


class TestGitignorePatterns:
    """Tests for RECOMMENDED_GITIGNORE_PATTERNS structure."""

    def test_env_pattern_present(self):
        patterns = [r["pattern"] for r in RECOMMENDED_GITIGNORE_PATTERNS]
        assert any(".env" in p for p in patterns)

    def test_pem_pattern_present(self):
        patterns = [r["pattern"] for r in RECOMMENDED_GITIGNORE_PATTERNS]
        assert any(".pem" in p or "pem" in p for p in patterns)

    def test_all_have_required_fields(self):
        required = {"pattern", "description", "severity"}
        for rec in RECOMMENDED_GITIGNORE_PATTERNS:
            missing = required - set(rec.keys())
            assert not missing, f"Gitignore recommendation missing fields: {missing}"
