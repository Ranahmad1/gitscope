# Contributing to gitscope

Thank you for your interest in improving gitscope! Contributions are welcome and appreciated.

---

## Ways to contribute

- **Add new secret patterns** — the most impactful contribution
- **Fix false positives** — help reduce noise for common patterns
- **Report bugs** — use the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md)
- **Suggest features** — use the [feature request template](.github/ISSUE_TEMPLATE/feature_request.md)
- **Improve documentation** — clarify usage, add examples

---

## Development setup

```bash
git clone https://github.com/Ranahmad1/gitscope.git
cd gitscope
pip install -e ".[dev]"
python -m pytest  # verify everything passes
```

---

## Adding a new detection pattern

All patterns live in `gitscope/patterns.py`. Adding a new secret pattern is straightforward.

### Pattern structure

Each entry in `SECRET_PATTERNS` is a Python dict:

```python
{
    "name": "My Service API Key",
    "regex": re.compile(r"my-pattern"),    # ALWAYS pre-compiled
    "severity": "high",                    # critical | high | medium | low
    "description": "What was found and why it matters.",
    "remediation": "Specific steps to fix this.",
}
```

### Severity guidelines

| Severity | When to use |
|---|---|
| `critical` | Direct authentication to a service with financial or data impact |
| `high` | Service tokens with significant access |
| `medium` | References to sensitive files, test/demo keys |
| `low` | Style/hygiene issues, missing `.gitignore` rules |

### Writing good regexes

- **Always pre-compile** with `re.compile(r"...")` — patterns are applied to every line of every file
- **Avoid catastrophic backtracking** — test your regex against large inputs
- **Use `(?i)` for case-insensitive matching** when appropriate
- **Don't over-match** — a pattern that fires on every string is worse than missing a real secret
- **Test both positive and negative cases**

### Testing your pattern

Add tests to `tests/test_patterns.py`:

```python
def test_my_service_key_detected(self):
    pattern = self._find_pattern("My Service API Key")
    assert pattern["regex"].search("MYSERVICE-abc123def456ghi789")

def test_my_service_key_not_overly_broad(self):
    pattern = self._find_pattern("My Service API Key")
    assert not pattern["regex"].search("some random string")
```

Run the tests:

```bash
python -m pytest tests/test_patterns.py -v
```

---

## Code style

- Follow the existing code style (no linter enforced, but keep it consistent)
- Docstrings on all public functions and classes
- No external runtime dependencies — only Python standard library

---

## Submitting a pull request

1. Fork the repository
2. Create a branch: `git checkout -b feat/my-new-pattern`
3. Make your changes
4. Run all tests: `python -m pytest`
5. Commit with a clear message: `feat: add detection for XYZ API keys`
6. Push and open a pull request

**PR checklist:**
- [ ] Tests added for new patterns (both positive and negative cases)
- [ ] All existing tests still pass
- [ ] Pattern `severity` is appropriate and documented
- [ ] `description` explains the risk clearly
- [ ] `remediation` gives actionable steps
- [ ] CHANGELOG.md updated

---

## License

By contributing to gitscope, you agree that your contributions will be licensed under the MIT License.
