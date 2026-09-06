---
name: New Detection Pattern
about: Suggest a new secret or sensitive file pattern for gitscope to detect
title: "[Pattern] Add detection for: "
labels: new-pattern
assignees: ''
---

## What should be detected?

The credential type, file type, or configuration issue to detect.

## Example of what it looks like in code

```
# Example (use fake/example values only, never real credentials)
API_KEY = "EXAMPLE_12345_fake_value_here"
```

## Proposed regex (optional)

```python
re.compile(r"your-pattern-here")
```

## Suggested severity

- [ ] Critical
- [ ] High
- [ ] Medium
- [ ] Low

## Reference

Link to documentation or public resources about this credential type.
