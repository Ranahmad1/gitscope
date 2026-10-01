"""
test_timestamp.py — Regression test for the JSON scan_timestamp format.

The timestamp used to be built as `isoformat() + "Z"`, which produced an
invalid value like "2026-09-06T10:30:00.123456+00:00Z".

Author: ranahmad1
License: MIT
"""

import io
import json
import re
from datetime import datetime

from gitscope.scanner import ScanResult
from gitscope.reporter import render_json


def _timestamp():
    buf = io.StringIO()
    render_json(ScanResult(repo_path="/fake/repo"), stream=buf)
    return json.loads(buf.getvalue())["scan_timestamp"]


def test_timestamp_is_utc_iso8601_with_z_suffix():
    ts = _timestamp()
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z", ts), ts


def test_timestamp_has_no_double_timezone_marker():
    ts = _timestamp()
    assert "+00:00" not in ts


def test_timestamp_is_parseable():
    ts = _timestamp()
    parsed = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ")
    assert parsed.year >= 2026
