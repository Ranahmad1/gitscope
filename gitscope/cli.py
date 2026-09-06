"""
cli.py — Command-line interface for gitscope.

Usage:
    gitscope [PATH] [OPTIONS]

Author: ranahmad1
License: MIT
"""

import argparse
import logging
import os
import sys

from gitscope import __version__
from gitscope.scanner import run_full_scan, DEFAULT_COMMIT_DEPTH
from gitscope.reporter import render_terminal, render_json, render_plain


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gitscope",
        description=(
            "gitscope — Git Repository Security Hygiene Auditor\n"
            "Scans your local git repository for secrets, misconfigurations, and hygiene issues."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  gitscope                          Scan current directory
  gitscope /path/to/repo            Scan a specific repository
  gitscope --json                   Output JSON report
  gitscope --no-history             Skip git commit history scan
  gitscope --depth 100              Scan last 100 commits
  gitscope --min-severity high      Only report high/critical findings
  gitscope --output report.json --json   Save JSON report to file
  gitscope --no-color               Disable ANSI colors

Exit codes:
  0  No findings at or above the minimum severity threshold
  1  Findings found at or above the minimum severity threshold
  2  Error during scan (invalid path, not a git repo, etc.)

Author: ranahmad1 <https://github.com/Ranahmad1>
""",
    )

    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to the git repository to scan (default: current directory)",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"gitscope {__version__}",
    )

    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON (useful for CI/CD and tooling integration)",
    )
    output_group.add_argument(
        "--plain",
        action="store_true",
        help="Output results as plain text with no ANSI colors",
    )

    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color codes in terminal output",
    )

    parser.add_argument(
        "--no-history",
        action="store_true",
        help="Skip git commit history scan (faster, but misses deleted secrets)",
    )

    parser.add_argument(
        "--depth",
        type=int,
        default=DEFAULT_COMMIT_DEPTH,
        metavar="N",
        help=f"Number of git commits to inspect (default: {DEFAULT_COMMIT_DEPTH})",
    )

    parser.add_argument(
        "--min-severity",
        choices=["low", "medium", "high", "critical"],
        default="low",
        metavar="LEVEL",
        help="Minimum severity level to report: low, medium, high, critical (default: low)",
    )

    parser.add_argument(
        "--output",
        metavar="FILE",
        help="Write report output to FILE instead of stdout",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging output",
    )

    parser.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical", "never"],
        default="medium",
        metavar="LEVEL",
        help=(
            "Exit with code 1 if any finding meets this severity level or above. "
            "Use 'never' to always exit 0 (default: medium)"
        ),
    )

    return parser


def configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(levelname)s: %(message)s",
        stream=sys.stderr,
    )


SEVERITY_RANK = {"low": 3, "medium": 2, "high": 1, "critical": 0}


def should_fail(result, fail_on: str) -> bool:
    """Return True if the scan result warrants a non-zero exit code."""
    if fail_on == "never":
        return False
    threshold = SEVERITY_RANK[fail_on]
    for finding in result.findings:
        if SEVERITY_RANK.get(finding.severity, 99) <= threshold:
            return True
    return False


def filter_findings(result, min_severity: str) -> None:
    """Remove findings below min_severity from result in-place."""
    threshold = SEVERITY_RANK[min_severity]
    result.findings = [
        f for f in result.findings
        if SEVERITY_RANK.get(f.severity, 99) <= threshold
    ]


def main(argv=None) -> int:
    """
    Main entry point.

    Returns:
        0: Clean (no significant findings)
        1: Findings above threshold found
        2: Scan error
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(args.verbose)

    try:
        result = run_full_scan(
            repo_path=args.path,
            scan_history=not args.no_history,
            commit_depth=args.depth,
        )
    except ValueError as exc:
        sys.stderr.write(f"gitscope: error: {exc}\n")
        return 2
    except KeyboardInterrupt:
        sys.stderr.write("\ngitscope: scan interrupted by user.\n")
        return 2
    except Exception as exc:
        sys.stderr.write(f"gitscope: unexpected error: {exc}\n")
        if args.verbose:
            import traceback
            traceback.print_exc(file=sys.stderr)
        return 2

    # Determine if we should fail before filtering (to catch all severities)
    fail = should_fail(result, args.fail_on)

    # Filter findings for output based on --min-severity
    filter_findings(result, args.min_severity)

    # Write report
    output_stream = sys.stdout
    output_file = None

    if args.output:
        try:
            output_file = open(args.output, "w", encoding="utf-8")
            output_stream = output_file
        except OSError as exc:
            sys.stderr.write(f"gitscope: cannot open output file: {exc}\n")
            return 2

    try:
        if args.json:
            render_json(result, stream=output_stream)
        elif args.plain:
            render_plain(result, stream=output_stream)
        else:
            render_terminal(result, stream=output_stream, no_color=args.no_color)
    finally:
        if output_file:
            output_file.close()

    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
