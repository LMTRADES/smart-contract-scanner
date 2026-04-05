"""
Vulnerability Scanner CLI Entry Point
Command-line interface for the smart contract vulnerability scanner.
"""

import argparse
import json
import sys
import os

from .analyzer import SolidityAnalyzer, severity_sort_key
from .patterns import Finding, Severity


def format_text(findings: list, verbose: bool = False) -> str:
    """Format findings as human-readable text output."""
    if not findings:
        return "\n✅ No vulnerabilities detected.\n"

    # Sort by severity then line number
    findings.sort(key=severity_sort_key)

    # Count by severity
    severity_counts = {s: 0 for s in Severity}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    lines = []
    lines.append("")
    lines.append("=" * 72)
    lines.append("  Smart Contract Vulnerability Scan Results")
    lines.append("=" * 72)
    lines.append("")

    # Summary
    lines.append("Summary:")
    for severity in Severity:
        count = severity_counts.get(severity, 0)
        if count > 0:
            icon = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🔵", "Info": "⚪"}
            lines.append(f"  {icon.get(severity.value, '')} {severity.value}: {count}")
    lines.append(f"  Total findings: {len(findings)}")
    lines.append("")
    lines.append("-" * 72)

    # Group by severity
    current_severity = None
    for f in findings:
        if f.severity != current_severity:
            current_severity = f.severity
            icon = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🔵", "Info": "⚪"}
            lines.append("")
            lines.append(f"  {icon.get(current_severity.value, '')} {current_severity.value.upper()}")
            lines.append("  " + "-" * 40)

        lines.append(f"")
        lines.append(f"  [{f.swc_id}] {f.title}")
        lines.append(f"    File: {f.file}")
        lines.append(f"    Line: {f.line}")
        lines.append(f"    Confidence: {f.confidence:.0%}")
        if verbose:
            lines.append(f"    Description: {f.description}")
            if f.code_snippet:
                lines.append(f"    Code:")
                for code_line in f.code_snippet.split('\n'):
                    lines.append(f"      {code_line}")
        lines.append(f"    Recommendation: {f.recommendation}")
        lines.append(f"    Matched: {f.pattern_matched[:80]}...")

    lines.append("")
    lines.append("=" * 72)

    # Overall risk assessment
    critical = severity_counts.get(Severity.CRITICAL, 0)
    high = severity_counts.get(Severity.HIGH, 0)
    if critical > 0:
        lines.append("  ⚠️  OVERALL RISK: CRITICAL - Do not deploy without fixes!")
    elif high > 0:
        lines.append("  ⚠️  OVERALL RISK: HIGH - Significant issues need attention.")
    elif severity_counts.get(Severity.MEDIUM, 0) > 0:
        lines.append("  ⚠️  OVERALL RISK: MEDIUM - Review recommended before deployment.")
    else:
        lines.append("  ✅ OVERALL RISK: LOW - Minor issues found.")

    lines.append("=" * 72)
    lines.append("")

    return '\n'.join(lines)


def format_json(findings: list) -> str:
    """Format findings as JSON output."""
    summary = {
        "total": len(findings),
        "by_severity": {s.value: 0 for s in Severity},
    }
    for f in findings:
        summary["by_severity"][f.severity.value] = summary["by_severity"].get(f.severity.value, 0) + 1

    findings.sort(key=lambda f: (
        {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}.get(
            f.severity, 5
        ),
        f.line,
    ))

    output = {
        "summary": summary,
        "findings": [f.to_dict() for f in findings],
    }

    return json.dumps(output, indent=2)


def main(args=None):
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="sol-scanner",
        description="Smart Contract Vulnerability Scanner - Static analysis for Solidity code",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sol-scanner contract.sol                     Scan a single file
  sol-scanner ./contracts/                     Scan all .sol files in directory
  sol-scanner -o json src/ > results.json      JSON output
  sol-scanner --verbose contracts/             Detailed output with code snippets
  sol-scanner --severity high ./src/            Only show High and Critical
        """,
    )

    parser.add_argument(
        'path',
        nargs='?',
        default=None,
        help='Path to .sol file or directory to scan',
    )
    parser.add_argument(
        '-o', '--output-format',
        choices=['text', 'json'],
        default='text',
        help='Output format (default: text)',
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show detailed descriptions and code snippets (text output)',
    )
    parser.add_argument(
        '--severity',
        choices=['all', 'critical', 'high', 'medium', 'low', 'info'],
        default='all',
        help='Minimum severity to report (default: all)',
    )
    parser.add_argument(
        '--list-patterns',
        action='store_true',
        help='List all available vulnerability patterns and exit',
    )
    parser.add_argument(
        '--version',
        action='store_true',
        help='Show version and exit',
    )

    parsed = parser.parse_args(args)

    from . import __version__

    if parsed.version:
        print(f"sol-scanner v{__version__}")
        return 0

    if parsed.list_patterns:
        from .patterns import PatternLibrary
        patterns = PatternLibrary.get_all_patterns()
        print(f"Available vulnerability patterns ({len(patterns)} total):")
        print(f"{'SWC ID':<10} {'Title':<45} {'Severity':<10}")
        print("-" * 68)
        for p in patterns:
            print(f"{p.swc_id:<10} {p.title:<45} {p.severity.value:<10}")
        return 0

    if not parsed.path:
        print("Error: Path is required for scanning. Use sol-scanner <path>", file=sys.stderr)
        return 1

    target = parsed.path
    if not os.path.exists(target):
        print(f"Error: Path not found: {target}", file=sys.stderr)
        return 1

    analyzer = SolidityAnalyzer()

    try:
        findings = analyzer.analyze(target)
    except Exception as e:
        print(f"Error during analysis: {e}", file=sys.stderr)
        return 1

    # Filter by severity
    if parsed.severity != 'all':
        severity_levels = {
            'critical': [Severity.CRITICAL],
            'high': [Severity.CRITICAL, Severity.HIGH],
            'medium': [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM],
            'low': [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW],
            'info': list(Severity),
        }
        allowed = severity_levels.get(parsed.severity, list(Severity))
        findings = [f for f in findings if f.severity in allowed]

    # Output
    if parsed.output_format == 'json':
        print(format_json(findings))
    else:
        print(format_text(findings, verbose=parsed.verbose))

    # Exit code: non-zero if critical/high findings
    critical_high = sum(
        1 for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)
    )
    return 0 if critical_high == 0 else 2
