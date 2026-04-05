"""
Smart Contract Static Analyzer
Performs pattern-based static analysis on Solidity source files.
"""

import os
import re
from typing import List, Tuple

from .patterns import Finding, PatternLibrary, VulnerabilityPattern, Severity


class SolidityAnalyzer:
    """
    Static analyzer for Solidity smart contracts.
    Uses regex-based pattern matching against a comprehensive vulnerability library.
    """

    def __init__(self):
        self.patterns = PatternLibrary.get_all_patterns()

    def analyze_file(self, file_path: str) -> List[Finding]:
        """Analyze a single Solidity file for vulnerabilities."""
        findings = []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except (IOError, UnicodeDecodeError) as e:
            # Return an info finding about the read error
            findings.append(Finding(
                swc_id="SWC-000",
                title="File Read Error",
                description=f"Could not read file: {str(e)}",
                severity=Severity.INFO,
                line=0,
                file=file_path,
                pattern_matched="",
                recommendation="Ensure the file exists and is readable.",
            ))
            return findings

        lines = content.split('\n')
        stripped_lines = [line.strip() for line in lines]
        full_stripped = ''.join(stripped_lines)  # For cross-line patterns

        for pattern_def in self.patterns:
            findings.extend(
                self._check_pattern(pattern_def, content, lines, stripped_lines, full_stripped, file_path)
            )

        return findings

    def analyze_directory(self, directory: str) -> List[Finding]:
        """Analyze all Solidity files in a directory recursively."""
        findings = []
        for root, _, files in os.walk(directory):
            for f in files:
                if f.endswith('.sol'):
                    file_path = os.path.join(root, f)
                    findings.extend(self.analyze_file(file_path))
        return findings

    def analyze(self, path: str) -> List[Finding]:
        """Analyze a file or directory."""
        if os.path.isfile(path):
            return self.analyze_file(path)
        elif os.path.isdir(path):
            return self.analyze_directory(path)
        else:
            raise FileNotFoundError(f"Path not found: {path}")

    def _check_pattern(
        self,
        pattern_def: VulnerabilityPattern,
        content: str,
        lines: List[str],
        stripped_lines: List[str],
        full_stripped: str,
        file_path: str
    ) -> List[Finding]:
        """Check content against a vulnerability pattern definition."""
        findings = []

        # Check negative patterns first
        has_negative = False
        for neg_pattern in pattern_def.negative_patterns:
            if re.search(neg_pattern, content, re.MULTILINE | re.DOTALL):
                has_negative = True
                break

        if has_negative:
            return findings

        # Check positive patterns
        for pat in pattern_def.patterns:
            try:
                # Try multiline matching for cross-line patterns
                for match in re.finditer(pat, content, re.MULTILINE | re.DOTALL):
                    line_num = self._get_line_number(content, match.start())
                    code_snippet = self._get_code_snippet(lines, line_num)
                    confidence = self._calculate_confidence(
                        pattern_def, pat, content, stripped_lines, line_num
                    )

                    if confidence >= pattern_def.min_confidence:
                        findings.append(Finding(
                            swc_id=pattern_def.swc_id,
                            title=pattern_def.title,
                            description=pattern_def.description,
                            severity=pattern_def.severity,
                            line=line_num,
                            file=file_path,
                            pattern_matched=match.group(0)[:200],
                            recommendation=pattern_def.recommendation,
                            code_snippet=code_snippet,
                            confidence=confidence,
                        ))
            except re.error:
                # Skip invalid regex patterns
                continue

        return findings

    def _get_line_number(self, content: str, match_pos: int) -> int:
        """Calculate line number from character position."""
        return content[:match_pos].count('\n') + 1

    def _get_code_snippet(self, lines: List[str], line_num: int, context: int = 2) -> str:
        """Get code snippet with context around the matched line."""
        start = max(0, line_num - context - 1)
        end = min(len(lines), line_num + context)
        snippet_lines = []
        for i in range(start, end):
            prefix = ">>>" if i == line_num - 1 else "   "
            snippet_lines.append(f"{prefix} {i + 1}: {lines[i]}")
        return '\n'.join(snippet_lines)

    def _calculate_confidence(
        self,
        pattern_def: VulnerabilityPattern,
        pattern: str,
        content: str,
        stripped_lines: List[str],
        line_num: int
    ) -> float:
        """Calculate confidence score for a finding."""
        confidence = pattern_def.min_confidence

        # Boost confidence for patterns preceded by comments that explain intent
        if line_num > 0:
            prev_line = stripped_lines[max(0, line_num - 2)]
            if prev_line.startswith('//') or prev_line.startswith('/*'):
                # Could be intentional - lower confidence if so
                lower_terms = ['safe', 'intentional', 'ok', 'reviewed', 'audited']
                if any(term in prev_line.lower() for term in lower_terms):
                    confidence *= 0.5

        # Boost confidence if multiple related patterns match
        related_count = 0
        for other_pat in pattern_def.patterns:
            if other_pat != pattern and re.search(other_pat, content, re.MULTILINE | re.DOTALL):
                related_count += 1
        if related_count > 0:
            confidence = min(1.0, confidence + related_count * 0.1)

        # Boost for specific high-signal keywords
        high_signal = ['call', 'send', 'transfer', 'delegatecall', 'selfdestruct', 'tx.origin']
        for keyword in high_signal:
            if keyword in pattern and keyword.lower() not in pattern_def.negative_patterns:
                confidence = min(1.0, confidence + 0.1)
                break

        return round(confidence, 2)


def severity_sort_key(finding: Finding) -> Tuple[int, int]:
    """Sort key for findings: severity first, then line number."""
    severity_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
    return (severity_order.get(finding.severity, 5), finding.line)
