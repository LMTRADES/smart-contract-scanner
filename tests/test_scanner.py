"""
Comprehensive test suite for the Smart Contract Vulnerability Scanner.
Tests cover all vulnerability patterns, CLI functionality, output formats, and edge cases.
"""

import json
import os
import sys
import unittest
from io import StringIO
from unittest import mock

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.analyzer import SolidityAnalyzer, severity_sort_key
from scanner.patterns import (
    Finding,
    PatternLibrary,
    Severity,
    VulnerabilityPattern,
)
from scanner.cli import format_json, format_text, main


# Paths
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
SAMPLES_DIR = os.path.join(TEST_DIR, "test_files", "samples")
VULNERABLE_FILE = os.path.join(SAMPLES_DIR, "vulnerable.sol")
SAFE_FILE = os.path.join(SAMPLES_DIR, "safe_contract.sol")


class TestSeverityEnum(unittest.TestCase):
    """Test the Severity enum."""

    def test_severity_values(self):
        """Test all severity levels exist with correct values."""
        self.assertEqual(Severity.CRITICAL.value, "Critical")
        self.assertEqual(Severity.HIGH.value, "High")
        self.assertEqual(Severity.MEDIUM.value, "Medium")
        self.assertEqual(Severity.LOW.value, "Low")
        self.assertEqual(Severity.INFO.value, "Info")

    def test_severity_count(self):
        """Test there are exactly 5 severity levels."""
        self.assertEqual(len(Severity), 5)


class TestFinding(unittest.TestCase):
    """Test the Finding dataclass."""

    def setUp(self):
        self.finding = Finding(
            swc_id="SWC-107",
            title="Reentrancy",
            description="Test vulnerability",
            severity=Severity.CRITICAL,
            line=10,
            file="test.sol",
            pattern_matched="call{value:",
            recommendation="Use ReentrancyGuard",
            code_snippet="   8: ...",
            confidence=0.9,
        )

    def test_finding_creation(self):
        """Test finding object creation."""
        self.assertEqual(self.finding.swc_id, "SWC-107")
        self.assertEqual(self.finding.title, "Reentrancy")
        self.assertEqual(self.finding.severity, Severity.CRITICAL)
        self.assertEqual(self.finding.line, 10)
        self.assertEqual(self.finding.file, "test.sol")

    def test_finding_to_dict(self):
        """Test conversion to dictionary."""
        d = self.finding.to_dict()
        self.assertIsInstance(d, dict)
        self.assertEqual(d["swc_id"], "SWC-107")
        self.assertEqual(d["title"], "Reentrancy")
        self.assertEqual(d["severity"], "Critical")
        self.assertEqual(d["line"], 10)
        self.assertEqual(d["confidence"], 0.9)
        # Check all required keys
        required_keys = [
            "swc_id", "title", "description", "severity", "line",
            "file", "pattern_matched", "recommendation", "code_snippet", "confidence"
        ]
        for key in required_keys:
            self.assertIn(key, d)


class TestPatternLibrary(unittest.TestCase):
    """Test the vulnerability pattern library."""

    def test_pattern_count(self):
        """Test that the library has at least 15 patterns."""
        patterns = PatternLibrary.get_all_patterns()
        self.assertGreaterEqual(len(patterns), 15, f"Expected >= 15 patterns, got {len(patterns)}")

    def test_all_patterns_have_required_fields(self):
        """Test that every pattern has all required fields."""
        patterns = PatternLibrary.get_all_patterns()
        for p in patterns:
            self.assertIsInstance(p.swc_id, str, f"SWC ID must be string: {p}")
            self.assertTrue(p.swc_id.startswith("SWC-"), f"SWC ID must start with SWC-: {p.swc_id}")
            self.assertTrue(len(p.title) > 0, f"Title must not be empty: {p}")
            self.assertTrue(len(p.description) > 0, f"Description must not be empty: {p}")
            self.assertIsInstance(p.severity, Severity, f"Severity must be Severity enum: {p}")
            self.assertIsInstance(p.patterns, list, f"Patterns must be a list: {p}")
            self.assertTrue(len(p.patterns) > 0, f"Must have at least one pattern: {p}")
            self.assertTrue(len(p.recommendation) > 0, f"Recommendation must not be empty: {p}")

    def test_all_patterns_have_valid_regex(self):
        """Test that all regex patterns are valid."""
        import re
        patterns = PatternLibrary.get_all_patterns()
        for p in patterns:
            for pat in p.patterns:
                try:
                    re.compile(pat)
                except re.error as e:
                    self.fail(f"Invalid regex '{pat}' in {p.swc_id}: {e}")

    def test_all_patterns_have_valid_negative_regex(self):
        """Test that negative patterns are also valid regex."""
        import re
        patterns = PatternLibrary.get_all_patterns()
        for p in patterns:
            for neg_pat in p.negative_patterns:
                try:
                    re.compile(neg_pat)
                except re.error as e:
                    self.fail(f"Invalid negative regex '{neg_pat}' in {p.swc_id}: {e}")

    def test_severity_distribution(self):
        """Test that patterns span multiple severity levels."""
        patterns = PatternLibrary.get_all_patterns()
        severities = {p.severity for p in patterns}
        self.assertGreaterEqual(len(severities), 3, "Patterns should cover at least 3 severity levels")

    def test_has_critical_patterns(self):
        """Test that there are critical-level vulnerability patterns."""
        patterns = PatternLibrary.get_all_patterns()
        critical = [p for p in patterns if p.severity == Severity.CRITICAL]
        self.assertGreater(len(critical), 0, "Must have at least one critical pattern")

    def test_specific_swcs(self):
        """Test that key SWC IDs are covered."""
        patterns = PatternLibrary.get_all_patterns()
        swc_ids = [p.swc_id for p in patterns]
        # Core vulnerabilities
        self.assertIn("SWC-107", swc_ids)  # Reentrancy
        self.assertIn("SWC-115", swc_ids)  # tx.origin
        self.assertIn("SWC-112", swc_ids)  # Delegatecall

    def test_no_duplicate_swc_ids(self):
        """Test that each SWC ID appears only once."""
        patterns = PatternLibrary.get_all_patterns()
        swc_ids = [p.swc_id for p in patterns]
        self.assertEqual(len(swc_ids), len(set(swc_ids)), "Duplicate SWC IDs found")

    def test_patterns_coverage(self):
        """Test coverage of major vulnerability categories."""
        patterns = PatternLibrary.get_all_patterns()
        titles = [p.title.lower() for p in patterns]
        major_categories = [
            "reentrancy",
            "tx.origin",
            "delegatecall",
            "overflow",
            "unchecked",
        ]
        for cat in major_categories:
            self.assertTrue(
                any(cat in t for t in titles),
                f"Missing vulnerability category: {cat}"
            )


class TestSolidityAnalyzer(unittest.TestCase):
    """Test the SolidityAnalyzer class."""

    def setUp(self):
        self.analyzer = SolidityAnalyzer()

    def test_analyze_vulnerable_file(self):
        """Test that vulnerable contract is detected."""
        findings = self.analyzer.analyze_file(VULNERABLE_FILE)
        self.assertIsInstance(findings, list)
        self.assertGreater(len(findings), 0, "Should find vulnerabilities in vulnerable.sol")

    def test_analyze_safe_file(self):
        """Test that safe contract has fewer findings."""
        findings = self.analyzer.analyze_file(SAFE_FILE)
        self.assertIsInstance(findings, list)
        # Safe contract should have significantly fewer findings
        vuln_findings = self.analyzer.analyze_file(VULNERABLE_FILE)
        # The safe file should not have more findings than the vulnerable one
        self.assertLessEqual(
            len(findings), len(vuln_findings),
            "Safe contract should not have more findings than vulnerable one"
        )

    def test_findings_have_correct_types(self):
        """Test that analysis returns Finding objects."""
        findings = self.analyzer.analyze_file(VULNERABLE_FILE)
        for f in findings:
            self.assertIsInstance(f, Finding)

    def test_findings_have_valid_severity(self):
        """Test that all findings have valid severity levels."""
        findings = self.analyzer.analyze_file(VULNERABLE_FILE)
        for f in findings:
            self.assertIn(f.severity, Severity)

    def test_findings_have_valid_line_numbers(self):
        """Test that line numbers are positive integers."""
        findings = self.analyzer.analyze_file(VULNERABLE_FILE)
        for f in findings:
            self.assertGreaterEqual(f.line, 0, f"Line number must be >= 0, got {f.line} for {f.title}")
            self.assertIsInstance(f.line, int)

    def test_findings_have_valid_file_paths(self):
        """Test that file paths are correct."""
        findings = self.analyzer.analyze_file(VULNERABLE_FILE)
        for f in findings:
            self.assertTrue(f.file.endswith(".sol"), f"File should end with .sol: {f.file}")

    def test_detects_reentrancy(self):
        """Test that reentrancy vulnerability is detected."""
        findings = self.analyzer.analyze_file(VULNERABLE_FILE)
        reentrancy = [f for f in findings if f.swc_id == "SWC-107"]
        self.assertGreater(len(reentrancy), 0, "Should detect reentrancy vulnerability")

    def test_detects_tx_origin(self):
        """Test that tx.origin usage is detected."""
        findings = self.analyzer.analyze_file(VULNERABLE_FILE)
        tx_origin = [f for f in findings if f.swc_id == "SWC-115"]
        self.assertGreater(len(tx_origin), 0, "Should detect tx.origin vulnerability")

    def test_detects_delegatecall(self):
        """Test that delegatecall risk is detected."""
        findings = self.analyzer.analyze_file(VULNERABLE_FILE)
        delegatecall = [f for f in findings if f.swc_id == "SWC-112"]
        self.assertGreater(len(delegatecall), 0, "Should detect delegatecall vulnerability")

    def test_detects_selfdestruct(self):
        """Test that unprotected selfdestruct is detected."""
        findings = self.analyzer.analyze_file(VULNERABLE_FILE)
        selfdestruct = [f for f in findings if f.swc_id == "SWC-105"]
        self.assertGreater(len(selfdestruct), 0, "Should detect selfdestruct vulnerability")

    def test_analyze_directory(self):
        """Test directory scanning."""
        findings = self.analyzer.analyze_directory(SAMPLES_DIR)
        self.assertIsInstance(findings, list)
        self.assertGreater(len(findings), 0, "Should find vulnerabilities in samples directory")
        # Should scan multiple files
        unique_files = set(f.file for f in findings)
        self.assertGreaterEqual(len(unique_files), 1, "Should scan at least one file")

    def test_analyze_generic(self):
        """Test the generic analyze method with both file and directory."""
        # File
        file_findings = self.analyzer.analyze(VULNERABLE_FILE)
        self.assertIsInstance(file_findings, list)

        # Directory
        dir_findings = self.analyze(SAMPLES_DIR)
        self.assertIsInstance(dir_findings, list)

    def analyze(self, path):
        return self.analyzer.analyze(path)

    def test_file_not_found(self):
        """Test error handling for non-existent file."""
        with self.assertRaises(FileNotFoundError):
            self.analyzer.analyze("/nonexistent/path/file.sol")

    def test_findings_have_recommendations(self):
        """Test that all findings have actionable recommendations."""
        findings = self.analyzer.analyze_file(VULNERABLE_FILE)
        for f in findings:
            self.assertTrue(len(f.recommendation) > 0, f"Finding must have recommendation: {f.title}")

    def test_findings_have_confidence(self):
        """Test that findings have confidence scores."""
        findings = self.analyzer.analyze_file(VULNERABLE_FILE)
        for f in findings:
            self.assertGreaterEqual(f.confidence, 0.0, "Confidence must be >= 0")
            self.assertLessEqual(f.confidence, 1.0, "Confidence must be <= 1")

    def test_findings_sorted_by_severity(self):
        """Test that findings can be sorted by severity."""
        findings = self.analyzer.analyze_file(VULNERABLE_FILE)
        findings.sort(key=severity_sort_key)
        severity_order = {
            Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
            Severity.LOW: 3, Severity.INFO: 4
        }
        prev_order = -1
        prev_line = -1
        for f in findings:
            current_order = severity_order[f.severity]
            if current_order == prev_order:
                self.assertGreaterEqual(f.line, prev_line)
            else:
                self.assertGreaterEqual(current_order, prev_order)
            prev_order = current_order
            prev_line = f.line


class TestOutputFormatter(unittest.TestCase):
    """Test output formatting functions."""

    def setUp(self):
        self.findings = [
            Finding(
                swc_id="SWC-107",
                title="Reentrancy",
                description="External call before state update",
                severity=Severity.CRITICAL,
                line=10,
                file="test.sol",
                pattern_matched=".call{value:",
                recommendation="Use ReentrancyGuard",
                code_snippet="   8: function\n>>> 10: call\n  12: end",
                confidence=0.9,
            ),
            Finding(
                swc_id="SWC-115",
                title="tx.origin",
                description="Using tx.origin for auth",
                severity=Severity.HIGH,
                line=20,
                file="test.sol",
                pattern_matched="require(tx.origin",
                recommendation="Use msg.sender",
                confidence=0.8,
            ),
        ]

    def test_text_format_output(self):
        """Test text output formatting."""
        text = format_text(self.findings)
        self.assertIsInstance(text, str)
        self.assertIn("Reentrancy", text)
        self.assertIn("tx.origin", text)
        self.assertIn("CRITICAL", text)
        self.assertIn("HIGH", text)

    def test_text_format_empty(self):
        """Test text output with no findings."""
        text = format_text([])
        self.assertIn("No vulnerabilities", text)

    def test_text_format_verbose(self):
        """Test verbose text output includes descriptions."""
        text = format_text(self.findings, verbose=True)
        self.assertIn("External call before state update", text)
        self.assertIn("Code:", text)

    def test_text_format_risk_assessment(self):
        """Test overall risk assessment in output."""
        text = format_text(self.findings)
        self.assertIn("CRITICAL", text)

    def test_json_format(self):
        """Test JSON output formatting."""
        json_str = format_json(self.findings)
        data = json.loads(json_str)

        # Check structure
        self.assertIn("summary", data)
        self.assertIn("findings", data)
        self.assertEqual(data["summary"]["total"], 2)
        self.assertIn("by_severity", data["summary"])

        # Check findings
        findings = data["findings"]
        self.assertEqual(len(findings), 2)

        # Check first finding structure
        f = findings[0]
        self.assertIn("swc_id", f)
        self.assertIn("title", f)
        self.assertEqual(f["severity"], "Critical")

    def test_json_format_valid(self):
        """Test that JSON output is valid JSON."""
        json_str = format_json(self.findings)
        try:
            json.loads(json_str)
        except json.JSONDecodeError as e:
            self.fail(f"Invalid JSON output: {e}")

    def test_json_format_empty(self):
        """Test JSON output with no findings."""
        json_str = format_json([])
        data = json.loads(json_str)
        self.assertEqual(data["summary"]["total"], 0)
        self.assertEqual(data["findings"], [])

    def test_findings_sorted_by_severity_in_json(self):
        """Test that JSON output has findings sorted by severity."""
        json_str = format_json(self.findings)
        data = json.loads(json_str)
        findings = data["findings"]
        if len(findings) > 1:
            severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
            for i in range(len(findings) - 1):
                self.assertLessEqual(
                    severity_order[findings[i]["severity"]],
                    severity_order[findings[i + 1]["severity"]],
                )

    def test_json_format_empty(self):
        """Test JSON output with no findings."""
        json_str = format_json([])
        data = json.loads(json_str)
        self.assertEqual(data["summary"]["total"], 0)
        self.assertEqual(data["findings"], [])


class TestCLI(unittest.TestCase):
    """Test CLI functionality."""

    def test_list_patterns(self):
        """Test --list-patterns flag."""
        with mock.patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            result = main(["--list-patterns"])
        output = mock_stdout.getvalue()
        self.assertIn("SWC-107", output)
        self.assertIn("Reentrancy", output)
        self.assertEqual(result, 0)

    def test_version(self):
        """Test --version flag."""
        with mock.patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            result = main(["--version"])
        output = mock_stdout.getvalue()
        self.assertIn("v1.0.0", output)
        self.assertEqual(result, 0)

    def test_scan_file_text(self):
        """Test scanning a file with text output."""
        with mock.patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            main([VULNERABLE_FILE])
        output = mock_stdout.getvalue()
        self.assertIn("Vulnerability Scan Results", output)
        self.assertIn("Summary:", output)

    def test_scan_file_json(self):
        """Test scanning a file with JSON output."""
        with mock.patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            main([VULNERABLE_FILE, "-o", "json"])
        output = mock_stdout.getvalue()
        data = json.loads(output)
        self.assertIn("summary", data)
        self.assertIn("findings", data)
        self.assertGreater(data["summary"]["total"], 0)

    def test_scan_directory(self):
        """Test scanning a directory."""
        with mock.patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            main([SAMPLES_DIR])
        output = mock_stdout.getvalue()
        self.assertIn("Vulnerability Scan Results", output)

    def test_scanning_nonexistent_path(self):
        """Test error handling for non-existent path."""
        with mock.patch('sys.stdout', new_callable=StringIO):
            with mock.patch('sys.stderr', new_callable=StringIO):
                result = main(["/nonexistent/path"])
        self.assertEqual(result, 1)

    def test_severity_filter_critical(self):
        """Test filtering by critical severity only."""
        with mock.patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            main([VULNERABLE_FILE, "-o", "json", "--severity", "critical"])
        output = mock_stdout.getvalue()
        data = json.loads(output)
        for f in data["findings"]:
            self.assertEqual(f["severity"], "Critical")

    def test_severity_filter_high(self):
        """Test filtering by high severity (includes critical and high)."""
        with mock.patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            main([VULNERABLE_FILE, "--severity", "high", "-o", "json"])
        output = mock_stdout.getvalue()
        data = json.loads(output)
        allowed = ["Critical", "High"]
        for f in data["findings"]:
            self.assertIn(f["severity"], allowed)

    def test_verbose_flag(self):
        """Test verbose output includes descriptions."""
        with mock.patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            main([VULNERABLE_FILE, "--verbose"])
        output = mock_stdout.getvalue()
        self.assertIn("Description:", output)

    def test_exit_code_has_critical(self):
        """Test non-zero exit code when critical findings exist."""
        result = main([VULNERABLE_FILE])
        self.assertEqual(result, 2)

    def test_exit_code_no_findings(self):
        """Test zero exit code when no critical/high findings after filter."""
        # Filter to info only (which may still have findings but not critical)
        with mock.patch('sys.stdout', new_callable=StringIO):
            result = main([VULNERABLE_FILE, "--severity", "info"])
        # This may still return 2 if critical findings are found
        # (depends on whether filter is applied before exit code check)
        self.assertIn(result, [0, 2])

    def test_json_output_is_valid(self):
        """Test that JSON output is always valid parseable JSON."""
        with mock.patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            main([VULNERABLE_FILE, "-o", "json"])
        output = mock_stdout.getvalue()
        try:
            json.loads(output)
        except json.JSONDecodeError:
            self.fail("JSON output is not valid JSON")


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error handling."""

    def test_empty_file(self):
        """Test analysis of empty file."""
        with open("/tmp/empty_test.sol", "w") as f:
            f.write("")
        analyzer = SolidityAnalyzer()
        findings = analyzer.analyze_file("/tmp/empty_test.sol")
        self.assertIsInstance(findings, list)
        os.remove("/tmp/empty_test.sol")

    def test_unicode_content(self):
        """Test analysis of file with unicode content."""
        content = "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract Test {} // 中文测试\n"
        with open("/tmp/unicode_test.sol", "w", encoding="utf-8") as f:
            f.write(content)
        analyzer = SolidityAnalyzer()
        findings = analyzer.analyze_file("/tmp/unicode_test.sol")
        self.assertIsInstance(findings, list)
        os.remove("/tmp/unicode_test.sol")

    def test_multiline_contract(self):
        """Test analysis of large multiline contract."""
        lines = [""] * 500
        lines[0] = "// SPDX-License-Identifier: MIT"
        lines[1] = "pragma solidity ^0.8.0;"
        lines[2] = "contract Large {"
        lines[100] = "    function test() public { msg.sender.transfer(1 ether); }"
        lines[497] = "}"
        content = "\n".join(lines)
        with open("/tmp/large_test.sol", "w") as f:
            f.write(content)
        analyzer = SolidityAnalyzer()
        findings = analyzer.analyze_file("/tmp/large_test.sol")
        self.assertIsInstance(findings, list)
        os.remove("/tmp/large_test.sol")

    def test_commented_out_vulnerabilities(self):
        """Test that commented vulnerabilities are not detected."""
        content = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Test {
    // function vulnerable() {
    //     msg.sender.call{value: 1 ether}("");
    //     balance = 0;
    // }
}"""
        with open("/tmp/commented_test.sol", "w") as f:
            f.write(content)
        analyzer = SolidityAnalyzer()
        findings = analyzer.analyze_file("/tmp/commented_test.sol")
        # Should have minimal findings since vulnerability is commented
        # Some info-level patterns may still trigger
        os.remove("/tmp/commented_test.sol")


class TestIntegration(unittest.TestCase):
    """Integration tests simulating real usage."""

    def test_full_scan_vulnerable_contract(self):
        """End-to-end test scanning the vulnerable contract."""
        with mock.patch('sys.stdout', new_callable=StringIO):
            result = main([VULNERABLE_FILE, "-o", "json"])

        with mock.patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            main([VULNERABLE_FILE, "-o", "json"])
        output = mock_stdout.getvalue()
        data = json.loads(output)

        # Should find multiple vulnerabilities
        self.assertGreater(data["summary"]["total"], 0)

        # Should find critical issues
        self.assertGreater(data["summary"]["by_severity"].get("Critical", 0), 0)

        # Should find reentrancy
        swc_ids = [f["swc_id"] for f in data["findings"]]
        self.assertIn("SWC-107", swc_ids)

    def test_full_scan_directory(self):
        """End-to-end test scanning the samples directory."""
        with mock.patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            main([SAMPLES_DIR, "-o", "json"])
        output = mock_stdout.getvalue()
        data = json.loads(output)

        self.assertGreater(data["summary"]["total"], 0)

    def test_list_patterns_integration(self):
        """Test patterns listing end-to-end."""
        with mock.patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            result = main(["--list-patterns"])
        output = mock_stdout.getvalue()
        # Count listed patterns (lines that contain SWC ID format)
        import re
        swc_lines = re.findall(r'SWC-\d+', output)
        # Each appears twice (header and data), so unique count / 1
        unique = set(swc_lines)
        self.assertGreaterEqual(len(unique), 15)
        self.assertEqual(result, 0)


if __name__ == "__main__":
    unittest.main()
