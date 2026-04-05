# Smart Contract Vulnerability Scanner

<div align="center">

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.8%2B-orange)
![License](https://img.shields.io/badge/license-MIT-green)
![Patterns](https://img.shields.io/badge/patterns-20%2B-brightgreen)

**A production-ready static analysis scanner for Solidity smart contracts.**

</div>

## Overview

A Python-based static analyzer that detects **20+ vulnerability types** in Solidity smart contracts. Built for security auditors, bug bounty hunters, and developers — this tool identifies common vulnerabilities using pattern-based analysis mapped to the **Smart Contract Weaknesses (SWC) Registry**.

Designed to be a lightweight, dependency-free alternative to heavier tools like Slither for quick audits, CI/CD pipelines, and bug bounty reconnaissance.

## Features

- **20+ Vulnerability Patterns** covering Critical → Info severity levels
- **SWC Registry Mapping** — every finding linked to an official SWC identifier
- **Severity-Ranked Output** — Critical, High, Medium, Low, Info classifications
- **Two Output Formats** — human-readable text and machine-readable JSON
- **CLI Tool** — single command to scan files or entire directories
- **Confidence Scoring** — each finding rated 0–100% confidence
- **Zero Dependencies** — pure Python, no pip install required
- **Code Snippets** — verbose mode shows exact code location with context
- **Negative Pattern Matching** — reduces false positives with exclusion logic

## Installation

### Option 1: Clone & Run (No Dependencies)
```bash
git clone https://github.com/LMTRADES/smart-contract-scanner.git
cd smart-contract-scanner
python -m scanner.cli /path/to/contract.sol
```

### Option 2: Install via pip
```bash
pip install -e .
sol-scanner /path/to/contract.sol
```

## Quick Start

### Scan a Single Contract
```bash
python -m scanner.cli MyContract.sol
```

### Scan a Directory
```bash
python -m scanner.cli ./contracts/
```

### JSON Output (for CI/CD or further processing)
```bash
python -m scanner.cli -o json ./src/ > results.json
```

### Verbose Mode (with code snippets & descriptions)
```bash
python -m scanner.cli --verbose ./contracts/
```

### Filter by Severity
```bash
# Show only Critical findings
python -m scanner.cli --severity critical ./contracts/

# Show Critical and High
python -m scanner.cli --severity high ./contracts/
```

### List All Patterns
```bash
python -m scanner.cli --list-patterns
```

### After pip install
```bash
sol-scanner --version
sol-scanner ./contracts/ -o json --verbose
```

## Vulnerability Patterns

The scanner checks for **20+ common vulnerability types** across all severity levels:

| SWC ID | Vulnerability | Severity |
|--------|--------------|----------|
| SWC-107 | Reentrancy | 🔴 Critical |
| SWC-115 | Authorization through tx.origin | 🔴 Critical |
| SWC-112 | Delegatecall to Untrusted Address | 🔴 Critical |
| SWC-105 | Unprotected Selfdestruct | 🔴 Critical |
| SWC-131 | Unexpected Ether Balance | 🟠 High |
| SWC-101 | Integer Overflow/Underflow | 🟠 High |
| SWC-104 | Unchecked Low-Level Call Return Value | 🟠 High |
| SWC-109 | Uninitialized Storage Pointer | 🟠 High |
| SWC-113 | Missing Events for Critical Operations | 🟠 High |
| SWC-114 | Transaction Order Dependence | 🟠 High |
| SWC-120 | Weak Randomness | 🟡 Medium |
| SWC-116 | Block Timestamp Dependence | 🟡 Medium |
| SWC-135 | Unencoded Return Data | 🟡 Medium |
| SWC-134 | Signature Malleability | 🟡 Medium |
| SWC-126 | Missing Zero Address Check | 🟡 Medium |
| SWC-118 | Incorrect Use of ERC20 Return Value | 🔵 Low |
| SWC-123 | Write to Arbitrary Storage Slot | 🔵 Low |
| SWC-128 | Contract Pragma Version Not Locked | ⚪ Info |
| SWC-136 | Missing Visibility Modifier | ⚪ Info |
| SWC-108 | State Variable Default Visibility | ⚪ Info |

## Usage Examples

### Example 1: Scan for Critical Vulnerabilities Only
```bash
$ sol-scanner --severity critical ./contracts/Bank.sol
```

### Example 2: JSON Output for CI/CD Pipeline
```bash
$ sol-scanner -o json ./contracts/ | jq '.summary'
{
  "total": 8,
  "by_severity": {
    "Critical": 2,
    "High": 3,
    "Medium": 2,
    "Low": 1,
    "Info": 0
  }
}
```

### Example 3: Detailed Audit Report
```bash
$ sol-scanner --verbose ./contracts/ -o text
```

Output:
```
========================================================================
  Smart Contract Vulnerability Scan Results
========================================================================

Summary:
  🔴 Critical: 2
  🟠 High: 3
  Total findings: 5
------------------------------------------------------------------------

  🔴 CRITICAL
  ----------------------------------------

  [SWC-107] Reentrancy
    File: ./contracts/Bank.sol
    Line: 15
    Confidence: 85%
    Description: External call allows attacker to re-enter before state update...
    Code:
       13:     function withdraw() public {
       14:       uint256 amount = balances[msg.sender];
    >>> 15:       (bool success, ) = msg.sender.call{value: amount}("");
       16:       require(success);
       17:       balances[msg.sender] = 0;
    Recommendation: Follow Checks-Effects-Interactions pattern. Use ReentrancyGuard modifier.
```

## Programmatic API

```python
from scanner.analyzer import SolidityAnalyzer
from scanner.cli import format_json, format_text

analyzer = SolidityAnalyzer()

# Scan a file
findings = analyzer.analyze_file("Contract.sol")

# Scan a directory
findings = analyzer.analyze_directory("./src/contracts/")

# Format output
print(format_text(findings, verbose=True))
print(format_json(findings))

# Each finding has:
# finding.swc_id        -> "SWC-107"
# finding.title         -> "Reentrancy"
# finding.severity      -> Severity.CRITICAL
# finding.line          -> 15
# finding.file          -> "Contract.sol"
# finding.code_snippet  -> (code with context)
# finding.recommendation -> remediation guidance
# finding.confidence    -> 0.85
```

## CI/CD Integration

### GitHub Actions
```yaml
- name: Scan Smart Contracts
  run: |
    pip install -e .
    sol-scanner -o json ./contracts/ > scan_results.json
    cat scan_results.json | jq '.summary'
```

### Pre-commit Hook
```yaml
- repo: local
  hooks:
    - id: sol-scanner
      name: Scan Solidity Contracts
      entry: sol-scanner --severity high
      language: python
      files: \.sol$
      pass_filenames: true
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No Critical or High findings |
| 1 | Error (file not found, parse error) |
| 2 | Critical or High findings detected |

## Architecture

```
smart-contract-scanner/
├── scanner/
│   ├── __init__.py          # Package init, version
│   ├── patterns.py          # Vulnerability pattern library (20+ patterns)
│   ├── analyzer.py          # Core static analysis engine
│   └── cli.py               # CLI entry point & formatters
├── tests/
│   ├── __init__.py
│   ├── test_scanner.py      # Comprehensive test suite
│   └── test_files/
│       └── samples/
│           ├── vulnerable.sol  # Intentionally vulnerable contract
│           └── safe_contract.sol  # Secure contract example
├── pyproject.toml           # Project configuration
├── README.md
└── .gitignore
```

## Running Tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run all tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ -v --cov=scanner --cov-report=term-missing

# Run specific test class
python -m pytest tests/test_scanner.py::TestPatternLibrary -v
```

## Limitations

- **Static analysis only** — does not execute code or detect runtime-only vulnerabilities
- **Pattern-based** — may produce false positives on complex custom patterns
- **Does not replace manual audit** — use as a first-pass screening tool
- **Single-file scope** — does not analyze cross-contract interactions or inheritance chains

## Contributing

1. Add new patterns to `scanner/patterns.py`
2. Write tests in `tests/test_scanner.py`
3. Sample contracts in `tests/test_files/samples/`
4. Submit PR with pattern description and SWC reference

## License

MIT — See [LICENSE](LICENSE) for details.

## Disclaimer

This tool is provided for educational and security research purposes. It does not guarantee detection of all vulnerabilities. Always perform manual audits before deploying smart contracts to production.

---

Built by [LMTRADES](https://github.com/LMTRADES)
