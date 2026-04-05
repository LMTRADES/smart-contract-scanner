"""
Vulnerability Pattern Library
Comprehensive pattern definitions based on Smart Contract Weaknesses (SWC) registry.
Covers 20+ vulnerability types with severity rankings.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, List, Optional
import re


class Severity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class Finding:
    """Represents a vulnerability finding."""
    swc_id: str
    title: str
    description: str
    severity: Severity
    line: int
    file: str
    pattern_matched: str
    recommendation: str
    code_snippet: str = ""
    confidence: float = 1.0

    def to_dict(self) -> dict:
        return {
            "swc_id": self.swc_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "line": self.line,
            "file": self.file,
            "pattern_matched": self.pattern_matched,
            "recommendation": self.recommendation,
            "code_snippet": self.code_snippet,
            "confidence": self.confidence,
        }


@dataclass
class VulnerabilityPattern:
    """Defines a vulnerability pattern to detect."""
    swc_id: str
    title: str
    description: str
    severity: Severity
    patterns: List[str]  # regex patterns
    recommendation: str
    check_function: Optional[Callable] = None
    negative_patterns: List[str] = field(default_factory=list)  # patterns that rule out the vulnerability
    min_confidence: float = 0.5


class PatternLibrary:
    """
    Library of vulnerability patterns for Solidity static analysis.
    Based on SWC Registry (https://swcregistry.io) and known exploit patterns.
    """

    @staticmethod
    def get_all_patterns() -> List[VulnerabilityPattern]:
        return [
            # === CRITICAL VULNERABILITIES ===
            VulnerabilityPattern(
                swc_id="SWC-107",
                title="Reentrancy",
                description=(
                    "External call allows attacker to re-enter before state update. "
                    "Classic DAO attack vector where contract state is modified after an external call, "
                    "allowing recursive entry before balance/state updates."
                ),
                severity=Severity.CRITICAL,
                patterns=[
                    # call/transfer/send followed by state change on next line (reentrancy pattern)
                    r'\b(?:call|transfer|send)\s*\(.*\)\s*;\s*\n[ \t]*(?:\w+\s*[+\-]?=|\w+\s*\[.*?\]\s*=)',
                    # .call{value:...} pattern (modern Solidity)
                    r'\.call\s*\{[^}]*value\s*:',
                    # Reentry: call then state assignment
                    r'\.call\s*\([^)]*\)[^;]*;[ \t]*\n[ \t]*(?:\w+\s*[+\-]?=|\w+\s*\[.*?\]\s*=)\s*\w',
                    # transfer then state mutation
                    r'\.transfer\s*\([^)]*\)[^;]*;[ \t]*\n[ \t]*(?:\w+\s*[+\-]?=|\w+\s*\[.*?\]\s*=)',
                ],
                recommendation="Follow Checks-Effects-Interactions pattern. Use ReentrancyGuard modifier.",
                min_confidence=0.5,
            ),

            VulnerabilityPattern(
                swc_id="SWC-115",
                title="Authorization through tx.origin",
                description=(
                    "Using tx.origin for authorization is vulnerable to phishing attacks. "
                    "An attacker can trick a user into calling a malicious contract which then "
                    "calls the vulnerable contract, passing the original tx.origin check."
                ),
                severity=Severity.CRITICAL,
                patterns=[
                    # require with tx.origin comparison
                    r'require\s*\([^)]*tx\.origin',
                    # tx.origin == check
                    r'tx\.origin\s*(?:==|!=)\s*\w+',
                    # if with tx.origin
                    r'if\s*\([^)]*tx\.origin',
                ],
                recommendation="Use msg.sender instead of tx.origin for authorization checks.",
                min_confidence=0.8,
            ),

            VulnerabilityPattern(
                swc_id="SWC-112",
                title="Delegatecall to Untrusted Address",
                description=(
                    "Delegatecall executes code in the context of the calling contract. "
                    "If the target address is user-controlled, an attacker can modify "
                    "contract state arbitrarily, including ownership."
                ),
                severity=Severity.CRITICAL,
                patterns=[
                    r'\w+\.delegatecall\s*\(',
                    r'\bdelegatecall\s*\(',
                    r'assembly\s*\{[^}]*delegatecall',
                ],
                recommendation="Never use delegatecall with user-controlled addresses. "
                               "Implement strict access controls and whitelisting for delegatecall targets.",
                min_confidence=0.8,
            ),

            VulnerabilityPattern(
                swc_id="SWC-105",
                title="Unprotected Selfdestruct",
                description=(
                    "Selfdestruct without proper access control allows anyone to "
                    "destroy the contract and send all ETH to a specified address."
                ),
                severity=Severity.CRITICAL,
                patterns=[
                    r'\bselfdestruct\s*\((?:[^()]*|\([^)]*\))*\)\s*;',
                    r'\bsuicide\s*\((?:[^()]*|\([^)]*\))*\)\s*;',
                ],
                recommendation="Add access control (onlyOwner, onlyAdmin) before selfdestruct calls.",
                negative_patterns=[
                    r'only(?:Owner|Admin)',
                ],
                min_confidence=0.6,
            ),

            VulnerabilityPattern(
                swc_id="SWC-131",
                title="Unexpected Ether Balance",
                description=(
                    "Contract balance can be forcibly increased by selfdestruct or pre-sent Ether. "
                    "Relying on address(this).balance for critical logic is dangerous."
                ),
                severity=Severity.HIGH,
                patterns=[
                    r'address\s*\(\s*this\s*\)\s*\.\s*balance',
                    r'\bthis\.balance\b',
                ],
                recommendation="Do not rely on address(this).balance for access control or critical logic.",
                min_confidence=0.8,
            ),

            # === HIGH SEVERITY VULNERABILITIES ===
            VulnerabilityPattern(
                swc_id="SWC-101",
                title="Integer Overflow/Underflow",
                description=(
                    "Arithmetic operations without SafeMath or Solidity 0.8+ can overflow/underflow, "
                    "leading to unexpected balance calculations and potential fund theft."
                ),
                severity=Severity.HIGH,
                patterns=[
                    # uint declaration with arithmetic assignment
                    r'\b(?:uint|uint8|uint16|uint24|uint32|uint48|uint56|uint64|uint96|uint128|uint160|uint192|uint224|uint256|int|int8|int16|int24|int32|int48|int56|int64|int96|int128|int160|int192|int224|int256)\s+\w+\s*=\s*\w+\s*(?:\+|\-|\*|%)\s*\w+',
                    # compound assignment operators
                    r'\b\w+\s*\+=\s*\w+',
                    r'\b\w+\s*\-=\s*\w+',
                    r'\b\w+\s*\*=\s*\w+',
                ],
                recommendation="Use Solidity 0.8+ (built-in overflow checks) or SafeMath library for "
                               "older versions. Consider using SafeCast for type conversions.",
                min_confidence=0.3,
            ),

            VulnerabilityPattern(
                swc_id="SWC-104",
                title="Unchecked Low-Level Call Return Value",
                description=(
                    "Low-level calls (call, delegatecall, staticcall) return a boolean indicating "
                    "success. Not checking this value means failures go unnoticed, potentially "
                    "leading to loss of funds or incorrect state."
                ),
                severity=Severity.HIGH,
                patterns=[
                    # call without capturing return value
                    r'(?<![=\w])\w+\.call\s*\{[^}]*\}\s*\([^)]*\)\s*;',
                    # plain .call(...) without result capture
                    r'(?<!success)\w+\.call\s*\([^)]*\)\s*;',
                    # .delegatecall without return check
                    r'\w+\.delegatecall\s*\([^)]*\)\s*;',
                    # .staticcall without capture
                    r'\w+\.staticcall\s*\([^)]*\)\s*;',
                ],
                recommendation="Always check the return value of low-level calls: "
                               "(bool success, ) = target.call(...); require(success);",
                min_confidence=0.5,
            ),

            VulnerabilityPattern(
                swc_id="SWC-109",
                title="Uninitialized Storage Pointer",
                description=(
                    "Uninitialized local storage variables can point to arbitrary storage slots, "
                    "leading to state corruption. Common in older Solidity versions."
                ),
                severity=Severity.HIGH,
                patterns=[
                    r'(?:(?:mapping|struct)\s+\w+\s+\w+\s*=\s*\w+\s*;)',
                    r'\bstruct\s+\w+\s+\w+\s*;',
                    r'\bmapping\s*\([^)]*\)\s+\w+\s*;',
                ],
                recommendation="Initialize storage variables explicitly. Use 'memory' for temporary data.",
                min_confidence=0.5,
            ),

            VulnerabilityPattern(
                swc_id="SWC-113",
                title="Missing Events for Critical Operations",
                description=(
                    "Absence of events for ownership transfers, critical parameter changes, "
                    "or fund movements makes it difficult to track important contract changes."
                ),
                severity=Severity.HIGH,
                patterns=[
                    r'(?:public|external)\s+function\s+(?:transferOwnership|changeOwner|setOwner)',
                    r'(?:public|external)\s+function\s+(?:withdraw|emergencyWithdraw)',
                ],
                recommendation="Emit events for all critical state changes to enable off-chain monitoring.",
                min_confidence=0.5,
            ),

            VulnerabilityPattern(
                swc_id="SWC-114",
                title="Transaction Order Dependence",
                description=(
                    "Contract behavior depends on transaction ordering, enabling frontrunning attacks. "
                    "Common in DEX operations, auctions, and any time-sensitive logic."
                ),
                severity=Severity.HIGH,
                patterns=[
                    r'(?:public|external)\s+function\s+\w+[^{]*{[^}]*(?:block\.number|block\.timestamp|now)[^{]*(?:buy|sell|swap|trade|bid|offer|exchange|invest)',
                    r'(?:buy|sell|swap|trade|bid|offer)[^{]*\{[^}]*(?:block\.number|block\.timestamp)',
                ],
                recommendation="Use commit-reveal schemes or time locks to mitigate frontrunning.",
                min_confidence=0.5,
            ),

            # === MEDIUM SEVERITY VULNERABILITIES ===
            VulnerabilityPattern(
                swc_id="SWC-120",
                title="Weak Randomness",
                description=(
                    "Using block.timestamp, block.number, or blockhash for randomness is predictable. "
                    "Miners can manipulate these values for gaming/lottery contracts."
                ),
                severity=Severity.MEDIUM,
                patterns=[
                    r'(?:block\.timestamp|block\.number|blockhash|now)\s*(?:%|mod|\+|\-|\*)\s*\w',
                    r'(?:keccak256|sha256|ripemd160)\s*\(\s*(?:abi\.encodePacked\s*)?\(\s*(?:block\.\w+|now|msg\.sender)',
                    r'(?<![a-zA-Z_.])\bnow\b(?!\w)',
                ],
                recommendation="Use Chainlink VRF or similar oracle-based randomness for critical randomness needs.",
                min_confidence=0.5,
            ),

            VulnerabilityPattern(
                swc_id="SWC-116",
                title="Block Timestamp Dependence",
                description=(
                    "Relying on block.timestamp for critical logic is dangerous as miners can "
                    "manipulate timestamps within a 15-second window."
                ),
                severity=Severity.MEDIUM,
                patterns=[
                    r'require\s*\(\s*(?:block\.timestamp|now)\s*(?:<|>|<=|>=|==)\s*\d+',
                    r'(?:if|require)\s*\([^)]*(?:block\.timestamp|now)\s*(?:<|>|<=|>=)',
                ],
                recommendation="Avoid block.timestamp for critical time checks. Use block numbers or "
                               "accept a 15-second manipulation window in design.",
                min_confidence=0.6,
            ),

            VulnerabilityPattern(
                swc_id="SWC-135",
                title="Unencoded Return Data",
                description=(
                    "Incorrectly handling return data from low-level calls can cause decoding errors "
                    "or return unexpected values."
                ),
                severity=Severity.MEDIUM,
                patterns=[
                    r'\(\s*\w+\s*,\s*\w+\s*\)\s*=\s*\w+\.call\s*',
                    r'abi\.decode\s*\([^)]*abi\.encode\s*\(',
                ],
                recommendation="Use properly typed interfaces or carefully validate return data encoding.",
                min_confidence=0.4,
            ),

            VulnerabilityPattern(
                swc_id="SWC-134",
                title="Signature Malleability",
                description=(
                    "ECDSA signatures can be manipulated (malleated) without invalidating them. "
                    "'s' value higher than secp256k1n/2 indicates malleability."
                ),
                severity=Severity.MEDIUM,
                patterns=[
                    r'(?<![a-zA-Z_.])ecrecover\s*\(',
                    r'ECDSA\.recover\s*\(',
                ],
                recommendation="Use OpenZeppelin's ECDSA library with tryRecover which prevents malleability.",
                min_confidence=0.5,
            ),

            VulnerabilityPattern(
                swc_id="SWC-126",
                title="Missing Zero Address Check",
                description=(
                    "Functions that accept address parameters should validate against zero address "
                    "to prevent tokens being sent to the null address."
                ),
                severity=Severity.MEDIUM,
                patterns=[
                    r'(?:public|external)\s+function\s+\w+[^)]*\baddress\s+\w+\s*[,)]',
                    r'(?:public|external)\s+function\s+\w+[^)]*\baddress\s+payable\s+\w+\s*[,)]',
                ],
                recommendation="Add require(target != address(0)) for critical address parameters.",
                min_confidence=0.3,
            ),

            # === LOW SEVERITY VULNERABILITIES ===
            VulnerabilityPattern(
                swc_id="SWC-118",
                title="Incorrect Use of ERC20 Return Value",
                description=(
                    "Some ERC20 tokens return false on failure instead of reverting. "
                    "Calling transfer/transferWithoutChecking without checking return value can fail silently."
                ),
                severity=Severity.LOW,
                patterns=[
                    r'\b\w+\.transfer\s*\([^)]*\)\s*;',
                    r'IERC20\s*\(\s*\w+\s*\)\.transfer\s*\([^)]*\)\s*;',
                ],
                recommendation="Use OpenZeppelin's SafeERC20 library which handles non-standard ERC20 tokens.",
                min_confidence=0.3,
            ),

            VulnerabilityPattern(
                swc_id="SWC-123",
                title="Write to Arbitrary Storage Slot",
                description=(
                    "Using assembly to write to arbitrary storage slots can corrupt contract state."
                ),
                severity=Severity.LOW,
                patterns=[
                    r'assembly\s*\{[^}]*sstore',
                ],
                recommendation="Avoid low-level storage manipulation. Use Solidity's storage mechanisms.",
                min_confidence=0.7,
            ),

            # === INFO SEVERITY ===
            VulnerabilityPattern(
                swc_id="SWC-128",
                title="Contract Pragma Version Not Locked",
                description=(
                    "Using loose pragma versions (e.g., >=0.5.0) can lead to unexpected behavior "
                    "when newer compiler versions introduce breaking changes."
                ),
                severity=Severity.INFO,
                patterns=[
                    r'pragma\s+solidity\s+\^',
                    r'pragma\s+experimental\s+ABIEncoderV2',
                ],
                recommendation="Lock pragma to a specific minor version (e.g., pragma solidity 0.8.19;).",
                min_confidence=0.8,
            ),

            VulnerabilityPattern(
                swc_id="SWC-136",
                title="Missing Visibility Modifier",
                description=(
                    "Functions without explicit visibility default to public in Solidity, "
                    "potentially exposing internal functions."
                ),
                severity=Severity.INFO,
                patterns=[
                    r'function\s+\w+\s*\([^)]*\)\s*\{',
                ],
                recommendation="Always specify function visibility (public, external, internal, private).",
                min_confidence=0.2,
            ),

            VulnerabilityPattern(
                swc_id="SWC-108",
                title="State Variable Default Visibility",
                description=(
                    "State variables without explicit visibility default to internal, "
                    "which may not be intentional."
                ),
                severity=Severity.INFO,
                patterns=[
                    r'(?:public|private|external)?\s*(?:uint|int|bool|address|bytes|string)\s+\w+\s*[=;]',
                ],
                recommendation="Explicitly declare state variable visibility.",
                min_confidence=0.2,
            ),

            # === Additional Hardcoded Secrets Pattern ===
            VulnerabilityPattern(
                swc_id="SWC-117",
                title="Hardcoded Secret or Private Key",
                description=(
                    "Hardcoded secrets, API keys, or private addresses in source code can be "
                    "extracted by attackers and used to compromise the system."
                ),
                severity=Severity.HIGH,
                patterns=[
                    r'(?:bytes32|string)\s+\w*\b(?:secret|key|password|api_key|private_key)\w*\b\s*=',
                    r'address\s+\w*\b(?:secret|hidden|admin|owner|multisig)\b\w*\s*=\s*0x',
                    r'=\s*0x[A-Fa-f0-9]{40}',
                ],
                recommendation="Use environment variables or on-chain configuration contracts for sensitive values.",
                negative_patterns=[
                    r'interface\s+\w+',
                    r'contract\s+\w+',
                ],
                min_confidence=0.5,
            ),
        ]
