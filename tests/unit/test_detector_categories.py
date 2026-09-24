# SPDX-License-Identifier: MIT

from __future__ import annotations

from pathlib import Path

import pytest

from wizard_audit.detectors import detect_all, rule_ids


EXPECTED_RULES = {
    "REENTRANCY-CEI-001",
    "TX-ORIGIN-001",
    "UNCHECKED-CALL-001",
    "DANGEROUS-DELEGATECALL-001",
    "SELFDESTRUCT-001",
    "TIMESTAMP-001",
    "WEAK-RANDOMNESS-001",
    "UNBOUNDED-LOOP-001",
    "FLOATING-PRAGMA-001",
}


@pytest.mark.parametrize(
    ("name", "source", "rule"),
    [
        (
            "tx_origin",
            """pragma solidity ^0.8.20; contract C { function f() external { require(tx.origin == msg.sender); } }""",
            "TX-ORIGIN-001",
        ),
        (
            "unchecked_call",
            """pragma solidity ^0.8.20; contract C { function f(address target) external { target.call(\"\"); } }""",
            "UNCHECKED-CALL-001",
        ),
        (
            "delegatecall",
            """pragma solidity ^0.8.20; contract C { function f(address target) external { target.delegatecall(\"\"); } }""",
            "DANGEROUS-DELEGATECALL-001",
        ),
        (
            "selfdestruct",
            """pragma solidity ^0.8.20; contract C { function f() external { selfdestruct(payable(msg.sender)); } }""",
            "SELFDESTRUCT-001",
        ),
        (
            "timestamp",
            """pragma solidity ^0.8.20; contract C { function f() external view returns (uint) { return block.timestamp; } }""",
            "TIMESTAMP-001",
        ),
        (
            "weak_randomness",
            """pragma solidity ^0.8.20; contract C { function f() external view returns (uint) { return uint(keccak256(abi.encode(block.timestamp))); } }""",
            "WEAK-RANDOMNESS-001",
        ),
        (
            "unbounded_loop",
            """pragma solidity ^0.8.20; contract C { uint[] users; function f() external { for (uint i = 0; i < users.length; i++) { } } }""",
            "UNBOUNDED-LOOP-001",
        ),
        (
            "exact_pragma",
            """pragma solidity 0.8.20; contract C {}""",
            "FLOATING-PRAGMA-001",
        ),
    ],
)
def test_each_source_detector_has_positive_fixture(tmp_path: Path, name: str, source: str, rule: str) -> None:
    path = tmp_path / f"{name}.sol"
    path.write_text(source, encoding="utf-8")
    assert any(finding.id == rule for finding in detect_all([path]))


def test_detector_catalog_has_positive_coverage_for_every_rule() -> None:
    assert set(rule_ids()) == EXPECTED_RULES


def test_reference_corpus_still_covers_reentrancy_and_safe_case() -> None:
    vulnerable = Path("tests/corpus/vulnerable/VulnerableVault.sol")
    safe = Path("tests/corpus/safe/SafeVault.sol")
    assert any(finding.id == "REENTRANCY-CEI-001" for finding in detect_all([vulnerable]))
    assert detect_all([safe]) == []
