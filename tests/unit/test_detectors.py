# SPDX-License-Identifier: MIT

from pathlib import Path

from wizard_audit.detectors import detect_all, rule_ids


def test_vulnerable_corpus_has_reentrancy_finding() -> None:
    findings = detect_all([Path("tests/corpus/vulnerable/VulnerableVault.sol")])
    assert any(item.id == "REENTRANCY-CEI-001" for item in findings)


def test_safe_corpus_has_no_findings() -> None:
    assert detect_all([Path("tests/corpus/safe/SafeVault.sol")]) == []


def test_detector_catalog_is_explicit() -> None:
    assert "REENTRANCY-CEI-001" in rule_ids()
    assert "UNCHECKED-CALL-001" in rule_ids()
    assert "TX-ORIGIN-001" in rule_ids()
