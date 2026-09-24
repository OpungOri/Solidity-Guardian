# SPDX-License-Identifier: MIT

from pathlib import Path

from wizard_audit.detectors import detect_reentrancy


def test_detects_external_call_before_balance_update() -> None:
    findings = detect_reentrancy([Path("tests/corpus/vulnerable/VulnerableVault.sol")])
    assert len(findings) == 1
    assert findings[0].id == "REENTRANCY-CEI-001"
    assert findings[0].function == "withdraw"
    assert findings[0].confidence == "high"


def test_safe_vault_has_no_ordering_finding() -> None:
    findings = detect_reentrancy([Path("tests/corpus/safe/SafeVault.sol")])
    assert findings == []
