# SPDX-License-Identifier: MIT

from pathlib import Path


ROOT = Path(__file__).parents[2]


def test_reference_corpus_contains_safe_and_vulnerable_contracts() -> None:
    vulnerable = ROOT / "tests/corpus/vulnerable/VulnerableVault.sol"
    safe = ROOT / "tests/corpus/safe/SafeVault.sol"

    assert vulnerable.is_file()
    assert safe.is_file()
    assert "call{value: amount}" in vulnerable.read_text(encoding="utf-8")
    assert "nonReentrant" in safe.read_text(encoding="utf-8")


def test_default_config_is_safe_for_release() -> None:
    config = (ROOT / "config/default.yaml").read_text(encoding="utf-8")
    assert "generate_poc: false" in config
    assert "strict: true" in config
