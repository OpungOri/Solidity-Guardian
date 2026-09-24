# SPDX-License-Identifier: MIT

from pathlib import Path

import pytest

from wizard_audit.validation import (
    ensure_within_root,
    validate_address,
    validate_file_path,
    validate_solc_version,
    validate_url,
)


def test_validation_accepts_expected_values(tmp_path: Path) -> None:
    source = tmp_path / "Contract.sol"
    source.write_text("contract C {}", encoding="utf-8")
    assert validate_file_path(str(source)) == source.resolve()
    assert ensure_within_root(source, tmp_path) == source.resolve()
    assert validate_solc_version("0.8.20") == "0.8.20"
    assert validate_address("0x" + "1" * 40) == "0x" + "1" * 40
    assert validate_url("https://example.test/rpc") == "https://example.test/rpc"


def test_validation_rejects_escape_and_invalid_inputs(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        ensure_within_root(tmp_path / ".." / "outside.sol", tmp_path)
    with pytest.raises(ValueError):
        validate_solc_version("latest")
    with pytest.raises(ValueError):
        validate_address("0x123")
    with pytest.raises(ValueError):
        validate_url("ftp://example.test")
