# SPDX-License-Identifier: MIT

from __future__ import annotations

from pathlib import Path

from wizard_audit.source_fetcher import OnChainSourceFetcher


def test_fetcher_rejects_empty_bytecode(tmp_path: Path) -> None:
    fetcher = OnChainSourceFetcher("http://rpc", "http://explorer", "key")
    fetcher._rpc = lambda method, params: "0x"  # type: ignore[method-assign]
    destination = tmp_path / "unused"
    try:
        fetcher.fetch("0x0000000000000000000000000000000000000001", destination)
    except RuntimeError as exc:
        assert "No deployed bytecode" in str(exc)
    else:
        raise AssertionError("empty bytecode must be rejected")
    assert not destination.exists(), "rejected fetch must not create the output directory"
