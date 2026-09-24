# SPDX-License-Identifier: MIT

from __future__ import annotations

import json
from pathlib import Path

from wizard_audit.source_fetcher import OnChainSourceFetcher


def test_unpack_single_source() -> None:
    files = OnChainSourceFetcher._unpack_source("pragma solidity ^0.8.20; contract A {}", "A")
    assert files == {"A.sol": "pragma solidity ^0.8.20; contract A {}"}


def test_unpack_standard_json_sources() -> None:
    source = json.dumps({"sources": {"src/A.sol": {"content": "contract A {}"}}})
    files = OnChainSourceFetcher._unpack_source("{" + source + "}", "A")
    assert files == {"src/A.sol": "contract A {}"}


def test_safe_name_prevents_absolute_path() -> None:
    assert OnChainSourceFetcher._safe_name("/src/A.sol") == "src_A.sol"
