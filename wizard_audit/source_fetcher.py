# SPDX-License-Identifier: MIT

from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class OnChainSource:
    directory: Path
    address: str
    chain_id: str | None
    explorer: str
    verified: bool
    bytecode_present: bool
    provenance: dict[str, Any]


class SourceFetchError(RuntimeError):
    """Raised when on-chain source cannot be safely acquired."""


class OnChainSourceFetcher:
    """Fetch verified source from an Etherscan-compatible explorer.

    An address alone contains bytecode, not Solidity source. This fetcher therefore
    requires both an explorer API key and an RPC URL, verifies that code exists at
    the address, and refuses to silently audit bytecode as source.
    """

    def __init__(self, rpc_url: str, explorer_url: str, api_key: str, timeout: int = 30) -> None:
        self.rpc_url = rpc_url.rstrip("/")
        self.explorer_url = explorer_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def fetch(self, address: str, destination: Path, chain_id: str | None = None) -> OnChainSource:
        bytecode = self._rpc("eth_getCode", [address, "latest"])
        if not isinstance(bytecode, str) or bytecode in {"0x", "0x0"}:
            raise SourceFetchError(f"No deployed bytecode found at {address}")

        query = urllib.parse.urlencode({
            "module": "contract", "action": "getsourcecode", "address": address,
            "apikey": self.api_key, **({"chainid": chain_id} if chain_id else {}),
        })
        payload = self._get_json(f"{self.explorer_url}?{query}")
        records = payload.get("result") if isinstance(payload, dict) else None
        if not isinstance(records, list) or not records or not isinstance(records[0], dict):
            raise SourceFetchError("Explorer returned no verified source metadata")
        record = records[0]
        source = record.get("SourceCode") or ""
        if not isinstance(source, str) or not source.strip():
            raise SourceFetchError("Contract source is not verified on the configured explorer; bytecode-only auditing is refused")

        files = self._unpack_source(source, record.get("ContractName") or "Contract")
        destination.mkdir(parents=True, exist_ok=True)
        for name, content in files.items():
            path = destination / self._safe_name(name)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        provenance = {
            "address": address,
            "chain_id": chain_id,
            "explorer": self.explorer_url,
            "contract_name": record.get("ContractName"),
            "compiler_version": record.get("CompilerVersion"),
            "optimization_used": record.get("OptimizationUsed"),
            "constructor_arguments": record.get("ConstructorArguments"),
            "bytecode_sha256": __import__("hashlib").sha256(bytecode.encode()).hexdigest(),
            "source_files": sorted(files),
        }
        (destination / "provenance.json").write_text(json.dumps(provenance, indent=2, sort_keys=True), encoding="utf-8")
        return OnChainSource(destination, address, chain_id, self.explorer_url, True, True, provenance)

    def _rpc(self, method: str, params: list[Any]) -> Any:
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
        request = urllib.request.Request(self.rpc_url, data=body, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = json.load(response)
        except Exception as exc:
            raise SourceFetchError(f"RPC request failed: {exc}") from exc
        if payload.get("error"):
            raise SourceFetchError(f"RPC error: {payload['error']}")
        return payload.get("result")

    def _get_json(self, url: str) -> dict[str, Any]:
        try:
            with urllib.request.urlopen(url, timeout=self.timeout) as response:
                payload = json.load(response)
        except Exception as exc:
            raise SourceFetchError(f"Explorer request failed: {exc}") from exc
        if payload.get("status") == "0" and payload.get("message") not in {"OK", "No records found"}:
            raise SourceFetchError(str(payload.get("result") or payload.get("message")))
        return payload

    @staticmethod
    def _unpack_source(source: str, contract_name: str) -> dict[str, str]:
        candidate = source.strip()
        if candidate.startswith("{{") and candidate.endswith("}}"):
            try:
                parsed = json.loads(candidate[1:-1])
                sources = parsed.get("sources", {})
                if isinstance(sources, dict):
                    return {str(name): str(item.get("content", "")) for name, item in sources.items() if isinstance(item, dict)}
            except json.JSONDecodeError:
                pass
        return {f"{contract_name or 'Contract'}.sol": source}

    @staticmethod
    def _safe_name(name: str) -> str:
        cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", name).lstrip("/")
        if not cleaned or cleaned == ".":
            raise SourceFetchError("Explorer returned an invalid source filename")
        return cleaned
