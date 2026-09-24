# SPDX-License-Identifier: MIT

from __future__ import annotations

import argparse
import json
import logging
import os
from typing import Sequence

from .diagnostics import Diagnostics
from .exporter import Exporter
from .models import AuditConfig
from .orchestrator import Orchestrator
from .source_fetcher import OnChainSourceFetcher, SourceFetchError
from .validation import validate_address, validate_file_path, validate_solc_version, validate_url


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit-first Solidity security analysis tool")
    parser.add_argument("-f", "--file")
    parser.add_argument("-d", "--dir")
    parser.add_argument("-o", "--output", default="./audit-output")
    parser.add_argument("--deep", action="store_true")
    parser.add_argument("--generate-poc", action="store_true")
    parser.add_argument("--solc-version")
    parser.add_argument("--rpc", help="RPC URL; required for --address source acquisition")
    parser.add_argument("--rpc-fork")
    parser.add_argument("--address", help="Contract address to audit; source is fetched from explorer")
    parser.add_argument("--chain-id", help="Explorer chain ID, e.g. 1, 137, 11155111")
    parser.add_argument("--explorer-api", default="https://api.etherscan.io/api", help="Etherscan-compatible API endpoint")
    parser.add_argument("--explorer-api-key", default=os.environ.get("WIZARD_EXPLORER_API_KEY"), help="Explorer API key")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--config")
    return parser


def configure_logging() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def main(argv: Sequence[str] | None = None) -> int:
    configure_logging()
    args = build_parser().parse_args(argv)
    correlation_id = os.environ.get("WIZARD_CORRELATION_ID") or None
    diagnostics = Diagnostics(correlation_id)
    try:
        file_path = validate_file_path(args.file) if args.file else None
        directory_path = validate_file_path(args.dir) if args.dir else None
        validate_solc_version(args.solc_version)
        validate_url(args.rpc)
        validate_url(args.rpc_fork)
        validate_url(args.explorer_api)
        validate_address(args.address)
        if args.address and not args.rpc:
            raise ValueError("--rpc is required with --address to verify deployed bytecode")
        if args.address and not args.explorer_api_key:
            raise ValueError("--explorer-api-key or WIZARD_EXPLORER_API_KEY is required with --address")
        if args.address and not file_path and not directory_path:
            fetched_dir = os.path.abspath(os.path.join(args.output, ".source"))
            fetched = OnChainSourceFetcher(args.rpc, args.explorer_api, args.explorer_api_key).fetch(args.address, __import__("pathlib").Path(fetched_dir), args.chain_id)
            directory_path = validate_file_path(fetched.directory)
            diagnostics.add("info", "source_fetch", "Fetched verified source", **fetched.provenance)
        elif args.address:
            diagnostics.add("info", "source_fetch", "Using supplied source with on-chain address evidence", address=args.address, chain_id=args.chain_id)
        config = AuditConfig(file=str(file_path) if file_path else None, directory=str(directory_path) if directory_path else None, output=args.output, deep=args.deep, generate_poc=args.generate_poc, strict=args.strict, solc_version=args.solc_version, rpc=args.rpc, rpc_fork=args.rpc_fork, capital_source="funded", fork_block=None, config_path=args.config, correlation_id=correlation_id, workspace_root=".")
        orchestrator = Orchestrator(config, diagnostics)
        results = orchestrator.run()
        exporter = Exporter(config, diagnostics)
        exporter.write_report(orchestrator.findings)
        exporter.write_summary(orchestrator.findings)
        exporter.write_diagnostics()
        print(json.dumps({"status": "ok", "results": results}, indent=2, sort_keys=True))
        return 0
    except (FileNotFoundError, PermissionError, ValueError, RuntimeError, SourceFetchError) as exc:
        diagnostics.add("error", "cli", str(exc), input_file=args.file, directory=args.dir, address=args.address)
        print(json.dumps({"status": "error", "message": str(exc)}, indent=2, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
