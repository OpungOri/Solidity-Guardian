# SPDX-License-Identifier: MIT

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .diagnostics import Diagnostics
from .models import AuditConfig, Finding


class Exporter:
    """Writes deterministic audit and disclosure artifacts."""

    def __init__(self, config: AuditConfig, diagnostics: Diagnostics) -> None:
        self.config = config
        self.diagnostics = diagnostics
        self.outdir = config.output_dir()
        self.outdir.mkdir(parents=True, exist_ok=True)

    def write_report(self, findings: list[Finding], *, evidence: dict[str, Any] | None = None) -> Path:
        payload = {
            "tool": "solidity-guardian",
            "schema_version": 1,
            "correlation_id": self.diagnostics.correlation_id,
            "findings": [self._finding_payload(item) for item in findings],
            "evidence": evidence or {},
        }
        return self._write_json("findings.json", payload)

    def write_summary(self, findings: list[Finding]) -> Path:
        categories: dict[str, int] = {}
        for finding in findings:
            categories[finding.category] = categories.get(finding.category, 0) + 1
        return self._write_json("summary.json", {"total_findings": len(findings), "by_category": categories})

    def write_diagnostics(self) -> Path:
        path = self.outdir / "diagnostics.json"
        path.write_text(self.diagnostics.to_json(), encoding="utf-8")
        return path

    def write_submission_bundle(self, findings: list[Finding], *, target: dict[str, Any] | None = None) -> Path:
        """Create a disclosure-ready Markdown report without claiming exploit execution."""
        target = target or {}
        lines = [
            "# Solidity Guardian – Security Finding Report",
            "",
            "> This report is generated from authorized defensive analysis. Static findings are hypotheses until reproduced in an isolated local fork or test environment.",
            "",
            "## Target",
            "",
            f"- Address: `{target.get('address', 'not supplied')}`",
            f"- Chain ID: `{target.get('chain_id', 'not supplied')}`",
            f"- Source verification: `{target.get('source_status', 'not supplied')}`",
            f"- Correlation ID: `{self.diagnostics.correlation_id}`",
            "",
            "## Findings",
            "",
        ]
        if not findings:
            lines.append("No findings were produced by the configured detectors.")
        for number, finding in enumerate(findings, start=1):
            lines.extend([
                f"### {number}. {finding.id} – {finding.title}",
                "",
                f"- Severity score: `{finding.score}`",
                f"- Confidence: `{finding.confidence}`",
                f"- Contract/function: `{finding.contract}.{finding.function}`",
                f"- Source location: `{finding.sources[0] if finding.sources else 'unknown'}:{finding.line}`",
                "",
                "**Impact / rationale**",
                "",
                finding.description,
                "",
                "**Evidence**",
                "",
            ])
            for evidence in finding.evidence:
                lines.append(f"- `{evidence.source}:{evidence.location}` — {json.dumps(evidence.detail, sort_keys=True)}")
            lines.extend(["", "**Reproduction status**", "", "- Static evidence generated.", "- Live exploitation was not attempted.", "- Reproduce only on an authorized local fork or test deployment.", ""])
        lines.extend([
            "## Recommended submission attachments",
            "",
            "- `findings.json`",
            "- `summary.json`",
            "- `diagnostics.json`",
            "- `provenance.json` when source was fetched from an explorer",
            "- `poc/` local reproduction scaffold, if generated",
            "",
            "## Limitations",
            "",
            "- Static analysis does not prove exploitability or economic impact.",
            "- Validate affected state, permissions, compiler settings, proxy implementation, and deployment block before submitting.",
            "- Follow the bug bounty program scope, safe-harbor rules, and disclosure format.",
        ])
        path = self.outdir / "submission.md"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    def write_poc_scaffold(self, findings: list[Finding], *, address: str | None = None, chain_id: str | None = None) -> Path:
        """Write a non-destructive Foundry scaffold; never runs it or broadcasts transactions."""
        poc = self.outdir / "poc"
        poc.mkdir(parents=True, exist_ok=True)
        first = findings[0] if findings else None
        contract_address = address or "0x0000000000000000000000000000000000000000"
        test = f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

contract GuardianReproductionTest is Test {{
    address constant TARGET = {contract_address};

    function setUp() public {{
        // Run only against an authorized local fork. Do not broadcast transactions.
        // Example: forge test --fork-url $RPC_URL --fork-block-number $BLOCK -vvv
        vm.createSelectFork(vm.envString("RPC_URL"));
    }}

    function test_ReproduceFinding() public {{
        // TODO: implement a minimal, read-only or local-fork reproduction for:
        // {first.id if first else 'NO-FINDING'}
        // Chain ID: {chain_id or 'configure explicitly'}
        // This scaffold intentionally contains no exploit call and no fund transfer.
        assertTrue(TARGET != address(0), "configure TARGET before running");
    }}
}}
'''
        (poc / "GuardianReproduction.t.sol").write_text(test, encoding="utf-8")
        (poc / "README.md").write_text(
            "# Local reproduction scaffold\n\n"
            "This scaffold is intentionally non-destructive. Fill in the minimal reproduction only after confirming program scope.\n\n"
            "```bash\n"
            "export RPC_URL='https://authorized-fork-rpc'\n"
            "forge test --fork-url \"$RPC_URL\" --fork-block-number <block> -vvv\n"
            "```\n\n"
            "Never use a live mainnet signing key, broadcast a transaction, drain funds, or interact with an out-of-scope target.\n",
            encoding="utf-8",
        )
        return poc

    def _write_json(self, name: str, payload: dict[str, Any]) -> Path:
        path = self.outdir / name
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path

    @staticmethod
    def _finding_payload(item: Finding) -> dict[str, Any]:
        return {
            "id": item.id,
            "category": item.category,
            "title": item.title,
            "contract": item.contract,
            "function": item.function,
            "line": item.line,
            "confidence": item.confidence,
            "score": item.score,
            "description": item.description,
            "evidence": [{"kind": ev.kind, "source": ev.source, "location": ev.location, "detail": ev.detail} for ev in item.evidence],
            "state_vars": item.state_vars,
            "sources": item.sources,
        }
