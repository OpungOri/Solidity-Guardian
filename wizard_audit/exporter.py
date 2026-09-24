# SPDX-License-Identifier: MIT

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .diagnostics import Diagnostics
from .models import AuditConfig, Finding


class Exporter:
    """Writes stable audit artifacts; it never executes generated content."""

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
        path = self.outdir / "findings.json"
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        return path

    def write_summary(self, findings: list[Finding]) -> Path:
        categories: dict[str, int] = {}
        for finding in findings:
            categories[finding.category] = categories.get(finding.category, 0) + 1
        path = self.outdir / "summary.json"
        path.write_text(json.dumps({"total_findings": len(findings), "by_category": categories}, indent=2, sort_keys=True), encoding="utf-8")
        return path

    def write_diagnostics(self) -> Path:
        path = self.outdir / "diagnostics.json"
        path.write_text(self.diagnostics.to_json(), encoding="utf-8")
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
            "evidence": [
                {"kind": ev.kind, "source": ev.source, "location": ev.location, "detail": ev.detail}
                for ev in item.evidence
            ],
            "state_vars": item.state_vars,
            "sources": item.sources,
        }
