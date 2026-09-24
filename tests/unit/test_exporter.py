# SPDX-License-Identifier: MIT

from __future__ import annotations

import json
from pathlib import Path

from wizard_audit.diagnostics import Diagnostics
from wizard_audit.exporter import Exporter
from wizard_audit.models import AuditConfig, Evidence, Finding


def test_report_artifacts_are_json_and_correlated(tmp_path: Path) -> None:
    diagnostics = Diagnostics("release-test")
    config = AuditConfig(output=str(tmp_path))
    exporter = Exporter(config, diagnostics)
    finding = Finding(
        id="TEST-001",
        category="test",
        title="Test finding",
        contract="C",
        function="f",
        line=1,
        confidence="high",
        score=1,
        description="Evidence-backed test finding",
        evidence=[Evidence(kind="source", source="C.sol", location="1:1")],
    )

    report_path = exporter.write_report([finding])
    summary_path = exporter.write_summary([finding])
    diagnostics_path = exporter.write_diagnostics()

    report = json.loads(report_path.read_text(encoding="utf-8"))
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    diagnostics_payload = json.loads(diagnostics_path.read_text(encoding="utf-8"))
    assert report["schema_version"] == 1
    assert report["correlation_id"] == "release-test"
    assert report["findings"][0]["id"] == "TEST-001"
    assert summary["total_findings"] == 1
    assert diagnostics_payload == []
