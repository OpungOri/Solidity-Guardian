# SPDX-License-Identifier: MIT

from pathlib import Path

from wizard_audit.exporter import Exporter
from wizard_audit.models import AuditConfig
from wizard_audit.diagnostics import Diagnostics


def test_submission_bundle_and_poc_scaffold(tmp_path: Path) -> None:
    exporter = Exporter(AuditConfig(output=str(tmp_path)), Diagnostics("test-correlation"))
    exporter.write_submission_bundle([])
    poc = exporter.write_poc_scaffold([])
    assert (tmp_path / "submission.md").is_file()
    assert (poc / "GuardianReproduction.t.sol").is_file()
    assert "poc_executed" not in (tmp_path / "submission.md").read_text(encoding="utf-8")
