# SPDX-License-Identifier: MIT

import json

from wizard_audit.cli import main


def test_cli_default_is_audit_only(tmp_path, monkeypatch):
    contract = tmp_path / "Contract.sol"
    contract.write_text("pragma solidity 0.8.20; contract Contract {}\n", encoding="utf-8")

    observed = {}

    def fake_run(self):
        observed["generate_poc"] = self.config.generate_poc
        return []

    monkeypatch.setattr("wizard_audit.orchestrator.Orchestrator.run", fake_run)
    exit_code = main(["-f", str(contract)])
    assert exit_code == 0
    assert observed["generate_poc"] is False


def test_cli_explicit_poc_flag_sets_generate_poc(tmp_path, monkeypatch):
    contract = tmp_path / "Contract.sol"
    contract.write_text("pragma solidity 0.8.20; contract Contract {}\n", encoding="utf-8")

    observed = {}

    def fake_run(self):
        observed["generate_poc"] = self.config.generate_poc
        return []

    monkeypatch.setattr("wizard_audit.orchestrator.Orchestrator.run", fake_run)
    exit_code = main(["-f", str(contract), "--generate-poc"])
    assert exit_code == 0
    assert observed["generate_poc"] is True
