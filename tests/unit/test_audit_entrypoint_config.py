# SPDX-License-Identifier: MIT

from pathlib import Path

import pytest

from wizard_audit.config import load_config


def test_default_config_is_audit_only() -> None:
    config = load_config(Path("config/default.yaml"), environ={}, cli_overrides={})
    assert config.generate_poc is False


def test_cli_overrides_environment(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text("output: file-output\n", encoding="utf-8")
    config = load_config(
        config_file,
        environ={"WIZARD_OUTPUT": "env-output"},
        cli_overrides={"output": "cli-output"},
    )
    assert config.output == "cli-output"


def test_invalid_boolean_is_rejected(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text("deep: maybe\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid boolean"):
        load_config(config_file, environ={}, cli_overrides={})


def test_negative_fork_block_is_rejected(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text("fork_block: -1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="must not be negative"):
        load_config(config_file, environ={}, cli_overrides={})
