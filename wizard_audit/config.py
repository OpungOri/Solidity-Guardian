# SPDX-License-Identifier: MIT

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Mapping

import yaml

from .models import AuditConfig
from .validation import validate_solc_version, validate_url

_FIELDS = frozenset(
    {
        "file",
        "directory",
        "output",
        "deep",
        "generate_poc",
        "format",
        "strict",
        "solc_version",
        "rpc",
        "rpc_fork",
        "capital_source",
        "fork_block",
        "config_path",
        "correlation_id",
        "workspace_root",
    }
)
_BOOL_FIELDS = frozenset({"deep", "generate_poc", "strict"})
_ENV_PREFIX = "WIZARD_"
_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off"})


def _as_bool(value: Any, *, field: str) -> bool:
    if isinstance(value, bool):
        return value
    normalized = str(value).strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    raise ValueError(f"Invalid boolean for {field}: {value!r}")


def _load_file(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"Config file does not exist: {path}")
    try:
        with path.open(encoding="utf-8") as stream:
            data = yaml.safe_load(stream) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"Unable to load config file {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("Config root must be a mapping")
    return {str(key): value for key, value in data.items() if str(key) in _FIELDS}


def _as_non_negative_int(value: Any, *, field: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid integer for {field}: {value!r}") from exc
    if parsed < 0:
        raise ValueError(f"{field} must not be negative")
    return parsed


def load_config(
    config_path: str | Path | None = None,
    *,
    cli_overrides: Mapping[str, Any] | None = None,
    environ: Mapping[str, str] | None = None,
) -> AuditConfig:
    """Load config with precedence: CLI > environment > YAML baseline."""
    explicit_path = config_path is not None
    selected = Path(config_path).expanduser() if explicit_path else Path("config/default.yaml")

    values: dict[str, Any] = _load_file(selected) if selected.is_file() else {}
    if explicit_path and not selected.is_file():
        raise FileNotFoundError(f"Config file does not exist: {selected}")

    env = environ if environ is not None else os.environ
    for key in sorted(_FIELDS):
        env_key = _ENV_PREFIX + key.upper()
        if env_key in env:
            values[key] = env[env_key]

    for key, value in (cli_overrides or {}).items():
        if key in _FIELDS and value is not None:
            values[key] = value

    for key in _BOOL_FIELDS:
        if key in values:
            values[key] = _as_bool(values[key], field=key)

    if values.get("fork_block") is not None:
        values["fork_block"] = _as_non_negative_int(values["fork_block"], field="fork_block")

    if values.get("solc_version"):
        values["solc_version"] = validate_solc_version(str(values["solc_version"]))

    if values.get("rpc"):
        values["rpc"] = validate_url(str(values["rpc"]))

    if values.get("rpc_fork"):
        values["rpc_fork"] = validate_url(str(values["rpc_fork"]))

    if selected.is_file():
        values["config_path"] = str(selected)

    return AuditConfig(**{key: value for key, value in values.items() if key in _FIELDS})
