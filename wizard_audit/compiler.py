# SPDX-License-Identifier: MIT

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .diagnostics import Diagnostics


class Compiler:
    """Bounded Solidity compiler wrapper using the stable standard-json interface."""

    def __init__(self, diagnostics: Diagnostics, workspace_root: Path) -> None:
        self.diagnostics = diagnostics
        self.workspace_root = workspace_root.resolve()

    def detect_pragma(self, source_files: list[Path]) -> str:
        for path in source_files:
            text = path.read_text(encoding="utf-8", errors="replace")
            match = re.search(r"pragma\s+solidity\s+([^;]+);", text)
            if match:
                return match.group(1).strip()
        return "0.8.20"

    def ensure_compiler(self, version: str) -> None:
        if shutil.which("solc") is None:
            raise RuntimeError("solc not found on PATH; install Solidity compiler or provide a compatible toolchain")
        if version:
            self.diagnostics.add("info", "compiler", "Using solc version", version=version)

    def compile(self, source_files: list[Path]) -> dict[str, Any]:
        """Compile sources through solc standard-json and return a normalized AST payload.

        `--combined-json ast-json` was removed from newer solc builds. Standard-json
        is supported by current and legacy compilers and keeps AST output structured.
        """
        if not source_files:
            raise ValueError("No Solidity source files supplied for compilation")

        solc_path = shutil.which("solc")
        if solc_path is None:
            raise RuntimeError("solc is required for AST compilation")

        sources: dict[str, dict[str, str]] = {}
        for source_file in source_files:
            source_key = self._source_key(source_file)
            sources[source_key] = {
                "content": source_file.read_text(encoding="utf-8", errors="replace")
            }

        request = {
            "language": "Solidity",
            "sources": sources,
            "settings": {
                "outputSelection": {"*": {"": ["ast"]}},
                "optimizer": {"enabled": False},
            },
        }

        try:
            proc = subprocess.run(
                [solc_path, "--standard-json"],
                cwd=str(self.workspace_root),
                env=self._sanitised_env(),
                input=json.dumps(request),
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"Compiler execution timed out after 120s: {exc}") from exc

        if proc.returncode != 0:
            stderr = (proc.stderr or "").strip()[:400]
            raise RuntimeError(f"Compiler failed: {stderr}")
        if not proc.stdout.strip():
            raise RuntimeError("Compiler produced empty output")

        try:
            payload = json.loads(proc.stdout)
        except ValueError as exc:
            raise RuntimeError("Compiler output is not valid JSON") from exc

        errors = payload.get("errors", [])
        fatal = [item for item in errors if item.get("severity") == "error"]
        if fatal:
            message = str(fatal[0].get("formattedMessage") or fatal[0].get("message") or "unknown compiler error")
            raise RuntimeError(f"Compiler failed: {message[:400]}")

        # SourceMapper consumes sourceList and recursively walks the AST nodes.
        payload["sourceList"] = list(sources)
        for source_key, source_payload in payload.get("sources", {}).items():
            ast = source_payload.get("ast")
            if isinstance(ast, dict):
                payload.setdefault("ast", []).append(ast)
        return payload

    def _source_key(self, source_file: Path) -> str:
        resolved = source_file.resolve()
        try:
            return resolved.relative_to(self.workspace_root).as_posix()
        except ValueError:
            return resolved.name

    def _sanitised_env(self) -> dict[str, str]:
        env = {
            key: value
            for key, value in os.environ.items()
            if key in {"PATH", "HOME", "TMPDIR", "USER", "SHELL", "PWD"}
        }
        env["PATH"] = env.get("PATH", os.environ.get("PATH", ""))
        return env
