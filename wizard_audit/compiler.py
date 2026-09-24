# SPDX-License-Identifier: MIT

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from .diagnostics import Diagnostics


class Compiler:
    """Bounded compiler wrapper with sanitised environment and explicit validation."""

    def __init__(self, diagnostics: Diagnostics, workspace_root: Path) -> None:
        self.diagnostics = diagnostics
        self.workspace_root = workspace_root.resolve()

    def detect_pragma(self, source_files: list[Path]) -> str:
        for path in source_files:
            text = path.read_text(encoding="utf-8", errors="replace")
            match = __import__("re").search(r"pragma\s+solidity\s+([^;]+);", text)
            if match:
                return match.group(1).strip()
        return "0.8.20"

    def ensure_compiler(self, version: str) -> None:
        if shutil.which("solc") is None:
            raise RuntimeError("solc not found on PATH; install Solidity compiler or provide a compatible toolchain")
        if version:
            self.diagnostics.add("info", "compiler", "Using solc version", version=version)

    def compile(self, source_files: list[Path]) -> dict:
        if not source_files:
            raise ValueError("No Solidity source files supplied for compilation")

        solc_path = shutil.which("solc")
        if solc_path is None:
            raise RuntimeError("solc is required for AST compilation")

        cmd = [solc_path, "--combined-json", "ast-json", "--allow-paths", str(self.workspace_root)]
        for source_file in source_files:
            cmd.append(str(source_file))

        env = self._sanitised_env()
        try:
            proc = subprocess.run(
                cmd,
                cwd=str(self.workspace_root),
                env=env,
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
            payload = __import__("json").loads(proc.stdout)
        except ValueError as exc:
            raise RuntimeError("Compiler output is not valid JSON") from exc

        return payload

    def _sanitised_env(self) -> dict[str, str]:
        env = {key: value for key, value in os.environ.items() if key in {"PATH", "HOME", "TMPDIR", "USER", "SHELL", "PWD"}}
        env["PATH"] = env.get("PATH", os.environ.get("PATH", ""))
        return env
