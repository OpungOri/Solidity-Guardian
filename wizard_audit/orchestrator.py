# SPDX-License-Identifier: MIT

from __future__ import annotations

from pathlib import Path
from typing import Any

from .diagnostics import Diagnostics
from .models import AuditConfig


class Orchestrator:
    """Coordinates the audit workflow and keeps the default mode audit/report-only."""

    def __init__(self, config: AuditConfig, diagnostics: Diagnostics | None = None) -> None:
        self.config = config
        self.diagnostics = diagnostics or Diagnostics(config.correlation_id)

    def run(self) -> list[dict[str, Any]]:
        if self.config.file is None and self.config.directory is None:
            raise ValueError("Either --file or --dir must be supplied")

        source_files = self._prepare_sources()
        if not source_files:
            raise FileNotFoundError("No Solidity files were found")

        from .compiler import Compiler
        from .source_mapper import SourceMapper

        compiler = Compiler(self.diagnostics, Path(self.config.workspace_root).resolve())
        version = compiler.detect_pragma(source_files)
        compiler.ensure_compiler(version)
        ast = compiler.compile(source_files)

        mapper = SourceMapper({path.name: path for path in source_files})
        mapping = mapper.build(ast)

        self.diagnostics.add(
            "info",
            "orchestrator",
            "Audit completed successfully",
            files=[str(path) for path in source_files],
            compiler_version=version,
            is_poc=self.config.generate_poc,
            mapping_keys=list(mapping),
        )

        return [
            {
                "file": str(path),
                "compiler_version": version,
                "mapped": path.name in mapping,
            }
            for path in source_files
        ]

    def _prepare_sources(self) -> list[Path]:
        selected: list[Path] = []
        if self.config.file:
            file_path = Path(self.config.file).expanduser().resolve()
            if file_path.is_file() and file_path.suffix.lower() == ".sol":
                selected.append(file_path)
        if self.config.directory:
            directory = Path(self.config.directory).expanduser().resolve()
            if directory.is_dir():
                for file_path in sorted(directory.rglob("*.sol")):
                    selected.append(file_path)
        return selected
