# SPDX-License-Identifier: MIT

from __future__ import annotations

from pathlib import Path


class SourceMapper:
    """Deterministic AST-to-source mapping using real source offsets and line starts."""

    def __init__(self, source_files: dict[str, Path]) -> None:
        self.source_files = source_files

    def build(self, ast: dict) -> dict[str, dict[str, object]]:
        mapping: dict[str, dict[str, object]] = {}
        source_names = ast.get("sourceList", []) if isinstance(ast, dict) else []

        for source_path, file_path in self.source_files.items():
            content = file_path.read_text(encoding="utf-8", errors="replace")
            line_starts = {0: 0}
            for index, ch in enumerate(content):
                if ch == "\n":
                    line_starts[index + 1] = index + 1
            mapping[source_path] = {
                "path": str(file_path),
                "line_starts": line_starts,
                "line_count": max(1, len(content.splitlines())),
            }

        for node in self._iter_nodes(ast):
            if node.get("nodeType") is None:
                continue
            src = node.get("src")
            if not isinstance(src, str) or not src:
                continue

            parsed = self._parse_src(src)
            if parsed is None:
                continue
            start, length, source_index = parsed

            file_key = self._resolve_source_file(start, source_index, source_names, mapping)
            if file_key is None:
                continue

            meta = mapping[file_key]
            line_starts = meta.get("line_starts", {})
            if not isinstance(line_starts, dict):
                continue

            node["_source_file"] = file_key
            node["_source_line"] = self._offset_to_line(start, line_starts)
            node["_source_offset"] = start
            node["_source_length"] = length
            node["_source_index"] = source_index

        return mapping

    @staticmethod
    def _iter_nodes(node: object):
        if isinstance(node, dict):
            yield node
            for value in node.values():
                yield from SourceMapper._iter_nodes(value)
        elif isinstance(node, list):
            for item in node:
                yield from SourceMapper._iter_nodes(item)

    @staticmethod
    def _parse_src(src: str) -> tuple[int, int, int] | None:
        parts = src.split(":")
        if len(parts) != 3:
            return None

        try:
            start = int(parts[0])
            length = int(parts[1])
            source_index = int(parts[2])
        except ValueError:
            return None

        if start < 0 or length < 0 or source_index < 0:
            return None

        return start, length, source_index

    @staticmethod
    def _offset_to_line(offset: int, line_starts: dict[int, int]) -> int:
        if not line_starts:
            return 1

        line = 1
        for start in sorted(line_starts):
            if start == 0:
                continue
            if start <= offset:
                line += 1
            else:
                break
        return max(1, line)

    def _resolve_source_file(
        self,
        offset: int,
        source_index: int | None,
        source_names: list[str],
        mapping: dict[str, dict[str, object]],
    ) -> str | None:
        if source_index is not None and 0 <= source_index < len(source_names):
            candidate = source_names[source_index]
            if candidate in mapping:
                return candidate

        for source_key, meta in mapping.items():
            line_starts = meta.get("line_starts", {})
            if not isinstance(line_starts, dict):
                continue
            if any(start <= offset for start in line_starts):
                return source_key
        return None

    def line_number_for(self, src: str, source_path: str) -> int:
        parsed = self._parse_src(src)
        if parsed is None:
            return 1
        start, _, _ = parsed
        meta = self.source_files.get(source_path)
        if meta is None:
            return 1
        content = meta.read_text(encoding="utf-8", errors="replace")
        line_starts = {0: 0}
        for index, ch in enumerate(content):
            if ch == "\n":
                line_starts[index + 1] = index + 1
        return self._offset_to_line(start, line_starts)
