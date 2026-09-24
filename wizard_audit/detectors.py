# SPDX-License-Identifier: MIT

from __future__ import annotations

import re
from pathlib import Path

from .models import Evidence, Finding


_EXTERNAL_VALUE_CALL = re.compile(r"\.call\s*\{\s*value\s*:")
_FUNCTION = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_CONTRACT = re.compile(r"\bcontract\s+([A-Za-z_][A-Za-z0-9_]*)\b")
_STATE_DECREMENT = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\s*\[[^\]]+\]\s*[-+]=")

_RULES = (
    "REENTRANCY-CEI-001",
    "ACCESS-CONTROL-001",
    "UNCHECKED-CALL-001",
    "DANGEROUS-DELEGATECALL-001",
    "SELFDESTRUCT-001",
    "TX-ORIGIN-001",
    "TIMESTAMP-001",
    "WEAK-RANDOMNESS-001",
    "UNBOUNDED-LOOP-001",
    "FLOATING-PRAGMA-001",
)


def _context(lines: list[str], index: int) -> tuple[str, int]:
    function = "<unknown>"
    for line_number in range(index + 1):
        match = _FUNCTION.search(lines[line_number])
        if match:
            function = match.group(1)
    return function, index + 1


def _finding(
    rule: str,
    category: str,
    title: str,
    description: str,
    path: Path,
    lines: list[str],
    index: int,
    *,
    score: int,
    confidence: str = "medium",
    end_index: int | None = None,
) -> Finding:
    contract_match = _CONTRACT.search("\n".join(lines))
    contract = contract_match.group(1) if contract_match else path.stem
    function, line = _context(lines, index)
    end_line = end_index + 1 if end_index is not None else line
    return Finding(
        id=rule,
        category=category,
        title=title,
        contract=contract,
        function=function,
        line=line,
        confidence=confidence,
        score=score,
        description=description,
        evidence=[
            Evidence(
                kind="source",
                source=str(path),
                location=f"{line}:{end_line}",
                detail={"rule": rule, "snippet": lines[index].strip()},
            )
        ],
        sources=[str(path)],
    )


def detect_reentrancy(files: list[Path]) -> list[Finding]:
    findings: list[Finding] = []
    for path in files:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        for index, line in enumerate(lines):
            if not _EXTERNAL_VALUE_CALL.search(line):
                continue
            window = lines[index + 1 : index + 9]
            decrement_offset = next(
                (offset for offset, candidate in enumerate(window, start=1) if _STATE_DECREMENT.search(candidate)),
                None,
            )
            if decrement_offset is None:
                continue
            findings.append(
                _finding(
                    "REENTRANCY-CEI-001",
                    "reentrancy",
                    "External value call occurs before balance update",
                    "A value-bearing external call occurs before a state balance update. Apply checks-effects-interactions or a proven reentrancy guard.",
                    path,
                    lines,
                    index,
                    score=8,
                    confidence="high",
                    end_index=index + decrement_offset,
                )
            )
    return findings


def detect_source_patterns(files: list[Path]) -> list[Finding]:
    """Run conservative source-pattern checks for common Solidity risk classes."""
    findings: list[Finding] = []
    checks: tuple[tuple[str, str, str, str, str, int], ...] = (
        (
            r"\btx\.origin\b",
            "ACCESS-CONTROL-001",
            "access-control",
            "Authorization uses tx.origin",
            "Use msg.sender or an explicit trusted-forwarder model; tx.origin can be confused by intermediary contracts.",
            7,
        ),
        (
            r"\.delegatecall\s*\(",
            "DANGEROUS-DELEGATECALL-001",
            "delegatecall",
            "Dynamic delegatecall can execute code in the caller's storage context.",
            "Restrict the target and validate the implementation before using delegatecall.",
            8,
        ),
        (
            r"\bselfdestruct\s*\(",
            "SELFDESTRUCT-001",
            "destructive-operation",
            "Contract destruction is reachable in source.",
            "Protect destruction with strong access control and document the lifecycle policy.",
            8,
        ),
        (
            r"\bblock\.timestamp\b|\bnow\b",
            "TIMESTAMP-001",
            "timestamp-dependence",
            "Block timestamp is used in contract logic.",
            "Do not use timestamp as a source of precise randomness or a security-critical boundary.",
            3,
        ),
        (
            r"\b(block\.timestamp|block\.number)\b[^\n]*(keccak256|abi\.encode)|\bkeccak256\s*\([^\n]*(block\.timestamp|block\.number)",
            "WEAK-RANDOMNESS-001",
            "weak-randomness",
            "Block metadata contributes to a randomness calculation.",
            "Use a verifiable randomness source for security-sensitive selection.",
            7,
        ),
        (
            r"\bfor\s*\([^;]*;[^;]*;",
            "UNBOUNDED-LOOP-001",
            "unbounded-loop",
            "A loop may iterate over caller- or storage-controlled data.",
            "Bound iterations or paginate work to avoid gas exhaustion.",
            4,
        ),
    )
    for path in files:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        text = "\n".join(lines)
        pragma = re.search(r"pragma\s+solidity\s+([^;]+);", text)
        if pragma and not any(char in pragma.group(1) for char in "^<>"):
            index = next(i for i, line in enumerate(lines) if "pragma solidity" in line)
            findings.append(
                _finding(
                    "FLOATING-PRAGMA-001",
                    "compiler",
                    "Exact Solidity pragma pins one compiler patch",
                    "An exact pragma reduces compiler portability and can cause unexpected build failures. Prefer a tested range and pin the compiler in CI.",
                    path,
                    lines,
                    index,
                    score=2,
                )
            )

        for pattern, rule, category, title, description, score in checks:
            compiled = re.compile(pattern, re.IGNORECASE)
            for index, line in enumerate(lines):
                if compiled.search(line):
                    findings.append(_finding(rule, category, title, description, path, lines, index, score=score))

        for index, line in enumerate(lines):
            if ".call(" not in line or ".call{" in line:
                continue
            nearby = "\n".join(lines[index : index + 3])
            if not re.search(r"\bbool|require\s*\(|assert\s*\(", nearby):
                findings.append(
                    _finding(
                        "UNCHECKED-CALL-001",
                        "unchecked-call",
                        "External call result is not checked",
                        "The return value of an external call is not visibly checked.",
                        path,
                        lines,
                        index,
                        score=6,
                    )
                )
    return findings


def detect_all(files: list[Path]) -> list[Finding]:
    findings = detect_reentrancy(files) + detect_source_patterns(files)
    return sorted(findings, key=lambda item: (item.sources[0] if item.sources else "", item.line, item.id))


def rule_ids() -> list[str]:
    return list(_RULES)
