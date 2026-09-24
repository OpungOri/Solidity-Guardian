# SPDX-License-Identifier: MIT

from __future__ import annotations

import re
from pathlib import Path

from .models import Evidence, Finding


_EXTERNAL_VALUE_CALL = re.compile(r"\.call\s*\{\s*value\s*:")
_FUNCTION = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_CONTRACT = re.compile(r"\bcontract\s+([A-Za-z_][A-Za-z0-9_]*)\b")
_STATE_DECREMENT = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\s*\[[^\]]+\]\s*-=")


def detect_reentrancy(files: list[Path]) -> list[Finding]:
    """Detect the narrow, evidence-backed checks-effects-interactions violation.

    This intentionally reports only when a value-bearing external call is followed
    shortly by a mapping decrement in the same function. It does not claim that
    every external call is exploitable; the finding describes the concrete ordering
    evidence and is conservative by design.
    """
    findings: list[Finding] = []
    for path in files:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        contract_match = _CONTRACT.search("\n".join(lines))
        contract = contract_match.group(1) if contract_match else path.stem
        current_function = "<unknown>"
        for index, line in enumerate(lines):
            function_match = _FUNCTION.search(line)
            if function_match:
                current_function = function_match.group(1)
            if not _EXTERNAL_VALUE_CALL.search(line):
                continue

            window = lines[index + 1 : index + 9]
            decrement_offset = next(
                (offset for offset, candidate in enumerate(window, start=1) if _STATE_DECREMENT.search(candidate)),
                None,
            )
            if decrement_offset is None:
                continue

            call_line = index + 1
            decrement_line = index + 1 + decrement_offset
            findings.append(
                Finding(
                    id="REENTRANCY-CEI-001",
                    category="reentrancy",
                    title="External value call occurs before balance update",
                    contract=contract,
                    function=current_function,
                    line=call_line,
                    confidence="high",
                    score=8,
                    description=(
                        "A value-bearing external call occurs before a mapping balance "
                        "decrement. Update state before interacting with the external "
                        "address or apply a proven reentrancy guard."
                    ),
                    evidence=[
                        Evidence(
                            kind="source",
                            source=str(path),
                            location=f"{call_line}:{decrement_line}",
                            detail={
                                "call_line": call_line,
                                "state_update_line": decrement_line,
                                "rule": "checks-effects-interactions",
                            },
                        )
                    ],
                    sources=[str(path)],
                )
            )
    return findings
