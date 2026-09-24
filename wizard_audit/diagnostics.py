# SPDX-License-Identifier: MIT

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any


class Diagnostics:
    """Structured, correlation-aware diagnostic event sink."""

    def __init__(self, correlation_id: str | None = None) -> None:
        self.correlation_id = correlation_id or str(uuid.uuid4())
        self.entries: list[dict[str, Any]] = []

    def add(self, level: str, source: str, message: str, **extra: Any) -> None:
        entry: dict[str, Any] = {
            "correlation_id": self.correlation_id,
            "level": level.lower(),
            "source": source,
            "message": message,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        entry.update(extra)
        self.entries.append(entry)
        getattr(logging.getLogger("solidity_guardian"), level.lower(), logging.info)(message)

    def to_json(self) -> str:
        return json.dumps(self.entries, indent=2, sort_keys=True)
