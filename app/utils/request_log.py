"""
Per-request search/crawl activity logging.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.core.config import settings


def append_request_log(
    context: dict[str, Any] | None,
    *,
    module: str,
    event: str,
    **details: Any,
) -> None:
    """Append a single structured line to request_log.log for the active scan."""
    path = _get_log_path(context)
    if path is None:
        return

    path.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).isoformat()
    parts = [timestamp, f"module={json.dumps(module)}", f"event={json.dumps(event)}"]
    for key, value in details.items():
        if value is None:
            continue
        parts.append(f"{key}={_serialize(value)}")

    with open(path, "a", encoding="utf-8") as f:
        f.write(" ".join(parts) + "\n")


def _get_log_path(context: dict[str, Any] | None) -> Path | None:
    if not context:
        return None

    explicit = context.get("request_log_path")
    if explicit:
        return Path(str(explicit))

    request_id = context.get("request_id")
    if not request_id:
        return None

    return Path(settings.data_dir) / "requests" / str(request_id) / "request_log.log"


def _serialize(value: Any) -> str:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return json.dumps(value)
    return json.dumps(value, sort_keys=True, default=str)
