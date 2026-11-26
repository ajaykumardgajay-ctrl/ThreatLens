"""JSON and NDJSON log parser."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from app.normalizer.canonical import normalize_record
from app.parsers.base import ParseResult
from app.schemas.models import ParseErrorItem


def parse_json_logs(
    content: str,
    batch_id: Optional[str] = None,
    is_synthetic: bool = False,
) -> ParseResult:
    stripped = content.strip()
    if not stripped:
        return ParseResult(format_detected="json", total_lines=0)

    events = []
    errors: List[ParseErrorItem] = []

    # Try full JSON payload first (list or {"events": [...]})
    if stripped.startswith("[") or stripped.startswith("{"):
        try:
            loaded = json.loads(stripped)
            items: List[Any]
            if isinstance(loaded, list):
                items = loaded
            elif isinstance(loaded, dict) and isinstance(loaded.get("events"), list):
                items = loaded["events"]
            elif isinstance(loaded, dict):
                items = [loaded]
            else:
                items = []

            for idx, item in enumerate(items, start=1):
                raw_line = json.dumps(item, separators=(",", ":"))
                if not isinstance(item, dict):
                    errors.append(
                        ParseErrorItem(
                            line_number=idx,
                            raw_line=raw_line[:300],
                            reason="JSON entry is not an object",
                        )
                    )
                    continue
                ev = normalize_record(
                    item,
                    raw_log=str(item.get("raw_log") or raw_line),
                    batch_id=batch_id,
                    is_synthetic=is_synthetic,
                )
                if ev is None:
                    errors.append(
                        ParseErrorItem(
                            line_number=idx,
                            raw_line=raw_line[:300],
                            reason="Missing or invalid timestamp in JSON object",
                        )
                    )
                else:
                    events.append(ev)

            return ParseResult(
                format_detected="json",
                total_lines=len(items),
                events=events,
                errors=errors,
            )
        except json.JSONDecodeError:
            pass  # Fall through to NDJSON line-by-line parsing

    lines = [ln for ln in content.splitlines() if ln.strip()]
    for idx, line in enumerate(lines, start=1):
        try:
            item: Dict[str, Any] = json.loads(line)
            if not isinstance(item, dict):
                raise ValueError("Line is not a JSON object")
            ev = normalize_record(
                item,
                raw_log=str(item.get("raw_log") or line),
                batch_id=batch_id,
                is_synthetic=is_synthetic,
            )
            if ev is None:
                errors.append(
                    ParseErrorItem(
                        line_number=idx,
                        raw_line=line[:300],
                        reason="Missing or invalid timestamp in NDJSON entry",
                    )
                )
            else:
                events.append(ev)
        except Exception as exc:
            errors.append(
                ParseErrorItem(
                    line_number=idx,
                    raw_line=line[:300],
                    reason=f"Malformed JSON line: {exc}",
                )
            )

    return ParseResult(
        format_detected="json",
        total_lines=len(lines),
        events=events,
        errors=errors,
    )
