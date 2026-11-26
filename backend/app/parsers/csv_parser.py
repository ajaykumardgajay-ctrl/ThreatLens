"""CSV log parser using Pandas."""

from __future__ import annotations

import io
from typing import Optional

import pandas as pd

from app.normalizer.canonical import normalize_record
from app.parsers.base import ParseResult
from app.schemas.models import ParseErrorItem


def parse_csv_logs(
    content: str,
    batch_id: Optional[str] = None,
    is_synthetic: bool = False,
) -> ParseResult:
    raw_lines = [ln for ln in content.splitlines() if ln.strip()]
    if not raw_lines:
        return ParseResult(format_detected="csv", total_lines=0)

    try:
        df = pd.read_csv(io.StringIO(content), dtype=str, keep_default_na=False)
    except Exception as exc:
        return ParseResult(
            format_detected="csv",
            total_lines=len(raw_lines),
            errors=[
                ParseErrorItem(
                    line_number=1,
                    raw_line=raw_lines[0][:200],
                    reason=f"CSV parse failure: {exc}",
                )
            ],
        )

    events = []
    errors = []
    data_lines = raw_lines[1:]  # excluding header

    for idx, row in df.iterrows():
        line_num = int(idx) + 2
        raw_line = (
            data_lines[int(idx)]
            if int(idx) < len(data_lines)
            else ",".join(str(v) for v in row.values)
        )
        rec = row.to_dict()
        event = normalize_record(
            rec,
            raw_log=str(rec.get("raw_log") or raw_line),
            batch_id=batch_id,
            is_synthetic=is_synthetic,
        )
        if event is None:
            errors.append(
                ParseErrorItem(
                    line_number=line_num,
                    raw_line=raw_line[:300],
                    reason="Missing or invalid timestamp field in CSV row",
                )
            )
        else:
            events.append(event)

    return ParseResult(
        format_detected="csv",
        total_lines=max(0, len(raw_lines) - 1),
        events=events,
        errors=errors,
    )
