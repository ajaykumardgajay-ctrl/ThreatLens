"""Web-server access log parser (Common / Combined Log Format & proxy variants)."""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

from app.normalizer.canonical import normalize_record
from app.parsers.base import ParseResult
from app.schemas.models import ParseErrorItem


# Example:
# 10.20.4.18 - j.patel [25/Nov/2026:10:15:22 +0000] "GET /api/v1/reports HTTP/1.1" 200 1842 "-" "Mozilla/5.0" host=web-gw-01 session=web-102
_COMBINED_RE = re.compile(
    r'^(?P<src_ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+HTTP/[\d.]+)?"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\d+|-)'
    r'(?:\s+"[^"]*"\s+"[^"]*")?(?P<extra>.*)$'
)

_KV_PAIR_RE = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')


def parse_web_access_line(line: str) -> Optional[Dict[str, Any]]:
    m = _COMBINED_RE.match(line.strip())
    if not m:
        return None
    gd = m.groupdict()
    extra = {}
    for km in _KV_PAIR_RE.finditer(gd.get("extra") or ""):
        extra[km.group(1)] = km.group(2) if km.group(2) is not None else km.group(3)

    user = gd["user"] if gd["user"] != "-" else extra.get("user", "anonymous")
    bytes_raw = gd["bytes"]
    bytes_val = int(bytes_raw) if bytes_raw.isdigit() else 0
    status_code = int(gd["status"])

    return {
        "timestamp": gd["ts"],
        "source_type": "web",
        "user": user,
        "src_ip": gd["src_ip"],
        "dest_ip": extra.get("dest_ip", ""),
        "geo": extra.get("geo", ""),
        "hostname": extra.get("host") or extra.get("hostname") or "web-gateway",
        "session_id": extra.get("session") or extra.get("session_id") or "",
        "action": f"http_{gd['method'].lower()}",
        "resource": gd["path"],
        "status": "success" if 200 <= status_code < 400 else "failure",
        "bytes_out": int(extra.get("bytes_out") or bytes_val),
    }


def parse_web_access_logs(
    content: str,
    batch_id: Optional[str] = None,
    is_synthetic: bool = False,
) -> ParseResult:
    lines = [ln for ln in content.splitlines() if ln.strip()]
    events = []
    errors = []

    for idx, line in enumerate(lines, start=1):
        parsed = parse_web_access_line(line)
        if not parsed:
            errors.append(
                ParseErrorItem(
                    line_number=idx,
                    raw_line=line[:300],
                    reason="Line did not match web access log format",
                )
            )
            continue
        ev = normalize_record(parsed, raw_log=line, batch_id=batch_id, is_synthetic=is_synthetic)
        if ev is None:
            errors.append(
                ParseErrorItem(
                    line_number=idx,
                    raw_line=line[:300],
                    reason="Invalid timestamp in web access log",
                )
            )
        else:
            events.append(ev)

    return ParseResult(
        format_detected="web_access",
        total_lines=len(lines),
        events=events,
        errors=errors,
    )
