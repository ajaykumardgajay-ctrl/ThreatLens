"""Canonical event normalizer for heterogeneous security logs."""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.schemas.models import CanonicalEvent, SourceType, StatusType


_SYSLOG_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

_SYSLOG_TS_RE = re.compile(
    r"^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})$"
)
_APACHE_TS_RE = re.compile(
    r"^(\d{2})/(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/(\d{4}):(\d{2}:\d{2}:\d{2})(?:\s*([+-]\d{4}))?$"
)


def parse_timestamp(value: Any, default_year: int = 2026) -> Optional[str]:
    """Normalize diverse timestamp formats into UTC ISO-8601 strings."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        try:
            dt = datetime.fromtimestamp(float(value), tz=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except (OSError, OverflowError, ValueError):
            return None

    text = str(value).strip().strip("[]")
    if not text:
        return None

    # Numeric epoch string
    if re.fullmatch(r"\d{10}(?:\.\d+)?", text):
        try:
            dt = datetime.fromtimestamp(float(text), tz=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except (OSError, OverflowError, ValueError):
            return None

    # ISO-8601 variants (including Python/Log4j comma milliseconds like 2026-11-25 14:02:11,452)
    iso_candidate = re.sub(r",(\d{3,6})", r".\1", text).replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(iso_candidate)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        pass

    # Apache / Nginx format: 25/Nov/2026:14:02:11 +0000
    m_apache = _APACHE_TS_RE.match(text)
    if m_apache:
        day, mon, year, hms, tz_str = m_apache.groups()
        month_num = _SYSLOG_MONTHS[mon]
        dt_str = f"{year}-{month_num:02d}-{int(day):02d} {hms}"
        if tz_str:
            dt = datetime.strptime(f"{dt_str} {tz_str}", "%Y-%m-%d %H:%M:%S %z")
            dt = dt.astimezone(timezone.utc)
        else:
            dt = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Syslog format: Nov 25 14:02:11
    m_sys = _SYSLOG_TS_RE.match(text)
    if m_sys:
        mon, day, hms = m_sys.groups()
        month_num = _SYSLOG_MONTHS[mon]
        dt = datetime.strptime(
            f"{default_year}-{month_num:02d}-{int(day):02d} {hms}",
            "%Y-%m-%d %H:%M:%S",
        ).replace(tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Common datetime formats (including Windows Event Viewer & Apache error logs)
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S,%f",
        "%d-%m-%Y %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
        "%d/%m/%Y %I:%M:%S %p",
        "%a %b %d %H:%M:%S %Y",
        "%a %b %d %H:%M:%S.%f %Y",
    ):
        try:
            dt = datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue

    return None


def _normalize_source_type(val: Any) -> SourceType:
    s = str(val or "system").strip().lower()
    if s in ("auth", "ssh", "pam", "authentication", "iam", "login"):
        return "auth"
    if s in ("web", "http", "nginx", "apache", "access"):
        return "web"
    if s in ("firewall", "fw", "iptables", "ufw", "asa", "paloalto", "pf"):
        return "firewall"
    if s in ("windows", "win", "evtx", "winevent", "sysmon"):
        return "windows"
    if s in ("proxy", "netflow", "network", "egress"):
        return "proxy"
    return "system"


def _normalize_status(val: Any) -> StatusType:
    if val is None:
        return "unknown"
    s = str(val).strip().lower()
    if s in ("success", "succeeded", "ok", "accepted", "allow", "allowed", "200", "201", "204"):
        return "success"
    if s in ("failure", "failed", "fail", "denied", "deny", "rejected", "error", "401", "403", "404", "500"):
        return "failure"
    if s.isdigit():
        code = int(s)
        if 200 <= code < 400:
            return "success"
        if code >= 400:
            return "failure"
    return "unknown"


def _safe_int(val: Any, default: int = 0) -> int:
    if val is None or val == "":
        return default
    try:
        return max(0, int(float(val)))
    except (TypeError, ValueError):
        return default


def normalize_record(
    record: Dict[str, Any],
    raw_log: str,
    batch_id: Optional[str] = None,
    is_synthetic: bool = False,
) -> Optional[CanonicalEvent]:
    """Convert a parsed dictionary into a validated CanonicalEvent."""
    lower_rec = {str(k).strip().lower(): v for k, v in record.items()}

    ts_raw = (
        lower_rec.get("timestamp")
        or lower_rec.get("time")
        or lower_rec.get("@timestamp")
        or lower_rec.get("ts")
        or lower_rec.get("datetime")
        or lower_rec.get("date and time")
        or lower_rec.get("created_at")
        or lower_rec.get("event_time")
        or (
            f"{lower_rec.get('date')} {lower_rec.get('time')}"
            if lower_rec.get("date") and lower_rec.get("time")
            else lower_rec.get("date")
        )
    )
    ts = parse_timestamp(ts_raw)
    if not ts:
        return None

    event_id = str(lower_rec.get("event_id") or lower_rec.get("id") or "").strip()
    if not event_id:
        event_id = f"evt_{uuid.uuid4().hex[:12]}"

    user = str(
        lower_rec.get("user")
        or lower_rec.get("username")
        or lower_rec.get("account")
        or lower_rec.get("actor")
        or "unknown"
    ).strip() or "unknown"

    src_ip = str(
        lower_rec.get("src_ip")
        or lower_rec.get("source_ip")
        or lower_rec.get("client_ip")
        or lower_rec.get("remote_addr")
        or lower_rec.get("ip")
        or ""
    ).strip()

    dest_ip = str(
        lower_rec.get("dest_ip")
        or lower_rec.get("destination_ip")
        or lower_rec.get("dst_ip")
        or ""
    ).strip()

    action = str(
        lower_rec.get("action")
        or lower_rec.get("event_action")
        or lower_rec.get("event")
        or lower_rec.get("method")
        or lower_rec.get("level")
        or "unknown"
    ).strip() or "unknown"

    resource = str(
        lower_rec.get("resource")
        or lower_rec.get("path")
        or lower_rec.get("url")
        or lower_rec.get("uri")
        or lower_rec.get("target")
        or lower_rec.get("message")
        or lower_rec.get("msg")
        or ""
    ).strip()

    return CanonicalEvent(
        event_id=event_id,
        timestamp=ts,
        source_type=_normalize_source_type(
            lower_rec.get("source_type") or lower_rec.get("source") or lower_rec.get("log_type")
        ),
        user=user,
        src_ip=src_ip,
        dest_ip=dest_ip,
        geo=str(lower_rec.get("geo") or lower_rec.get("location") or lower_rec.get("country") or "").strip(),
        hostname=str(lower_rec.get("hostname") or lower_rec.get("host") or lower_rec.get("server") or "unknown").strip() or "unknown",
        session_id=str(lower_rec.get("session_id") or lower_rec.get("session") or "").strip(),
        action=action,
        resource=resource,
        status=_normalize_status(lower_rec.get("status") or lower_rec.get("outcome") or lower_rec.get("status_code")),
        bytes_out=_safe_int(lower_rec.get("bytes_out") or lower_rec.get("bytes") or lower_rec.get("size") or 0),
        raw_log=raw_log,
        pid=str(lower_rec.get("pid")).strip() if lower_rec.get("pid") not in (None, "") else None,
        target_user=str(lower_rec.get("target_user")).strip()
        if lower_rec.get("target_user") not in (None, "")
        else None,
        ingestion_batch=batch_id,
        is_synthetic=bool(lower_rec.get("is_synthetic", is_synthetic)),
    )
