"""Windows Security & Sysmon Event log parser."""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

from app.normalizer.canonical import normalize_record
from app.parsers.base import ParseResult
from app.schemas.models import ParseErrorItem


_TS_PREFIX = (
    r"(?P<ts>(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r"|(?:\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?))"
)

# Examples:
# 2026-11-25T14:02:11Z WIN-DC01 Security[4625]: Account=admin_01 IpAddress=185.220.101.4 LogonType=10 Status=0xC000006D
# 2026-11-25T14:07:19Z WIN-DC01 Microsoft-Windows-Security-Auditing[4732]: Member=svc_backup Group=Administrators SubjectUser=admin_01
_WIN_RE = re.compile(
    rf"^{_TS_PREFIX}\s+(?P<host>\S+)\s+"
    r"(?:Microsoft-Windows-Security-Auditing|Security|Sysmon|WinEventLog)(?:\[(?P<evid>\d+)\])?:\s+(?P<body>.+)$",
    re.IGNORECASE,
)

_KV_RE = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')

EVENT_ID_MAP: Dict[str, tuple[str, str]] = {
    "4624": ("win_logon_success", "success"),
    "4625": ("win_logon_failed", "failure"),
    "4648": ("win_explicit_creds", "success"),
    "4672": ("privilege_grant", "success"),
    "4720": ("win_user_created", "success"),
    "4728": ("privilege_grant", "success"),
    "4732": ("privilege_grant", "success"),
    "4688": ("win_process_create", "success"),
    "1102": ("win_audit_log_cleared", "success"),
    "1": ("sysmon_process_create", "success"),
    "3": ("sysmon_network_connect", "success"),
    "11": ("sysmon_file_create", "success"),
}


def parse_windows_event_line(line: str) -> Optional[Dict[str, Any]]:
    m = _WIN_RE.match(line.strip())
    if not m:
        return None
    gd = m.groupdict()
    body = gd["body"]
    kv: Dict[str, str] = {}
    for km in _KV_RE.finditer(body):
        kv[km.group(1).lower()] = km.group(2) if km.group(2) is not None else km.group(3)

    evid = gd.get("evid") or kv.get("eventid") or kv.get("event_id") or ""
    action, default_status = EVENT_ID_MAP.get(evid, (f"win_event_{evid or 'audit'}", "unknown"))

    user = (
        kv.get("subjectuser")
        or kv.get("account")
        or kv.get("user")
        or kv.get("username")
        or "unknown"
    )
    target_user = kv.get("targetuser") or kv.get("member") or None

    if user == "unknown":
        um = re.search(r"Account Name:\s*(\S+)", body, re.IGNORECASE)
        if um:
            user = um.group(1)

    src_ip = kv.get("ipaddress") or kv.get("src_ip") or kv.get("sourceip") or ""
    if not src_ip:
        im = re.search(r"Source Network Address:\s*(\d{1,3}(?:\.\d{1,3}){3})", body, re.IGNORECASE)
        if im:
            src_ip = im.group(1)

    resource = (
        kv.get("process")
        or kv.get("commandline")
        or kv.get("resource")
        or kv.get("group")
        or (f"EventID:{evid}" if evid else "")
    )
    if evid == "1102":
        resource = "Security Audit Log Cleared (EventID 1102)"

    status = kv.get("status", default_status)
    if status.startswith("0x") and evid == "4625":
        status = "failure"

    return {
        "timestamp": gd["ts"],
        "source_type": "windows" if evid not in ("4624", "4625") else "auth",
        "user": user,
        "src_ip": src_ip,
        "dest_ip": kv.get("dest_ip") or kv.get("destinationip") or "",
        "geo": kv.get("geo", ""),
        "hostname": gd["host"],
        "session_id": kv.get("logonid") or kv.get("session") or "",
        "action": action,
        "resource": resource,
        "status": status,
        "bytes_out": int(kv.get("bytes_out") or 0),
        "target_user": target_user,
    }


def parse_windows_event_logs(
    content: str,
    batch_id: Optional[str] = None,
    is_synthetic: bool = False,
) -> ParseResult:
    lines = [ln for ln in content.splitlines() if ln.strip()]
    events = []
    errors = []
    for idx, line in enumerate(lines, start=1):
        parsed = parse_windows_event_line(line)
        if not parsed:
            errors.append(
                ParseErrorItem(
                    line_number=idx,
                    raw_line=line[:300],
                    reason="Line did not match Windows Security/Sysmon event format",
                )
            )
            continue
        ev = normalize_record(parsed, raw_log=line, batch_id=batch_id, is_synthetic=is_synthetic)
        if ev is None:
            errors.append(
                ParseErrorItem(
                    line_number=idx,
                    raw_line=line[:300],
                    reason="Invalid timestamp in Windows event log",
                )
            )
        else:
            events.append(ev)

    return ParseResult(
        format_detected="windows_event",
        total_lines=len(lines),
        events=events,
        errors=errors,
    )
