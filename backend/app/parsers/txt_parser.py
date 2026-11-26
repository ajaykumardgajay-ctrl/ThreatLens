"""Mixed/raw TXT and generic syslog log parser."""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

from app.normalizer.canonical import normalize_record
from app.parsers.base import ParseResult
from app.parsers.firewall_parser import parse_firewall_line
from app.parsers.os_audit_parser import parse_os_audit_line
from app.parsers.ssh_auth_parser import parse_ssh_auth_line
from app.parsers.web_access_parser import parse_web_access_line
from app.parsers.windows_event_parser import parse_windows_event_line
from app.schemas.models import ParseErrorItem


_KV_PAIR_RE = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')

_TS_TOKEN = (
    r"(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
    r"|\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
    r"|\d{2}/\d{2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}(?:\s*[AP]M)?)"
)

_PRI_PREFIX_RE = re.compile(r"^<\d+>(?:\d+\s+)?")

_GENERIC_SYSLOG_RE = re.compile(
    rf"^(?P<ts>{_TS_TOKEN})\s+"
    r"(?P<host>[a-zA-Z0-9_.-]+)\s+(?P<proc>[a-zA-Z0-9_.-]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.+)$"
)

_GENERIC_TS_RE = re.compile(
    rf"^\[?(?P<ts>{_TS_TOKEN})\]?\s+(?P<msg>.+)$"
)

_IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_USER_RE = re.compile(r"(?:user(?:name)?=|for user |for )([a-zA-Z0-9_.-]+)", re.IGNORECASE)


def _parse_kv_fallback(line: str) -> Optional[Dict[str, str]]:
    kv: Dict[str, str] = {}
    for m in _KV_PAIR_RE.finditer(line):
        kv[m.group(1)] = m.group(2) if m.group(2) is not None else m.group(3)
    if any(k in kv for k in ("timestamp", "ts", "time", "datetime")):
        return kv
    return None


def _parse_generic_syslog_fallback(line: str) -> Optional[Dict[str, Any]]:
    stripped = line.strip()
    m = _GENERIC_SYSLOG_RE.match(stripped)
    if m:
        gd = m.groupdict()
        msg = gd["msg"]
        kv = _parse_kv_fallback(msg) or {}
        ip_m = _IPV4_RE.search(msg)
        user_m = _USER_RE.search(msg)
        msg_l = msg.lower()
        status = kv.get("status") or (
            "failure"
            if any(w in msg_l for w in ("fail", "error", "denied", "reject", "invalid", "block"))
            else "success"
            if any(w in msg_l for w in ("accept", "allow", "success", "opened", "ok"))
            else "unknown"
        )
        proc = gd["proc"].lower()
        source_type = (
            "auth"
            if any(k in proc or k in msg_l for k in ("auth", "login", "pam", "sshd"))
            else "firewall"
            if any(k in proc for k in ("ufw", "iptables", "firewall", "asa"))
            else "system"
        )
        return {
            "timestamp": gd["ts"],
            "source_type": kv.get("source_type", source_type),
            "user": kv.get("user") or (user_m.group(1) if user_m else "unknown"),
            "src_ip": kv.get("src_ip") or (ip_m.group(1) if ip_m else ""),
            "dest_ip": kv.get("dest_ip", ""),
            "hostname": gd["host"],
            "action": kv.get("action") or proc,
            "resource": kv.get("resource") or msg[:160],
            "status": status,
            "bytes_out": kv.get("bytes_out", 0),
            "pid": gd.get("pid"),
        }

    m2 = _GENERIC_TS_RE.match(stripped)
    if m2:
        gd = m2.groupdict()
        msg = gd["msg"]
        kv = _parse_kv_fallback(msg) or {}
        ip_m = _IPV4_RE.search(msg)
        user_m = _USER_RE.search(msg)
        msg_l = msg.lower()
        status = kv.get("status") or (
            "failure"
            if any(w in msg_l for w in ("fail", "error", "denied", "reject", "invalid", "block"))
            else "success"
            if any(w in msg_l for w in ("accept", "allow", "success", "ok"))
            else "unknown"
        )
        return {
            "timestamp": gd["ts"],
            "source_type": kv.get("source_type", "system"),
            "user": kv.get("user") or (user_m.group(1) if user_m else "unknown"),
            "src_ip": kv.get("src_ip") or (ip_m.group(1) if ip_m else ""),
            "dest_ip": kv.get("dest_ip", ""),
            "hostname": kv.get("hostname") or kv.get("host") or "unknown",
            "action": kv.get("action") or "log_event",
            "resource": kv.get("resource") or msg[:160],
            "status": status,
            "bytes_out": kv.get("bytes_out", 0),
        }

    return None


def parse_txt_logs(
    content: str,
    batch_id: Optional[str] = None,
    is_synthetic: bool = False,
) -> ParseResult:
    lines = [ln for ln in content.splitlines() if ln.strip()]
    events = []
    errors = []

    for idx, raw_line in enumerate(lines, start=1):
        clean_line = _PRI_PREFIX_RE.sub("", raw_line.strip())
        parsed = (
            parse_ssh_auth_line(clean_line)
            or parse_windows_event_line(clean_line)
            or parse_firewall_line(clean_line)
            or parse_web_access_line(clean_line)
            or parse_os_audit_line(clean_line)
            or _parse_kv_fallback(clean_line)
            or _parse_generic_syslog_fallback(clean_line)
        )
        if not parsed:
            errors.append(
                ParseErrorItem(
                    line_number=idx,
                    raw_line=raw_line[:300],
                    reason="Unrecognized log line format (no valid timestamp or known pattern)",
                )
            )
            continue
        ev = normalize_record(parsed, raw_log=raw_line, batch_id=batch_id, is_synthetic=is_synthetic)
        if ev is None:
            errors.append(
                ParseErrorItem(
                    line_number=idx,
                    raw_line=raw_line[:300],
                    reason="Missing or invalid timestamp",
                )
            )
        else:
            events.append(ev)

    return ParseResult(
        format_detected="txt_mixed",
        total_lines=len(lines),
        events=events,
        errors=errors,
    )
