"""Linux SSH and raw authentication log parser."""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

from app.normalizer.canonical import normalize_record
from app.parsers.base import ParseResult
from app.schemas.models import ParseErrorItem


# Example:
# Nov 25 14:02:11 prod-bastion-01 sshd[4102]: Failed password for invalid user admin_01 from 185.220.101.4 port 51234 ssh2
# 2026-11-25T14:04:03Z prod-bastion-01 sshd[4190]: Accepted password for admin_01 from 185.220.101.4 port 51900 ssh2 geo="Frankfurt, DE" session=sess-4190
_SSH_RE = re.compile(
    r"^(?P<ts>(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})|(?:\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?))\s+"
    r"(?P<host>\S+)\s+sshd(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<outcome>Failed|Accepted)\s+(?P<method>\S+)\s+for\s+(?:invalid user\s+)?(?P<user>\S+)\s+"
    r"from\s+(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
    r"(?:\s+port\s+\d+)?(?:\s+\S+)?"
    r"(?P<extra>.*)$"
)

_AUTH_KV_RE = re.compile(
    r"^(?P<ts>(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})|(?:\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?))\s+"
    r"(?P<host>\S+)\s+(?:auth|pam_unix|login|sshd)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)

_KV_PAIR_RE = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')


def _extract_kv(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for m in _KV_PAIR_RE.finditer(text or ""):
        key = m.group(1)
        val = m.group(2) if m.group(2) is not None else m.group(3)
        out[key] = val
    return out


def parse_ssh_auth_line(line: str) -> Optional[Dict[str, Any]]:
    m = _SSH_RE.match(line.strip())
    if m:
        gd = m.groupdict()
        extra = _extract_kv(gd.get("extra") or "")
        outcome = gd["outcome"].lower()
        status = "success" if outcome == "accepted" else "failure"
        action = "ssh_login_success" if status == "success" else "ssh_login_failed"
        pid = gd.get("pid") or ""
        return {
            "timestamp": gd["ts"],
            "source_type": "auth",
            "user": gd["user"],
            "src_ip": gd["src_ip"],
            "dest_ip": extra.get("dest_ip", ""),
            "geo": extra.get("geo", ""),
            "hostname": gd["host"],
            "session_id": extra.get("session") or extra.get("session_id") or (f"ssh-{pid}" if pid else ""),
            "action": action,
            "resource": f"ssh:{gd['method']}",
            "status": status,
            "bytes_out": 0,
            "pid": pid or None,
        }

    m2 = _AUTH_KV_RE.match(line.strip())
    if m2:
        gd = m2.groupdict()
        msg = gd["msg"]
        kv = _extract_kv(msg)
        if not kv and "session opened" not in msg.lower() and "authentication failure" not in msg.lower():
            return None
        user = kv.get("user") or kv.get("ruser") or ""
        if not user:
            um = re.search(r"for user (\S+)", msg)
            if um:
                user = um.group(1)
        status = kv.get("status", "unknown")
        if "failure" in msg.lower() or "failed" in msg.lower() or "invalid" in msg.lower():
            status = "failure"
        elif "opened" in msg.lower() or "accepted" in msg.lower() or "success" in msg.lower():
            status = "success"
        return {
            "timestamp": gd["ts"],
            "source_type": "auth",
            "user": user or "unknown",
            "src_ip": kv.get("src_ip") or kv.get("rhost") or "",
            "dest_ip": kv.get("dest_ip", ""),
            "geo": kv.get("geo", ""),
            "hostname": gd["host"],
            "session_id": kv.get("session") or kv.get("session_id") or "",
            "action": kv.get("action") or ("auth_failure" if status == "failure" else "auth_session"),
            "resource": kv.get("resource") or "pam_auth",
            "status": status,
            "bytes_out": int(kv.get("bytes_out", 0) or 0),
            "pid": gd.get("pid"),
        }
    return None


def parse_ssh_auth_logs(
    content: str,
    batch_id: Optional[str] = None,
    is_synthetic: bool = False,
) -> ParseResult:
    lines = [ln for ln in content.splitlines() if ln.strip()]
    events = []
    errors = []

    for idx, line in enumerate(lines, start=1):
        parsed = parse_ssh_auth_line(line)
        if not parsed:
            errors.append(
                ParseErrorItem(
                    line_number=idx,
                    raw_line=line[:300],
                    reason="Line did not match SSH/auth log pattern",
                )
            )
            continue
        ev = normalize_record(parsed, raw_log=line, batch_id=batch_id, is_synthetic=is_synthetic)
        if ev is None:
            errors.append(
                ParseErrorItem(
                    line_number=idx,
                    raw_line=line[:300],
                    reason="Invalid timestamp in SSH/auth log line",
                )
            )
        else:
            events.append(ev)

    return ParseResult(
        format_detected="ssh_auth",
        total_lines=len(lines),
        events=events,
        errors=errors,
    )
