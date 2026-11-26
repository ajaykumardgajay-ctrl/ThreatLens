"""Operating-system, sudo, auditd, file-access, and egress transfer log parser."""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

from app.normalizer.canonical import normalize_record
from app.parsers.base import ParseResult
from app.schemas.models import ParseErrorItem


# Sudo log example:
# 2026-11-25T14:07:19Z prod-app-01 sudo[6102]: admin_01 : TTY=pts/0 ; PWD=/home/admin_01 ; USER=root ; COMMAND=/usr/sbin/usermod -aG wheel,backup_ops svc_backup session=sess-4190
_SUDO_RE = re.compile(
    r"^(?P<ts>(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})|(?:\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?))\s+"
    r"(?P<host>\S+)\s+sudo(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<user>\S+)\s*:\s*(?P<body>.*)$"
)

# Audit / system / netflow KV log example:
# 2026-11-25T14:09:44Z prod-app-01 auditd[7120]: type=FILE_ACCESS user=svc_backup action=file_read resource=/var/secure/payroll_export.csv status=success session=sess-svc-09 pid=7120
# 2026-11-25T14:11:30Z prod-app-01 netflow[8011]: user=svc_backup src_ip=10.20.1.15 dest_ip=185.220.101.4 action=outbound_transfer resource=tcp/443 bytes_out=438304768 status=success session=sess-svc-09
_SYS_KV_RE = re.compile(
    r"^(?P<ts>(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})|(?:\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?))\s+"
    r"(?P<host>\S+)\s+(?P<proc>[a-zA-Z0-9_.-]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<body>.+)$"
)

_KV_PAIR_RE = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')


def _extract_kv(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for m in _KV_PAIR_RE.finditer(text or ""):
        out[m.group(1)] = m.group(2) if m.group(2) is not None else m.group(3)
    return out


def _infer_target_user(cmd: str) -> Optional[str]:
    # usermod -aG wheel,backup_ops svc_backup -> svc_backup
    m = re.search(r"\b(?:usermod|useradd|passwd|gpasswd|su|chown)\b.*\s+([a-zA-Z0-9_.-]+)\s*$", cmd)
    if m:
        candidate = m.group(1)
        if not candidate.startswith("-") and "/" not in candidate:
            return candidate
    m2 = re.search(r"useradd\s+(?:-\S+\s+)*([a-zA-Z0-9_.-]+)", cmd)
    if m2:
        return m2.group(1)
    return None


def parse_os_audit_line(line: str) -> Optional[Dict[str, Any]]:
    stripped = line.strip()
    m_sudo = _SUDO_RE.match(stripped)
    if m_sudo:
        gd = m_sudo.groupdict()
        body = gd["body"]
        kv = _extract_kv(body)
        cmd_match = re.search(r"COMMAND=(.+?)(?:\s+(?:session|src_ip|target_user)=|$)", body)
        cmd = cmd_match.group(1).strip() if cmd_match else body
        target_user = kv.get("target_user") or _infer_target_user(cmd)
        is_priv_mod = any(
            tok in cmd.lower()
            for tok in ("usermod", "useradd", "groupadd", "gpasswd", "visudo", "chmod", "chown", "sudoers")
        )
        action = "privilege_grant" if (is_priv_mod and target_user) else "sudo_exec"
        return {
            "timestamp": gd["ts"],
            "source_type": "system",
            "user": gd["user"],
            "src_ip": kv.get("src_ip", ""),
            "dest_ip": kv.get("dest_ip", ""),
            "geo": kv.get("geo", ""),
            "hostname": gd["host"],
            "session_id": kv.get("session") or kv.get("session_id") or "",
            "action": action,
            "resource": cmd,
            "status": kv.get("status", "success"),
            "bytes_out": int(kv.get("bytes_out", 0) or 0),
            "pid": gd.get("pid"),
            "target_user": target_user,
        }

    m_sys = _SYS_KV_RE.match(stripped)
    if m_sys:
        gd = m_sys.groupdict()
        proc = gd["proc"].lower()
        # Avoid stealing sshd lines handled by ssh_auth_parser
        if proc == "sshd":
            return None
        kv = _extract_kv(gd["body"])
        if not kv:
            return None
        body_l = gd["body"].lower()
        src_ip = kv.get("src_ip", "")
        dest_ip = kv.get("dest_ip", "")
        if not src_ip:
            ip_m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", gd["body"])
            if ip_m and ip_m.group(1) != dest_ip:
                src_ip = ip_m.group(1)
        status = kv.get("status") or (
            "failure"
            if any(w in body_l for w in ("fail", "error", "denied", "reject", "invalid"))
            else "success"
        )
        source_type = "proxy" if proc in ("netflow", "proxy", "firewall", "egress") else "system"
        action = kv.get("action") or kv.get("type") or proc
        return {
            "timestamp": gd["ts"],
            "source_type": source_type,
            "user": kv.get("user") or kv.get("acct") or "unknown",
            "src_ip": src_ip,
            "dest_ip": dest_ip,
            "geo": kv.get("geo", ""),
            "hostname": gd["host"],
            "session_id": kv.get("session") or kv.get("session_id") or "",
            "action": action,
            "resource": kv.get("resource") or kv.get("exe") or kv.get("path") or kv.get("cmd") or "",
            "status": status,
            "bytes_out": int(kv.get("bytes_out") or kv.get("bytes") or 0),
            "pid": kv.get("pid") or gd.get("pid"),
            "target_user": kv.get("target_user"),
        }

    return None


def parse_os_audit_logs(
    content: str,
    batch_id: Optional[str] = None,
    is_synthetic: bool = False,
) -> ParseResult:
    lines = [ln for ln in content.splitlines() if ln.strip()]
    events = []
    errors = []

    for idx, line in enumerate(lines, start=1):
        parsed = parse_os_audit_line(line)
        if not parsed:
            errors.append(
                ParseErrorItem(
                    line_number=idx,
                    raw_line=line[:300],
                    reason="Line did not match OS/audit log format",
                )
            )
            continue
        ev = normalize_record(parsed, raw_log=line, batch_id=batch_id, is_synthetic=is_synthetic)
        if ev is None:
            errors.append(
                ParseErrorItem(
                    line_number=idx,
                    raw_line=line[:300],
                    reason="Invalid timestamp in OS/audit log",
                )
            )
        else:
            events.append(ev)

    return ParseResult(
        format_detected="os_audit",
        total_lines=len(lines),
        events=events,
        errors=errors,
    )
