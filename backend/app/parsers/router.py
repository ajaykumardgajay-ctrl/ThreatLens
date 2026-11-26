"""Format detection and parser routing."""

from __future__ import annotations

from typing import Optional

from app.parsers.base import ParseResult
from app.parsers.csv_parser import parse_csv_logs
from app.parsers.firewall_parser import parse_firewall_logs
from app.parsers.json_parser import parse_json_logs
from app.parsers.os_audit_parser import parse_os_audit_logs
from app.parsers.ssh_auth_parser import parse_ssh_auth_logs
from app.parsers.txt_parser import parse_txt_logs
from app.parsers.web_access_parser import parse_web_access_logs
from app.parsers.windows_event_parser import parse_windows_event_logs


def detect_log_format(content: str, filename: Optional[str] = None) -> str:
    """Heuristically detect log format from filename and content."""
    fname = (filename or "").lower()
    if fname.endswith(".csv"):
        return "csv"
    if fname.endswith(".json") or fname.endswith(".jsonl") or fname.endswith(".ndjson"):
        return "json"

    stripped = content.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        return "json"

    first_lines = [ln.strip() for ln in content.splitlines() if ln.strip()][:5]
    if not first_lines:
        return "txt"

    first = first_lines[0]
    if "," in first and any(
        col in first.lower()
        for col in ("timestamp", "event_id", "src_ip", "user", "time", "date", "ip")
    ):
        return "csv"

    if all("sshd" in ln for ln in first_lines):
        return "ssh_auth"
    if all(
        any(tok in ln for tok in ("Security[", "Sysmon[", "WinEventLog[", "Microsoft-Windows-Security-Auditing"))
        for ln in first_lines
    ):
        return "windows_event"
    if all(
        any(tok in ln for tok in ("UFW ", "SRC=", "%ASA-", "iptables", "firewall"))
        for ln in first_lines
    ):
        return "firewall"
    if all('"GET ' in ln or '"POST ' in ln or '"PUT ' in ln or '"DELETE ' in ln for ln in first_lines):
        return "web_access"
    if all("sudo" in ln or "auditd" in ln or "netflow" in ln for ln in first_lines):
        return "os_audit"

    return "txt"


def parse_logs(
    content: str,
    log_format: str = "auto",
    filename: Optional[str] = None,
    batch_id: Optional[str] = None,
    is_synthetic: bool = False,
) -> ParseResult:
    fmt = log_format.lower().strip() if log_format else "auto"
    if fmt == "auto":
        fmt = detect_log_format(content, filename=filename)

    if fmt == "csv":
        return parse_csv_logs(content, batch_id=batch_id, is_synthetic=is_synthetic)
    if fmt in ("json", "jsonl", "ndjson"):
        return parse_json_logs(content, batch_id=batch_id, is_synthetic=is_synthetic)
    if fmt in ("ssh", "ssh_auth", "auth"):
        return parse_ssh_auth_logs(content, batch_id=batch_id, is_synthetic=is_synthetic)
    if fmt in ("firewall", "fw", "iptables", "ufw", "asa"):
        return parse_firewall_logs(content, batch_id=batch_id, is_synthetic=is_synthetic)
    if fmt in ("windows", "windows_event", "evtx", "sysmon"):
        return parse_windows_event_logs(content, batch_id=batch_id, is_synthetic=is_synthetic)
    if fmt in ("web", "web_access", "apache", "nginx"):
        return parse_web_access_logs(content, batch_id=batch_id, is_synthetic=is_synthetic)
    if fmt in ("os", "os_audit", "audit", "system"):
        return parse_os_audit_logs(content, batch_id=batch_id, is_synthetic=is_synthetic)

    return parse_txt_logs(content, batch_id=batch_id, is_synthetic=is_synthetic)
