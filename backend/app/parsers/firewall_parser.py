"""Firewall log parser (iptables/UFW, Cisco ASA, Palo Alto, and KV firewall logs)."""

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

# Example:
# 2026-11-25T14:05:12Z fw-edge-01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=185.220.101.4 DST=10.20.1.5 PROTO=TCP SPT=51220 DPT=22
_IPTABLES_RE = re.compile(
    rf"^{_TS_PREFIX}\s+(?P<host>\S+)\s+(?:kernel|iptables|ufw|firewall|pf)(?:\[\d+\])?:\s*(?P<body>.*)$",
    re.IGNORECASE,
)

# Example:
# 2026-11-25T14:05:12Z fw-edge-01 %ASA-4-106023: Deny tcp src outside:185.220.101.4/51220 dst inside:10.20.1.5/22
_ASA_RE = re.compile(
    rf"^{_TS_PREFIX}\s+(?P<host>\S+)\s+%ASA-\d+-\d+:\s*(?P<action>Deny|Built|Teardown|Permit)\s+"
    r"(?P<proto>\S+)\s+src\s+\S+?:(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})(?:/(?P<spt>\d+))?\s+"
    r"dst\s+\S+?:(?P<dest_ip>\d{1,3}(?:\.\d{1,3}){3})(?:/(?P<dpt>\d+))?",
    re.IGNORECASE,
)

_KV_RE = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')


def parse_firewall_line(line: str) -> Optional[Dict[str, Any]]:
    stripped = line.strip()

    m_asa = _ASA_RE.match(stripped)
    if m_asa:
        gd = m_asa.groupdict()
        act = gd["action"].lower()
        is_block = act in ("deny", "drop", "block")
        dpt = gd.get("dpt") or ""
        return {
            "timestamp": gd["ts"],
            "source_type": "firewall",
            "user": "network",
            "src_ip": gd["src_ip"],
            "dest_ip": gd["dest_ip"],
            "hostname": gd["host"],
            "action": f"fw_{act}",
            "resource": f"{gd['proto'].lower()}/{dpt}" if dpt else gd["proto"].lower(),
            "status": "failure" if is_block else "success",
            "bytes_out": 0,
        }

    m_ipt = _IPTABLES_RE.match(stripped)
    if m_ipt:
        gd = m_ipt.groupdict()
        body = gd["body"]
        kv: Dict[str, str] = {}
        for km in _KV_RE.finditer(body):
            kv[km.group(1).upper()] = km.group(2) if km.group(2) is not None else km.group(3)

        src_ip = kv.get("SRC") or kv.get("SRC_IP") or ""
        dest_ip = kv.get("DST") or kv.get("DEST_IP") or ""
        if not src_ip and not dest_ip:
            return None

        proto = (kv.get("PROTO") or "tcp").lower()
        dpt = kv.get("DPT") or kv.get("DST_PORT") or ""
        raw_act = (kv.get("ACTION") or "").lower()
        if not raw_act:
            if "BLOCK" in body.upper() or "DROP" in body.upper() or "DENY" in body.upper():
                raw_act = "block"
            else:
                raw_act = "allow"

        is_block = raw_act in ("block", "drop", "deny", "reject")
        return {
            "timestamp": gd["ts"],
            "source_type": "firewall",
            "user": kv.get("USER", "network"),
            "src_ip": src_ip,
            "dest_ip": dest_ip,
            "hostname": gd["host"],
            "action": f"fw_{raw_act}",
            "resource": f"{proto}/{dpt}" if dpt else proto,
            "status": "failure" if is_block else "success",
            "bytes_out": int(kv.get("BYTES") or kv.get("BYTES_OUT") or 0),
        }

    return None


def parse_firewall_logs(
    content: str,
    batch_id: Optional[str] = None,
    is_synthetic: bool = False,
) -> ParseResult:
    lines = [ln for ln in content.splitlines() if ln.strip()]
    events = []
    errors = []
    for idx, line in enumerate(lines, start=1):
        parsed = parse_firewall_line(line)
        if not parsed:
            errors.append(
                ParseErrorItem(
                    line_number=idx,
                    raw_line=line[:300],
                    reason="Line did not match firewall log pattern (iptables/UFW/ASA)",
                )
            )
            continue
        ev = normalize_record(parsed, raw_log=line, batch_id=batch_id, is_synthetic=is_synthetic)
        if ev is None:
            errors.append(
                ParseErrorItem(
                    line_number=idx,
                    raw_line=line[:300],
                    reason="Invalid timestamp in firewall log line",
                )
            )
        else:
            events.append(ev)

    return ParseResult(
        format_detected="firewall",
        total_lines=len(lines),
        events=events,
        errors=errors,
    )
