"""Log-first analyzer summary, IOC extraction, sample presets, and report exporter."""

from __future__ import annotations

import csv
import io
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Union
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.schemas.models import CanonicalEvent, Finding, IncidentDetail


SAMPLE_PRESETS: Dict[str, Dict[str, str]] = {
    "ssh_intrusion": {
        "id": "ssh_intrusion",
        "name": "SSH Brute Force + Privilege Pivot",
        "format": "txt",
        "description": "Raw OpenSSH + sudo + auditd + netflow logs showing brute force, login, usermod pivot, and exfiltration.",
        "raw_text": "\n".join(
            [
                '2026-11-25T13:10:00Z prod-bastion-01 sshd[3901]: Accepted publickey for admin_01 from 49.207.212.14 port 50112 ssh2 geo="Bengaluru, IN" session=sess-blr-01',
                '2026-11-25T14:01:02Z prod-bastion-01 sshd[4101]: Failed password for admin_01 from 185.220.101.4 port 51201 ssh2 geo="Frankfurt, DE"',
                '2026-11-25T14:01:14Z prod-bastion-01 sshd[4102]: Failed password for admin_01 from 185.220.101.4 port 51202 ssh2 geo="Frankfurt, DE"',
                '2026-11-25T14:01:28Z prod-bastion-01 sshd[4103]: Failed password for admin_01 from 185.220.101.4 port 51203 ssh2 geo="Frankfurt, DE"',
                '2026-11-25T14:01:41Z prod-bastion-01 sshd[4104]: Failed password for admin_01 from 185.220.101.4 port 51204 ssh2 geo="Frankfurt, DE"',
                '2026-11-25T14:01:55Z prod-bastion-01 sshd[4105]: Failed password for admin_01 from 185.220.101.4 port 51205 ssh2 geo="Frankfurt, DE"',
                '2026-11-25T14:02:11Z prod-bastion-01 sshd[4106]: Failed password for admin_01 from 185.220.101.4 port 51206 ssh2 geo="Frankfurt, DE"',
                '2026-11-25T14:04:03Z prod-bastion-01 sshd[4190]: Accepted password for admin_01 from 185.220.101.4 port 51900 ssh2 geo="Frankfurt, DE" session=sess-4190',
                '2026-11-25T14:07:19Z prod-app-01 sudo[6102]: admin_01 : TTY=pts/0 ; PWD=/home/admin_01 ; USER=root ; COMMAND=/usr/sbin/usermod -aG wheel,backup_ops svc_backup session=sess-4190 src_ip=185.220.101.4 target_user=svc_backup',
                '2026-11-25T14:09:44Z prod-app-01 auditd[7120]: type=FILE_ACCESS user=svc_backup action=file_read resource=/var/secure/payroll_export.csv status=success session=sess-svc-09 pid=7120',
                '2026-11-25T14:11:30Z prod-app-01 netflow[8011]: user=svc_backup src_ip=10.20.1.15 dest_ip=185.220.101.4 action=outbound_transfer resource=tcp/443 bytes_out=438304768 status=success session=sess-svc-09',
            ]
        ),
    },
    "web_sqli": {
        "id": "web_sqli",
        "name": "Nginx / Apache SQLi & Traversal",
        "format": "web_access",
        "description": "Web access logs mixing normal traffic with SQL injection, XSS, and .env/passwd traversal probes.",
        "raw_text": "\n".join(
            [
                '10.20.4.18 - j.patel [25/Nov/2026:12:00:10 +0000] "GET /dashboard HTTP/1.1" 200 4120 "-" "Mozilla/5.0" host=web-gw-01',
                '10.20.4.22 - m.chen [25/Nov/2026:12:01:02 +0000] "GET /api/v1/reports HTTP/1.1" 200 1840 "-" "Mozilla/5.0" host=web-gw-01',
                '91.214.124.88 - - [25/Nov/2026:12:02:11 +0000] "GET /api/v1/users?id=1%20UNION%20SELECT%20password%20FROM%20users-- HTTP/1.1" 500 512 "-" "sqlmap/1.7" host=web-gw-01',
                '91.214.124.88 - - [25/Nov/2026:12:02:19 +0000] "GET /../../etc/passwd HTTP/1.1" 403 280 "-" "curl/8.4" host=web-gw-01',
                '91.214.124.88 - - [25/Nov/2026:12:02:25 +0000] "GET /.env HTTP/1.1" 404 196 "-" "Nuclei" host=web-gw-01',
                '198.51.100.44 - - [25/Nov/2026:12:04:01 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 403 310 "-" "Mozilla/5.0" host=web-gw-01',
            ]
        ),
    },
    "firewall_scan": {
        "id": "firewall_scan",
        "name": "UFW / iptables Port Scan & ASA Deny",
        "format": "firewall",
        "description": "Edge firewall blocks showing multi-port reconnaissance from an external scanner.",
        "raw_text": "\n".join(
            [
                "2026-11-25T15:10:01Z fw-edge-01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=45.155.205.91 DST=10.20.1.5 PROTO=TCP SPT=49101 DPT=22",
                "2026-11-25T15:10:02Z fw-edge-01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=45.155.205.91 DST=10.20.1.5 PROTO=TCP SPT=49102 DPT=23",
                "2026-11-25T15:10:03Z fw-edge-01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=45.155.205.91 DST=10.20.1.5 PROTO=TCP SPT=49103 DPT=445",
                "2026-11-25T15:10:04Z fw-edge-01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=45.155.205.91 DST=10.20.1.5 PROTO=TCP SPT=49104 DPT=3389",
                "2026-11-25T15:10:05Z fw-edge-01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=45.155.205.91 DST=10.20.1.5 PROTO=TCP SPT=49105 DPT=5432",
                "2026-11-25T15:10:06Z fw-edge-01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=45.155.205.91 DST=10.20.1.5 PROTO=TCP SPT=49106 DPT=6379",
                "2026-11-25T15:10:08Z fw-edge-01 %ASA-4-106023: Deny tcp src outside:45.155.205.91/49107 dst inside:10.20.1.5/9200",
            ]
        ),
    },
    "windows_ad": {
        "id": "windows_ad",
        "name": "Windows AD Logon Failures + Audit Clear",
        "format": "windows_event",
        "description": "Windows Security Event IDs 4625 (failed logons), 4624 (logon), 4732 (group add), and 1102 (audit log cleared).",
        "raw_text": "\n".join(
            [
                "2026-11-25T16:00:01Z WIN-DC01 Security[4625]: Account=svc_sql IpAddress=194.26.135.12 LogonType=10 Status=0xC000006D",
                "2026-11-25T16:00:05Z WIN-DC01 Security[4625]: Account=svc_sql IpAddress=194.26.135.12 LogonType=10 Status=0xC000006D",
                "2026-11-25T16:00:09Z WIN-DC01 Security[4625]: Account=svc_sql IpAddress=194.26.135.12 LogonType=10 Status=0xC000006D",
                "2026-11-25T16:00:13Z WIN-DC01 Security[4625]: Account=svc_sql IpAddress=194.26.135.12 LogonType=10 Status=0xC000006D",
                "2026-11-25T16:00:18Z WIN-DC01 Security[4625]: Account=svc_sql IpAddress=194.26.135.12 LogonType=10 Status=0xC000006D",
                "2026-11-25T16:00:25Z WIN-DC01 Security[4624]: Account=svc_sql IpAddress=194.26.135.12 LogonType=10 session=win-901",
                "2026-11-25T16:01:10Z WIN-DC01 Security[4732]: SubjectUser=svc_sql Member=backup_adm Group=Administrators session=win-901",
                "2026-11-25T16:02:02Z WIN-DC01 Security[1102]: SubjectUser=backup_adm session=win-901",
            ]
        ),
    },
}


def build_analyzer_summary(
    events: List[CanonicalEvent],
    findings: List[Finding],
    incidents: List[IncidentDetail],
) -> Dict[str, Any]:
    """Compute log-first aggregations, IOC extractions, and top entity breakdowns."""
    ip_stats: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"ip": "", "total": 0, "failures": 0, "bytes_out": 0, "geos": set(), "users": set()}
    )
    user_stats: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"user": "", "total": 0, "failures": 0, "bytes_out": 0, "ips": set()}
    )
    host_counts: Counter[str] = Counter()
    action_counts: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    resource_counts: Counter[str] = Counter()

    flagged_ips = {f.src_ip for f in findings if f.src_ip}
    flagged_users = {f.affected_user for f in findings if f.affected_user}
    for inc in incidents:
        for ip in inc.source_ips:
            if not ip.startswith("10.") and not ip.startswith("192.168."):
                flagged_ips.add(ip)
        for u in inc.affected_accounts:
            flagged_users.add(u)

    for ev in events:
        source_counts[ev.source_type] += 1
        status_counts[ev.status] += 1
        action_counts[ev.action] += 1
        if ev.hostname and ev.hostname != "unknown":
            host_counts[ev.hostname] += 1
        if ev.resource:
            resource_counts[ev.resource] += 1

        if ev.src_ip:
            s = ip_stats[ev.src_ip]
            s["ip"] = ev.src_ip
            s["total"] += 1
            if ev.status == "failure":
                s["failures"] += 1
            s["bytes_out"] += ev.bytes_out
            if ev.geo:
                s["geos"].add(ev.geo)
            if ev.user and ev.user != "unknown":
                s["users"].add(ev.user)

        if ev.user and ev.user not in ("unknown", "network"):
            u = user_stats[ev.user]
            u["user"] = ev.user
            u["total"] += 1
            if ev.status == "failure":
                u["failures"] += 1
            u["bytes_out"] += ev.bytes_out
            if ev.src_ip:
                u["ips"].add(ev.src_ip)

    top_ips = sorted(
        [
            {
                "ip": v["ip"],
                "total": v["total"],
                "failures": v["failures"],
                "bytes_out": v["bytes_out"],
                "geos": sorted(v["geos"]),
                "users": sorted(v["users"])[:5],
                "is_flagged": v["ip"] in flagged_ips,
            }
            for v in ip_stats.values()
        ],
        key=lambda x: (x["is_flagged"], x["failures"], x["total"]),
        reverse=True,
    )[:15]

    top_users = sorted(
        [
            {
                "user": v["user"],
                "total": v["total"],
                "failures": v["failures"],
                "bytes_out": v["bytes_out"],
                "unique_ips": len(v["ips"]),
                "is_flagged": v["user"] in flagged_users,
            }
            for v in user_stats.values()
        ],
        key=lambda x: (x["is_flagged"], x["failures"], x["bytes_out"], x["total"]),
        reverse=True,
    )[:15]

    # Extracted IOCs directly backed by findings
    iocs: List[Dict[str, Any]] = []
    seen_ioc = set()
    for f in findings:
        if f.src_ip and ("ip", f.src_ip) not in seen_ioc:
            seen_ioc.add(("ip", f.src_ip))
            iocs.append(
                {
                    "type": "IP Address",
                    "value": f.src_ip,
                    "severity": f.severity,
                    "context": f.detector_name,
                    "finding_id": f.finding_id,
                }
            )
        if f.affected_user and f.affected_user not in ("unknown", "network") and ("user", f.affected_user) not in seen_ioc:
            seen_ioc.add(("user", f.affected_user))
            iocs.append(
                {
                    "type": "Account",
                    "value": f.affected_user,
                    "severity": f.severity,
                    "context": f.detector_name,
                    "finding_id": f.finding_id,
                }
            )

    for ev in events:
        if ev.dest_ip and ev.bytes_out >= 50 * 1024 * 1024 and ("ext", ev.dest_ip) not in seen_ioc:
            seen_ioc.add(("ext", ev.dest_ip))
            iocs.append(
                {
                    "type": "Exfil Destination",
                    "value": ev.dest_ip,
                    "severity": "critical",
                    "context": f"{ev.bytes_out / (1024 * 1024):.1f} MB outbound from {ev.user}",
                    "finding_id": "",
                }
            )
        if any(p in (ev.resource or "").lower() for p in ("/var/secure/", "/etc/shadow", "payroll", "/etc/passwd", ".env")) and ("res", ev.resource) not in seen_ioc:
            seen_ioc.add(("res", ev.resource))
            iocs.append(
                {
                    "type": "Sensitive Path",
                    "value": ev.resource,
                    "severity": "high",
                    "context": f"Accessed by {ev.user} ({ev.action})",
                    "finding_id": "",
                }
            )

    return {
        "total_events": len(events),
        "total_findings": len(findings),
        "total_incidents": len(incidents),
        "time_range": {
            "start": events[0].timestamp if events else None,
            "end": events[-1].timestamp if events else None,
        },
        "source_counts": dict(source_counts),
        "status_counts": dict(status_counts),
        "top_actions": [{"action": k, "count": v} for k, v in action_counts.most_common(10)],
        "top_hosts": [{"hostname": k, "count": v} for k, v in host_counts.most_common(10)],
        "top_resources": [{"resource": k, "count": v} for k, v in resource_counts.most_common(10)],
        "top_ips": top_ips,
        "top_users": top_users,
        "iocs": iocs,
    }


def _build_pdf_report(
    summary: Dict[str, Any],
    findings: List[Finding],
    incidents: List[IncidentDetail],
) -> bytes:
    """Render a clean, readable security investigation PDF report."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        leftMargin=0.6 * inch,
        rightMargin=0.6 * inch,
        topMargin=0.6 * inch,
        bottomMargin=0.6 * inch,
        title="ThreatLens Security Log Analysis Report",
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "TLTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "TLSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        textColor=colors.HexColor("#475569"),
        spaceAfter=12,
    )
    h2_style = ParagraphStyle(
        "TLH2",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#b45309"),
        spaceBefore=12,
        spaceAfter=6,
    )
    h3_style = ParagraphStyle(
        "TLH3",
        parent=styles["Heading3"],
        fontName="Helvetica-Bold",
        fontSize=10.5,
        leading=14,
        textColor=colors.HexColor("#991b1b"),
        spaceBefore=8,
        spaceAfter=4,
    )
    body_style = ParagraphStyle(
        "TLBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#1e293b"),
        spaceAfter=4,
    )
    cell_style = ParagraphStyle(
        "TLCell",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8,
        leading=10.5,
        textColor=colors.HexColor("#1e293b"),
    )
    cell_bold = ParagraphStyle(
        "TLCellBold",
        parent=cell_style,
        fontName="Helvetica-Bold",
        textColor=colors.white,
    )

    story: List[Any] = []
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    story.append(Paragraph("ThreatLens — Security Log Analysis &amp; Incident Report", title_style))
    story.append(Paragraph(f"Generated: {escape(generated_at)}", subtitle_style))

    # Executive Summary Table
    win_start = summary["time_range"]["start"] or "N/A"
    win_end = summary["time_range"]["end"] or "N/A"
    kpi_rows = [
        [
            Paragraph("Metric", cell_bold),
            Paragraph("Value", cell_bold),
        ],
        [Paragraph("Total Events Analyzed", cell_style), Paragraph(str(summary["total_events"]), cell_style)],
        [Paragraph("Time Window", cell_style), Paragraph(f"{escape(win_start)} to {escape(win_end)}", cell_style)],
        [Paragraph("Total Findings", cell_style), Paragraph(str(summary["total_findings"]), cell_style)],
        [Paragraph("Reconstructed Incidents", cell_style), Paragraph(str(summary["total_incidents"]), cell_style)],
        [Paragraph("Extracted IOCs", cell_style), Paragraph(str(len(summary["iocs"])), cell_style)],
    ]
    kpi_table = Table(kpi_rows, colWidths=[2.1 * inch, 5.1 * inch])
    kpi_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#18181b")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(kpi_table)
    story.append(Spacer(1, 8))

    # IOC Table
    story.append(Paragraph("Extracted Indicators of Compromise (IOCs)", h2_style))
    if summary["iocs"]:
        ioc_rows = [
            [
                Paragraph("Type", cell_bold),
                Paragraph("Value", cell_bold),
                Paragraph("Severity", cell_bold),
                Paragraph("Context", cell_bold),
            ]
        ]
        for ioc in summary["iocs"][:30]:
            ioc_rows.append(
                [
                    Paragraph(escape(str(ioc["type"])), cell_style),
                    Paragraph(f"<font name='Courier'>{escape(str(ioc['value']))}</font>", cell_style),
                    Paragraph(escape(str(ioc["severity"]).upper()), cell_style),
                    Paragraph(escape(str(ioc["context"])), cell_style),
                ]
            )
        ioc_table = Table(ioc_rows, colWidths=[1.25 * inch, 1.9 * inch, 0.85 * inch, 3.2 * inch])
        ioc_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#18181b")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        story.append(ioc_table)
    else:
        story.append(Paragraph("No high-confidence IOCs extracted from the current log set.", body_style))

    # Reconstructed Incidents
    story.append(Paragraph("Reconstructed Incidents &amp; Attack Timelines", h2_style))
    if not incidents:
        story.append(Paragraph("No correlated multi-stage incidents were reconstructed.", body_style))
    for inc in incidents:
        story.append(
            Paragraph(
                f"{escape(inc.incident_id)}: {escape(inc.title)} "
                f"[{escape(inc.severity.upper())} — Risk Score {inc.risk_score}/100]",
                h3_style,
            )
        )
        story.append(
            Paragraph(
                f"<b>Accounts:</b> {escape(', '.join(inc.affected_accounts) or 'unknown')} &nbsp;|&nbsp; "
                f"<b>Hosts:</b> {escape(', '.join(inc.affected_hosts) or 'unknown')} &nbsp;|&nbsp; "
                f"<b>IPs:</b> {escape(', '.join(inc.source_ips) or 'none')}",
                body_style,
            )
        )
        story.append(
            Paragraph(
                f"<i>Scoring note: {escape(inc.score_breakdown.scoring_note)}</i>",
                body_style,
            )
        )
        for step in inc.timeline:
            story.append(
                Paragraph(
                    f"<b>{step.step_index}. [{escape(step.timestamp)}] {escape(step.stage)}</b> "
                    f"(<font name='Courier'>{escape(step.event_id)}</font>): {escape(step.explanation)}",
                    body_style,
                )
            )
        story.append(Spacer(1, 6))

    # Detection Findings
    story.append(Paragraph("Detection Findings", h2_style))
    if not findings:
        story.append(Paragraph("No detection findings triggered.", body_style))
    for f in findings[:40]:
        ev_refs = ", ".join(f.supporting_event_ids[:6])
        story.append(
            Paragraph(
                f"<b>[{escape(f.finding_id)}] {escape(f.detector_name)}</b> "
                f"({escape(f.severity.upper())}, {escape(f.detection_source)}): "
                f"{escape(f.description)} "
                f"<font name='Courier' size='8'>[Events: {escape(ev_refs)}]</font>",
                body_style,
            )
        )

    def _add_page_num(canvas, doc_obj):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#64748b"))
        canvas.drawRightString(letter[0] - 0.6 * inch, 0.4 * inch, f"ThreatLens Report | Page {doc_obj.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=_add_page_num, onLaterPages=_add_page_num)
    return buf.getvalue()


def export_report(
    fmt: str,
    events: List[CanonicalEvent],
    findings: List[Finding],
    incidents: List[IncidentDetail],
) -> tuple[Union[str, bytes], str, str]:
    """Return (content, media_type, filename) in pdf, json, or csv."""
    fmt_l = fmt.lower().strip()
    summary = build_analyzer_summary(events, findings, incidents)

    if fmt_l == "json":
        payload = {
            "summary": summary,
            "incidents": [inc.model_dump() for inc in incidents],
            "findings": [f.model_dump() for f in findings],
        }
        return (
            json.dumps(payload, indent=2),
            "application/json",
            "threatlens_security_report.json",
        )

    if fmt_l == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(
            [
                "event_id",
                "timestamp",
                "source_type",
                "user",
                "src_ip",
                "dest_ip",
                "hostname",
                "action",
                "resource",
                "status",
                "bytes_out",
                "raw_log",
            ]
        )
        for ev in events:
            writer.writerow(
                [
                    ev.event_id,
                    ev.timestamp,
                    ev.source_type,
                    ev.user,
                    ev.src_ip,
                    ev.dest_ip,
                    ev.hostname,
                    ev.action,
                    ev.resource,
                    ev.status,
                    ev.bytes_out,
                    ev.raw_log,
                ]
            )
        return buf.getvalue(), "text/csv", "threatlens_normalized_events.csv"

    pdf_bytes = _build_pdf_report(summary, findings, incidents)
    return pdf_bytes, "application/pdf", "threatlens_security_report.pdf"
