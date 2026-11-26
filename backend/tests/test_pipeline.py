"""Automated unit and integration tests for TRACEPOINT."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from fastapi.testclient import TestClient

# Ensure backend/ is importable
BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.config import settings
from app.correlation.engine import correlate_findings
from app.database.db import init_db, reset_db
from app.detectors.rules import (
    detect_brute_force,
    detect_data_exfiltration,
    detect_impossible_travel,
    detect_privilege_escalation,
)
from app.incidents.reconstructor import run_detection_and_reconstruction
from app.main import app
from app.ml.ml_anomaly import engineer_behavioral_features, score_events_ml
from app.normalizer.canonical import normalize_record, parse_timestamp
from app.parsers.csv_parser import parse_csv_logs
from app.parsers.json_parser import parse_json_logs
from app.parsers.os_audit_parser import parse_os_audit_logs
from app.parsers.ssh_auth_parser import parse_ssh_auth_logs
from app.parsers.txt_parser import parse_txt_logs
from app.parsers.web_access_parser import parse_web_access_logs
from app.scoring.engine import calculate_risk_score
from data.generate_demo import generate_synthetic_events


def test_parsers_and_error_handling():
    # 1. CSV parser + malformed line resilience
    csv_text = (
        "timestamp,source_type,user,src_ip,action,status,bytes_out\n"
        "2026-11-25T10:00:00Z,auth,alice,10.1.1.2,ssh_login_success,success,0\n"
        "bad-timestamp,auth,bob,10.1.1.3,ssh_login_failed,failure,0\n"
    )
    res_csv = parse_csv_logs(csv_text)
    assert res_csv.parsed_count == 1
    assert res_csv.skipped_count == 1
    assert res_csv.events[0].user == "alice"

    # 2. JSON & NDJSON parser
    json_text = json.dumps(
        [
            {"timestamp": "2026-11-25T10:05:00Z", "user": "carol", "action": "login", "status": "success"},
            {"user": "missing_ts"},
        ]
    )
    res_json = parse_json_logs(json_text)
    assert res_json.parsed_count == 1
    assert res_json.skipped_count == 1

    # 3. SSH auth parser
    ssh_text = (
        "Nov 25 14:02:11 prod-bastion-01 sshd[4102]: Failed password for admin_01 from 185.220.101.4 port 51234 ssh2\n"
        "2026-11-25T14:04:03Z prod-bastion-01 sshd[4190]: Accepted password for admin_01 from 185.220.101.4 port 51900 ssh2 session=sess-4190\n"
        "corrupted unparseable ssh line\n"
    )
    res_ssh = parse_ssh_auth_logs(ssh_text)
    assert res_ssh.parsed_count == 2
    assert res_ssh.skipped_count == 1
    assert res_ssh.events[0].status == "failure"
    assert res_ssh.events[1].status == "success"
    assert res_ssh.events[1].session_id == "sess-4190"

    # 4. Web access parser
    web_text = '10.20.4.18 - j.patel [25/Nov/2026:10:15:22 +0000] "GET /api/v1/reports HTTP/1.1" 200 1842 "-" "Mozilla/5.0"\n'
    res_web = parse_web_access_logs(web_text)
    assert res_web.parsed_count == 1
    assert res_web.events[0].source_type == "web"
    assert res_web.events[0].resource == "/api/v1/reports"

    # 5. OS audit & sudo parser
    os_text = (
        "2026-11-25T14:07:19Z prod-app-01 sudo[6102]: admin_01 : TTY=pts/0 ; USER=root ; COMMAND=/usr/sbin/usermod -aG wheel svc_backup session=sess-4190 target_user=svc_backup\n"
        "2026-11-25T14:09:44Z prod-app-01 auditd[7120]: user=svc_backup action=file_read resource=/var/secure/payroll_export.csv status=success\n"
    )
    res_os = parse_os_audit_logs(os_text)
    assert res_os.parsed_count == 2
    assert res_os.events[0].action == "privilege_grant"
    assert res_os.events[0].target_user == "svc_backup"
    assert res_os.events[1].resource == "/var/secure/payroll_export.csv"

    # 6. Mixed TXT parser
    res_txt = parse_txt_logs(ssh_text + web_text + os_text)
    assert res_txt.parsed_count == 5
    assert res_txt.skipped_count == 1


def test_canonical_normalization_formats():
    assert parse_timestamp("2026-11-25T14:04:03Z") == "2026-11-25T14:04:03Z"
    assert parse_timestamp("25/Nov/2026:14:02:11 +0000") == "2026-11-25T14:02:11Z"
    assert parse_timestamp("Nov 25 14:02:11") == "2026-11-25T14:02:11Z"
    ev = normalize_record(
        {"timestamp": "2026-11-25 14:00:00", "username": "alice", "source_type": "ssh", "status": "200"},
        raw_log="raw",
    )
    assert ev is not None
    assert ev.source_type == "auth"
    assert ev.status == "success"
    assert ev.raw_log == "raw"


def test_individual_detectors():
    # Brute force
    bf_evs = [
        normalize_record(
            {
                "event_id": f"bf_{i}",
                "timestamp": f"2026-11-25T14:01:{i:02d}Z",
                "source_type": "auth",
                "user": "admin_01",
                "src_ip": "185.220.101.4",
                "action": "ssh_login_failed",
                "status": "failure",
            },
            raw_log=f"fail {i}",
        )
        for i in range(6)
    ]
    bf_findings = detect_brute_force([e for e in bf_evs if e], threshold=5, window_seconds=120)
    assert len(bf_findings) == 1
    assert len(bf_findings[0].supporting_event_ids) == 6

    # Impossible travel
    it_evs = [
        normalize_record(
            {
                "event_id": "it_1",
                "timestamp": "2026-11-25T13:10:00Z",
                "source_type": "auth",
                "user": "admin_01",
                "src_ip": "49.207.212.14",
                "geo": "Bengaluru, IN",
                "action": "ssh_login_success",
                "status": "success",
            },
            raw_log="blr",
        ),
        normalize_record(
            {
                "event_id": "it_2",
                "timestamp": "2026-11-25T14:04:03Z",
                "source_type": "auth",
                "user": "admin_01",
                "src_ip": "185.220.101.4",
                "geo": "Frankfurt, DE",
                "action": "ssh_login_success",
                "status": "success",
            },
            raw_log="fra",
        ),
    ]
    it_findings = detect_impossible_travel([e for e in it_evs if e])
    assert len(it_findings) == 1
    assert "Bengaluru" in it_findings[0].description and "Frankfurt" in it_findings[0].description

    # Privilege escalation
    pe_ev = normalize_record(
        {
            "event_id": "pe_1",
            "timestamp": "2026-11-25T14:07:19Z",
            "source_type": "system",
            "user": "admin_01",
            "action": "privilege_grant",
            "resource": "/usr/sbin/usermod -aG wheel svc_backup",
            "target_user": "svc_backup",
            "status": "success",
        },
        raw_log="sudo usermod",
    )
    pe_findings = detect_privilege_escalation([pe_ev])  # type: ignore[list-item]
    assert len(pe_findings) == 1

    # Outbound exfiltration
    exf_evs = [
        normalize_record(
            {
                "event_id": f"norm_{i}",
                "timestamp": f"2026-11-25T10:0{i}:00Z",
                "source_type": "proxy",
                "user": "svc_backup",
                "bytes_out": int(3.8 * 1024 * 1024),
                "action": "outbound_transfer",
                "status": "success",
            },
            raw_log="norm",
        )
        for i in range(4)
    ] + [
        normalize_record(
            {
                "event_id": "spike_1",
                "timestamp": "2026-11-25T14:11:30Z",
                "source_type": "proxy",
                "user": "svc_backup",
                "dest_ip": "185.220.101.4",
                "bytes_out": 418 * 1024 * 1024,
                "action": "outbound_transfer",
                "status": "success",
            },
            raw_log="spike",
        )
    ]
    exf_findings = detect_data_exfiltration([e for e in exf_evs if e])
    assert len(exf_findings) == 1
    assert "418.0 MB" in exf_findings[0].description


def test_unrelated_events_not_merged_simply_by_time():
    # Two unrelated users on different hosts and IPs within 5 minutes should stay separate incidents
    e1 = normalize_record(
        {
            "event_id": "unrel_1",
            "timestamp": "2026-11-25T15:00:00Z",
            "source_type": "system",
            "user": "alice",
            "src_ip": "10.1.1.10",
            "hostname": "host-a",
            "action": "file_read",
            "resource": "/etc/shadow",
            "status": "success",
        },
        raw_log="alice read shadow",
    )
    e2 = normalize_record(
        {
            "event_id": "unrel_2",
            "timestamp": "2026-11-25T15:03:00Z",
            "source_type": "system",
            "user": "bob",
            "src_ip": "10.2.2.20",
            "hostname": "host-b",
            "action": "file_read",
            "resource": "/var/secure/payroll.csv",
            "status": "success",
        },
        raw_log="bob read payroll",
    )
    _, incidents, _ = run_detection_and_reconstruction([e1, e2])  # type: ignore[list-item]
    assert len(incidents) == 2


def test_per_event_ml_anomaly_and_ml_only_surfacing():
    # Build 20 normal daytime events for alice + 1 ML-only multi-feature outlier (no hard rule fired:
    # non-sensitive resource /srv/export_cache.bin, 35 MB transfer vs 1 MB baseline (< 50 MB rule floor),
    # rare IP, rare resource, 11:00 UTC daytime)
    normal_evs = [
        normalize_record(
            {
                "event_id": f"ml_norm_{i}",
                "timestamp": f"2026-11-25T{10 + (i % 6):02d}:{i % 50:02d}:00Z",
                "source_type": "web",
                "user": "alice",
                "src_ip": "10.20.1.10",
                "hostname": "app-01",
                "action": "http_get",
                "resource": "/dashboard",
                "status": "success",
                "bytes_out": 500_000,
            },
            raw_log=f"normal {i}",
        )
        for i in range(25)
    ]
    ml_only_ev = normalize_record(
        {
            "event_id": "ml_outlier_01",
            "timestamp": "2026-11-25T11:30:00Z",
            "source_type": "proxy",
            "user": "alice",
            "src_ip": "203.0.113.88",
            "hostname": "app-01",
            "action": "outbound_transfer",
            "resource": "/srv/batch/cache_snapshot_99.tar",
            "status": "success",
            "bytes_out": 35 * 1024 * 1024,  # 35 MB (< 50 MB rule floor, 70x above alice's 0.5 MB baseline)
        },
        raw_log="alice 35MB rare transfer from new IP",
    )
    all_evs = [e for e in normal_evs + [ml_only_ev] if e]
    feat_df = engineer_behavioral_features(all_evs)
    assert "bytes_out_zscore" in feat_df.columns
    assert "user_ip_rarity" in feat_df.columns
    assert "rolling_fail_count_10m" in feat_df.columns
    assert "events_per_min_window" in feat_df.columns

    ml_scores = score_events_ml(all_evs, threshold=60.0)
    assert ml_scores["ml_outlier_01"]["ml_anomaly_score"] >= 60.0
    assert len(ml_scores["ml_outlier_01"]["ml_reasons"]) >= 1

    findings, incidents, _ = run_detection_and_reconstruction(all_evs)
    ml_only_findings = [f for f in findings if f.detector_name == "Behavioral Anomaly (ML)"]
    assert len(ml_only_findings) >= 1
    assert any(
        any(step.stage == "Behavioral Anomaly (ML)" for step in inc.timeline)
        and any("Behavioral Anomaly (ML)" in n.label for n in inc.graph.nodes)
        for inc in incidents
    )


def test_end_to_end_synthetic_demo_and_api(tmp_path):
    # Point DB to isolated temp file
    settings.db_path = str(tmp_path / "test_tracepoint.db")
    init_db(settings.db_path)
    reset_db(settings.db_path)

    # Generate synthetic events >= 1,000 and run pipeline directly
    raw_events = generate_synthetic_events()
    assert len(raw_events) >= 1000

    with TestClient(app) as client:
        resp = client.post("/api/demo/load")
        assert resp.status_code == 200
        report = resp.json()
        assert report["parsed_count"] >= 1000
        assert report["skipped_count"] == 0
        assert report["incidents_detected"] >= 1

        inc_list = client.get("/api/incidents").json()
        assert len(inc_list) >= 2  # INC-2026-041 + secondary dev_contractor brute force

        top_inc_id = inc_list[0]["incident_id"]
        assert top_inc_id == "INC-2026-041"
        detail = client.get(f"/api/incidents/{top_inc_id}").json()

        # 1. Risk score matches 25+20+25+15+11 = 96/100
        assert detail["risk_score"] == 96
        assert detail["severity"] == "critical"

        # 2. All 5 stages detected & chronologically ordered
        timeline = detail["timeline"]
        assert len(timeline) == 5
        timestamps = [step["timestamp"] for step in timeline]
        assert timestamps == sorted(timestamps)
        assert timestamps == [
            "2026-11-25T14:02:11Z",
            "2026-11-25T14:04:03Z",
            "2026-11-25T14:07:19Z",
            "2026-11-25T14:09:44Z",
            "2026-11-25T14:11:30Z",
        ]

        # 3. Identity transition admin_01 -> svc_backup reconstructed in graph
        graph = detail["graph"]
        esc_edges = [
            e for e in graph["edges"]
            if e["relationship_type"] == "ESCALATED_TO"
            and e["source"] == "user:admin_01"
            and e["target"] == "user:svc_backup"
        ]
        assert len(esc_edges) == 1
        assert len(esc_edges[0]["supporting_event_ids"]) >= 1

        # 4. Every finding has valid evidence references
        for f in detail["findings"]:
            assert len(f["supporting_event_ids"]) >= 1
            assert len(f["raw_log_references"]) >= 1

        # 5. Investigation assistant returns grounded evidence
        qa = client.post(
            "/api/investigate",
            json={
                "incident_id": top_inc_id,
                "question": "Which systems were accessed after privilege escalation?",
            },
        )
        assert qa.status_code == 200
        qa_body = qa.json()
        assert "payroll_export.csv" in qa_body["answer"]
        assert len(qa_body["cited_event_ids"]) >= 1

        # 6. Metrics endpoint reflects live DB counts
        metrics = client.get("/api/metrics").json()
        assert metrics["total_events_processed"] >= 1000
        assert metrics["critical_incidents"] >= 1
        assert "admin_01" in metrics["high_risk_accounts"]

        # 7. Analyzer summary, regex search, and report export
        summary = client.get("/api/analyzer/summary").json()
        assert summary["total_events"] >= 1000
        assert len(summary["iocs"]) >= 2

        regex_res = client.get("/api/logs", params={"q": "payroll_export|usermod", "regex": "true"}).json()
        assert regex_res["total"] >= 2

        pdf_export = client.get("/api/analyzer/export", params={"format": "pdf"})
        assert pdf_export.status_code == 200
        assert pdf_export.headers["content-type"].startswith("application/pdf")
        assert pdf_export.content.startswith(b"%PDF-")
        assert len(pdf_export.content) > 1000

        # 8. Firewall, Windows Event, and Web Attack presets
        for preset_id in ("web_sqli", "firewall_scan", "windows_ad"):
            pr = client.post(f"/api/analyzer/presets/{preset_id}")
            assert pr.status_code == 200
            assert pr.json()["parsed_count"] >= 4
            assert pr.json()["findings_generated"] >= 1

        # 9. Uploading a new log file replaces previous workspace data by default
        custom_log = (
            b"2026-11-25T18:10:00Z app-node-09 auth[1201]: Failed login for user=bob from 203.0.113.99\n"
            b"2026-11-25T18:10:05Z app-node-09 auth[1202]: Accepted login for user=bob from 203.0.113.99\n"
        )
        up = client.post(
            "/api/logs/upload",
            files={"file": ("custom_sample.log", custom_log, "text/plain")},
        )
        assert up.status_code == 200
        up_body = up.json()
        assert up_body["parsed_count"] == 2
        assert up_body["processed_count"] == 2
        logs_now = client.get("/api/logs", params={"sort_by": "final_event_risk"}).json()
        assert logs_now["total"] == 2
        assert all(ev["user"] == "bob" for ev in logs_now["events"])
        assert "ml_anomaly_score" in logs_now["events"][0]
        assert "final_event_risk" in logs_now["events"][0]

        # 10. Live ML anomaly threshold update endpoint
        upd = client.put("/api/settings", json={"ml_anomaly_threshold": 50.0})
        assert upd.status_code == 200
        assert upd.json()["settings"]["ml_anomaly_threshold"] == 50.0
        # Restore default 60.0
        client.put("/api/settings", json={"ml_anomaly_threshold": 60.0})
