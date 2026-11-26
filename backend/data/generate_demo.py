"""Synthetic demo dataset generator for TRACEPOINT (>= 1,200 realistic mixed events)."""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List


NORMAL_USERS = [
    ("j.patel", "10.20.4.18", "Bengaluru, IN", "ws-eng-14"),
    ("m.chen", "10.20.4.22", "Singapore, SG", "ws-eng-08"),
    ("s.kumar", "10.20.5.11", "Bengaluru, IN", "ws-fin-03"),
    ("a.rodriguez", "10.20.6.31", "New York, US", "ws-ops-02"),
    ("d.kim", "10.20.4.45", "San Francisco, US", "ws-eng-19"),
    ("r.nair", "10.20.5.19", "Mumbai, IN", "ws-sec-01"),
    ("l.wright", "10.20.7.12", "London, UK", "ws-hr-04"),
    ("k.osei", "10.20.6.50", "London, UK", "ws-ops-09"),
    ("t.nguyen", "10.20.4.61", "Singapore, SG", "ws-eng-27"),
    ("p.sharma", "10.20.5.28", "Hyderabad, IN", "ws-fin-07"),
]

WEB_PATHS = [
    "/api/v1/reports",
    "/api/v1/health",
    "/dashboard",
    "/api/v1/tickets",
    "/static/app.js",
    "/api/v1/metrics/daily",
    "/docs/runbook",
    "/api/v1/profile",
]

SYS_RESOURCES = [
    "/var/log/app/worker.log",
    "/srv/app/config.yaml",
    "/opt/deploy/release_notes.txt",
    "/var/cache/nginx/status",
    "/tmp/daily_sync.lock",
]


def generate_synthetic_events(seed: int = 2026) -> List[Dict[str, Any]]:
    """Generate >= 1,200 synthetic events including normal baselines and multi-stage attack."""
    rng = random.Random(seed)
    base_day = datetime(2026, 11, 25, 8, 0, 0, tzinfo=timezone.utc)
    events: List[Dict[str, Any]] = []
    seq = 1

    def next_id() -> str:
        nonlocal seq
        eid = f"evt_syn_{seq:05d}"
        seq += 1
        return eid

    # 1. Normal employee logins, web requests, OS file activity, and small egress baselines (~1,160 events)
    for i in range(1140):
        user, ip, geo, host = NORMAL_USERS[i % len(NORMAL_USERS)]
        offset_sec = rng.randint(0, 9 * 3600 + 3000)  # 08:00 to ~17:50 UTC
        ts = (base_day + timedelta(seconds=offset_sec)).strftime("%Y-%m-%dT%H:%M:%SZ")
        kind = i % 10

        if kind in (0, 1):
            # Normal auth login (occasional single mistyped password)
            failed = rng.random() < 0.04
            status = "failure" if failed else "success"
            action = "ssh_login_failed" if failed else "ssh_login_success"
            sess = f"sess-norm-{user[:3]}-{i // 10:03d}"
            raw = (
                f"{ts} {host} sshd[{2000 + (i % 900)}]: "
                f"{'Failed' if failed else 'Accepted'} publickey for {user} "
                f"from {ip} port {40000 + (i % 10000)} ssh2 geo=\"{geo}\" session={sess}"
            )
            events.append(
                {
                    "event_id": next_id(),
                    "timestamp": ts,
                    "source_type": "auth",
                    "user": user,
                    "src_ip": ip,
                    "dest_ip": "",
                    "geo": geo,
                    "hostname": host,
                    "session_id": sess,
                    "action": action,
                    "resource": "ssh:publickey",
                    "status": status,
                    "bytes_out": 0,
                    "raw_log": raw,
                    "is_synthetic": True,
                }
            )
        elif kind in (2, 3, 4, 5, 6):
            # Normal web request
            path = rng.choice(WEB_PATHS)
            method = "POST" if path.endswith("tickets") and rng.random() < 0.3 else "GET"
            size = rng.randint(640, 14500)
            apache_ts = (base_day + timedelta(seconds=offset_sec)).strftime("%d/%b/%Y:%H:%M:%S +0000")
            raw = (
                f'{ip} - {user} [{apache_ts}] "{method} {path} HTTP/1.1" 200 {size} '
                f'"-" "Mozilla/5.0" host=web-gw-01 session=web-{i % 50:02d}'
            )
            events.append(
                {
                    "event_id": next_id(),
                    "timestamp": ts,
                    "source_type": "web",
                    "user": user,
                    "src_ip": ip,
                    "dest_ip": "10.20.1.5",
                    "geo": geo,
                    "hostname": "web-gw-01",
                    "session_id": f"web-{i % 50:02d}",
                    "action": f"http_{method.lower()}",
                    "resource": path,
                    "status": "success",
                    "bytes_out": size,
                    "raw_log": raw,
                    "is_synthetic": True,
                }
            )
        elif kind in (7, 8):
            # Normal OS file read / status check
            res = rng.choice(SYS_RESOURCES)
            raw = (
                f"{ts} prod-app-01 auditd[{3000 + (i % 500)}]: "
                f"type=FILE_ACCESS user={user} action=file_read resource={res} "
                f"status=success session=sys-{i % 40:02d}"
            )
            events.append(
                {
                    "event_id": next_id(),
                    "timestamp": ts,
                    "source_type": "system",
                    "user": user,
                    "src_ip": ip,
                    "dest_ip": "",
                    "geo": geo,
                    "hostname": "prod-app-01",
                    "session_id": f"sys-{i % 40:02d}",
                    "action": "file_read",
                    "resource": res,
                    "status": "success",
                    "bytes_out": 0,
                    "raw_log": raw,
                    "is_synthetic": True,
                }
            )
        else:
            # Normal small outbound sync (~2.5 - 4.8 MB)
            bytes_val = rng.randint(2_200_000, 4_800_000)
            raw = (
                f"{ts} prod-app-01 netflow[{4000 + (i % 300)}]: "
                f"user={user} src_ip={ip} dest_ip=10.20.99.10 action=outbound_transfer "
                f"resource=tcp/443 bytes_out={bytes_val} status=success"
            )
            events.append(
                {
                    "event_id": next_id(),
                    "timestamp": ts,
                    "source_type": "proxy",
                    "user": user,
                    "src_ip": ip,
                    "dest_ip": "10.20.99.10",
                    "geo": geo,
                    "hostname": "prod-app-01",
                    "session_id": "",
                    "action": "outbound_transfer",
                    "resource": "tcp/443",
                    "status": "success",
                    "bytes_out": bytes_val,
                    "raw_log": raw,
                    "is_synthetic": True,
                }
            )

    # 2. Normal 7-day-style baseline activity for svc_backup (~3.8 MB regular backup syncs)
    for hour_offset in (9, 10, 11, 12):
        ts = datetime(2026, 11, 25, hour_offset, 15, 0, tzinfo=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        bytes_val = int(3.8 * 1024 * 1024)  # 3,984,588 bytes = 3.8 MB baseline
        raw = (
            f"{ts} prod-app-01 netflow[4801]: user=svc_backup src_ip=10.20.1.15 "
            f"dest_ip=10.20.99.20 action=outbound_transfer resource=tcp/443 "
            f"bytes_out={bytes_val} status=success session=sess-bk-{hour_offset}"
        )
        events.append(
            {
                "event_id": next_id(),
                "timestamp": ts,
                "source_type": "proxy",
                "user": "svc_backup",
                "src_ip": "10.20.1.15",
                "dest_ip": "10.20.99.20",
                "geo": "Bengaluru, IN",
                "hostname": "prod-app-01",
                "session_id": f"sess-bk-{hour_offset}",
                "action": "outbound_transfer",
                "resource": "tcp/443",
                "status": "success",
                "bytes_out": bytes_val,
                "raw_log": raw,
                "is_synthetic": True,
            }
        )

    # 3. Prior legitimate Bengaluru session for admin_01 (provides geo baseline for Impossible Travel)
    ts_blr = "2026-11-25T13:10:00Z"
    events.append(
        {
            "event_id": next_id(),
            "timestamp": ts_blr,
            "source_type": "auth",
            "user": "admin_01",
            "src_ip": "49.207.212.14",
            "dest_ip": "10.20.1.5",
            "geo": "Bengaluru, IN",
            "hostname": "prod-bastion-01",
            "session_id": "sess-blr-01",
            "action": "ssh_login_success",
            "resource": "ssh:publickey",
            "status": "success",
            "bytes_out": 0,
            "raw_log": (
                f"{ts_blr} prod-bastion-01 sshd[3901]: Accepted publickey for admin_01 "
                f"from 49.207.212.14 port 50112 ssh2 geo=\"Bengaluru, IN\" session=sess-blr-01"
            ),
            "is_synthetic": True,
        }
    )

    # 4. MULTI-STAGE ATTACK SCENARIO (INC-2026-041):
    # Stage 1: 32 failed SSH attempts against admin_01 within 90s ending at 14:02:11Z
    bf_end = datetime(2026, 11, 25, 14, 2, 11, tzinfo=timezone.utc)
    bf_start = bf_end - timedelta(seconds=86)
    for k in range(32):
        dt = bf_start + timedelta(seconds=int(k * (86 / 31)))
        if k == 31:
            dt = bf_end
        ts_k = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        raw_bf = (
            f"{ts_k} prod-bastion-01 sshd[{4100 + k}]: Failed password for admin_01 "
            f"from 185.220.101.4 port {51200 + k} ssh2 geo=\"Frankfurt, DE\""
        )
        events.append(
            {
                "event_id": next_id(),
                "timestamp": ts_k,
                "source_type": "auth",
                "user": "admin_01",
                "src_ip": "185.220.101.4",
                "dest_ip": "10.20.1.5",
                "geo": "Frankfurt, DE",
                "hostname": "prod-bastion-01",
                "session_id": "",
                "action": "ssh_login_failed",
                "resource": "ssh:password",
                "status": "failure",
                "bytes_out": 0,
                "raw_log": raw_bf,
                "pid": str(4100 + k),
                "is_synthetic": True,
            }
        )

    # Stage 2: 14:04:03Z — Successful suspicious login from 185.220.101.4 (Frankfurt, DE)
    ts_login = "2026-11-25T14:04:03Z"
    events.append(
        {
            "event_id": next_id(),
            "timestamp": ts_login,
            "source_type": "auth",
            "user": "admin_01",
            "src_ip": "185.220.101.4",
            "dest_ip": "10.20.1.5",
            "geo": "Frankfurt, DE",
            "hostname": "prod-bastion-01",
            "session_id": "sess-4190",
            "action": "ssh_login_success",
            "resource": "ssh:password",
            "status": "success",
            "bytes_out": 0,
            "raw_log": (
                f"{ts_login} prod-bastion-01 sshd[4190]: Accepted password for admin_01 "
                f"from 185.220.101.4 port 51900 ssh2 geo=\"Frankfurt, DE\" session=sess-4190"
            ),
            "pid": "4190",
            "is_synthetic": True,
        }
    )

    # Stage 3: 14:07:19Z — Privilege escalation: admin_01 grants elevated permissions to svc_backup
    ts_priv = "2026-11-25T14:07:19Z"
    events.append(
        {
            "event_id": next_id(),
            "timestamp": ts_priv,
            "source_type": "system",
            "user": "admin_01",
            "src_ip": "185.220.101.4",
            "dest_ip": "",
            "geo": "Frankfurt, DE",
            "hostname": "prod-app-01",
            "session_id": "sess-4190",
            "action": "privilege_grant",
            "resource": "/usr/sbin/usermod -aG wheel,backup_ops svc_backup",
            "status": "success",
            "bytes_out": 0,
            "raw_log": (
                f"{ts_priv} prod-app-01 sudo[6102]: admin_01 : TTY=pts/0 ; PWD=/home/admin_01 ; "
                f"USER=root ; COMMAND=/usr/sbin/usermod -aG wheel,backup_ops svc_backup "
                f"session=sess-4190 src_ip=185.220.101.4 target_user=svc_backup"
            ),
            "pid": "6102",
            "target_user": "svc_backup",
            "is_synthetic": True,
        }
    )

    # Stage 4: 14:09:44Z — Sensitive resource access by svc_backup
    ts_sens = "2026-11-25T14:09:44Z"
    events.append(
        {
            "event_id": next_id(),
            "timestamp": ts_sens,
            "source_type": "system",
            "user": "svc_backup",
            "src_ip": "10.20.1.15",
            "dest_ip": "",
            "geo": "",
            "hostname": "prod-app-01",
            "session_id": "sess-svc-09",
            "action": "file_read",
            "resource": "/var/secure/payroll_export.csv",
            "status": "success",
            "bytes_out": 0,
            "raw_log": (
                f"{ts_sens} prod-app-01 auditd[7120]: type=FILE_ACCESS user=svc_backup "
                f"action=file_read resource=/var/secure/payroll_export.csv "
                f"status=success session=sess-svc-09 pid=7120"
            ),
            "pid": "7120",
            "is_synthetic": True,
        }
    )

    # Stage 5: 14:11:30Z — 418 MB outbound transfer by svc_backup to attacker IP 185.220.101.4
    ts_exf = "2026-11-25T14:11:30Z"
    exf_bytes = 418 * 1024 * 1024  # 438,304,768 bytes = 418.0 MB
    events.append(
        {
            "event_id": next_id(),
            "timestamp": ts_exf,
            "source_type": "proxy",
            "user": "svc_backup",
            "src_ip": "10.20.1.15",
            "dest_ip": "185.220.101.4",
            "geo": "",
            "hostname": "prod-app-01",
            "session_id": "sess-svc-09",
            "action": "outbound_transfer",
            "resource": "tcp/443",
            "status": "success",
            "bytes_out": exf_bytes,
            "raw_log": (
                f"{ts_exf} prod-app-01 netflow[8011]: user=svc_backup src_ip=10.20.1.15 "
                f"dest_ip=185.220.101.4 action=outbound_transfer resource=tcp/443 "
                f"bytes_out={exf_bytes} status=success session=sess-svc-09"
            ),
            "pid": "8011",
            "is_synthetic": True,
        }
    )

    # 5. Secondary unrelated suspicious activity at 16:30Z (verifies non-merging of unrelated events)
    sec_base = datetime(2026, 11, 25, 16, 30, 0, tzinfo=timezone.utc)
    for k in range(7):
        ts_sec = (sec_base + timedelta(seconds=k * 6)).strftime("%Y-%m-%dT%H:%M:%SZ")
        events.append(
            {
                "event_id": next_id(),
                "timestamp": ts_sec,
                "source_type": "auth",
                "user": "dev_contractor",
                "src_ip": "203.0.113.77",
                "dest_ip": "10.20.8.14",
                "geo": "Amsterdam, NL",
                "hostname": "dev-db-02",
                "session_id": "",
                "action": "ssh_login_failed",
                "resource": "ssh:password",
                "status": "failure",
                "bytes_out": 0,
                "raw_log": (
                    f"{ts_sec} dev-db-02 sshd[{9100 + k}]: Failed password for dev_contractor "
                    f"from 203.0.113.77 port {60100 + k} ssh2 geo=\"Amsterdam, NL\""
                ),
                "pid": str(9100 + k),
                "is_synthetic": True,
            }
        )

    events.sort(key=lambda e: (e["timestamp"], e["event_id"]))
    return events


def ensure_demo_dataset(output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    events = generate_synthetic_events()
    with output_path.open("w", encoding="utf-8") as fh:
        for ev in events:
            fh.write(json.dumps(ev) + "\n")
    return output_path


if __name__ == "__main__":
    dest = Path(__file__).resolve().parent / "synthetic_demo_logs.jsonl"
    ensure_demo_dataset(dest)
    print(f"Generated synthetic demo dataset at {dest}")
