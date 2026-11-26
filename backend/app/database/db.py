"""SQLite database initialization and persistence layer for TRACEPOINT."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from app.config import settings
from app.schemas.models import CanonicalEvent, Finding, IncidentDetail


def _ensure_parent(db_path: str) -> None:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)


@contextmanager
def get_connection(db_path: Optional[str] = None) -> Iterator[sqlite3.Connection]:
    path = db_path or settings.db_path
    _ensure_parent(path)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db(db_path: Optional[str] = None) -> None:
    """Create tables and indexes if they do not already exist."""
    with get_connection(db_path) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                source_type TEXT NOT NULL,
                user TEXT NOT NULL,
                src_ip TEXT,
                dest_ip TEXT,
                geo TEXT,
                hostname TEXT,
                session_id TEXT,
                action TEXT,
                resource TEXT,
                status TEXT,
                bytes_out INTEGER DEFAULT 0,
                raw_log TEXT NOT NULL,
                pid TEXT,
                target_user TEXT,
                ingestion_batch TEXT,
                is_synthetic INTEGER DEFAULT 0,
                rule_score REAL DEFAULT 0.0,
                ml_anomaly_score REAL DEFAULT 0.0,
                final_event_risk REAL DEFAULT 0.0,
                ml_reasons_json TEXT,
                ml_feature_deviations_json TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_user ON events(user);
            CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);

            CREATE TABLE IF NOT EXISTS findings (
                finding_id TEXT PRIMARY KEY,
                detector_name TEXT NOT NULL,
                detector_category TEXT NOT NULL,
                detection_source TEXT NOT NULL,
                severity TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                affected_user TEXT NOT NULL,
                src_ip TEXT,
                hostname TEXT,
                description TEXT NOT NULL,
                triggered_condition TEXT NOT NULL,
                supporting_event_ids_json TEXT NOT NULL,
                raw_log_references_json TEXT NOT NULL,
                confidence REAL NOT NULL,
                confidence_label TEXT NOT NULL,
                anomaly_score REAL,
                feature_contributions_json TEXT,
                incident_id TEXT,
                is_synthetic INTEGER DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_findings_inc ON findings(incident_id);
            CREATE INDEX IF NOT EXISTS idx_findings_ts ON findings(timestamp);

            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                severity TEXT NOT NULL,
                first_observed TEXT NOT NULL,
                last_observed TEXT NOT NULL,
                affected_accounts_json TEXT NOT NULL,
                affected_hosts_json TEXT NOT NULL,
                source_ips_json TEXT NOT NULL,
                attack_stages_json TEXT NOT NULL,
                evidence_count INTEGER NOT NULL,
                finding_count INTEGER NOT NULL,
                is_synthetic INTEGER DEFAULT 0,
                detail_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS ingestion_batches (
                batch_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                format_detected TEXT NOT NULL,
                total_lines INTEGER NOT NULL,
                parsed_count INTEGER NOT NULL,
                skipped_count INTEGER NOT NULL,
                processed_count INTEGER NOT NULL,
                errors_json TEXT NOT NULL
            );
            """
        )
        # Lightweight migration for existing SQLite files missing per-event / finding ML columns
        existing_cols = {
            row["name"] for row in conn.execute("PRAGMA table_info(events)").fetchall()
        }
        migrations = [
            ("rule_score", "REAL DEFAULT 0.0"),
            ("ml_anomaly_score", "REAL DEFAULT 0.0"),
            ("final_event_risk", "REAL DEFAULT 0.0"),
            ("ml_reasons_json", "TEXT"),
            ("ml_feature_deviations_json", "TEXT"),
        ]
        for col_name, col_type in migrations:
            if col_name not in existing_cols:
                conn.execute(f"ALTER TABLE events ADD COLUMN {col_name} {col_type}")

        existing_f_cols = {
            row["name"] for row in conn.execute("PRAGMA table_info(findings)").fetchall()
        }
        for col_name, col_type in (
            ("rule_score", "REAL DEFAULT 0.0"),
            ("final_event_risk", "REAL DEFAULT 0.0"),
            ("ml_reasons_json", "TEXT"),
        ):
            if col_name not in existing_f_cols:
                conn.execute(f"ALTER TABLE findings ADD COLUMN {col_name} {col_type}")


def reset_db(db_path: Optional[str] = None) -> None:
    """Clear all runtime data while preserving schema."""
    with get_connection(db_path) as conn:
        conn.executescript(
            """
            DELETE FROM events;
            DELETE FROM findings;
            DELETE FROM incidents;
            DELETE FROM ingestion_batches;
            """
        )


def save_events(events: List[CanonicalEvent], db_path: Optional[str] = None) -> None:
    if not events:
        return
    with get_connection(db_path) as conn:
        conn.executemany(
            """
            INSERT OR REPLACE INTO events (
                event_id, timestamp, source_type, user, src_ip, dest_ip, geo,
                hostname, session_id, action, resource, status, bytes_out,
                raw_log, pid, target_user, ingestion_batch, is_synthetic,
                rule_score, ml_anomaly_score, final_event_risk,
                ml_reasons_json, ml_feature_deviations_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    e.event_id,
                    e.timestamp,
                    e.source_type,
                    e.user,
                    e.src_ip,
                    e.dest_ip,
                    e.geo,
                    e.hostname,
                    e.session_id,
                    e.action,
                    e.resource,
                    e.status,
                    e.bytes_out,
                    e.raw_log,
                    e.pid,
                    e.target_user,
                    e.ingestion_batch,
                    1 if e.is_synthetic else 0,
                    float(e.rule_score or 0.0),
                    float(e.ml_anomaly_score or 0.0),
                    float(e.final_event_risk or 0.0),
                    json.dumps(e.ml_reasons or []),
                    json.dumps(e.ml_feature_deviations or []),
                )
                for e in events
            ],
        )


def get_all_events(db_path: Optional[str] = None) -> List[CanonicalEvent]:
    with get_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM events ORDER BY timestamp ASC, event_id ASC"
        ).fetchall()
    return [
        CanonicalEvent(
            event_id=r["event_id"],
            timestamp=r["timestamp"],
            source_type=r["source_type"],
            user=r["user"],
            src_ip=r["src_ip"] or "",
            dest_ip=r["dest_ip"] or "",
            geo=r["geo"] or "",
            hostname=r["hostname"] or "unknown",
            session_id=r["session_id"] or "",
            action=r["action"] or "unknown",
            resource=r["resource"] or "",
            status=r["status"] or "unknown",
            bytes_out=int(r["bytes_out"] or 0),
            raw_log=r["raw_log"],
            pid=r["pid"],
            target_user=r["target_user"],
            ingestion_batch=r["ingestion_batch"],
            is_synthetic=bool(r["is_synthetic"]),
            rule_score=float(r["rule_score"] or 0.0),
            ml_anomaly_score=float(r["ml_anomaly_score"] or 0.0),
            final_event_risk=float(r["final_event_risk"] or 0.0),
            ml_reasons=json.loads(r["ml_reasons_json"]) if r["ml_reasons_json"] else [],
            ml_feature_deviations=json.loads(r["ml_feature_deviations_json"])
            if r["ml_feature_deviations_json"]
            else [],
        )
        for r in rows
    ]


def replace_findings_and_incidents(
    findings: List[Finding],
    incidents: List[IncidentDetail],
    db_path: Optional[str] = None,
) -> None:
    """Replace computed findings and incidents after full pipeline run."""
    with get_connection(db_path) as conn:
        conn.execute("DELETE FROM findings")
        conn.execute("DELETE FROM incidents")

        if findings:
            conn.executemany(
                """
                INSERT INTO findings (
                    finding_id, detector_name, detector_category, detection_source,
                    severity, timestamp, affected_user, src_ip, hostname,
                    description, triggered_condition, supporting_event_ids_json,
                    raw_log_references_json, confidence, confidence_label,
                    anomaly_score, feature_contributions_json, rule_score, final_event_risk, ml_reasons_json, incident_id, is_synthetic
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        f.finding_id,
                        f.detector_name,
                        f.detector_category,
                        f.detection_source,
                        f.severity,
                        f.timestamp,
                        f.affected_user,
                        f.src_ip,
                        f.hostname,
                        f.description,
                        f.triggered_condition,
                        json.dumps(f.supporting_event_ids),
                        json.dumps(f.raw_log_references),
                        f.confidence,
                        f.confidence_label,
                        f.anomaly_score,
                        json.dumps(f.feature_contributions)
                        if f.feature_contributions is not None
                        else None,
                        float(f.rule_score or 0.0),
                        float(f.final_event_risk or 0.0),
                        json.dumps(f.ml_reasons or []),
                        f.incident_id,
                        1 if f.is_synthetic else 0,
                    )
                    for f in findings
                ],
            )

        if incidents:
            conn.executemany(
                """
                INSERT INTO incidents (
                    incident_id, title, risk_score, severity, first_observed,
                    last_observed, affected_accounts_json, affected_hosts_json,
                    source_ips_json, attack_stages_json, evidence_count,
                    finding_count, is_synthetic, detail_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        inc.incident_id,
                        inc.title,
                        inc.risk_score,
                        inc.severity,
                        inc.first_observed,
                        inc.last_observed,
                        json.dumps(inc.affected_accounts),
                        json.dumps(inc.affected_hosts),
                        json.dumps(inc.source_ips),
                        json.dumps(inc.attack_stages),
                        inc.evidence_count,
                        inc.finding_count,
                        1 if inc.is_synthetic else 0,
                        inc.model_dump_json(),
                    )
                    for inc in incidents
                ],
            )


def get_all_findings(db_path: Optional[str] = None) -> List[Finding]:
    with get_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM findings ORDER BY timestamp ASC"
        ).fetchall()
    return [
        Finding(
            finding_id=r["finding_id"],
            detector_name=r["detector_name"],
            detector_category=r["detector_category"],
            detection_source=r["detection_source"],
            severity=r["severity"],
            timestamp=r["timestamp"],
            affected_user=r["affected_user"],
            src_ip=r["src_ip"] or "",
            hostname=r["hostname"] or "",
            description=r["description"],
            triggered_condition=r["triggered_condition"],
            supporting_event_ids=json.loads(r["supporting_event_ids_json"]),
            raw_log_references=json.loads(r["raw_log_references_json"]),
            confidence=float(r["confidence"]),
            confidence_label=r["confidence_label"],
            anomaly_score=r["anomaly_score"],
            feature_contributions=json.loads(r["feature_contributions_json"])
            if r["feature_contributions_json"]
            else None,
            rule_score=float(r["rule_score"] or 0.0),
            final_event_risk=float(r["final_event_risk"] or 0.0),
            ml_reasons=json.loads(r["ml_reasons_json"]) if r["ml_reasons_json"] else [],
            incident_id=r["incident_id"],
            is_synthetic=bool(r["is_synthetic"]),
        )
        for r in rows
    ]


def get_all_incidents(db_path: Optional[str] = None) -> List[IncidentDetail]:
    with get_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT detail_json FROM incidents ORDER BY risk_score DESC, first_observed DESC"
        ).fetchall()
    return [IncidentDetail.model_validate_json(r["detail_json"]) for r in rows]


def get_incident_by_id(
    incident_id: str, db_path: Optional[str] = None
) -> Optional[IncidentDetail]:
    with get_connection(db_path) as conn:
        row = conn.execute(
            "SELECT detail_json FROM incidents WHERE incident_id = ?", (incident_id,)
        ).fetchone()
    if not row:
        return None
    return IncidentDetail.model_validate_json(row["detail_json"])


def save_ingestion_batch(
    batch_id: str,
    created_at: str,
    format_detected: str,
    total_lines: int,
    parsed_count: int,
    skipped_count: int,
    processed_count: int,
    errors: List[Dict[str, Any]],
    db_path: Optional[str] = None,
) -> None:
    with get_connection(db_path) as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO ingestion_batches (
                batch_id, created_at, format_detected, total_lines,
                parsed_count, skipped_count, processed_count, errors_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                batch_id,
                created_at,
                format_detected,
                total_lines,
                parsed_count,
                skipped_count,
                processed_count,
                json.dumps(errors),
            ),
        )


def get_ingestion_batches(db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    with get_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM ingestion_batches ORDER BY created_at DESC"
        ).fetchall()
    return [
        {
            "batch_id": r["batch_id"],
            "created_at": r["created_at"],
            "format_detected": r["format_detected"],
            "total_lines": r["total_lines"],
            "parsed_count": r["parsed_count"],
            "skipped_count": r["skipped_count"],
            "processed_count": r["processed_count"],
            "errors": json.loads(r["errors_json"]),
        }
        for r in rows
    ]
