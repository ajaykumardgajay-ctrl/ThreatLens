"""FastAPI REST API routes for TRACEPOINT."""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import Response

from app.analyzer.summary import SAMPLE_PRESETS, build_analyzer_summary, export_report
from app.assistant.investigator import answer_investigation_question
from app.config import DATA_DIR, settings
from app.database.db import (
    get_all_events,
    get_all_findings,
    get_all_incidents,
    get_incident_by_id,
    get_ingestion_batches,
    replace_findings_and_incidents,
    reset_db,
    save_events,
    save_ingestion_batch,
)
from app.incidents.reconstructor import run_detection_and_reconstruction
from app.ml.anomaly import ml_detector
from app.parsers.router import parse_logs
from app.schemas.models import (
    AnalyzeRequest,
    ConfigUpdateRequest,
    IncidentSummary,
    IngestionReport,
    InvestigationRequest,
    InvestigationResponse,
)

router = APIRouter(prefix="/api", tags=["tracepoint"])


def _recompute_pipeline() -> Dict[str, Any]:
    """Run full detection, ML scoring, correlation, graph, and incident reconstruction on DB events."""
    events = get_all_events()
    findings, incidents, ml_result = run_detection_and_reconstruction(events)
    save_events(events)  # Persist enriched per-event rule_score, ml_anomaly_score, final_event_risk, ml_reasons
    replace_findings_and_incidents(findings, incidents)
    return {
        "events_count": len(events),
        "findings_count": len(findings),
        "incidents_count": len(incidents),
        "ml_result": ml_result,
    }


def _ingest_text_and_analyze(
    raw_text: str,
    log_format: str = "auto",
    filename: Optional[str] = None,
    is_synthetic: bool = False,
    replace_existing: bool = False,
) -> IngestionReport:
    if replace_existing:
        reset_db()

    batch_id = f"batch_{uuid.uuid4().hex[:10]}"
    parsed = parse_logs(
        raw_text,
        log_format=log_format,
        filename=filename,
        batch_id=batch_id,
        is_synthetic=is_synthetic,
    )
    save_events(parsed.events)
    stats = _recompute_pipeline()

    save_ingestion_batch(
        batch_id=batch_id,
        created_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        format_detected=parsed.format_detected,
        total_lines=parsed.total_lines,
        parsed_count=parsed.parsed_count,
        skipped_count=parsed.skipped_count,
        processed_count=stats["events_count"],
        errors=[e.model_dump() for e in parsed.errors[:100]],
    )

    return IngestionReport(
        batch_id=batch_id,
        filename=filename or "pasted_logs",
        format_detected=parsed.format_detected,
        total_lines=parsed.total_lines,
        parsed_count=parsed.parsed_count,
        skipped_count=parsed.skipped_count,
        processed_count=stats["events_count"],
        errors=parsed.errors[:100],
        incidents_detected=stats["incidents_count"],
        findings_generated=stats["findings_count"],
    )


@router.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok", "service": "TRACEPOINT"}


@router.post("/logs/upload", response_model=IngestionReport)
async def upload_logs(
    file: UploadFile = File(...),
    log_format: str = Form("auto"),
    is_synthetic: bool = Form(False),
    replace_existing: bool = Form(True),
) -> IngestionReport:
    content_bytes = await file.read()
    try:
        content = content_bytes.decode("utf-8", errors="replace")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Unable to decode uploaded file: {exc}")
    if not content.strip():
        raise HTTPException(status_code=400, detail="Uploaded log file is empty.")
    return _ingest_text_and_analyze(
        content,
        log_format=log_format,
        filename=file.filename,
        is_synthetic=is_synthetic,
        replace_existing=replace_existing,
    )


@router.post("/logs/analyze", response_model=IngestionReport)
def analyze_logs(payload: AnalyzeRequest) -> IngestionReport:
    if not payload.raw_text.strip():
        raise HTTPException(status_code=400, detail="raw_text cannot be empty.")
    return _ingest_text_and_analyze(
        payload.raw_text,
        log_format=payload.log_format,
        is_synthetic=payload.is_synthetic,
        replace_existing=payload.replace_existing,
    )


@router.get("/logs")
def list_logs(
    source_type: Optional[str] = Query(None),
    user: Optional[str] = Query(None),
    src_ip: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    incident_id: Optional[str] = Query(None),
    q: Optional[str] = Query(None),
    regex: bool = Query(False),
    sort_by: str = Query("timestamp"),
    limit: int = Query(100, ge=1, le=2000),
    offset: int = Query(0, ge=0),
) -> Dict[str, Any]:
    events = get_all_events()
    if incident_id:
        inc = get_incident_by_id(incident_id)
        if not inc:
            raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")
        ev_set = set(inc.evidence_event_ids)
        events = [e for e in events if e.event_id in ev_set]

    if source_type:
        events = [e for e in events if e.source_type == source_type]
    if user:
        events = [e for e in events if user.lower() in e.user.lower()]
    if src_ip:
        events = [e for e in events if src_ip in e.src_ip or src_ip in e.dest_ip]
    if status:
        events = [e for e in events if e.status == status]
    if q:
        if regex:
            try:
                pattern = re.compile(q, re.IGNORECASE)
            except re.error as exc:
                raise HTTPException(status_code=400, detail=f"Invalid regex pattern: {exc}")
            events = [
                e
                for e in events
                if pattern.search(e.raw_log)
                or pattern.search(e.user)
                or pattern.search(e.action)
                or pattern.search(e.resource)
                or pattern.search(e.src_ip)
            ]
        else:
            ql = q.lower()
            events = [
                e
                for e in events
                if ql in e.raw_log.lower()
                or ql in e.user.lower()
                or ql in e.action.lower()
                or ql in e.resource.lower()
                or ql in e.src_ip.lower()
                or ql in e.event_id.lower()
            ]

    if sort_by == "final_event_risk":
        events.sort(key=lambda e: (-e.final_event_risk, -e.ml_anomaly_score, e.timestamp))
    elif sort_by == "ml_anomaly_score":
        events.sort(key=lambda e: (-e.ml_anomaly_score, -e.final_event_risk, e.timestamp))

    total = len(events)
    sliced = events[offset : offset + limit]
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "events": [e.model_dump() for e in sliced],
    }


@router.get("/incidents", response_model=List[IncidentSummary])
def list_incidents() -> List[IncidentSummary]:
    incidents = get_all_incidents()
    return [
        IncidentSummary(
            incident_id=inc.incident_id,
            title=inc.title,
            risk_score=inc.risk_score,
            severity=inc.severity,
            first_observed=inc.first_observed,
            last_observed=inc.last_observed,
            affected_accounts=inc.affected_accounts,
            affected_hosts=inc.affected_hosts,
            source_ips=inc.source_ips,
            attack_stages=inc.attack_stages,
            evidence_count=inc.evidence_count,
            finding_count=inc.finding_count,
            is_synthetic=inc.is_synthetic,
            rule_score=inc.rule_score,
            ml_anomaly_score=inc.ml_anomaly_score,
            combined_risk_score=inc.combined_risk_score,
        )
        for inc in incidents
    ]


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: str) -> Dict[str, Any]:
    inc = get_incident_by_id(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")
    return inc.model_dump()


@router.get("/incidents/{incident_id}/timeline")
def get_incident_timeline(incident_id: str) -> Dict[str, Any]:
    inc = get_incident_by_id(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")
    return {
        "incident_id": inc.incident_id,
        "title": inc.title,
        "total_steps": len(inc.timeline),
        "timeline": [t.model_dump() for t in inc.timeline],
    }


@router.get("/incidents/{incident_id}/graph")
def get_incident_graph(incident_id: str) -> Dict[str, Any]:
    inc = get_incident_by_id(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")
    return inc.graph.model_dump()


@router.get("/incidents/{incident_id}/evidence")
def get_incident_evidence(incident_id: str) -> Dict[str, Any]:
    inc = get_incident_by_id(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")
    all_events = {e.event_id: e for e in get_all_events()}
    evidence_events = [
        all_events[eid].model_dump()
        for eid in inc.evidence_event_ids
        if eid in all_events
    ]
    return {
        "incident_id": inc.incident_id,
        "findings": [f.model_dump() for f in inc.findings],
        "events": evidence_events,
        "score_breakdown": inc.score_breakdown.model_dump(),
        "summary_claims": inc.summary_claims,
    }


@router.get("/findings")
def list_findings(
    detection_source: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    incident_id: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    findings = get_all_findings()
    if detection_source:
        findings = [f for f in findings if f.detection_source == detection_source]
    if category:
        findings = [f for f in findings if f.detector_category == category]
    if severity:
        findings = [f for f in findings if f.severity == severity]
    if incident_id:
        findings = [f for f in findings if f.incident_id == incident_id]
    return [f.model_dump() for f in findings]


@router.get("/metrics")
def get_metrics() -> Dict[str, Any]:
    events = get_all_events()
    findings = get_all_findings()
    incidents = get_all_incidents()
    batches = get_ingestion_batches()
    ml_res = ml_detector.score_events(events) if events else {
        "status": "empty",
        "training_samples": ml_detector.training_samples_count,
        "training_source": ml_detector.last_trained_source,
        "observations_scored": 0,
        "anomalies_flagged": 0,
        "user_scores": [],
    }

    sev_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for inc in incidents:
        sev_dist[inc.severity] = sev_dist.get(inc.severity, 0) + 1

    high_risk_accounts = sorted(
        {
            acct
            for inc in incidents
            if inc.severity in ("critical", "high")
            for acct in inc.affected_accounts
        }
    )

    source_counts = {"auth": 0, "web": 0, "system": 0, "proxy": 0, "firewall": 0, "windows": 0}
    for ev in events:
        source_counts[ev.source_type] = source_counts.get(ev.source_type, 0) + 1

    # Hourly activity histogram for Overview chart
    hourly_buckets: Dict[str, Dict[str, int]] = {}
    for ev in events:
        hr = ev.timestamp[:13] + ":00Z"
        bucket = hourly_buckets.setdefault(hr, {"total": 0, "failures": 0})
        bucket["total"] += 1
        if ev.status == "failure":
            bucket["failures"] += 1
    activity_series = [
        {"hour": k, "total": v["total"], "failures": v["failures"]}
        for k, v in sorted(hourly_buckets.items())
    ]

    return {
        "total_events_processed": len(events),
        "total_findings": len(findings),
        "rule_findings_count": sum(1 for f in findings if f.detection_source == "rule"),
        "ml_findings_count": sum(1 for f in findings if f.detection_source == "ml"),
        "total_incidents": len(incidents),
        "critical_incidents": sev_dist["critical"],
        "high_risk_accounts": high_risk_accounts,
        "severity_distribution": sev_dist,
        "source_distribution": source_counts,
        "activity_series": activity_series,
        "ml_statistics": {
            "is_trained": ml_detector.is_trained,
            "training_samples": ml_detector.training_samples_count,
            "training_source": ml_detector.last_trained_source,
            "observations_scored": ml_res.get("observations_scored", 0),
            "anomalies_flagged": ml_res.get("anomalies_flagged", 0),
            "top_user_scores": ml_res.get("user_scores", [])[:8],
        },
        "recent_batches": batches[:10],
        "has_synthetic_data": any(e.is_synthetic for e in events),
    }


@router.post("/investigate", response_model=InvestigationResponse)
async def investigate(payload: InvestigationRequest) -> InvestigationResponse:
    inc = get_incident_by_id(payload.incident_id)
    if not inc:
        raise HTTPException(
            status_code=404, detail=f"Incident '{payload.incident_id}' not found."
        )
    events_by_id = {e.event_id: e for e in get_all_events()}
    return await answer_investigation_question(inc, events_by_id, payload.question)


@router.post("/demo/load", response_model=IngestionReport)
def load_demo_dataset() -> IngestionReport:
    from data.generate_demo import ensure_demo_dataset

    demo_path = ensure_demo_dataset(DATA_DIR / "synthetic_demo_logs.jsonl")
    reset_db()
    raw_text = demo_path.read_text(encoding="utf-8")
    return _ingest_text_and_analyze(
        raw_text,
        log_format="json",
        filename=demo_path.name,
        is_synthetic=True,
    )


@router.post("/demo/reset")
def reset_demo_environment() -> Dict[str, str]:
    reset_db()
    ml_detector.train_on_baseline()
    return {"status": "reset", "message": "Database cleared and ML baseline reset."}


@router.get("/settings")
def get_runtime_settings() -> Dict[str, Any]:
    return {
        "brute_force_threshold": settings.brute_force_threshold,
        "brute_force_window_seconds": settings.brute_force_window_seconds,
        "impossible_travel_speed_kmh": settings.impossible_travel_speed_kmh,
        "correlation_window_minutes": settings.correlation_window_minutes,
        "outbound_spike_multiplier": settings.outbound_spike_multiplier,
        "ml_anomaly_threshold": settings.ml_anomaly_threshold,
        "score_weights": settings.score_weights,
        "llm_configured": bool(settings.llm_api_key),
    }


@router.put("/settings")
def update_runtime_settings(payload: ConfigUpdateRequest) -> Dict[str, Any]:
    if payload.brute_force_threshold is not None:
        settings.brute_force_threshold = max(2, payload.brute_force_threshold)
    if payload.brute_force_window_seconds is not None:
        settings.brute_force_window_seconds = max(10, payload.brute_force_window_seconds)
    if payload.impossible_travel_speed_kmh is not None:
        settings.impossible_travel_speed_kmh = max(100.0, payload.impossible_travel_speed_kmh)
    if payload.correlation_window_minutes is not None:
        settings.correlation_window_minutes = max(5, payload.correlation_window_minutes)
    if payload.outbound_spike_multiplier is not None:
        settings.outbound_spike_multiplier = max(2.0, payload.outbound_spike_multiplier)
    if payload.ml_anomaly_threshold is not None:
        settings.ml_anomaly_threshold = min(99.0, max(10.0, float(payload.ml_anomaly_threshold)))
    if payload.score_weights:
        settings.score_weights.update(payload.score_weights)

    stats = _recompute_pipeline()
    return {
        "status": "updated",
        "recomputed": {
            "incidents_count": stats["incidents_count"],
            "findings_count": stats["findings_count"],
        },
        "settings": get_runtime_settings(),
    }


@router.post("/ml/retrain")
def retrain_ml_model() -> Dict[str, Any]:
    events = get_all_events()
    info = ml_detector.train_on_baseline(events)
    stats = _recompute_pipeline()
    return {
        "status": "retrained",
        "training": info,
        "incidents_count": stats["incidents_count"],
        "findings_count": stats["findings_count"],
    }


@router.get("/analyzer/summary")
def get_analyzer_summary() -> Dict[str, Any]:
    events = get_all_events()
    findings = get_all_findings()
    incidents = get_all_incidents()
    return build_analyzer_summary(events, findings, incidents)


@router.get("/analyzer/presets")
def list_sample_presets() -> List[Dict[str, str]]:
    return [
        {
            "id": p["id"],
            "name": p["name"],
            "format": p["format"],
            "description": p["description"],
        }
        for p in SAMPLE_PRESETS.values()
    ]


@router.post("/analyzer/presets/{preset_id}", response_model=IngestionReport)
def load_sample_preset(preset_id: str, reset_first: bool = Query(True)) -> IngestionReport:
    preset = SAMPLE_PRESETS.get(preset_id)
    if not preset:
        raise HTTPException(status_code=404, detail=f"Preset '{preset_id}' not found.")
    if reset_first:
        reset_db()
    return _ingest_text_and_analyze(
        preset["raw_text"],
        log_format=preset["format"],
        filename=f"{preset_id}.log",
        is_synthetic=True,
    )


@router.get("/analyzer/export")
def download_report(format: str = Query("pdf")) -> Response:
    events = get_all_events()
    findings = get_all_findings()
    incidents = get_all_incidents()
    content, media_type, filename = export_report(format, events, findings, incidents)
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
