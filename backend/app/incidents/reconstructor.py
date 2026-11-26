"""Incident reconstruction and full pipeline orchestration."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

from app.config import settings
from app.correlation.engine import CorrelationCluster, correlate_findings
from app.detectors.rules import run_all_rule_detectors
from app.graph.builder import build_attack_graph
from app.ml.anomaly import ml_detector
from app.ml.ml_anomaly import score_events_ml
from app.schemas.models import (
    AttackGraph,
    CanonicalEvent,
    Finding,
    IncidentDetail,
    TimelineEntry,
)
from app.scoring.engine import calculate_risk_score


def _parse_iso(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)


def _classify_stage_name(ev: CanonicalEvent, cats: List[str]) -> str:
    if "brute_force" in cats and ev.status == "failure":
        return "Credential Brute Force"
    if "impossible_travel" in cats or ev.action == "ssh_login_success":
        return "Suspicious Authentication / Initial Access"
    if "privilege_escalation" in cats or ev.action == "privilege_grant":
        return "Privilege Escalation & Identity Pivot"
    if "sensitive_resource_access" in cats:
        return "Sensitive Resource Access"
    if "data_exfiltration" in cats or (ev.bytes_out >= 10 * 1024 * 1024 and "ml_anomaly" not in cats):
        return "Data Exfiltration"
    if "unusual_login_time" in cats:
        return "Off-Hours Authentication"
    if "ml_anomaly" in cats:
        return "Behavioral Anomaly (ML)"
    return "Anomalous Activity"


def _build_timeline(
    cluster: CorrelationCluster,
    graph: AttackGraph,
    event_map: Dict[str, CanonicalEvent],
) -> List[TimelineEntry]:
    ev_findings: Dict[str, List[Finding]] = {}
    for f in cluster.findings:
        for eid in f.supporting_event_ids:
            ev_findings.setdefault(eid, []).append(f)

    # Index edges by source/target event node
    node_edges: Dict[str, List[str]] = {}
    corr_edges: Dict[Tuple[str, str], Tuple[str, str, float]] = {}
    for edge in graph.edges:
        node_edges.setdefault(edge.source, []).append(edge.id)
        node_edges.setdefault(edge.target, []).append(edge.id)
        if edge.relationship_type == "CORRELATED_WITH":
            corr_edges[(edge.source, edge.target)] = (
                edge.id,
                edge.correlation_reason,
                edge.time_difference_seconds,
            )

    stage_events = sorted(cluster.stage_events, key=lambda e: (e.timestamp, e.event_id))
    entries: List[TimelineEntry] = []

    for idx, ev in enumerate(stage_events, start=1):
        linked = ev_findings.get(ev.event_id, [])
        cats = [f.detector_category for f in linked]
        stage = _classify_stage_name(ev, cats)
        ev_node = f"event:{ev.event_id}"

        highlight_nodes = [ev_node, f"user:{ev.user}"]
        if ev.target_user:
            highlight_nodes.append(f"user:{ev.target_user}")
        if ev.src_ip:
            highlight_nodes.append(f"ip:{ev.src_ip}")
        if ev.hostname and ev.hostname != "unknown":
            highlight_nodes.append(f"host:{ev.hostname}")
        if ev.session_id:
            highlight_nodes.append(f"session:{ev.session_id}")
        if ev.resource and (ev.resource.startswith("/") or "sensitive_resource_access" in cats):
            highlight_nodes.append(f"resource:{ev.resource}")
        if ev.bytes_out > 0 and (ev.dest_ip or "data_exfiltration" in cats):
            highlight_nodes.append(f"ext:{ev.dest_ip or ev.resource or 'external-endpoint'}")

        highlight_edges = list(node_edges.get(ev_node, []))

        rel_prev = "Initial observed stage in reconstructed chain."
        if idx > 1:
            prev_ev = stage_events[idx - 2]
            prev_node = f"event:{prev_ev.event_id}"
            dt = (_parse_iso(ev.timestamp) - _parse_iso(prev_ev.timestamp)).total_seconds()
            corr_info = corr_edges.get((prev_node, ev_node))
            if corr_info:
                corr_edge_id, corr_reason, corr_dt = corr_info
                if corr_edge_id not in highlight_edges:
                    highlight_edges.append(corr_edge_id)
                rel_prev = f"+{int(corr_dt)}s after previous stage ({corr_reason})"
            else:
                rel_prev = f"+{int(dt)}s after previous stage"

        # Grounded explanation using actual finding or event attributes
        if linked:
            primary_f = sorted(linked, key=lambda f: f.confidence, reverse=True)[0]
            explanation = f"{primary_f.description} [Event {ev.event_id}]"
        else:
            explanation = (
                f"Account '{ev.user}' performed '{ev.action}' on {ev.hostname} "
                f"(status={ev.status}) [Event {ev.event_id}]."
            )

        entries.append(
            TimelineEntry(
                step_index=idx,
                event_id=ev.event_id,
                timestamp=ev.timestamp,
                stage=stage,
                user=ev.user,
                target_user=ev.target_user,
                src_ip=ev.src_ip,
                dest_ip=ev.dest_ip,
                hostname=ev.hostname,
                action=ev.action,
                resource=ev.resource,
                status=ev.status,
                bytes_out=ev.bytes_out,
                raw_log=ev.raw_log,
                finding_ids=[f.finding_id for f in linked],
                highlight_node_ids=list(dict.fromkeys(highlight_nodes)),
                highlight_edge_ids=list(dict.fromkeys(highlight_edges)),
                relationship_to_previous=rel_prev,
                explanation=explanation,
                rule_score=ev.rule_score,
                ml_anomaly_score=ev.ml_anomaly_score,
                final_event_risk=ev.final_event_risk,
                ml_reasons=ev.ml_reasons,
                ml_feature_deviations=ev.ml_feature_deviations,
            )
        )

    return entries


def _build_incident_title_and_summary(
    incident_id: str,
    cluster: CorrelationCluster,
    timeline: List[TimelineEntry],
    accounts: List[str],
    hosts: List[str],
    ips: List[str],
    stages: List[str],
    risk_score: int,
) -> Tuple[str, str, List[Dict[str, Any]]]:
    has_bf = any(f.detector_category == "brute_force" for f in cluster.findings)
    has_pe = any(f.detector_category == "privilege_escalation" for f in cluster.findings)
    has_exf = any(f.detector_category == "data_exfiltration" for f in cluster.findings)

    if has_bf and has_pe and has_exf:
        title = f"Multi-Stage Compromise & Data Exfiltration ({' -> '.join(accounts[:2])})"
    elif has_pe and has_exf:
        title = f"Privilege Escalation & Outbound Exfiltration ({accounts[0]})"
    elif has_bf:
        title = f"Credential Brute-Force & Suspicious Access ({accounts[0]})"
    elif has_exf:
        title = f"Anomalous Outbound Data Transfer ({accounts[0]})"
    else:
        title = f"Correlated Security Incident ({accounts[0]})"

    claims: List[Dict[str, Any]] = []
    for step in timeline:
        claims.append(
            {
                "stage": step.stage,
                "claim": step.explanation,
                "timestamp": step.timestamp,
                "supporting_event_ids": [step.event_id],
                "finding_ids": step.finding_ids,
            }
        )

    summary_parts = [
        f"{incident_id} spans {len(timeline)} correlated attack stages across accounts "
        f"{', '.join(accounts)} on host(s) {', '.join(hosts) or 'unknown'} "
        f"(prioritisation score {risk_score}/100)."
    ]
    for step in timeline:
        summary_parts.append(f"[{step.timestamp}] {step.stage}: {step.explanation}")

    return title, " ".join(summary_parts), claims


def run_detection_and_reconstruction(
    events: List[CanonicalEvent],
) -> Tuple[List[Finding], List[IncidentDetail], Dict[str, Any]]:
    """Run the full hybrid detection -> per-event ML -> correlation -> graph -> scoring pipeline."""
    if not events:
        return [], [], {"status": "empty", "observations_scored": 0, "anomalies_flagged": 0, "user_scores": []}

    event_map = {e.event_id: e for e in events}
    rule_findings = run_all_rule_detectors(events)

    # 1. Compute per-event rule_score (0-100) from deterministic findings
    sev_scores = {"critical": 92.0, "high": 76.0, "medium": 54.0, "low": 32.0}
    ev_rule_cats: Dict[str, List[Tuple[str, float]]] = {}
    for f in rule_findings:
        base_s = sev_scores.get(f.severity, 40.0)
        for eid in f.supporting_event_ids:
            ev_rule_cats.setdefault(eid, []).append((f.detector_category, base_s))

    # 2. Per-event explainable ML scoring (Pandas + RobustScaler + IsolationForest)
    ml_threshold = float(getattr(settings, "ml_anomaly_threshold", 60.0))
    ml_per_event = score_events_ml(events, threshold=ml_threshold)

    # 3. Combine into unified final_event_risk and enrich CanonicalEvent objects
    rule_covered_eids = set(ev_rule_cats.keys())
    ml_only_findings: List[Finding] = []

    for ev in events:
        cats_scores = ev_rule_cats.get(ev.event_id, [])
        if cats_scores:
            distinct_cats = {c for c, _ in cats_scores}
            r_score = min(100.0, max(s for _, s in cats_scores) + 5.0 * max(0, len(distinct_cats) - 1))
        else:
            r_score = 0.0

        ml_info = ml_per_event.get(ev.event_id, {})
        m_score = float(ml_info.get("ml_anomaly_score", 0.0))
        m_reasons = list(ml_info.get("ml_reasons", []))
        m_devs = list(ml_info.get("ml_feature_deviations", []))

        boost = 15.0 if (r_score > 0.0 and m_score >= ml_threshold) else 0.0
        combined = min(100.0, round(0.6 * r_score + 0.4 * m_score + boost, 1))

        ev.rule_score = round(r_score, 1)
        ev.ml_anomaly_score = round(m_score, 1)
        ev.final_event_risk = combined
        ev.ml_reasons = m_reasons
        ev.ml_feature_deviations = m_devs

        # Events that trigger ONLY the ML layer surface in findings, timeline, and attack graph
        if ev.event_id not in rule_covered_eids and m_score >= ml_threshold:
            digest = hashlib.sha1(f"ML-EVT:{ev.event_id}".encode("utf-8")).hexdigest()[:8].upper()
            sev = "high" if m_score >= 80.0 else "medium"
            reason_text = "; ".join(m_reasons[:3]) if m_reasons else "Multi-feature statistical deviation"
            ml_only_findings.append(
                Finding(
                    finding_id=f"FND-ML-{digest}",
                    detector_name="Behavioral Anomaly (ML)",
                    detector_category="ml_anomaly",
                    detection_source="ml",
                    severity=sev,
                    timestamp=ev.timestamp,
                    affected_user=ev.user,
                    src_ip=ev.src_ip,
                    hostname=ev.hostname,
                    description=(
                        f"Behavioral Anomaly (ML) flagged event {ev.event_id} for '{ev.user}' "
                        f"(ML score {m_score:.1f}/100): {reason_text}."
                    ),
                    triggered_condition=f"ml_anomaly_score ({m_score:.1f}) >= threshold ({ml_threshold:.0f})",
                    supporting_event_ids=[ev.event_id],
                    raw_log_references=[ev.raw_log],
                    confidence=round(min(0.92, max(0.55, m_score / 100.0)), 2),
                    confidence_label="medium-high" if m_score >= 75.0 else "medium",
                    anomaly_score=round(m_score / 100.0, 3),
                    feature_contributions=m_devs[:6],
                    rule_score=0.0,
                    final_event_risk=combined,
                    ml_reasons=m_reasons,
                    is_synthetic=ev.is_synthetic,
                )
            )

    # Enrich rule findings with peak ML score, ml_reasons, and hybrid final_event_risk
    for f in rule_findings:
        sup_evs = [event_map[eid] for eid in f.supporting_event_ids if eid in event_map]
        if sup_evs:
            f.rule_score = round(max(e.rule_score for e in sup_evs), 1)
            peak_ml = max(e.ml_anomaly_score for e in sup_evs)
            f.anomaly_score = round(peak_ml / 100.0, 3)
            f.final_event_risk = round(max(e.final_event_risk for e in sup_evs), 1)
            best_ev = max(sup_evs, key=lambda e: e.ml_anomaly_score)
            f.ml_reasons = best_ev.ml_reasons
            if best_ev.ml_feature_deviations:
                f.feature_contributions = best_ev.ml_feature_deviations[:6]

    ml_result = ml_detector.score_events(events)
    all_findings = sorted(
        rule_findings + ml_only_findings,
        key=lambda f: (-f.final_event_risk, f.timestamp),
    )
    clusters = correlate_findings(all_findings, events)

    # Pre-score clusters to order highest combined risk first
    scored_clusters = []
    for cluster in clusters:
        breakdown = calculate_risk_score(cluster.findings)
        ev_objs_tmp = [event_map[eid] for eid in cluster.all_evidence_event_ids if eid in event_map]
        peak_ml_inc = round(max((e.ml_anomaly_score for e in ev_objs_tmp), default=0.0), 1)
        inc_rule = float(breakdown.total_score)
        inc_boost = 12.0 if (inc_rule > 0.0 and peak_ml_inc >= ml_threshold) else 0.0
        combined_inc = min(100.0, round(0.6 * inc_rule + 0.4 * peak_ml_inc + inc_boost, 1))
        scored_clusters.append((combined_inc, breakdown.total_score, cluster, breakdown, peak_ml_inc))

    scored_clusters.sort(key=lambda item: (-item[0], -item[1], item[2].findings[0].timestamp))

    incidents: List[IncidentDetail] = []
    for idx, (combined_inc, _, cluster, breakdown, peak_ml_inc) in enumerate(scored_clusters):
        inc_num = 41 + idx
        incident_id = f"INC-2026-{inc_num:03d}"

        for f in cluster.findings:
            f.incident_id = incident_id

        graph = build_attack_graph(incident_id, cluster, event_map)
        timeline = _build_timeline(cluster, graph, event_map)

        ev_objs = [event_map[eid] for eid in cluster.all_evidence_event_ids if eid in event_map]
        ev_objs.sort(key=lambda e: e.timestamp)

        accounts: List[str] = []
        for e in cluster.stage_events:
            if e.user and e.user != "unknown" and e.user not in accounts:
                accounts.append(e.user)
            if e.target_user and e.target_user not in accounts:
                accounts.append(e.target_user)
        if not accounts:
            accounts = sorted({f.affected_user for f in cluster.findings})

        hosts = sorted({e.hostname for e in ev_objs if e.hostname and e.hostname != "unknown"})
        ips = sorted({ip for e in ev_objs for ip in (e.src_ip, e.dest_ip) if ip})
        stages = list(dict.fromkeys(step.stage for step in timeline))

        first_obs = ev_objs[0].timestamp if ev_objs else cluster.findings[0].timestamp
        last_obs = ev_objs[-1].timestamp if ev_objs else cluster.findings[-1].timestamp

        title, explanation, claims = _build_incident_title_and_summary(
            incident_id,
            cluster,
            timeline,
            accounts,
            hosts,
            ips,
            stages,
            breakdown.total_score,
        )

        incidents.append(
            IncidentDetail(
                incident_id=incident_id,
                title=title,
                risk_score=breakdown.total_score,
                severity=breakdown.severity,
                first_observed=first_obs,
                last_observed=last_obs,
                affected_accounts=accounts,
                affected_hosts=hosts,
                source_ips=ips,
                attack_stages=stages,
                evidence_count=len(cluster.all_evidence_event_ids),
                finding_count=len(cluster.findings),
                is_synthetic=any(f.is_synthetic for f in cluster.findings),
                rule_score=float(breakdown.total_score),
                ml_anomaly_score=peak_ml_inc,
                combined_risk_score=combined_inc,
                explanation=explanation,
                summary_claims=claims,
                score_breakdown=breakdown,
                findings=cluster.findings,
                timeline=timeline,
                graph=graph,
                evidence_event_ids=cluster.all_evidence_event_ids,
            )
        )

    return all_findings, incidents, ml_result
