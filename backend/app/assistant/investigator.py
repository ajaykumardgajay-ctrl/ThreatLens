"""Evidence-grounded investigation assistant with deterministic offline engine and optional LLM."""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

import httpx

from app.config import settings
from app.schemas.models import CanonicalEvent, IncidentDetail, InvestigationResponse


def _deterministic_answer(
    incident: IncidentDetail,
    events_by_id: Dict[str, CanonicalEvent],
    question: str,
) -> InvestigationResponse:
    q = question.lower().strip()
    timeline = incident.timeline
    findings = incident.findings
    cited_events: List[str] = []
    cited_findings: List[str] = []
    snippets: List[Dict[str, Any]] = []
    missing_note: Optional[str] = None

    def add_ev_citation(eid: str) -> None:
        if eid not in cited_events:
            cited_events.append(eid)
        ev = events_by_id.get(eid)
        if ev and len(snippets) < 12:
            snippets.append(
                {
                    "event_id": ev.event_id,
                    "timestamp": ev.timestamp,
                    "user": ev.user,
                    "action": ev.action,
                    "raw_log": ev.raw_log,
                }
            )

    # 1. Raw logs request
    if "raw log" in q or "show all logs" in q or "log lines" in q:
        inc_events = [
            events_by_id[eid]
            for eid in incident.evidence_event_ids
            if eid in events_by_id
        ]
        lines = []
        for ev in inc_events[:25]:
            add_ev_citation(ev.event_id)
            lines.append(f"- [{ev.event_id}] ({ev.timestamp}) {ev.raw_log}")
        extra = (
            f"\n\n(Showing 25 of {len(inc_events)} total correlated evidence logs. Use Evidence Explorer for full pagination.)"
            if len(inc_events) > 25
            else ""
        )
        answer = (
            f"Raw log evidence associated with {incident.incident_id} ({len(inc_events)} total events):\n"
            + "\n".join(lines)
            + extra
        )
        return InvestigationResponse(
            incident_id=incident.incident_id,
            question=question,
            answer=answer,
            mode="deterministic",
            cited_event_ids=cited_events,
            cited_finding_ids=[f.finding_id for f in findings],
            evidence_snippets=snippets,
        )

    # 2. Initial entry point
    if any(k in q for k in ("initial entry", "entry point", "how did", "start", "first")):
        if not timeline:
            return InvestigationResponse(
                incident_id=incident.incident_id,
                question=question,
                answer="No timeline events are recorded for this incident.",
                mode="deterministic",
                missing_evidence_note="Incident timeline is empty.",
            )
        bf_findings = [f for f in findings if f.detector_category == "brute_force"]
        login_steps = [
            s for s in timeline
            if "auth" in s.stage.lower() or "login" in s.action.lower() or "brute" in s.stage.lower()
        ]
        parts = [f"Initial entry point for {incident.incident_id}:"]
        if bf_findings:
            bf = bf_findings[0]
            cited_findings.append(bf.finding_id)
            for eid in bf.supporting_event_ids[:4]:
                add_ev_citation(eid)
            parts.append(
                f"1. Credential Brute-Force ({bf.finding_id}): {bf.description} "
                f"(supporting events include {', '.join(bf.supporting_event_ids[:3])}...)."
            )
        for s in login_steps:
            add_ev_citation(s.event_id)
            for fid in s.finding_ids:
                if fid not in cited_findings:
                    cited_findings.append(fid)
            if s.status == "success":
                parts.append(
                    f"2. Successful Access [{s.event_id}] at {s.timestamp}: account '{s.user}' "
                    f"authenticated from {s.src_ip or 'unknown IP'} on host '{s.hostname}'."
                )
        return InvestigationResponse(
            incident_id=incident.incident_id,
            question=question,
            answer="\n".join(parts),
            mode="deterministic",
            cited_event_ids=cited_events,
            cited_finding_ids=cited_findings,
            evidence_snippets=snippets,
        )

    # 3. Systems/resources accessed after privilege escalation (check before generic 'escalat')
    if any(k in q for k in ("after privilege", "systems were accessed", "resources accessed", "files")):
        pe_steps = [s for s in timeline if "privilege" in s.stage.lower()]
        if not pe_steps:
            return InvestigationResponse(
                incident_id=incident.incident_id,
                question=question,
                answer=f"No privilege escalation stage was detected in {incident.incident_id}.",
                mode="deterministic",
                missing_evidence_note="No privilege escalation event found in incident timeline.",
            )
        pe_ts = pe_steps[0].timestamp
        add_ev_citation(pe_steps[0].event_id)
        post_steps = [s for s in timeline if s.timestamp > pe_ts]
        if not post_steps:
            return InvestigationResponse(
                incident_id=incident.incident_id,
                question=question,
                answer=f"Privilege escalation occurred at {pe_ts} [{pe_steps[0].event_id}], with no subsequent correlated steps recorded.",
                mode="deterministic",
                cited_event_ids=cited_events,
                evidence_snippets=snippets,
                missing_evidence_note="No post-escalation events correlated.",
            )
        lines = [
            f"Following privilege escalation at {pe_ts} [{pe_steps[0].event_id}], the following activity was observed:"
        ]
        for s in post_steps:
            add_ev_citation(s.event_id)
            for fid in s.finding_ids:
                if fid not in cited_findings:
                    cited_findings.append(fid)
            lines.append(
                f"- [{s.event_id}] {s.timestamp} | Host: {s.hostname} | User: {s.user} | "
                f"Action: {s.action} | Resource/Target: {s.resource or s.dest_ip or 'N/A'}"
            )
        return InvestigationResponse(
            incident_id=incident.incident_id,
            question=question,
            answer="\n".join(lines),
            mode="deterministic",
            cited_event_ids=cited_events,
            cited_finding_ids=cited_findings,
            evidence_snippets=snippets,
        )

    # 4. Compromised account & privilege pivot
    if any(k in q for k in ("compromised", "which account", "pivot", "escalat")):
        esc_edges = [e for e in incident.graph.edges if e.relationship_type == "ESCALATED_TO"]
        pe_findings = [f for f in findings if f.detector_category == "privilege_escalation"]
        parts = [
            f"Affected accounts in {incident.incident_id}: {', '.join(incident.affected_accounts)}."
        ]
        if pe_findings:
            for f in pe_findings:
                cited_findings.append(f.finding_id)
                for eid in f.supporting_event_ids:
                    add_ev_citation(eid)
                parts.append(f"- {f.detector_name} ({f.finding_id}): {f.description}")
        if esc_edges:
            for edge in esc_edges:
                for eid in edge.supporting_event_ids:
                    add_ev_citation(eid)
                parts.append(
                    f"- Identity transition in attack graph: {edge.source} --[ESCALATED_TO]--> {edge.target} "
                    f"({edge.correlation_reason}; evidence: {', '.join(edge.supporting_event_ids)})."
                )
        else:
            missing_note = "No explicit account-to-account privilege escalation edge was recorded."
        return InvestigationResponse(
            incident_id=incident.incident_id,
            question=question,
            answer="\n".join(parts),
            mode="deterministic",
            cited_event_ids=cited_events,
            cited_finding_ids=cited_findings,
            evidence_snippets=snippets,
            missing_evidence_note=missing_note,
        )

    # 5. Exfiltration evidence
    if any(k in q for k in ("exfiltrat", "outbound", "transfer", "bytes", "data spike")):
        exf_findings = [f for f in findings if f.detector_category == "data_exfiltration"]
        if not exf_findings:
            return InvestigationResponse(
                incident_id=incident.incident_id,
                question=question,
                answer=f"No outbound data exfiltration findings were triggered for {incident.incident_id}.",
                mode="deterministic",
                missing_evidence_note="No data_exfiltration finding exists in this incident.",
            )
        lines = [f"Exfiltration evidence for {incident.incident_id}:"]
        for f in exf_findings:
            cited_findings.append(f.finding_id)
            for eid in f.supporting_event_ids:
                add_ev_citation(eid)
                ev = events_by_id.get(eid)
                raw_info = f" | Raw log: `{ev.raw_log}`" if ev else ""
                lines.append(
                    f"- Finding {f.finding_id}: {f.description} "
                    f"(Condition: {f.triggered_condition}; Event [{eid}]{raw_info})"
                )
        return InvestigationResponse(
            incident_id=incident.incident_id,
            question=question,
            answer="\n".join(lines),
            mode="deterministic",
            cited_event_ids=cited_events,
            cited_finding_ids=cited_findings,
            evidence_snippets=snippets,
        )

    # 6. Why critical / risk score
    if any(k in q for k in ("critical", "why", "risk score", "score", "severity", "classified")):
        sb = incident.score_breakdown
        lines = [
            f"{incident.incident_id} has a risk prioritisation score of {sb.total_score}/{sb.max_score} "
            f"(severity: {sb.severity.upper()}). Note: {sb.scoring_note}",
            "Score breakdown:",
        ]
        for c in sb.contributions:
            for fid in c.finding_ids:
                if fid not in cited_findings:
                    cited_findings.append(fid)
            for eid in c.supporting_event_ids[:3]:
                add_ev_citation(eid)
            sup_note = (
                f" ({c.suppressed_duplicates} duplicate findings suppressed)"
                if c.suppressed_duplicates
                else ""
            )
            lines.append(
                f"- +{c.points} pts | {c.detector_name}: {c.rationale}{sup_note} "
                f"[Evidence: {', '.join(c.supporting_event_ids[:3])}]"
            )
        return InvestigationResponse(
            incident_id=incident.incident_id,
            question=question,
            answer="\n".join(lines),
            mode="deterministic",
            cited_event_ids=cited_events,
            cited_finding_ids=cited_findings,
            evidence_snippets=snippets,
        )

    # 7. Timeline / what happened between first and last event
    if any(k in q for k in ("between", "timeline", "chronolog", "sequence", "happened", "replay", "summary")):
        lines = [
            f"Reconstructed sequence for {incident.incident_id} ({incident.first_observed} to {incident.last_observed}):"
        ]
        for s in timeline:
            add_ev_citation(s.event_id)
            for fid in s.finding_ids:
                if fid not in cited_findings:
                    cited_findings.append(fid)
            lines.append(
                f"{s.step_index}. [{s.timestamp}] {s.stage} — {s.explanation} ({s.relationship_to_previous})"
            )
        return InvestigationResponse(
            incident_id=incident.incident_id,
            question=question,
            answer="\n".join(lines),
            mode="deterministic",
            cited_event_ids=cited_events,
            cited_finding_ids=cited_findings,
            evidence_snippets=snippets,
        )

    # 8. General grounded fallback + explicit gap check
    for s in timeline:
        add_ev_citation(s.event_id)
    for f in findings:
        if f.finding_id not in cited_findings:
            cited_findings.append(f.finding_id)

    # Check if user asked about specific telemetry not present
    if any(tok in q for tok in ("dns", "malware", "edr", "process tree", "registry", "ransomware")):
        missing_note = (
            "The ingested evidence for this incident contains authentication, OS/audit, and network transfer logs; "
            "no DNS, registry, or EDR malware-hash telemetry is present in the incident records."
        )

    answer = (
        f"Grounded summary for {incident.incident_id} ({incident.severity.upper()}, {incident.risk_score}/100):\n"
        f"- Accounts: {', '.join(incident.affected_accounts)}\n"
        f"- Hosts: {', '.join(incident.affected_hosts) or 'unknown'}\n"
        f"- IPs: {', '.join(incident.source_ips) or 'none'}\n"
        f"- Attack stages: {' -> '.join(incident.attack_stages)}\n"
        f"- Evidence count: {incident.evidence_count} events across {incident.finding_count} findings.\n"
        + (f"\nEvidence gap: {missing_note}" if missing_note else "")
    )
    return InvestigationResponse(
        incident_id=incident.incident_id,
        question=question,
        answer=answer,
        mode="deterministic",
        cited_event_ids=cited_events,
        cited_finding_ids=cited_findings,
        evidence_snippets=snippets,
        missing_evidence_note=missing_note,
    )


async def answer_investigation_question(
    incident: IncidentDetail,
    events_by_id: Dict[str, CanonicalEvent],
    question: str,
) -> InvestigationResponse:
    """Answer an analyst question using grounded incident data, with optional LLM synthesis."""
    deterministic = _deterministic_answer(incident, events_by_id, question)
    api_key = settings.llm_api_key or os.getenv("TRACEPOINT_LLM_API_KEY", "")
    if not api_key:
        return deterministic

    # Optional LLM synthesis strictly grounded in retrieved structured context
    context_payload = {
        "incident_id": incident.incident_id,
        "title": incident.title,
        "risk_score": incident.risk_score,
        "severity": incident.severity,
        "affected_accounts": incident.affected_accounts,
        "affected_hosts": incident.affected_hosts,
        "source_ips": incident.source_ips,
        "timeline": [t.model_dump() for t in incident.timeline],
        "findings": [f.model_dump() for f in incident.findings],
        "score_breakdown": incident.score_breakdown.model_dump(),
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"{settings.llm_base_url.rstrip('/')}/chat/completions",
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "model": settings.llm_model,
                    "temperature": 0.1,
                    "messages": [
                        {
                            "role": "system",
                            "content": (
                                "You are TRACEPOINT's cybersecurity investigation assistant. "
                                "Answer strictly from the provided JSON incident evidence. "
                                "Cite supporting event_ids in brackets (e.g. [evt_...]). "
                                "NEVER invent IP addresses, usernames, resources, or timestamps. "
                                "If evidence is missing, explicitly state that it is missing."
                            ),
                        },
                        {
                            "role": "user",
                            "content": f"Incident Data:\n{json.dumps(context_payload)}\n\nAnalyst Question: {question}",
                        },
                    ],
                },
            )
            resp.raise_for_status()
            data = resp.json()
            text = data["choices"][0]["message"]["content"].strip()
            deterministic.answer = text
            deterministic.mode = "llm"
            return deterministic
    except Exception:
        # Clean deterministic fallback if optional LLM fails
        return deterministic
