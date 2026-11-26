"""Event correlation engine using NetworkX to reconstruct connected multi-stage incidents."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

import networkx as nx

from app.config import settings
from app.schemas.models import CanonicalEvent, Finding


def _parse_iso(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)


@dataclass
class CorrelationCluster:
    """A connected component of correlated findings, anchor events, and pivot links."""

    findings: List[Finding] = field(default_factory=list)
    stage_events: List[CanonicalEvent] = field(default_factory=list)
    all_evidence_event_ids: List[str] = field(default_factory=list)
    pivot_links: List[Dict[str, object]] = field(default_factory=list)


def _select_stage_anchor_event(
    finding: Finding, event_map: Dict[str, CanonicalEvent]
) -> Optional[CanonicalEvent]:
    """Choose the primary anchor event representing a finding in timeline/graph stages."""
    evs = [event_map[eid] for eid in finding.supporting_event_ids if eid in event_map]
    if not evs:
        return None
    evs.sort(key=lambda e: e.timestamp)

    if finding.detector_category == "brute_force":
        # Pick the last failed attempt in the burst as the brute-force stage anchor
        # (any subsequent successful login will have its own impossible_travel or login stage)
        failures = [e for e in evs if e.status == "failure"]
        return failures[-1] if failures else evs[-1]

    if finding.detector_category == "impossible_travel":
        # Anchor on the suspicious destination login (second event)
        return evs[-1]

    if finding.detector_category == "data_exfiltration":
        return max(evs, key=lambda e: e.bytes_out)

    return evs[-1]


def _events_have_entity_link(
    a: CanonicalEvent,
    b: CanonicalEvent,
    fa: Optional[Finding] = None,
    fb: Optional[Finding] = None,
) -> Optional[Tuple[str, float]]:
    """Determine if two events share an explicit security-relevant entity or pivot relationship."""
    # 1. Explicit identity transition / privilege pivot (A grants privilege to B's user, or vice versa)
    if a.target_user and b.user and a.target_user == b.user and a.user != b.user:
        return (
            f"Identity pivot: '{a.user}' granted elevated privileges to '{b.user}'",
            0.96,
        )
    if b.target_user and a.user and b.target_user == a.user and b.user != a.user:
        return (
            f"Identity pivot: '{b.user}' granted elevated privileges to '{a.user}'",
            0.96,
        )

    # 2. Same user identity (excluding unknown)
    if a.user and b.user and a.user != "unknown" and a.user == b.user:
        return (f"Shared user identity '{a.user}'", 0.90)

    # 3. IP pivot: shared src_ip, or src_ip matches dest_ip (e.g. attacker IP becomes exfil target)
    ips_a = {ip for ip in (a.src_ip, a.dest_ip) if ip and not ip.startswith("127.")}
    ips_b = {ip for ip in (b.src_ip, b.dest_ip) if ip and not ip.startswith("127.")}
    shared_ips = ips_a & ips_b
    if shared_ips:
        ip_str = sorted(shared_ips)[0]
        return (f"Shared external/network IP pivot ({ip_str})", 0.89)

    # 4. Shared session ID
    if a.session_id and b.session_id and a.session_id == b.session_id:
        return (f"Shared session identifier '{a.session_id}'", 0.92)

    # 5. Same host + same PID
    if (
        a.hostname
        and b.hostname
        and a.hostname != "unknown"
        and a.hostname == b.hostname
        and a.pid
        and b.pid
        and a.pid == b.pid
    ):
        return (f"Shared host '{a.hostname}' and process PID {a.pid}", 0.86)

    # 6. Same host + shared non-trivial resource
    if (
        a.hostname
        and b.hostname
        and a.hostname != "unknown"
        and a.hostname == b.hostname
        and a.resource
        and b.resource
        and a.resource == b.resource
    ):
        return (f"Shared host '{a.hostname}' and resource '{a.resource}'", 0.84)

    # 7. Overlapping supporting event IDs across findings
    if fa and fb:
        overlap = set(fa.supporting_event_ids) & set(fb.supporting_event_ids)
        if overlap:
            return (f"Shared supporting event ({sorted(overlap)[0]})", 0.93)

    return None


def correlate_findings(
    findings: List[Finding],
    events: List[CanonicalEvent],
    correlation_window_minutes: Optional[int] = None,
) -> List[CorrelationCluster]:
    """Correlate findings and their anchor events into connected incident clusters via NetworkX."""
    if not findings:
        return []

    max_minutes = (
        correlation_window_minutes
        if correlation_window_minutes is not None
        else settings.correlation_window_minutes
    )
    max_seconds = max_minutes * 60.0

    event_map: Dict[str, CanonicalEvent] = {e.event_id: e for e in events}
    # Separate rule findings and ML findings so ML findings attach to matching rule clusters
    # rather than bridging unrelated rule clusters solely via shared user over a wider window.
    rule_findings = [f for f in findings if f.detection_source == "rule"]
    ml_findings = [f for f in findings if f.detection_source == "ml"]

    primary_findings = rule_findings if rule_findings else ml_findings
    g = nx.Graph()

    anchors: Dict[str, CanonicalEvent] = {}
    for idx, f in enumerate(primary_findings):
        anchor = _select_stage_anchor_event(f, event_map)
        if anchor is None:
            continue
        anchors[f.finding_id] = anchor
        g.add_node(f.finding_id, finding=f, anchor=anchor)

    node_ids = list(g.nodes())
    for i in range(len(node_ids)):
        for j in range(i + 1, len(node_ids)):
            fid_a, fid_b = node_ids[i], node_ids[j]
            fa: Finding = g.nodes[fid_a]["finding"]
            fb: Finding = g.nodes[fid_b]["finding"]
            ea: CanonicalEvent = g.nodes[fid_a]["anchor"]
            eb: CanonicalEvent = g.nodes[fid_b]["anchor"]

            # Order chronologically
            if ea.timestamp > eb.timestamp:
                fa, fb = fb, fa
                ea, eb = eb, ea
                fid_a, fid_b = fid_b, fid_a

            dt_sec = (_parse_iso(eb.timestamp) - _parse_iso(ea.timestamp)).total_seconds()
            if dt_sec > max_seconds:
                continue

            link = _events_have_entity_link(ea, eb, fa=fa, fb=fb)
            if link:
                reason, conf = link
                g.add_edge(
                    fid_a,
                    fid_b,
                    reason=reason,
                    confidence=conf,
                    time_diff=dt_sec,
                    src_event_id=ea.event_id,
                    dst_event_id=eb.event_id,
                )

    # Also bridge via intermediate host/session/IP context events if a user logged in on host A
    # and another event occurred on host A in same session, already handled by _events_have_entity_link.
    # Now build clusters from connected components.
    clusters: List[CorrelationCluster] = []
    assigned_ml_ids: Set[str] = set()

    for comp in nx.connected_components(g):
        comp_findings: List[Finding] = [g.nodes[nid]["finding"] for nid in comp]
        comp_findings.sort(key=lambda f: f.timestamp)

        # Attach matching ML findings for affected users within correlation window
        comp_users = {f.affected_user for f in comp_findings}
        for f in comp_findings:
            for eid in f.supporting_event_ids:
                ev = event_map.get(eid)
                if ev and ev.target_user:
                    comp_users.add(ev.target_user)

        t_min = min(_parse_iso(f.timestamp) for f in comp_findings)
        t_max = max(_parse_iso(f.timestamp) for f in comp_findings)

        if rule_findings:
            for mf in ml_findings:
                if mf.finding_id in assigned_ml_ids:
                    continue
                if mf.affected_user in comp_users:
                    mt = _parse_iso(mf.timestamp)
                    if (
                        (t_min - mt).total_seconds() <= max_seconds
                        and (mt - t_max).total_seconds() <= max_seconds
                    ):
                        comp_findings.append(mf)
                        assigned_ml_ids.add(mf.finding_id)

        comp_findings.sort(key=lambda f: f.timestamp)

        # Collect unique anchor/stage events + all supporting evidence event IDs
        stage_ev_map: Dict[str, CanonicalEvent] = {}
        evidence_ids: Set[str] = set()
        rule_covered_ids: Set[str] = set()
        for f in comp_findings:
            if f.detection_source == "rule":
                anchor = _select_stage_anchor_event(f, event_map)
                if anchor:
                    stage_ev_map[anchor.event_id] = anchor
                for eid in f.supporting_event_ids:
                    evidence_ids.add(eid)
                    rule_covered_ids.add(eid)

        for f in comp_findings:
            if f.detection_source == "ml":
                for eid in f.supporting_event_ids:
                    evidence_ids.add(eid)
                    if eid not in rule_covered_ids and eid in event_map and f.detector_name == "Behavioral Anomaly (ML)":
                        stage_ev_map[eid] = event_map[eid]

        stage_events = sorted(stage_ev_map.values(), key=lambda e: (e.timestamp, e.event_id))

        # Build explicit pivot links from the correlation graph edges
        pivot_links = []
        sub_g = g.subgraph(comp)
        for u, v, data in sub_g.edges(data=True):
            pivot_links.append(
                {
                    "src_event_id": data["src_event_id"],
                    "dst_event_id": data["dst_event_id"],
                    "reason": data["reason"],
                    "confidence": data["confidence"],
                    "time_diff": data["time_diff"],
                }
            )

        clusters.append(
            CorrelationCluster(
                findings=comp_findings,
                stage_events=stage_events,
                all_evidence_event_ids=sorted(
                    evidence_ids,
                    key=lambda eid: (
                        event_map[eid].timestamp if eid in event_map else "",
                        eid,
                    ),
                ),
                pivot_links=pivot_links,
            )
        )

    # Handle any standalone ML findings that didn't match a rule cluster
    for mf in ml_findings:
        if rule_findings and mf.finding_id not in assigned_ml_ids:
            evs = [event_map[eid] for eid in mf.supporting_event_ids if eid in event_map]
            evs.sort(key=lambda e: e.timestamp)
            clusters.append(
                CorrelationCluster(
                    findings=[mf],
                    stage_events=evs[:5],
                    all_evidence_event_ids=[e.event_id for e in evs],
                    pivot_links=[],
                )
            )

    return clusters
