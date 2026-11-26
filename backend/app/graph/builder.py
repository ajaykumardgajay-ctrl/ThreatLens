"""Directed attack graph reconstruction using NetworkX."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import networkx as nx

from app.correlation.engine import CorrelationCluster
from app.schemas.models import AttackGraph, CanonicalEvent, Finding, GraphEdge, GraphNode


def _parse_iso(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)


def _stage_label(ev: CanonicalEvent, finding_cats: List[str]) -> str:
    if "brute_force" in finding_cats and ev.status == "failure":
        return f"Brute-Force Burst ({ev.user})"
    if ev.action == "ssh_login_success" or "impossible_travel" in finding_cats:
        return f"Suspicious Login ({ev.user})"
    if ev.action == "privilege_grant" or "privilege_escalation" in finding_cats:
        target = f" -> {ev.target_user}" if ev.target_user else ""
        return f"Privilege Escalation ({ev.user}{target})"
    if "sensitive_resource_access" in finding_cats:
        return f"Sensitive Access ({ev.resource.split('/')[-1] or ev.resource})"
    if "data_exfiltration" in finding_cats or (
        ev.bytes_out >= 10 * 1024 * 1024 and "ml_anomaly" not in finding_cats
    ):
        mb = ev.bytes_out / (1024 * 1024)
        return f"Outbound Exfiltration ({mb:.1f} MB)"
    if "ml_anomaly" in finding_cats:
        return f"Behavioral Anomaly (ML) ({ev.user})"
    return f"{ev.action} ({ev.user})"


def build_attack_graph(
    incident_id: str,
    cluster: CorrelationCluster,
    event_map: Dict[str, CanonicalEvent],
) -> AttackGraph:
    """Construct a typed NetworkX DiGraph of entities, events, and causal relationships."""
    nx_graph = nx.DiGraph()
    nodes_dict: Dict[str, GraphNode] = {}
    edges_list: List[GraphEdge] = []
    edge_dedup: Dict[Tuple[str, str, str], GraphEdge] = {}

    # Map event_id -> finding categories & highest severity
    ev_findings: Dict[str, List[Finding]] = {}
    for f in cluster.findings:
        for eid in f.supporting_event_ids:
            ev_findings.setdefault(eid, []).append(f)

    def ensure_node(
        node_id: str,
        node_type: str,
        label: str,
        timestamp: Optional[str] = None,
        severity: Optional[str] = None,
        is_suspicious: bool = False,
        event_id: Optional[str] = None,
        metadata: Optional[Dict[str, object]] = None,
    ) -> None:
        if node_id not in nodes_dict:
            nodes_dict[node_id] = GraphNode(
                id=node_id,
                node_type=node_type,  # type: ignore[arg-type]
                label=label,
                timestamp=timestamp,
                severity=severity,
                is_suspicious=is_suspicious,
                event_ids=[event_id] if event_id else [],
                metadata=metadata or {},
            )
            nx_graph.add_node(node_id, node_type=node_type, label=label)
        else:
            existing = nodes_dict[node_id]
            if event_id and event_id not in existing.event_ids:
                existing.event_ids.append(event_id)
            if is_suspicious:
                existing.is_suspicious = True

    def add_edge(
        source: str,
        target: str,
        relationship_type: str,
        event_id: str,
        timestamp: str,
        time_diff: float,
        reason: str,
        confidence: float,
    ) -> str:
        key = (source, target, relationship_type)
        if key in edge_dedup:
            existing = edge_dedup[key]
            if event_id not in existing.supporting_event_ids:
                existing.supporting_event_ids.append(event_id)
            return existing.id

        edge_id = f"edge_{len(edges_list) + 1:03d}"
        edge = GraphEdge(
            id=edge_id,
            source=source,
            target=target,
            relationship_type=relationship_type,  # type: ignore[arg-type]
            supporting_event_ids=[event_id],
            timestamp=timestamp,
            time_difference_seconds=round(max(0.0, time_diff), 2),
            correlation_reason=reason,
            confidence=round(confidence, 2),
        )
        edge_dedup[key] = edge
        edges_list.append(edge)
        nx_graph.add_edge(source, target, relationship_type=relationship_type, edge_id=edge_id)
        return edge_id

    stage_events = sorted(cluster.stage_events, key=lambda e: (e.timestamp, e.event_id))
    # Filter out historical baseline login from primary attack spine if it's purely prior geo context
    # while still keeping it in graph as context node if present in stage_events
    stage_event_node_ids: List[str] = []
    attack_path_edge_ids: List[str] = []

    for ev in stage_events:
        linked_findings = ev_findings.get(ev.event_id, [])
        cats = [f.detector_category for f in linked_findings]
        sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        top_sev = max(
            (f.severity for f in linked_findings),
            key=lambda s: sev_order.get(s, 0),
            default="medium",
        )

        # User node
        user_node_id = f"user:{ev.user}"
        ensure_node(
            user_node_id,
            "User",
            ev.user,
            is_suspicious=True,
            event_id=ev.event_id,
            metadata={"account": ev.user},
        )

        # Event node
        ev_node_id = f"event:{ev.event_id}"
        stage_event_node_ids.append(ev_node_id)
        ensure_node(
            ev_node_id,
            "Event",
            _stage_label(ev, cats),
            timestamp=ev.timestamp,
            severity=top_sev,
            is_suspicious=True,
            event_id=ev.event_id,
            metadata={
                "action": ev.action,
                "status": ev.status,
                "raw_log": ev.raw_log,
                "categories": cats,
            },
        )

        # User -> PERFORMED -> Event
        e_perf = add_edge(
            user_node_id,
            ev_node_id,
            "PERFORMED",
            ev.event_id,
            ev.timestamp,
            0.0,
            f"Account '{ev.user}' executed action '{ev.action}'",
            0.95,
        )
        attack_path_edge_ids.append(e_perf)

        # Source IP -> AUTHENTICATED_FROM (User <-> IP)
        if ev.src_ip:
            ip_node_id = f"ip:{ev.src_ip}"
            ensure_node(
                ip_node_id,
                "IP address",
                f"{ev.src_ip}" + (f" ({ev.geo})" if ev.geo else ""),
                is_suspicious=ev.source_type == "auth",
                event_id=ev.event_id,
                metadata={"ip": ev.src_ip, "geo": ev.geo},
            )
            if ev.source_type == "auth" or "login" in ev.action.lower():
                add_edge(
                    user_node_id,
                    ip_node_id,
                    "AUTHENTICATED_FROM",
                    ev.event_id,
                    ev.timestamp,
                    0.0,
                    f"Authentication event from source IP {ev.src_ip}"
                    + (f" ({ev.geo})" if ev.geo else ""),
                    0.92,
                )

        # Host node
        if ev.hostname and ev.hostname != "unknown":
            host_node_id = f"host:{ev.hostname}"
            ensure_node(
                host_node_id,
                "Host",
                ev.hostname,
                is_suspicious=False,
                event_id=ev.event_id,
                metadata={"hostname": ev.hostname},
            )
            add_edge(
                ev_node_id,
                host_node_id,
                "EXECUTED",
                ev.event_id,
                ev.timestamp,
                0.0,
                f"Event occurred on host '{ev.hostname}'",
                0.95,
            )

        # Session node
        if ev.session_id:
            sess_node_id = f"session:{ev.session_id}"
            ensure_node(
                sess_node_id,
                "Session",
                ev.session_id,
                is_suspicious=False,
                event_id=ev.event_id,
                metadata={"session_id": ev.session_id},
            )
            add_edge(
                ev_node_id,
                sess_node_id,
                "EXECUTED",
                ev.event_id,
                ev.timestamp,
                0.0,
                f"Bound to session '{ev.session_id}'",
                0.90,
            )

        # Identity transition: User -> ESCALATED_TO -> Target User
        if ev.target_user:
            target_node_id = f"user:{ev.target_user}"
            ensure_node(
                target_node_id,
                "User",
                ev.target_user,
                is_suspicious=True,
                event_id=ev.event_id,
                metadata={"account": ev.target_user, "escalated_from": ev.user},
            )
            e_esc = add_edge(
                user_node_id,
                target_node_id,
                "ESCALATED_TO",
                ev.event_id,
                ev.timestamp,
                0.0,
                f"Privilege pivot: '{ev.user}' granted elevated permissions to '{ev.target_user}' via '{ev.resource}'",
                0.96,
            )
            attack_path_edge_ids.append(e_esc)

        # Resource access node (file / sensitive target / command)
        if ev.resource and (
            "sensitive_resource_access" in cats
            or ev.resource.startswith("/")
            or "payroll" in ev.resource.lower()
        ):
            res_node_id = f"resource:{ev.resource}"
            ensure_node(
                res_node_id,
                "Resource",
                ev.resource,
                is_suspicious="sensitive_resource_access" in cats,
                event_id=ev.event_id,
                metadata={"resource": ev.resource},
            )
            e_acc = add_edge(
                ev_node_id,
                res_node_id,
                "ACCESSED",
                ev.event_id,
                ev.timestamp,
                0.0,
                f"Account '{ev.user}' accessed resource '{ev.resource}'",
                0.92,
            )
            if "sensitive_resource_access" in cats:
                attack_path_edge_ids.append(e_acc)

        # External endpoint transfer
        if ev.bytes_out > 0 and (ev.dest_ip or "data_exfiltration" in cats):
            ext_label = ev.dest_ip or ev.resource or "external-endpoint"
            ext_node_id = f"ext:{ext_label}"
            mb = ev.bytes_out / (1024 * 1024)
            ensure_node(
                ext_node_id,
                "External endpoint",
                f"{ext_label} ({mb:.1f} MB)",
                is_suspicious="data_exfiltration" in cats,
                event_id=ev.event_id,
                metadata={"dest_ip": ev.dest_ip, "bytes_out": ev.bytes_out},
            )
            e_tx = add_edge(
                ev_node_id,
                ext_node_id,
                "TRANSFERRED_TO",
                ev.event_id,
                ev.timestamp,
                0.0,
                f"Outbound transfer of {mb:.1f} MB to external endpoint {ext_label}",
                0.93,
            )
            attack_path_edge_ids.append(e_tx)

    # Sequential CORRELATED_WITH edges connecting consecutive stage events
    for prev_ev, curr_ev in zip(stage_events, stage_events[1:]):
        dt = (_parse_iso(curr_ev.timestamp) - _parse_iso(prev_ev.timestamp)).total_seconds()
        reason_parts = []
        if prev_ev.target_user and prev_ev.target_user == curr_ev.user:
            reason_parts.append(
                f"Privilege pivot from '{prev_ev.user}' to '{curr_ev.user}'"
            )
        elif prev_ev.user == curr_ev.user:
            reason_parts.append(f"Same account '{curr_ev.user}'")

        ips_prev = {ip for ip in (prev_ev.src_ip, prev_ev.dest_ip) if ip}
        ips_curr = {ip for ip in (curr_ev.src_ip, curr_ev.dest_ip) if ip}
        shared_ips = ips_prev & ips_curr
        if shared_ips:
            reason_parts.append(f"Shared IP {sorted(shared_ips)[0]}")
        if prev_ev.session_id and prev_ev.session_id == curr_ev.session_id:
            reason_parts.append(f"Shared session {prev_ev.session_id}")
        if not reason_parts:
            reason_parts.append(f"Correlated within {int(dt)}s on host {curr_ev.hostname}")

        e_corr = add_edge(
            f"event:{prev_ev.event_id}",
            f"event:{curr_ev.event_id}",
            "CORRELATED_WITH",
            curr_ev.event_id,
            curr_ev.timestamp,
            dt,
            "; ".join(reason_parts),
            0.91,
        )
        attack_path_edge_ids.append(e_corr)

    attack_path_nodes = list(
        dict.fromkeys(
            stage_event_node_ids
            + [nid for nid, n in nodes_dict.items() if n.node_type in ("User", "Resource", "External endpoint")]
        )
    )

    return AttackGraph(
        incident_id=incident_id,
        nodes=list(nodes_dict.values()),
        edges=edges_list,
        attack_path_node_ids=attack_path_nodes,
        attack_path_edge_ids=list(dict.fromkeys(attack_path_edge_ids)),
    )
