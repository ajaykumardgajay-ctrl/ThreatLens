"""Pydantic schemas for TRACEPOINT APIs and pipeline components."""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field


SourceType = Literal["auth", "web", "system", "proxy", "firewall", "windows"]
StatusType = Literal["success", "failure", "unknown"]
SeverityType = Literal["critical", "high", "medium", "low"]


class CanonicalEvent(BaseModel):
    """Canonical normalised security log event."""

    event_id: str
    timestamp: str  # ISO-8601
    source_type: SourceType = "system"
    user: str = "unknown"
    src_ip: str = ""
    dest_ip: str = ""
    geo: str = ""
    hostname: str = "unknown"
    session_id: str = ""
    action: str = "unknown"
    resource: str = ""
    status: StatusType = "unknown"
    bytes_out: int = 0
    raw_log: str = ""
    # Optional metadata preserved for correlation (never hides raw_log)
    pid: Optional[str] = None
    target_user: Optional[str] = None
    ingestion_batch: Optional[str] = None
    is_synthetic: bool = False
    rule_score: float = 0.0
    ml_anomaly_score: float = 0.0
    final_event_risk: float = 0.0
    ml_reasons: List[str] = Field(default_factory=list)
    ml_feature_deviations: List[Dict[str, Any]] = Field(default_factory=list)


class ParseErrorItem(BaseModel):
    line_number: int
    raw_line: str
    reason: str


class IngestionReport(BaseModel):
    batch_id: str
    filename: str = ""
    format_detected: str
    total_lines: int
    parsed_count: int
    skipped_count: int
    processed_count: int
    errors: List[ParseErrorItem] = Field(default_factory=list)
    incidents_detected: int = 0
    findings_generated: int = 0


class Finding(BaseModel):
    """Structured finding emitted by rule-based or ML detectors."""

    finding_id: str
    detector_name: str
    detector_category: Literal[
        "brute_force",
        "impossible_travel",
        "unusual_login_time",
        "privilege_escalation",
        "sensitive_resource_access",
        "data_exfiltration",
        "ml_anomaly",
    ]
    detection_source: Literal["rule", "ml"] = "rule"
    severity: SeverityType
    timestamp: str
    affected_user: str
    src_ip: str = ""
    hostname: str = ""
    description: str
    triggered_condition: str
    supporting_event_ids: List[str] = Field(default_factory=list)
    raw_log_references: List[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    confidence_label: str = "high"
    anomaly_score: Optional[float] = None
    feature_contributions: Optional[List[Dict[str, Any]]] = None
    rule_score: float = 0.0
    final_event_risk: float = 0.0
    ml_reasons: List[str] = Field(default_factory=list)
    incident_id: Optional[str] = None
    is_synthetic: bool = False


class GraphNode(BaseModel):
    id: str
    node_type: Literal[
        "User",
        "IP address",
        "Host",
        "Session",
        "Event",
        "Resource",
        "External endpoint",
    ]
    label: str
    timestamp: Optional[str] = None
    severity: Optional[str] = None
    is_suspicious: bool = False
    event_ids: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    relationship_type: Literal[
        "AUTHENTICATED_FROM",
        "PERFORMED",
        "EXECUTED",
        "ESCALATED_TO",
        "ACCESSED",
        "TRANSFERRED_TO",
        "CORRELATED_WITH",
    ]
    supporting_event_ids: List[str] = Field(default_factory=list)
    timestamp: str
    time_difference_seconds: float = 0.0
    correlation_reason: str
    confidence: float = Field(ge=0.0, le=1.0)


class AttackGraph(BaseModel):
    incident_id: str
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)
    attack_path_node_ids: List[str] = Field(default_factory=list)
    attack_path_edge_ids: List[str] = Field(default_factory=list)


class ScoreContribution(BaseModel):
    category: str
    detector_name: str
    points: int
    suppressed_duplicates: int = 0
    finding_ids: List[str] = Field(default_factory=list)
    supporting_event_ids: List[str] = Field(default_factory=list)
    confidence: float
    rationale: str


class RiskScoreBreakdown(BaseModel):
    total_score: int = Field(ge=0, le=100)
    raw_uncapped_score: int = 0
    max_score: int = 100
    severity: SeverityType
    scoring_note: str = (
        "Incident prioritisation score (0-100), not a probability of malicious intent."
    )
    contributions: List[ScoreContribution] = Field(default_factory=list)


class TimelineEntry(BaseModel):
    step_index: int
    event_id: str
    timestamp: str
    stage: str
    user: str
    target_user: Optional[str] = None
    src_ip: str = ""
    dest_ip: str = ""
    hostname: str = ""
    action: str
    resource: str = ""
    status: str = ""
    bytes_out: int = 0
    raw_log: str
    finding_ids: List[str] = Field(default_factory=list)
    highlight_node_ids: List[str] = Field(default_factory=list)
    highlight_edge_ids: List[str] = Field(default_factory=list)
    relationship_to_previous: str = ""
    explanation: str = ""
    rule_score: float = 0.0
    ml_anomaly_score: float = 0.0
    final_event_risk: float = 0.0
    ml_reasons: List[str] = Field(default_factory=list)
    ml_feature_deviations: List[Dict[str, Any]] = Field(default_factory=list)


class IncidentSummary(BaseModel):
    incident_id: str
    title: str
    risk_score: int
    severity: SeverityType
    first_observed: str
    last_observed: str
    affected_accounts: List[str] = Field(default_factory=list)
    affected_hosts: List[str] = Field(default_factory=list)
    source_ips: List[str] = Field(default_factory=list)
    attack_stages: List[str] = Field(default_factory=list)
    evidence_count: int = 0
    finding_count: int = 0
    is_synthetic: bool = False
    rule_score: float = 0.0
    ml_anomaly_score: float = 0.0
    combined_risk_score: float = 0.0


class IncidentDetail(IncidentSummary):
    explanation: str
    summary_claims: List[Dict[str, Any]] = Field(default_factory=list)
    score_breakdown: RiskScoreBreakdown
    findings: List[Finding] = Field(default_factory=list)
    timeline: List[TimelineEntry] = Field(default_factory=list)
    graph: AttackGraph
    evidence_event_ids: List[str] = Field(default_factory=list)


class AnalyzeRequest(BaseModel):
    raw_text: str
    log_format: str = "auto"
    is_synthetic: bool = False
    replace_existing: bool = True


class InvestigationRequest(BaseModel):
    incident_id: str
    question: str


class InvestigationResponse(BaseModel):
    incident_id: str
    question: str
    answer: str
    mode: Literal["deterministic", "llm"] = "deterministic"
    cited_event_ids: List[str] = Field(default_factory=list)
    cited_finding_ids: List[str] = Field(default_factory=list)
    evidence_snippets: List[Dict[str, Any]] = Field(default_factory=list)
    missing_evidence_note: Optional[str] = None


class ConfigUpdateRequest(BaseModel):
    brute_force_threshold: Optional[int] = None
    brute_force_window_seconds: Optional[int] = None
    impossible_travel_speed_kmh: Optional[float] = None
    correlation_window_minutes: Optional[int] = None
    outbound_spike_multiplier: Optional[float] = None
    ml_anomaly_threshold: Optional[float] = None
    score_weights: Optional[Dict[str, int]] = None
