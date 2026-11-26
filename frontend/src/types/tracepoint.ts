export type SeverityType = 'critical' | 'high' | 'medium' | 'low';
export type SourceType = 'auth' | 'web' | 'system' | 'proxy' | 'firewall' | 'windows';

export interface CanonicalEvent {
  event_id: string;
  timestamp: string;
  source_type: SourceType;
  user: string;
  src_ip: string;
  dest_ip: string;
  geo: string;
  hostname: string;
  session_id: string;
  action: string;
  resource: string;
  status: 'success' | 'failure' | 'unknown';
  bytes_out: number;
  raw_log: string;
  pid?: string | null;
  target_user?: string | null;
  ingestion_batch?: string | null;
  is_synthetic: boolean;
  rule_score: number;
  ml_anomaly_score: number;
  final_event_risk: number;
  ml_reasons: string[];
  ml_feature_deviations: {
    feature: string;
    observed: number;
    baseline: number;
    z_score: number;
    detail?: string;
  }[];
}

export interface FeatureContribution {
  feature: string;
  observed: number;
  baseline_mean: number;
  z_score: number;
  direction: string;
}

export interface Finding {
  finding_id: string;
  detector_name: string;
  detector_category: string;
  detection_source: 'rule' | 'ml';
  severity: SeverityType;
  timestamp: string;
  affected_user: string;
  src_ip: string;
  hostname: string;
  description: string;
  triggered_condition: string;
  supporting_event_ids: string[];
  raw_log_references: string[];
  confidence: number;
  confidence_label: string;
  anomaly_score?: number | null;
  feature_contributions?: (FeatureContribution & { baseline?: number; detail?: string })[] | null;
  rule_score?: number;
  final_event_risk?: number;
  ml_reasons?: string[];
  incident_id?: string | null;
  is_synthetic: boolean;
}

export interface GraphNodeData {
  id: string;
  node_type:
    | 'User'
    | 'IP address'
    | 'Host'
    | 'Session'
    | 'Event'
    | 'Resource'
    | 'External endpoint';
  label: string;
  timestamp?: string | null;
  severity?: string | null;
  is_suspicious: boolean;
  event_ids: string[];
  metadata: Record<string, unknown>;
}

export interface GraphEdgeData {
  id: string;
  source: string;
  target: string;
  relationship_type:
    | 'AUTHENTICATED_FROM'
    | 'PERFORMED'
    | 'EXECUTED'
    | 'ESCALATED_TO'
    | 'ACCESSED'
    | 'TRANSFERRED_TO'
    | 'CORRELATED_WITH';
  supporting_event_ids: string[];
  timestamp: string;
  time_difference_seconds: number;
  correlation_reason: string;
  confidence: number;
}

export interface AttackGraph {
  incident_id: string;
  nodes: GraphNodeData[];
  edges: GraphEdgeData[];
  attack_path_node_ids: string[];
  attack_path_edge_ids: string[];
}

export interface ScoreContribution {
  category: string;
  detector_name: string;
  points: number;
  suppressed_duplicates: number;
  finding_ids: string[];
  supporting_event_ids: string[];
  confidence: number;
  rationale: string;
}

export interface RiskScoreBreakdown {
  total_score: number;
  raw_uncapped_score: number;
  max_score: number;
  severity: SeverityType;
  scoring_note: string;
  contributions: ScoreContribution[];
}

export interface TimelineEntry {
  step_index: number;
  event_id: string;
  timestamp: string;
  stage: string;
  user: string;
  target_user?: string | null;
  src_ip: string;
  dest_ip: string;
  hostname: string;
  action: string;
  resource: string;
  status: string;
  bytes_out: number;
  raw_log: string;
  finding_ids: string[];
  highlight_node_ids: string[];
  highlight_edge_ids: string[];
  relationship_to_previous: string;
  explanation: string;
  rule_score?: number;
  ml_anomaly_score?: number;
  final_event_risk?: number;
  ml_reasons?: string[];
  ml_feature_deviations?: {
    feature: string;
    observed: number;
    baseline: number;
    z_score: number;
    detail?: string;
  }[];
}

export interface IncidentSummary {
  incident_id: string;
  title: string;
  risk_score: number;
  severity: SeverityType;
  first_observed: string;
  last_observed: string;
  affected_accounts: string[];
  affected_hosts: string[];
  source_ips: string[];
  attack_stages: string[];
  evidence_count: number;
  finding_count: number;
  is_synthetic: boolean;
  rule_score?: number;
  ml_anomaly_score?: number;
  combined_risk_score?: number;
}

export interface SummaryClaim {
  stage: string;
  claim: string;
  timestamp: string;
  supporting_event_ids: string[];
  finding_ids: string[];
}

export interface IncidentDetail extends IncidentSummary {
  explanation: string;
  summary_claims: SummaryClaim[];
  score_breakdown: RiskScoreBreakdown;
  findings: Finding[];
  timeline: TimelineEntry[];
  graph: AttackGraph;
  evidence_event_ids: string[];
}

export interface ParseErrorItem {
  line_number: number;
  raw_line: string;
  reason: string;
}

export interface IngestionReport {
  batch_id: string;
  filename?: string;
  format_detected: string;
  total_lines: number;
  parsed_count: number;
  skipped_count: number;
  processed_count: number;
  errors: ParseErrorItem[];
  incidents_detected: number;
  findings_generated: number;
}

export interface MetricsResponse {
  total_events_processed: number;
  total_findings: number;
  rule_findings_count: number;
  ml_findings_count: number;
  total_incidents: number;
  critical_incidents: number;
  high_risk_accounts: string[];
  severity_distribution: Record<SeverityType, number>;
  source_distribution: Record<SourceType, number>;
  activity_series: { hour: string; total: number; failures: number }[];
  ml_statistics: {
    is_trained: boolean;
    training_samples: number;
    training_source: string;
    observations_scored: number;
    anomalies_flagged: number;
    top_user_scores: {
      user: string;
      window: string;
      anomaly_score: number;
      is_outlier: boolean;
      event_count: number;
      top_feature: string;
      top_z_score: number;
    }[];
  };
  recent_batches: {
    batch_id: string;
    created_at: string;
    format_detected: string;
    total_lines: number;
    parsed_count: number;
    skipped_count: number;
    processed_count: number;
  }[];
  has_synthetic_data: boolean;
}

export interface InvestigationResponse {
  incident_id: string;
  question: string;
  answer: string;
  mode: 'deterministic' | 'llm';
  cited_event_ids: string[];
  cited_finding_ids: string[];
  evidence_snippets: {
    event_id: string;
    timestamp: string;
    user: string;
    action: string;
    raw_log: string;
  }[];
  missing_evidence_note?: string | null;
}

export interface RuntimeSettings {
  brute_force_threshold: number;
  brute_force_window_seconds: number;
  impossible_travel_speed_kmh: number;
  correlation_window_minutes: number;
  outbound_spike_multiplier: number;
  ml_anomaly_threshold: number;
  score_weights: Record<string, number>;
  llm_configured: boolean;
}

export interface SamplePreset {
  id: string;
  name: string;
  format: string;
  description: string;
}

export interface AnalyzerSummary {
  total_events: number;
  total_findings: number;
  total_incidents: number;
  time_range: { start: string | null; end: string | null };
  source_counts: Record<string, number>;
  status_counts: Record<string, number>;
  top_actions: { action: string; count: number }[];
  top_hosts: { hostname: string; count: number }[];
  top_resources: { resource: string; count: number }[];
  top_ips: {
    ip: string;
    total: number;
    failures: number;
    bytes_out: number;
    geos: string[];
    users: string[];
    is_flagged: boolean;
  }[];
  top_users: {
    user: string;
    total: number;
    failures: number;
    bytes_out: number;
    unique_ips: number;
    is_flagged: boolean;
  }[];
  iocs: {
    type: string;
    value: string;
    severity: SeverityType;
    context: string;
    finding_id: string;
  }[];
}
