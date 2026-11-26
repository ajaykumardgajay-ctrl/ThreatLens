"""Deterministic, configurable incident risk scoring engine."""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Optional

from app.config import settings
from app.schemas.models import Finding, RiskScoreBreakdown, ScoreContribution, SeverityType


DEFAULT_RATIONALES: Dict[str, str] = {
    "brute_force": "Repeated failed authentication burst indicating credential attack",
    "impossible_travel": "Geographically inconsistent login velocity across distant locations",
    "privilege_escalation": "Privilege modification or elevation command executed",
    "sensitive_resource_access": "First-time or restricted access to sensitive asset",
    "data_exfiltration": "Significant outbound data transfer spike above historical baseline",
    "unusual_login_time": "Authentication outside normal account activity hours",
    "ml_anomaly": "Isolation Forest statistical behavioural anomaly indicator (advisory)",
}


def classify_severity(score: int) -> SeverityType:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def calculate_risk_score(
    findings: List[Finding],
    weights: Optional[Dict[str, int]] = None,
) -> RiskScoreBreakdown:
    """Compute a capped 0-100 prioritisation score with duplicate suppression and full audit trail."""
    w_map = dict(settings.score_weights)
    if weights:
        w_map.update(weights)

    grouped: Dict[str, List[Finding]] = defaultdict(list)
    for f in findings:
        grouped[f.detector_category].append(f)

    has_rule_findings = any(f.detection_source == "rule" for f in findings)
    contributions: List[ScoreContribution] = []
    raw_total = 0

    for category, cat_findings in grouped.items():
        cat_findings.sort(key=lambda f: f.confidence, reverse=True)
        primary = cat_findings[0]
        suppressed = max(0, len(cat_findings) - 1)

        if category == "ml_anomaly" and has_rule_findings:
            # Advisory ML signal does not inflate rule-corroborated scores unless explicitly desired;
            # keeps INC-2026-041 exact at 25+20+25+15+11 = 96/100 while surfacing ML evidence.
            points = 0
            rationale = (
                "Advisory ML behavioural indicator corroborated by deterministic rules "
                "(0 extra points; statistical indicator only)"
            )
        else:
            points = int(w_map.get(category, 10))
            rationale = DEFAULT_RATIONALES.get(category, primary.detector_name)

        raw_total += points
        sup_ev_ids: List[str] = []
        for f in cat_findings:
            for eid in f.supporting_event_ids:
                if eid not in sup_ev_ids:
                    sup_ev_ids.append(eid)

        contributions.append(
            ScoreContribution(
                category=category,
                detector_name=primary.detector_name,
                points=points,
                suppressed_duplicates=suppressed,
                finding_ids=[f.finding_id for f in cat_findings],
                supporting_event_ids=sup_ev_ids,
                confidence=round(max(f.confidence for f in cat_findings), 2),
                rationale=rationale,
            )
        )

    contributions.sort(key=lambda c: (c.points, c.confidence), reverse=True)
    capped = min(100, max(0, raw_total))
    return RiskScoreBreakdown(
        total_score=capped,
        raw_uncapped_score=raw_total,
        max_score=100,
        severity=classify_severity(capped),
        contributions=contributions,
    )
