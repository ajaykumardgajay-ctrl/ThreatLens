"""Behavioural ML anomaly detection using Scikit-learn Isolation Forest."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from app.schemas.models import CanonicalEvent, Finding


FEATURE_NAMES = [
    "login_frequency",
    "failed_login_ratio",
    "unique_ip_count",
    "unique_resource_count",
    "outbound_bytes",
    "activity_hour",
    "session_frequency",
    "unusual_resource_access",
]

SENSITIVE_KEYWORDS = (
    "/var/secure/",
    "/etc/shadow",
    "payroll",
    "credentials",
    "id_rsa",
    "secret",
    "/admin/export",
)


def _generate_synthetic_normal_baseline(n_samples: int = 600, seed: int = 42) -> np.ndarray:
    """Generate realistic normal corporate user hourly activity baselines."""
    rng = np.random.default_rng(seed)
    login_freq = rng.integers(1, 5, size=n_samples).astype(float)
    failed_ratio = rng.choice([0.0, 0.0, 0.0, 0.05, 0.1, 0.2], size=n_samples)
    unique_ips = rng.choice([1, 1, 1, 2], size=n_samples).astype(float)
    unique_res = rng.integers(2, 12, size=n_samples).astype(float)
    outbound_bytes = rng.lognormal(mean=14.4, sigma=0.65, size=n_samples)  # ~1.5-5 MB normal range
    activity_hour = rng.integers(8, 19, size=n_samples).astype(float)
    session_freq = rng.integers(1, 4, size=n_samples).astype(float)
    unusual_res = np.zeros(n_samples, dtype=float)

    return np.column_stack(
        [
            login_freq,
            failed_ratio,
            unique_ips,
            unique_res,
            outbound_bytes,
            activity_hour,
            session_freq,
            unusual_res,
        ]
    )


class BehavioralAnomalyDetector:
    """Isolation Forest wrapper trained on normal user behavioural baselines."""

    def __init__(self) -> None:
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            n_estimators=160,
            contamination=0.03,
            random_state=42,
        )
        self.baseline_means: np.ndarray = np.zeros(len(FEATURE_NAMES))
        self.baseline_stds: np.ndarray = np.ones(len(FEATURE_NAMES))
        self.training_samples_count: int = 0
        self.last_trained_source: str = "synthetic_normal_baseline"
        self.is_trained: bool = False
        self.train_on_baseline()

    def train_on_baseline(
        self,
        custom_events: Optional[List[CanonicalEvent]] = None,
    ) -> Dict[str, Any]:
        """Train Isolation Forest on synthetic normal baseline + optional clean baseline events."""
        synthetic_x = _generate_synthetic_normal_baseline()
        combined_x = synthetic_x
        source_label = "synthetic_normal_baseline"

        if custom_events and len(custom_events) >= 25:
            extracted, _ = self._extract_user_window_features(custom_events)
            # Filter out extreme failed-login bursts or huge egress spikes when building normal baseline
            if len(extracted) >= 8:
                clean_rows = [
                    row for row in extracted
                    if row[1] <= 0.35 and row[4] < 50 * 1024 * 1024 and row[7] == 0.0
                ]
                if len(clean_rows) >= 6:
                    combined_x = np.vstack([synthetic_x, np.array(clean_rows, dtype=float)])
                    source_label = "synthetic_plus_observed_baseline"

        self.baseline_means = np.mean(combined_x, axis=0)
        self.baseline_stds = np.maximum(np.std(combined_x, axis=0), 1e-6)
        x_scaled = self.scaler.fit_transform(combined_x)
        self.model.fit(x_scaled)
        self.training_samples_count = int(len(combined_x))
        self.last_trained_source = source_label
        self.is_trained = True

        return {
            "is_trained": self.is_trained,
            "training_samples": self.training_samples_count,
            "source": self.last_trained_source,
            "features": FEATURE_NAMES,
        }

    def _extract_user_window_features(
        self, events: List[CanonicalEvent]
    ) -> Tuple[List[List[float]], List[Dict[str, Any]]]:
        """Aggregate canonical events into (user, hourly_bucket) behavioural feature vectors."""
        buckets: Dict[Tuple[str, str], List[CanonicalEvent]] = defaultdict(list)
        for ev in events:
            if not ev.user or ev.user == "unknown":
                continue
            dt = datetime.fromisoformat(ev.timestamp.replace("Z", "+00:00")).astimezone(timezone.utc)
            bucket_key = dt.strftime("%Y-%m-%dT%H")
            buckets[(ev.user, bucket_key)].append(ev)

        vectors: List[List[float]] = []
        meta: List[Dict[str, Any]] = []

        for (user, bucket), evs in sorted(buckets.items()):
            evs_sorted = sorted(evs, key=lambda e: e.timestamp)
            auth_evs = [
                e for e in evs_sorted
                if e.source_type == "auth" or "login" in e.action.lower() or "ssh" in e.action.lower()
            ]
            login_freq = float(len(auth_evs))
            failed_count = sum(1 for e in auth_evs if e.status == "failure")
            failed_ratio = float(failed_count / len(auth_evs)) if auth_evs else 0.0
            unique_ips = float(len({e.src_ip for e in evs_sorted if e.src_ip}))
            unique_resources = float(len({e.resource for e in evs_sorted if e.resource}))
            outbound_bytes = float(sum(e.bytes_out for e in evs_sorted))
            first_dt = datetime.fromisoformat(evs_sorted[0].timestamp.replace("Z", "+00:00")).astimezone(timezone.utc)
            activity_hour = float(first_dt.hour)
            sessions = {e.session_id for e in evs_sorted if e.session_id}
            session_freq = float(max(1, len(sessions)))
            unusual_res = float(
                sum(
                    1 for e in evs_sorted
                    if any(k in (e.resource or "").lower() for k in SENSITIVE_KEYWORDS)
                )
            )

            vectors.append(
                [
                    login_freq,
                    failed_ratio,
                    unique_ips,
                    unique_resources,
                    outbound_bytes,
                    activity_hour,
                    session_freq,
                    unusual_res,
                ]
            )
            meta.append(
                {
                    "user": user,
                    "bucket": bucket,
                    "events": evs_sorted,
                }
            )

        return vectors, meta

    def score_events(self, events: List[CanonicalEvent]) -> Dict[str, Any]:
        """Score behavioural windows and emit interpretable ML anomaly findings."""
        if not events:
            return {
                "status": "insufficient_data",
                "message": "No events available for behavioural scoring.",
                "observations_scored": 0,
                "anomalies_flagged": 0,
                "user_scores": [],
                "findings": [],
            }

        if not self.is_trained:
            self.train_on_baseline()

        vectors, meta = self._extract_user_window_features(events)
        if not vectors:
            return {
                "status": "insufficient_data",
                "message": "Insufficient user-attributed events to compute behavioural features.",
                "observations_scored": 0,
                "anomalies_flagged": 0,
                "user_scores": [],
                "findings": [],
            }

        x = np.array(vectors, dtype=float)
        x_scaled = self.scaler.transform(x)
        raw_scores = self.model.decision_function(x_scaled)  # negative = more anomalous
        preds = self.model.predict(x_scaled)  # -1 = outlier, 1 = inlier

        findings: List[Finding] = []
        user_scores: List[Dict[str, Any]] = []

        for idx, (row, m, raw_score, pred) in enumerate(zip(x, meta, raw_scores, preds)):
            # Convert decision_function into intuitive [0, 1] anomaly indicator (higher = more anomalous)
            norm_anomaly = float(np.clip(0.5 - raw_score * 1.6, 0.0, 1.0))

            # Feature-level statistical deviations vs training baseline
            z_scores = (row - self.baseline_means) / self.baseline_stds
            contributions = []
            for f_idx, f_name in enumerate(FEATURE_NAMES):
                z = float(z_scores[f_idx])
                contributions.append(
                    {
                        "feature": f_name,
                        "observed": round(float(row[f_idx]), 3),
                        "baseline_mean": round(float(self.baseline_means[f_idx]), 3),
                        "z_score": round(z, 2),
                        "direction": "above_baseline" if z >= 0 else "below_baseline",
                    }
                )
            contributions.sort(key=lambda c: abs(c["z_score"]), reverse=True)

            evs: List[CanonicalEvent] = m["events"]
            user = m["user"]
            user_scores.append(
                {
                    "user": user,
                    "window": m["bucket"],
                    "anomaly_score": round(norm_anomaly, 3),
                    "is_outlier": bool(pred == -1 or norm_anomaly >= 0.62),
                    "event_count": len(evs),
                    "top_feature": contributions[0]["feature"],
                    "top_z_score": contributions[0]["z_score"],
                }
            )

            # Flag strong statistical outliers (require meaningful deviation so normal noise stays clean)
            max_abs_z = abs(contributions[0]["z_score"])
            if (pred == -1 and norm_anomaly >= 0.62 and max_abs_z >= 2.2) or norm_anomaly >= 0.72:
                top3 = contributions[:3]
                top_summary = ", ".join(
                    f"{c['feature']}={c['observed']} (baseline {c['baseline_mean']}, z={c['z_score']:+.1f})"
                    for c in top3
                )
                # Keep supporting evidence bounded to the highest-signal events in that window
                ranked_evs = sorted(
                    evs,
                    key=lambda e: (
                        e.bytes_out > 0,
                        e.status == "failure",
                        any(k in (e.resource or "").lower() for k in SENSITIVE_KEYWORDS),
                    ),
                    reverse=True,
                )[:10]

                digest = hashlib.sha1(f"ML:{user}:{m['bucket']}".encode("utf-8")).hexdigest()[:8].upper()
                severity = "high" if norm_anomaly >= 0.80 else "medium"
                ips = [e.src_ip for e in evs if e.src_ip]
                findings.append(
                    Finding(
                        finding_id=f"FND-ML-{digest}",
                        detector_name="Isolation Forest Behavioural Anomaly Detector",
                        detector_category="ml_anomaly",
                        detection_source="ml",
                        severity=severity,
                        timestamp=evs[-1].timestamp,
                        affected_user=user,
                        src_ip=ips[-1] if ips else "",
                        hostname=evs[-1].hostname,
                        description=(
                            f"Isolation Forest flagged an anomalous behavioural window ({m['bucket']} UTC) "
                            f"for account '{user}' (anomaly indicator {norm_anomaly:.2f}/1.00). "
                            f"Primary statistical deviations: {top_summary}. "
                            f"Note: This score is a statistical anomaly indicator, not causal proof of malicious intent."
                        ),
                        triggered_condition=(
                            f"isolation_forest_anomaly_indicator={norm_anomaly:.3f} "
                            f"(top_deviation={top3[0]['feature']} z={top3[0]['z_score']:+.1f})"
                        ),
                        supporting_event_ids=[e.event_id for e in ranked_evs],
                        raw_log_references=[e.raw_log for e in ranked_evs[:5]],
                        confidence=round(min(0.88, max(0.50, norm_anomaly)), 2),
                        confidence_label="medium-high" if norm_anomaly >= 0.75 else "medium",
                        anomaly_score=round(norm_anomaly, 3),
                        feature_contributions=contributions[:5],
                        is_synthetic=any(e.is_synthetic for e in evs),
                    )
                )

        user_scores.sort(key=lambda u: u["anomaly_score"], reverse=True)
        return {
            "status": "ok",
            "training_samples": self.training_samples_count,
            "training_source": self.last_trained_source,
            "observations_scored": len(user_scores),
            "anomalies_flagged": len(findings),
            "user_scores": user_scores,
            "findings": findings,
        }


ml_detector = BehavioralAnomalyDetector()
