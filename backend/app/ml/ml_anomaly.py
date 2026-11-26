"""Explainable per-event ML anomaly detection using Pandas, RobustScaler, and IsolationForest."""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler

from app.schemas.models import CanonicalEvent


ML_FEATURE_COLUMNS = [
    "hour_of_day",
    "is_odd_hour",
    "user_ip_rarity",
    "user_resource_rarity",
    "rolling_fail_count_10m",
    "events_per_min_window",
    "bytes_out_zscore",
    "geo_distance_km",
    "geo_velocity_kmh",
]

GEO_COORDS: Dict[str, Tuple[float, float]] = {
    "bengaluru, in": (12.9716, 77.5946),
    "bangalore, in": (12.9716, 77.5946),
    "mumbai, in": (19.0760, 72.8777),
    "hyderabad, in": (17.3850, 78.4867),
    "delhi, in": (28.7041, 77.1025),
    "frankfurt, de": (50.1109, 8.6821),
    "berlin, de": (52.5200, 13.4050),
    "london, uk": (51.5074, -0.1278),
    "amsterdam, nl": (52.3676, 4.9041),
    "new york, us": (40.7128, -74.0060),
    "san francisco, us": (37.7749, -122.4194),
    "singapore, sg": (1.3521, 103.8198),
    "tokyo, jp": (35.6762, 139.6503),
    "sydney, au": (-33.8688, 151.2093),
    "moscow, ru": (55.7558, 37.6173),
}


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def _circular_hour_diff(h1: float, h2: float) -> float:
    diff = abs(h1 - h2)
    return min(diff, 24.0 - diff)


def _synthetic_baseline_feature_rows(n: int = 80, seed: int = 42) -> pd.DataFrame:
    """Fallback normal baseline feature rows used when an uploaded batch is very small (< 15 events)."""
    rng = np.random.default_rng(seed)
    return pd.DataFrame(
        {
            "hour_of_day": rng.integers(8, 18, size=n).astype(float),
            "is_odd_hour": np.zeros(n, dtype=float),
            "user_ip_rarity": rng.choice([0.05, 0.1, 0.2], size=n),
            "user_resource_rarity": rng.choice([0.05, 0.1, 0.2], size=n),
            "rolling_fail_count_10m": np.zeros(n, dtype=float),
            "events_per_min_window": rng.uniform(0.2, 1.0, size=n),
            "bytes_out_zscore": rng.normal(0.0, 0.4, size=n),
            "geo_distance_km": np.zeros(n, dtype=float),
            "geo_velocity_kmh": np.zeros(n, dtype=float),
        }
    )


def engineer_behavioral_features(events: List[CanonicalEvent]) -> pd.DataFrame:
    """Engineer per-event behavioral features from normalized CanonicalEvent records."""
    if not events:
        return pd.DataFrame()

    rows = [
        {
            "event_id": e.event_id,
            "timestamp": e.timestamp,
            "source_type": e.source_type,
            "user": e.user or "unknown",
            "src_ip": e.src_ip or "",
            "action": e.action or "unknown",
            "resource": e.resource or "",
            "status": e.status or "unknown",
            "bytes_out": float(e.bytes_out or 0),
            "geo": e.geo or "",
        }
        for e in events
    ]
    df = pd.DataFrame(rows)
    df["dt"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    df = df.sort_values(["dt", "event_id"]).reset_index(drop=True)
    epoch_sec = (df["dt"].astype("int64") // 10**9).to_numpy(dtype=np.float64)

    # 1. hour_of_day & is_odd_hour (deviation from user's median active hour)
    df["hour_of_day"] = df["dt"].dt.hour.fillna(12).astype(float)
    df["minute_of_day"] = df["dt"].dt.minute.fillna(0).astype(float)

    user_counts = df["user"].value_counts().to_dict()
    user_median_hour = df.groupby("user")["hour_of_day"].median().to_dict()

    is_odd = np.zeros(len(df), dtype=float)
    hour_devs = np.zeros(len(df), dtype=float)
    for i, (u, hr) in enumerate(zip(df["user"], df["hour_of_day"])):
        cnt = user_counts.get(u, 0)
        if cnt >= 4 and u != "unknown":
            med_h = float(user_median_hour.get(u, 12.0))
            dev = _circular_hour_diff(float(hr), med_h)
            hour_devs[i] = dev
            if dev >= 5.0:
                is_odd[i] = 1.0
        else:
            # Default business hours baseline [7..20]
            if hr < 7.0 or hr > 20.0:
                is_odd[i] = 1.0
                hour_devs[i] = min(abs(hr - 7.0), abs(hr - 20.0))
    df["is_odd_hour"] = is_odd
    df["hour_deviation"] = hour_devs
    df["user_median_hour"] = df["user"].map(user_median_hour).fillna(12.0)

    # 2. user_ip_rarity: 1.0 if (user, src_ip) rarely/never appeared, else inverse frequency
    ui_counts = df.groupby(["user", "src_ip"]).size().to_dict()
    ip_rarity = np.zeros(len(df), dtype=float)
    ip_seen_count = np.zeros(len(df), dtype=float)
    for i, (u, ip) in enumerate(zip(df["user"], df["src_ip"])):
        if not ip:
            ip_rarity[i] = 0.0
            continue
        c = float(ui_counts.get((u, ip), 1))
        ip_seen_count[i] = c
        u_tot = float(user_counts.get(u, 1))
        if c <= 1.0 and u_tot >= 2.0:
            ip_rarity[i] = 1.0
        else:
            ip_rarity[i] = round(min(1.0, 1.0 / max(c, 1.0)), 4)
    df["user_ip_rarity"] = ip_rarity
    df["user_ip_count"] = ip_seen_count

    # 3. user_resource_rarity: inverse frequency of resource accessed by user
    ur_counts = df.groupby(["user", "resource"]).size().to_dict()
    res_rarity = np.zeros(len(df), dtype=float)
    res_seen_count = np.zeros(len(df), dtype=float)
    for i, (u, res) in enumerate(zip(df["user"], df["resource"])):
        if not res:
            res_rarity[i] = 0.0
            continue
        c = float(ur_counts.get((u, res), 1))
        res_seen_count[i] = c
        res_rarity[i] = round(min(1.0, 1.0 / max(c, 1.0)), 4)
    df["user_resource_rarity"] = res_rarity
    df["user_resource_count"] = res_seen_count

    # 4 & 5. rolling_fail_count_10m & events_per_min_window (5m) using binary search O(N log N)
    fail_10m = np.zeros(len(df), dtype=float)
    epm_5m = np.zeros(len(df), dtype=float)

    # Pre-index sorted timestamps per user and per src_ip
    is_fail_arr = (df["status"] == "failure").to_numpy()
    user_indices: Dict[str, List[int]] = {}
    ip_indices: Dict[str, List[int]] = {}
    for i, (u, ip) in enumerate(zip(df["user"], df["src_ip"])):
        if u and u != "unknown":
            user_indices.setdefault(u, []).append(i)
        if ip:
            ip_indices.setdefault(ip, []).append(i)

    user_ts_cache = {u: epoch_sec[idxs] for u, idxs in user_indices.items()}
    user_fail_ts_cache = {
        u: epoch_sec[[idx for idx in idxs if is_fail_arr[idx]]]
        for u, idxs in user_indices.items()
    }
    ip_ts_cache = {ip: epoch_sec[idxs] for ip, idxs in ip_indices.items()}
    ip_fail_ts_cache = {
        ip: epoch_sec[[idx for idx in idxs if is_fail_arr[idx]]]
        for ip, idxs in ip_indices.items()
    }

    for i in range(len(df)):
        t = epoch_sec[i]
        u = df["user"].iat[i]
        ip = df["src_ip"].iat[i]

        u_fails = 0
        if u in user_fail_ts_cache and len(user_fail_ts_cache[u]) > 0:
            arr = user_fail_ts_cache[u]
            lo = np.searchsorted(arr, t - 600.0, side="left")
            hi = np.searchsorted(arr, t, side="right")
            u_fails = int(hi - lo)

        ip_fails = 0
        if ip in ip_fail_ts_cache and len(ip_fail_ts_cache[ip]) > 0:
            arr = ip_fail_ts_cache[ip]
            lo = np.searchsorted(arr, t - 600.0, side="left")
            hi = np.searchsorted(arr, t, side="right")
            ip_fails = int(hi - lo)

        fail_10m[i] = float(max(u_fails, ip_fails))

        u_burst = 0
        if u in user_ts_cache and len(user_ts_cache[u]) > 0:
            arr = user_ts_cache[u]
            lo = np.searchsorted(arr, t - 300.0, side="left")
            hi = np.searchsorted(arr, t, side="right")
            u_burst = int(hi - lo)

        ip_burst = 0
        if ip in ip_ts_cache and len(ip_ts_cache[ip]) > 0:
            arr = ip_ts_cache[ip]
            lo = np.searchsorted(arr, t - 300.0, side="left")
            hi = np.searchsorted(arr, t, side="right")
            ip_burst = int(hi - lo)

        epm_5m[i] = round(float(max(u_burst, ip_burst)) / 5.0, 3)

    df["rolling_fail_count_10m"] = fail_10m
    df["events_per_min_window"] = epm_5m

    # 6. bytes_out_zscore & ratio vs user's normal transfer volume
    non_extreme = df[(df["bytes_out"] > 0) & (df["bytes_out"] < 100 * 1024 * 1024)]
    global_med_bytes = float(non_extreme["bytes_out"].median()) if len(non_extreme) > 0 else float(1024 * 1024)

    user_med_bytes_map: Dict[str, float] = {}
    user_std_log_map: Dict[str, float] = {}
    for u, grp in df.groupby("user"):
        vals = grp.loc[(grp["bytes_out"] > 0) & (grp["bytes_out"] < 100 * 1024 * 1024), "bytes_out"]
        if len(vals) >= 2:
            user_med_bytes_map[u] = float(vals.median())
            log_vals = np.log1p(vals.to_numpy())
            user_std_log_map[u] = float(max(np.std(log_vals), 0.35))
        else:
            user_med_bytes_map[u] = global_med_bytes
            user_std_log_map[u] = 0.75

    bytes_z = np.zeros(len(df), dtype=float)
    bytes_ratio = np.ones(len(df), dtype=float)
    user_base_bytes = np.zeros(len(df), dtype=float)

    for i, (u, b) in enumerate(zip(df["user"], df["bytes_out"])):
        base_b = user_med_bytes_map.get(u, global_med_bytes)
        user_base_bytes[i] = base_b
        if b <= 0:
            bytes_z[i] = 0.0
            bytes_ratio[i] = 0.0
        else:
            ratio = float(b) / max(base_b, 1024.0)
            bytes_ratio[i] = round(ratio, 2)
            z = (math.log1p(b) - math.log1p(base_b)) / user_std_log_map.get(u, 0.75)
            bytes_z[i] = round(max(0.0, z), 3)

    df["bytes_out_zscore"] = bytes_z
    df["bytes_ratio"] = bytes_ratio
    df["user_baseline_bytes"] = user_base_bytes

    # 7. geo_distance_km & geo_velocity_kmh since previous successful login
    geo_dist = np.zeros(len(df), dtype=float)
    geo_vel = np.zeros(len(df), dtype=float)
    prev_geo_label = [""] * len(df)
    last_user_login: Dict[str, Tuple[float, str, Tuple[float, float]]] = {}

    for i in range(len(df)):
        u = df["user"].iat[i]
        status = df["status"].iat[i]
        src_type = df["source_type"].iat[i]
        act = str(df["action"].iat[i]).lower()
        geo_str = str(df["geo"].iat[i]).strip()
        geo_key = geo_str.lower()

        is_login_success = status == "success" and (src_type == "auth" or "login" in act or "logon" in act)
        if is_login_success and geo_key in GEO_COORDS and u != "unknown":
            coords = GEO_COORDS[geo_key]
            t_curr = epoch_sec[i]
            if u in last_user_login:
                t_prev, prev_label, prev_coords = last_user_login[u]
                if prev_label.lower() != geo_key:
                    d_km = _haversine_km(prev_coords[0], prev_coords[1], coords[0], coords[1])
                    hours = max((t_curr - t_prev) / 3600.0, 1e-4)
                    geo_dist[i] = round(d_km, 1)
                    geo_vel[i] = round(d_km / hours, 1)
                    prev_geo_label[i] = prev_label
            last_user_login[u] = (t_curr, geo_str, coords)

    df["geo_distance_km"] = geo_dist
    df["geo_velocity_kmh"] = geo_vel
    df["prev_geo_label"] = prev_geo_label

    return df


def _build_event_explanations(
    row: pd.Series,
    ds_means: Dict[str, float],
    ds_stds: Dict[str, float],
) -> Tuple[List[str], List[Dict[str, Any]]]:
    """Generate human-readable ml_reasons and structured feature deviations for a flagged event."""
    reasons: List[str] = []
    deviations: List[Dict[str, Any]] = []

    user = str(row["user"])
    hr = int(row["hour_of_day"])
    mn = int(row["minute_of_day"])

    # Outbound bytes deviation
    if float(row["bytes_out"]) > 0 and float(row["bytes_ratio"]) >= 3.0:
        obs_mb = float(row["bytes_out"]) / (1024 * 1024)
        base_mb = float(row["user_baseline_bytes"]) / (1024 * 1024)
        reasons.append(
            f"Outbound bytes {float(row['bytes_ratio']):.1f}x above user baseline ({obs_mb:.1f} MB vs {base_mb:.1f} MB)"
        )
    deviations.append(
        {
            "feature": "bytes_out_zscore",
            "observed": round(float(row["bytes_out_zscore"]), 2),
            "baseline": round(ds_means["bytes_out_zscore"], 2),
            "z_score": round((float(row["bytes_out_zscore"]) - ds_means["bytes_out_zscore"]) / ds_stds["bytes_out_zscore"], 2),
            "detail": f"{float(row['bytes_out']) / (1024 * 1024):.2f} MB vs {float(row['user_baseline_bytes']) / (1024 * 1024):.2f} MB user median",
        }
    )

    # First-time / rare IP
    if str(row["src_ip"]) and float(row["user_ip_rarity"]) >= 0.9:
        reasons.append(f"First-time or rare source IP {row['src_ip']} for user {user}")
    deviations.append(
        {
            "feature": "user_ip_rarity",
            "observed": round(float(row["user_ip_rarity"]), 2),
            "baseline": round(ds_means["user_ip_rarity"], 2),
            "z_score": round((float(row["user_ip_rarity"]) - ds_means["user_ip_rarity"]) / ds_stds["user_ip_rarity"], 2),
            "detail": f"Seen {int(row['user_ip_count'])} time(s) for {user}",
        }
    )

    # Odd hour activity
    if float(row["is_odd_hour"]) >= 1.0:
        reasons.append(
            f"Activity at {hr:02d}:{mn:02d} UTC outside normal active hours (median {int(row['user_median_hour']):02d}:00 UTC)"
        )
    deviations.append(
        {
            "feature": "is_odd_hour",
            "observed": round(float(row["is_odd_hour"]), 2),
            "baseline": round(ds_means["is_odd_hour"], 2),
            "z_score": round((float(row["is_odd_hour"]) - ds_means["is_odd_hour"]) / ds_stds["is_odd_hour"], 2),
            "detail": f"Observed {hr:02d}:{mn:02d} UTC vs {int(row['user_median_hour']):02d}:00 UTC user median",
        }
    )

    # Rolling failure count & burst activity
    if float(row["rolling_fail_count_10m"]) >= 3.0:
        reasons.append(
            f"{int(row['rolling_fail_count_10m'])} failed authentication/access events in trailing 10-minute window"
        )
    deviations.append(
        {
            "feature": "rolling_fail_count_10m",
            "observed": round(float(row["rolling_fail_count_10m"]), 1),
            "baseline": round(ds_means["rolling_fail_count_10m"], 2),
            "z_score": round((float(row["rolling_fail_count_10m"]) - ds_means["rolling_fail_count_10m"]) / ds_stds["rolling_fail_count_10m"], 2),
            "detail": f"{int(row['rolling_fail_count_10m'])} failures in trailing 10m",
        }
    )

    if float(row["events_per_min_window"]) >= 2.0:
        reasons.append(
            f"High burst rate of {float(row['events_per_min_window']):.1f} events/min in 5-minute window"
        )
    deviations.append(
        {
            "feature": "events_per_min_window",
            "observed": round(float(row["events_per_min_window"]), 2),
            "baseline": round(ds_means["events_per_min_window"], 2),
            "z_score": round((float(row["events_per_min_window"]) - ds_means["events_per_min_window"]) / ds_stds["events_per_min_window"], 2),
            "detail": f"{float(row['events_per_min_window']):.2f} events/min (5m window)",
        }
    )

    # Geo velocity
    if float(row["geo_velocity_kmh"]) >= 800.0:
        reasons.append(
            f"Impossible travel velocity ~{float(row['geo_velocity_kmh']):,.0f} km/h across {float(row['geo_distance_km']):,.0f} km from {row['prev_geo_label']}"
        )
    deviations.append(
        {
            "feature": "geo_velocity_kmh",
            "observed": round(float(row["geo_velocity_kmh"]), 1),
            "baseline": round(ds_means["geo_velocity_kmh"], 2),
            "z_score": round((float(row["geo_velocity_kmh"]) - ds_means["geo_velocity_kmh"]) / ds_stds["geo_velocity_kmh"], 2),
            "detail": f"{float(row['geo_distance_km']):,.0f} km jump" if float(row["geo_distance_km"]) > 0 else "No geo jump",
        }
    )

    # Rare resource
    if str(row["resource"]) and float(row["user_resource_rarity"]) >= 0.9:
        reasons.append(f"Rare or first-time resource '{row['resource']}' accessed by {user}")
    deviations.append(
        {
            "feature": "user_resource_rarity",
            "observed": round(float(row["user_resource_rarity"]), 2),
            "baseline": round(ds_means["user_resource_rarity"], 2),
            "z_score": round((float(row["user_resource_rarity"]) - ds_means["user_resource_rarity"]) / ds_stds["user_resource_rarity"], 2),
            "detail": f"Resource seen {int(row['user_resource_count'])} time(s) for {user}",
        }
    )

    # Sort deviations by absolute z-score descending
    deviations.sort(key=lambda d: abs(d["z_score"]), reverse=True)
    if not reasons:
        top_d = deviations[0]
        reasons.append(
            f"Multi-feature IsolationForest outlier (primary deviation: {top_d['feature']} z={top_d['z_score']:+.1f})"
        )

    return reasons, deviations


def score_events_ml(
    events: List[CanonicalEvent],
    threshold: float = 60.0,
) -> Dict[str, Dict[str, Any]]:
    """Run RobustScaler + IsolationForest(150, 0.05, 42) and return per-event scores & explanations."""
    if not events:
        return {}

    df = engineer_behavioral_features(events)
    if df.empty:
        return {}

    x_obs = df[ML_FEATURE_COLUMNS].to_numpy(dtype=float)

    # Augment very small uploads (<15 events) with normal baseline rows so IsolationForest has clean variance
    if len(df) < 15:
        base_df = _synthetic_baseline_feature_rows(n=80, seed=42)
        x_fit = np.vstack([base_df[ML_FEATURE_COLUMNS].to_numpy(dtype=float), x_obs])
    else:
        x_fit = x_obs

    scaler = RobustScaler()
    x_fit_scaled = scaler.fit_transform(x_fit)
    x_obs_scaled = scaler.transform(x_obs)

    model = IsolationForest(
        n_estimators=150,
        contamination=0.05,
        random_state=42,
    )
    model.fit(x_fit_scaled)

    # decision_function: >0 inliers, <0 outliers
    dec_scores = model.decision_function(x_obs_scaled)
    min_neg = float(np.min(dec_scores)) if np.min(dec_scores) < 0 else -0.15
    neg_scale = max(abs(min_neg), 0.18)
    max_pos = float(np.max(dec_scores)) if np.max(dec_scores) > 0 else 0.15
    pos_scale = max(max_pos, 0.12)

    ml_scores = np.zeros(len(df), dtype=float)
    for i, d in enumerate(dec_scores):
        if d >= 0:
            # Inliers map [0, max_pos] -> [48, 4]
            ml_scores[i] = max(4.0, 48.0 - (d / pos_scale) * 44.0)
        else:
            # Outliers map [0, min_neg] -> [50, 100]; strong outliers score >= 60
            ml_scores[i] = min(100.0, 50.0 + (-d / neg_scale) * 50.0)

    # Dataset baseline stats for z-score explainability
    ds_means = {col: float(np.mean(x_fit[:, idx])) for idx, col in enumerate(ML_FEATURE_COLUMNS)}
    ds_stds = {
        col: float(max(np.std(x_fit[:, idx]), 1e-3))
        for idx, col in enumerate(ML_FEATURE_COLUMNS)
    }

    results: Dict[str, Dict[str, Any]] = {}
    for i in range(len(df)):
        eid = str(df["event_id"].iat[i])
        score_val = round(float(ml_scores[i]), 1)
        row = df.iloc[i]
        # Compute feature deviations for borderline-and-above events (>= 50) for fast storage + slider responsiveness
        if score_val >= min(threshold, 50.0):
            reasons, deviations = _build_event_explanations(row, ds_means, ds_stds)
        else:
            reasons, deviations = [], []

        results[eid] = {
            "ml_anomaly_score": score_val,
            "is_ml_flagged": score_val >= threshold,
            "ml_reasons": reasons if score_val >= threshold else [],
            "ml_reasons_all": reasons,
            "ml_feature_deviations": deviations,
        }

    return results
