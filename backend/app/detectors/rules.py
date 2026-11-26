"""Deterministic rule-based security detectors for TRACEPOINT."""

from __future__ import annotations

import hashlib
import math
import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from app.config import settings
from app.schemas.models import CanonicalEvent, Finding


# Reference coordinates for velocity estimation (used only as corroborating signal)
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

SENSITIVE_PATTERNS = (
    "/var/secure/",
    "/etc/shadow",
    "/etc/sudoers",
    "payroll",
    "salary",
    "credentials",
    ".ssh/id_rsa",
    "id_rsa",
    "secret",
    "private_key",
    "backup_keys",
    "/admin/export",
    "pii_dump",
    "customer_db",
)

PRIV_ESC_TOKENS = (
    "usermod",
    "useradd",
    "groupadd",
    "gpasswd",
    "visudo",
    "sudoers",
    "chmod +s",
    "chmod 4755",
    "setuid",
    "privilege_grant",
)


def _parse_iso(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)


def _finding_id(prefix: str, seed: str) -> str:
    digest = hashlib.sha1(seed.encode("utf-8")).hexdigest()[:8].upper()
    return f"FND-{prefix}-{digest}"


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def _is_private_ip(ip: str) -> bool:
    return (
        ip.startswith("10.")
        or ip.startswith("192.168.")
        or ip.startswith("127.")
        or bool(re.match(r"^172\.(1[6-9]|2\d|3[0-1])\.", ip))
    )


def detect_brute_force(
    events: List[CanonicalEvent],
    threshold: Optional[int] = None,
    window_seconds: Optional[int] = None,
) -> List[Finding]:
    """Detect repeated failed authentication bursts grouped by (user, src_ip)."""
    thresh = threshold if threshold is not None else settings.brute_force_threshold
    win = window_seconds if window_seconds is not None else settings.brute_force_window_seconds

    failed_by_key: Dict[Tuple[str, str], List[CanonicalEvent]] = defaultdict(list)
    success_by_key: Dict[Tuple[str, str], List[CanonicalEvent]] = defaultdict(list)

    for ev in events:
        is_auth = ev.source_type == "auth" or "login" in ev.action.lower() or "ssh" in ev.action.lower()
        if not is_auth or not ev.src_ip:
            continue
        key = (ev.user, ev.src_ip)
        if ev.status == "failure":
            failed_by_key[key].append(ev)
        elif ev.status == "success":
            success_by_key[key].append(ev)

    findings: List[Finding] = []
    for (user, src_ip), fails in failed_by_key.items():
        fails.sort(key=lambda e: e.timestamp)
        if len(fails) < thresh:
            continue

        # Sliding window to capture bursts
        i = 0
        used_indices = set()
        while i < len(fails):
            if i in used_indices:
                i += 1
                continue
            t_start = _parse_iso(fails[i].timestamp)
            j = i
            while j < len(fails) and (_parse_iso(fails[j].timestamp) - t_start).total_seconds() <= win:
                j += 1
            burst = fails[i:j]
            if len(burst) >= thresh:
                for k in range(i, j):
                    used_indices.add(k)
                t_end = _parse_iso(burst[-1].timestamp)
                duration = max(1, int((t_end - t_start).total_seconds()))

                # Check for subsequent successful login from same (user, src_ip) within 15 minutes
                subsequent_success: Optional[CanonicalEvent] = None
                for sev_ev in sorted(success_by_key.get((user, src_ip), []), key=lambda e: e.timestamp):
                    dt_after = (_parse_iso(sev_ev.timestamp) - t_end).total_seconds()
                    if 0 <= dt_after <= 900:
                        subsequent_success = sev_ev
                        break

                supporting_ids = [e.event_id for e in burst]
                raw_refs = [e.raw_log for e in burst[:5]]
                if subsequent_success:
                    supporting_ids.append(subsequent_success.event_id)
                    raw_refs.append(subsequent_success.raw_log)

                severity = "critical" if (subsequent_success or len(burst) >= thresh * 3) else "high"
                conf = 0.96 if subsequent_success else 0.88
                desc = (
                    f"{len(burst)} failed authentication attempts against account '{user}' "
                    f"from {src_ip} within {duration}s"
                )
                if subsequent_success:
                    desc += f", followed by a successful login at {subsequent_success.timestamp}"

                findings.append(
                    Finding(
                        finding_id=_finding_id("BF", f"{user}:{src_ip}:{burst[0].timestamp}:{len(burst)}"),
                        detector_name="Brute Force Authentication Detector",
                        detector_category="brute_force",
                        detection_source="rule",
                        severity=severity,
                        timestamp=burst[-1].timestamp,
                        affected_user=user,
                        src_ip=src_ip,
                        hostname=burst[-1].hostname,
                        description=desc,
                        triggered_condition=(
                            f"failed_logins >= {thresh} within {win}s "
                            f"(observed {len(burst)} failures in {duration}s"
                            + ("; subsequent_success=True)" if subsequent_success else ")")
                        ),
                        supporting_event_ids=supporting_ids,
                        raw_log_references=raw_refs,
                        confidence=conf,
                        confidence_label="high",
                        is_synthetic=any(e.is_synthetic for e in burst),
                    )
                )
                i = j
            else:
                i += 1

    return findings


def detect_impossible_travel(
    events: List[CanonicalEvent],
    speed_threshold_kmh: Optional[float] = None,
) -> List[Finding]:
    """Detect geographically inconsistent logins or suspicious rapid IP transitions."""
    max_speed = (
        speed_threshold_kmh
        if speed_threshold_kmh is not None
        else settings.impossible_travel_speed_kmh
    )
    auth_success_by_user: Dict[str, List[CanonicalEvent]] = defaultdict(list)

    for ev in events:
        if ev.status == "success" and (ev.source_type == "auth" or "login" in ev.action.lower()):
            if ev.src_ip:
                auth_success_by_user[ev.user].append(ev)

    findings: List[Finding] = []
    for user, logins in auth_success_by_user.items():
        logins.sort(key=lambda e: e.timestamp)
        for prev_ev, curr_ev in zip(logins, logins[1:]):
            if prev_ev.src_ip == curr_ev.src_ip:
                continue

            t1 = _parse_iso(prev_ev.timestamp)
            t2 = _parse_iso(curr_ev.timestamp)
            hours = max((t2 - t1).total_seconds() / 3600.0, 1e-4)

            geo1 = prev_ev.geo.strip().lower()
            geo2 = curr_ev.geo.strip().lower()

            if geo1 and geo2 and geo1 != geo2 and geo1 in GEO_COORDS and geo2 in GEO_COORDS:
                c1, c2 = GEO_COORDS[geo1], GEO_COORDS[geo2]
                dist_km = _haversine_km(c1[0], c1[1], c2[0], c2[1])
                velocity = dist_km / hours
                if velocity >= max_speed:
                    findings.append(
                        Finding(
                            finding_id=_finding_id("IT", f"{user}:{prev_ev.event_id}:{curr_ev.event_id}"),
                            detector_name="Impossible Travel & Geolocation Velocity Detector",
                            detector_category="impossible_travel",
                            detection_source="rule",
                            severity="high",
                            timestamp=curr_ev.timestamp,
                            affected_user=user,
                            src_ip=curr_ev.src_ip,
                            hostname=curr_ev.hostname,
                            description=(
                                f"Account '{user}' authenticated from {curr_ev.src_ip} ({curr_ev.geo}) "
                                f"{hours * 60:.1f} minutes after authenticating from {prev_ev.src_ip} ({prev_ev.geo}). "
                                f"Estimated velocity ~{velocity:,.0f} km/h across {dist_km:,.0f} km. "
                                f"Note: IP geolocation is treated as corroborating evidence, not conclusive proof."
                            ),
                            triggered_condition=(
                                f"estimated_velocity ({velocity:,.0f} km/h) >= {max_speed:,.0f} km/h "
                                f"between '{prev_ev.geo}' and '{curr_ev.geo}'"
                            ),
                            supporting_event_ids=[prev_ev.event_id, curr_ev.event_id],
                            raw_log_references=[prev_ev.raw_log, curr_ev.raw_log],
                            confidence=0.82,
                            confidence_label="medium-high",
                            is_synthetic=prev_ev.is_synthetic or curr_ev.is_synthetic,
                        )
                    )
            elif (
                (not geo1 or not geo2 or geo1 not in GEO_COORDS or geo2 not in GEO_COORDS)
                and not _is_private_ip(curr_ev.src_ip)
                and hours <= 0.5
                and prev_ev.src_ip.split(".")[:2] != curr_ev.src_ip.split(".")[:2]
            ):
                # Graceful fallback when geographic metadata is missing/unreliable
                findings.append(
                    Finding(
                        finding_id=_finding_id("IT", f"{user}:{prev_ev.event_id}:{curr_ev.event_id}:nogeo"),
                        detector_name="Impossible Travel & Geolocation Velocity Detector",
                        detector_category="impossible_travel",
                        detection_source="rule",
                        severity="medium",
                        timestamp=curr_ev.timestamp,
                        affected_user=user,
                        src_ip=curr_ev.src_ip,
                        hostname=curr_ev.hostname,
                        description=(
                            f"Rapid IP transition for account '{user}' from {prev_ev.src_ip} to external IP "
                            f"{curr_ev.src_ip} within {hours * 60:.1f} minutes (geolocation incomplete or unavailable; "
                            f"flagged with reduced confidence)."
                        ),
                        triggered_condition=(
                            f"rapid_ip_transition <= 30 min with missing/unverified geo "
                            f"({prev_ev.src_ip} -> {curr_ev.src_ip})"
                        ),
                        supporting_event_ids=[prev_ev.event_id, curr_ev.event_id],
                        raw_log_references=[prev_ev.raw_log, curr_ev.raw_log],
                        confidence=0.58,
                        confidence_label="medium",
                        is_synthetic=prev_ev.is_synthetic or curr_ev.is_synthetic,
                    )
                )

    return findings


def detect_unusual_login_time(events: List[CanonicalEvent]) -> List[Finding]:
    """Detect successful logins outside an account's baseline or default active hours."""
    logins_by_user: Dict[str, List[CanonicalEvent]] = defaultdict(list)
    for ev in events:
        if ev.status == "success" and (ev.source_type == "auth" or "login" in ev.action.lower()):
            logins_by_user[ev.user].append(ev)

    findings: List[Finding] = []
    for user, logins in logins_by_user.items():
        hours = [_parse_iso(e.timestamp).hour for e in logins]
        # Build account baseline if sufficient history exists; else use default business hours
        if len(hours) >= 6:
            min_h = min(hours)
            max_h = max(hours)
            # Use IQR/majority window to avoid letting 1 outlier shift the baseline
            sorted_h = sorted(hours)
            low_bound = max(0, sorted_h[max(0, len(sorted_h) // 6)] - 1)
            high_bound = min(23, sorted_h[min(len(sorted_h) - 1, (5 * len(sorted_h)) // 6)] + 1)
            if high_bound - low_bound < 4:
                low_bound = settings.unusual_login_start_hour
                high_bound = settings.unusual_login_end_hour
        else:
            low_bound = settings.unusual_login_start_hour
            high_bound = settings.unusual_login_end_hour

        for ev in logins:
            hr = _parse_iso(ev.timestamp).hour
            if hr < low_bound or hr > high_bound:
                findings.append(
                    Finding(
                        finding_id=_finding_id("ULT", f"{user}:{ev.event_id}"),
                        detector_name="Unusual Login Time Detector",
                        detector_category="unusual_login_time",
                        detection_source="rule",
                        severity="medium",
                        timestamp=ev.timestamp,
                        affected_user=user,
                        src_ip=ev.src_ip,
                        hostname=ev.hostname,
                        description=(
                            f"Account '{user}' logged in at {hr:02d}:00 UTC from {ev.src_ip or 'unknown IP'}, "
                            f"outside expected baseline window ({low_bound:02d}:00–{high_bound:02d}:00 UTC)."
                        ),
                        triggered_condition=f"login_hour ({hr}) outside baseline [{low_bound}, {high_bound}]",
                        supporting_event_ids=[ev.event_id],
                        raw_log_references=[ev.raw_log],
                        confidence=0.68,
                        confidence_label="medium",
                        is_synthetic=ev.is_synthetic,
                    )
                )

    return findings


def detect_privilege_escalation(events: List[CanonicalEvent]) -> List[Finding]:
    """Detect sudo privilege grants, usermod/group modifications, and permission escalations."""
    findings: List[Finding] = []
    for ev in events:
        action_l = ev.action.lower()
        res_l = ev.resource.lower()
        raw_l = ev.raw_log.lower()

        is_grant_action = action_l in ("privilege_grant", "privilege_escalation", "sudo_usermod")
        has_priv_token = any(tok in res_l or tok in raw_l for tok in PRIV_ESC_TOKENS)
        is_root_sudo = action_l == "sudo_exec" and ("user=root" in raw_l or "sudo" in raw_l)

        if not (is_grant_action or has_priv_token or is_root_sudo):
            continue

        # Ignore routine benign sudo status checks if not modifying privileges
        if is_root_sudo and not (is_grant_action or has_priv_token):
            if any(safe in res_l for safe in ("systemctl status", "journalctl", "df -h", "ls ")):
                continue

        target_desc = f" targeting account '{ev.target_user}'" if ev.target_user else ""
        severity = "critical" if (ev.target_user or is_grant_action or "usermod" in res_l or "sudoers" in res_l) else "high"
        conf = 0.94 if (ev.target_user or is_grant_action or has_priv_token) else 0.76

        findings.append(
            Finding(
                finding_id=_finding_id("PE", f"{ev.user}:{ev.event_id}"),
                detector_name="Privilege Escalation Detector",
                detector_category="privilege_escalation",
                detection_source="rule",
                severity=severity,
                timestamp=ev.timestamp,
                affected_user=ev.user,
                src_ip=ev.src_ip,
                hostname=ev.hostname,
                description=(
                    f"Account '{ev.user}' executed privilege modification on {ev.hostname}{target_desc}: "
                    f"{ev.resource or ev.action}."
                ),
                triggered_condition=(
                    f"action='{ev.action}' / privileged command matched escalation rules"
                    + (f" (target_user='{ev.target_user}')" if ev.target_user else "")
                ),
                supporting_event_ids=[ev.event_id],
                raw_log_references=[ev.raw_log],
                confidence=conf,
                confidence_label="high" if conf >= 0.85 else "medium-high",
                is_synthetic=ev.is_synthetic,
            )
        )

    return findings


def detect_sensitive_resource_access(events: List[CanonicalEvent]) -> List[Finding]:
    """Detect first-time or unusual access to restricted files and sensitive resources."""
    seen_user_resources: Dict[str, set] = defaultdict(set)
    findings: List[Finding] = []

    for ev in sorted(events, key=lambda e: e.timestamp):
        res_l = (ev.resource or "").lower()
        if not res_l:
            continue
        matched_pat = next((p for p in SENSITIVE_PATTERNS if p in res_l), None)
        if not matched_pat:
            seen_user_resources[ev.user].add(res_l)
            continue

        first_time = res_l not in seen_user_resources[ev.user]
        seen_user_resources[ev.user].add(res_l)

        findings.append(
            Finding(
                finding_id=_finding_id("SRA", f"{ev.user}:{ev.event_id}"),
                detector_name="Sensitive Resource Access Detector",
                detector_category="sensitive_resource_access",
                detection_source="rule",
                severity="high",
                timestamp=ev.timestamp,
                affected_user=ev.user,
                src_ip=ev.src_ip,
                hostname=ev.hostname,
                description=(
                    f"Account '{ev.user}' performed {'first-time ' if first_time else ''}access to "
                    f"restricted resource '{ev.resource}' on {ev.hostname}."
                ),
                triggered_condition=(
                    f"resource matched sensitive pattern '{matched_pat}'"
                    + (" + first_time_access_for_user" if first_time else "")
                ),
                supporting_event_ids=[ev.event_id],
                raw_log_references=[ev.raw_log],
                confidence=0.90 if first_time else 0.78,
                confidence_label="high" if first_time else "medium-high",
                is_synthetic=ev.is_synthetic,
            )
        )

    return findings


def detect_data_exfiltration(
    events: List[CanonicalEvent],
    spike_multiplier: Optional[float] = None,
    min_bytes: Optional[int] = None,
) -> List[Finding]:
    """Detect outbound data transfer spikes compared against account/host baselines."""
    mult = spike_multiplier if spike_multiplier is not None else settings.outbound_spike_multiplier
    floor_bytes = min_bytes if min_bytes is not None else settings.outbound_min_bytes

    egress_by_user: Dict[str, List[int]] = defaultdict(list)
    all_normal_bytes: List[int] = []

    for ev in events:
        if ev.bytes_out > 0:
            # Exclude huge transfers (>100 MB) from baseline calculation so spikes don't mask themselves
            if ev.bytes_out < 100 * 1024 * 1024:
                egress_by_user[ev.user].append(ev.bytes_out)
                all_normal_bytes.append(ev.bytes_out)

    global_baseline = (
        sorted(all_normal_bytes)[len(all_normal_bytes) // 2]
        if all_normal_bytes
        else int(3.8 * 1024 * 1024)
    )

    findings: List[Finding] = []
    for ev in events:
        if ev.bytes_out <= 0:
            continue
        user_hist = sorted(egress_by_user.get(ev.user, []))
        # If user has baseline samples, take median; otherwise fallback to 3.8 MB / global baseline
        if len(user_hist) >= 3:
            baseline = float(user_hist[len(user_hist) // 2])
        else:
            baseline = float(max(global_baseline, 1024 * 1024))

        ratio = ev.bytes_out / max(baseline, 1.0)
        if ev.bytes_out >= floor_bytes and ratio >= mult:
            mb_out = ev.bytes_out / (1024 * 1024)
            mb_base = baseline / (1024 * 1024)
            dest = ev.dest_ip or ev.resource or "external endpoint"
            findings.append(
                Finding(
                    finding_id=_finding_id("EXF", f"{ev.user}:{ev.event_id}"),
                    detector_name="Outbound Data Exfiltration Detector",
                    detector_category="data_exfiltration",
                    detection_source="rule",
                    severity="critical" if mb_out >= 100 else "high",
                    timestamp=ev.timestamp,
                    affected_user=ev.user,
                    src_ip=ev.src_ip,
                    hostname=ev.hostname,
                    description=(
                        f"Account '{ev.user}' transferred {mb_out:.1f} MB outbound to {dest} "
                        f"from {ev.hostname}, exceeding the {mb_base:.1f} MB baseline by {ratio:.1f}x."
                    ),
                    triggered_condition=(
                        f"bytes_out ({mb_out:.1f} MB) >= {floor_bytes / (1024 * 1024):.0f} MB "
                        f"AND ratio ({ratio:.1f}x) >= {mult:.1f}x baseline ({mb_base:.1f} MB)"
                    ),
                    supporting_event_ids=[ev.event_id],
                    raw_log_references=[ev.raw_log],
                    confidence=0.91,
                    confidence_label="high",
                    is_synthetic=ev.is_synthetic,
                )
            )

    return findings


def detect_web_and_perimeter_threats(events: List[CanonicalEvent]) -> List[Finding]:
    """Detect web payload attacks (SQLi/XSS/traversal), firewall port scans, and audit tampering."""
    findings: List[Finding] = []
    sqli_re = re.compile(r"(?:union\s+select|or\s+1=1|information_schema|sleep\(\d+\)|'--)", re.IGNORECASE)
    xss_re = re.compile(r"(?:<script|onerror=|javascript:alert)", re.IGNORECASE)
    trav_re = re.compile(r"(?:\.\./\.\./|/etc/passwd|/proc/self/environ|wp-login\.php|\.env\b)", re.IGNORECASE)

    fw_blocks_by_ip: Dict[str, List[CanonicalEvent]] = defaultdict(list)

    for ev in events:
        if ev.source_type == "web":
            target_str = f"{ev.resource} {ev.raw_log}"
            attack_kind = None
            if sqli_re.search(target_str):
                attack_kind = "SQL Injection Probe"
            elif xss_re.search(target_str):
                attack_kind = "Cross-Site Scripting (XSS) Probe"
            elif trav_re.search(target_str):
                attack_kind = "Path Traversal / Sensitive File Probe"
            if attack_kind:
                findings.append(
                    Finding(
                        finding_id=_finding_id("WEB", f"{ev.src_ip}:{ev.event_id}"),
                        detector_name="Web Attack & Payload Signature Detector",
                        detector_category="sensitive_resource_access",
                        detection_source="rule",
                        severity="high",
                        timestamp=ev.timestamp,
                        affected_user=ev.user,
                        src_ip=ev.src_ip,
                        hostname=ev.hostname,
                        description=f"{attack_kind} observed from {ev.src_ip or 'unknown IP'} targeting '{ev.resource}'.",
                        triggered_condition=f"web_payload_signature='{attack_kind}'",
                        supporting_event_ids=[ev.event_id],
                        raw_log_references=[ev.raw_log],
                        confidence=0.89,
                        confidence_label="high",
                        is_synthetic=ev.is_synthetic,
                    )
                )

        if ev.source_type == "firewall" and ev.status == "failure" and ev.src_ip:
            fw_blocks_by_ip[ev.src_ip].append(ev)

        if ev.action == "win_audit_log_cleared":
            findings.append(
                Finding(
                    finding_id=_finding_id("WIN", f"{ev.hostname}:{ev.event_id}"),
                    detector_name="Windows Audit Log Tampering Detector",
                    detector_category="privilege_escalation",
                    detection_source="rule",
                    severity="critical",
                    timestamp=ev.timestamp,
                    affected_user=ev.user,
                    src_ip=ev.src_ip,
                    hostname=ev.hostname,
                    description=f"Security audit log cleared (EventID 1102) on {ev.hostname} by '{ev.user}'.",
                    triggered_condition="action=='win_audit_log_cleared'",
                    supporting_event_ids=[ev.event_id],
                    raw_log_references=[ev.raw_log],
                    confidence=0.95,
                    confidence_label="high",
                    is_synthetic=ev.is_synthetic,
                )
            )

    for src_ip, blocked in fw_blocks_by_ip.items():
        distinct_ports = {e.resource for e in blocked if e.resource}
        if len(blocked) >= 6 or len(distinct_ports) >= 4:
            blocked.sort(key=lambda e: e.timestamp)
            findings.append(
                Finding(
                    finding_id=_finding_id("FW", f"{src_ip}:{blocked[0].timestamp}"),
                    detector_name="Firewall Port Scan & Blocked Burst Detector",
                    detector_category="brute_force",
                    detection_source="rule",
                    severity="high",
                    timestamp=blocked[-1].timestamp,
                    affected_user="network",
                    src_ip=src_ip,
                    hostname=blocked[-1].hostname,
                    description=(
                        f"Source IP {src_ip} generated {len(blocked)} blocked firewall events "
                        f"across {len(distinct_ports)} port/protocol target(s) ({', '.join(sorted(distinct_ports)[:6])})."
                    ),
                    triggered_condition=f"blocked_connections={len(blocked)}, distinct_targets={len(distinct_ports)}",
                    supporting_event_ids=[e.event_id for e in blocked],
                    raw_log_references=[e.raw_log for e in blocked[:5]],
                    confidence=0.87,
                    confidence_label="high",
                    is_synthetic=any(e.is_synthetic for e in blocked),
                )
            )

    return findings


def run_all_rule_detectors(events: List[CanonicalEvent]) -> List[Finding]:
    """Execute all deterministic rule-based detectors across normalized events."""
    if not events:
        return []
    ordered = sorted(events, key=lambda e: e.timestamp)
    findings: List[Finding] = []
    findings.extend(detect_brute_force(ordered))
    findings.extend(detect_impossible_travel(ordered))
    findings.extend(detect_unusual_login_time(ordered))
    findings.extend(detect_privilege_escalation(ordered))
    findings.extend(detect_sensitive_resource_access(ordered))
    findings.extend(detect_data_exfiltration(ordered))
    findings.extend(detect_web_and_perimeter_threats(ordered))
    findings.sort(key=lambda f: f.timestamp)
    return findings
