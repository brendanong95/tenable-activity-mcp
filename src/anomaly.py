"""Baseline comparison and threshold-based anomaly flagging.

Every threshold is a named constant at the top of this module - no magic numbers
buried in the checks - so an operator can tune sensitivity in one place.

All comparisons run in Python and produce *findings*: each finding carries the
observed value, the threshold it crossed, and a plain-English ``reasoning``
string.  Nothing here returns a bare boolean, and the calling model is never
asked to do the arithmetic itself.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Any, Sequence

from .classifier import ACCESS_API_KEY, actor_label
from .tenable_client import parse_iso8601, to_iso, utc_now

# --------------------------------------------------------------------------- #
# Tunable thresholds
# --------------------------------------------------------------------------- #

#: Default rolling baseline window, in days.
DEFAULT_BASELINE_DAYS = 30

#: Re-fetch/recompute baselines when the stored ones are older than this.
BASELINE_REFRESH_MAX_AGE_HOURS = 12

#: Window events/day must exceed baseline average by this factor to flag.
SPIKE_MULTIPLIER = 3.0
#: Below this many events in the window, a spike is statistical noise.
SPIKE_MIN_WINDOW_EVENTS = 20
#: Below this baseline rate, ratios explode meaninglessly; skip the check.
SPIKE_MIN_BASELINE_EVENTS_PER_DAY = 0.5

#: Only IPs seen within this many days count as "known" for an actor.
NEW_IP_LOOKBACK_DAYS = 30
#: An actor needs at least this many known IPs before a new one is meaningful.
NEW_IP_MIN_KNOWN_IPS = 1

#: N failures inside this many minutes for one actor is a burst.
FAILED_AUTH_BURST_COUNT = 5
FAILED_AUTH_BURST_WINDOW_MINUTES = 10

#: Sustained-failure check: flag when an actor's failure rate exceeds this
#: percentage over at least this many events.
HIGH_FAILURE_RATE_PCT = 50.0
HIGH_FAILURE_RATE_MIN_EVENTS = 10

#: Off-hours are [OFF_HOURS_START_HOUR, 24) plus [0, OFF_HOURS_END_HOUR), in UTC.
OFF_HOURS_START_HOUR = 20
OFF_HOURS_END_HOUR = 6
#: Minimum off-hours events before the check can fire.
OFF_HOURS_MIN_EVENTS = 10
#: Window off-hours share must exceed baseline share by this factor.
OFF_HOURS_RATIO_MULTIPLIER = 2.0
#: Floor applied to the baseline share so a near-zero baseline cannot divide-by-noise.
OFF_HOURS_BASELINE_RATIO_FLOOR = 0.10

#: An actor needs this many known actions before an unseen action is notable.
NEW_ACTION_MIN_KNOWN_ACTIONS = 3
#: Cap on how many new actions are listed in one finding.
NEW_ACTION_REPORT_LIMIT = 10

SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"
SEVERITY_ORDER = {SEVERITY_HIGH: 0, SEVERITY_MEDIUM: 1, SEVERITY_LOW: 2}

FINDING_NEW_ACTOR = "new_actor"
FINDING_VOLUME_SPIKE = "volume_spike"
FINDING_NEW_SOURCE_IP = "new_source_ip"
FINDING_FAILURE_BURST = "failed_auth_burst"
FINDING_HIGH_FAILURE_RATE = "high_failure_rate"
FINDING_OFF_HOURS = "off_hours_spike"
FINDING_NEW_ACTION = "new_action"


def thresholds_snapshot() -> dict[str, Any]:
    """The active threshold configuration, echoed back with every result."""
    return {
        "spike_multiplier": SPIKE_MULTIPLIER,
        "spike_min_window_events": SPIKE_MIN_WINDOW_EVENTS,
        "spike_min_baseline_events_per_day": SPIKE_MIN_BASELINE_EVENTS_PER_DAY,
        "new_ip_lookback_days": NEW_IP_LOOKBACK_DAYS,
        "new_ip_min_known_ips": NEW_IP_MIN_KNOWN_IPS,
        "failed_auth_burst_count": FAILED_AUTH_BURST_COUNT,
        "failed_auth_burst_window_minutes": FAILED_AUTH_BURST_WINDOW_MINUTES,
        "high_failure_rate_pct": HIGH_FAILURE_RATE_PCT,
        "high_failure_rate_min_events": HIGH_FAILURE_RATE_MIN_EVENTS,
        "off_hours_utc": f"{OFF_HOURS_START_HOUR:02d}:00-{OFF_HOURS_END_HOUR:02d}:00",
        "off_hours_min_events": OFF_HOURS_MIN_EVENTS,
        "off_hours_ratio_multiplier": OFF_HOURS_RATIO_MULTIPLIER,
        "off_hours_baseline_ratio_floor": OFF_HOURS_BASELINE_RATIO_FLOOR,
        "new_action_min_known_actions": NEW_ACTION_MIN_KNOWN_ACTIONS,
    }


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def is_off_hours(stamp: datetime) -> bool:
    """True when a UTC timestamp falls in the configured off-hours band."""
    hour = stamp.hour
    if OFF_HOURS_START_HOUR > OFF_HOURS_END_HOUR:  # band wraps midnight
        return hour >= OFF_HOURS_START_HOUR or hour < OFF_HOURS_END_HOUR
    return OFF_HOURS_START_HOUR <= hour < OFF_HOURS_END_HOUR


def window_days(window_start: datetime | None, window_end: datetime | None) -> float:
    """Length of the analysis window in days, floored at a partial day."""
    if not window_start or not window_end:
        return 1.0
    seconds = (window_end - window_start).total_seconds()
    return max(seconds / 86400.0, 1.0 / 24.0)


def _finding(
    finding_type: str,
    severity: str,
    actor_id: str,
    actor_name: str | None,
    reasoning: str,
    evidence: dict[str, Any],
    threshold: dict[str, Any],
) -> dict[str, Any]:
    return {
        "type": finding_type,
        "severity": severity,
        "actor_id": actor_id,
        "actor_name": actor_name,
        "reasoning": reasoning,
        "evidence": evidence,
        "threshold": threshold,
    }


def _timestamps(records: Sequence[dict[str, Any]]) -> list[datetime]:
    stamps = [parse_iso8601(r.get("received")) for r in records]
    return sorted(s for s in stamps if s is not None)


# --------------------------------------------------------------------------- #
# Individual checks
# --------------------------------------------------------------------------- #


def check_new_actor(
    actor_id: str,
    records: Sequence[dict[str, Any]],
    baseline: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Flag an actor with no history at all before this window."""
    known = baseline is not None and (
        baseline.get("lifetime_events", 0) > 0 or baseline.get("baseline_total_events", 0) > 0
    )
    if known:
        return []
    name = records[0].get("actor_name") if records else None
    stamps = _timestamps(records)
    api_key_events = sum(1 for r in records if r.get("access_type") == ACCESS_API_KEY)
    return [
        _finding(
            FINDING_NEW_ACTOR,
            SEVERITY_HIGH if api_key_events else SEVERITY_MEDIUM,
            actor_id,
            name,
            (
                f"Actor '{name or actor_id}' has no recorded history in the local baseline "
                f"but generated {len(records)} event(s) in this window "
                f"({api_key_events} via API key). Either the actor is genuinely new or the "
                "baseline has never been populated for it."
            ),
            {
                "window_event_count": len(records),
                "apikey_event_count": api_key_events,
                "first_event": to_iso(stamps[0]) if stamps else None,
                "last_event": to_iso(stamps[-1]) if stamps else None,
                "actions": sorted({str(r.get("action")) for r in records})[:10],
            },
            {"rule": "no baseline history for this actor"},
        )
    ]


def check_volume_spike(
    actor_id: str,
    records: Sequence[dict[str, Any]],
    baseline: dict[str, Any] | None,
    observed_days: float,
) -> list[dict[str, Any]]:
    """Flag when events/day exceeds SPIKE_MULTIPLIER x the baseline average."""
    if baseline is None:
        return []
    baseline_avg = float(baseline.get("avg_events_per_day") or 0.0)
    count = len(records)
    if count < SPIKE_MIN_WINDOW_EVENTS:
        return []
    if baseline_avg < SPIKE_MIN_BASELINE_EVENTS_PER_DAY:
        return []
    observed_rate = count / max(observed_days, 1.0 / 24.0)
    if observed_rate <= baseline_avg * SPIKE_MULTIPLIER:
        return []
    ratio = round(observed_rate / baseline_avg, 2)
    return [
        _finding(
            FINDING_VOLUME_SPIKE,
            SEVERITY_HIGH if ratio >= SPIKE_MULTIPLIER * 2 else SEVERITY_MEDIUM,
            actor_id,
            baseline.get("actor_name") or (records[0].get("actor_name") if records else None),
            (
                f"Actor generated {count} event(s) over {round(observed_days, 2)} day(s) "
                f"({round(observed_rate, 2)}/day) versus a baseline of "
                f"{round(baseline_avg, 2)}/day across {baseline.get('window_days')} day(s) - "
                f"{ratio}x the historical rate, above the {SPIKE_MULTIPLIER}x threshold."
            ),
            {
                "window_event_count": count,
                "window_days": round(observed_days, 2),
                "observed_events_per_day": round(observed_rate, 2),
                "baseline_events_per_day": round(baseline_avg, 2),
                "ratio": ratio,
                "baseline_window_days": baseline.get("window_days"),
                "top_actions": [
                    {"action": action, "count": n}
                    for action, n in Counter(
                        str(r.get("action")) for r in records
                    ).most_common(5)
                ],
            },
            {"spike_multiplier": SPIKE_MULTIPLIER, "min_window_events": SPIKE_MIN_WINDOW_EVENTS},
        )
    ]


def check_new_source_ips(
    actor_id: str,
    records: Sequence[dict[str, Any]],
    baseline: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Flag source IPs absent from the actor's recent known-IP set."""
    if baseline is None:
        return []
    known = {str(ip) for ip in baseline.get("known_ips") or []}
    if len(known) < NEW_IP_MIN_KNOWN_IPS:
        return []
    unseen: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        for ip in record.get("source_ips") or []:
            if str(ip) not in known:
                unseen[str(ip)].append(record)
    if not unseen:
        return []
    findings = []
    for ip, hits in sorted(unseen.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        stamps = _timestamps(hits)
        api_key_hits = sum(1 for r in hits if r.get("access_type") == ACCESS_API_KEY)
        findings.append(
            _finding(
                FINDING_NEW_SOURCE_IP,
                SEVERITY_HIGH if api_key_hits else SEVERITY_MEDIUM,
                actor_id,
                baseline.get("actor_name"),
                (
                    f"Source IP {ip} produced {len(hits)} event(s) for this actor but does not "
                    f"appear in the {NEW_IP_LOOKBACK_DAYS}-day baseline of "
                    f"{len(known)} known IP(s). {api_key_hits} of those event(s) were API-key "
                    "driven."
                ),
                {
                    "new_ip": ip,
                    "event_count": len(hits),
                    "apikey_event_count": api_key_hits,
                    "first_event": to_iso(stamps[0]) if stamps else None,
                    "last_event": to_iso(stamps[-1]) if stamps else None,
                    "known_ips": sorted(known)[:20],
                    "actions": sorted({str(r.get("action")) for r in hits})[:10],
                },
                {
                    "new_ip_lookback_days": NEW_IP_LOOKBACK_DAYS,
                    "min_known_ips": NEW_IP_MIN_KNOWN_IPS,
                },
            )
        )
    return findings


def check_failure_burst(
    actor_id: str,
    records: Sequence[dict[str, Any]],
    baseline: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Flag FAILED_AUTH_BURST_COUNT failures inside a sliding time window."""
    stamped: list[tuple[datetime, dict[str, Any]]] = []
    for record in records:
        if not record.get("is_failure"):
            continue
        stamp = parse_iso8601(record.get("received"))
        if stamp is not None:
            stamped.append((stamp, record))
    stamped.sort(key=lambda pair: pair[0])
    if len(stamped) < FAILED_AUTH_BURST_COUNT:
        return []

    span = timedelta(minutes=FAILED_AUTH_BURST_WINDOW_MINUTES)
    best: tuple[int, datetime, datetime, list[dict[str, Any]]] | None = None
    left = 0
    for right in range(len(stamped)):
        while stamped[right][0] - stamped[left][0] > span:
            left += 1
        size = right - left + 1
        if best is None or size > best[0]:
            best = (
                size,
                stamped[left][0],
                stamped[right][0],
                [r for _, r in stamped[left : right + 1]],
            )
    if best is None or best[0] < FAILED_AUTH_BURST_COUNT:
        return []

    size, start, end, burst_records = best
    name = baseline.get("actor_name") if baseline else None
    ips = sorted({ip for r in burst_records for ip in (r.get("source_ips") or [])})
    return [
        _finding(
            FINDING_FAILURE_BURST,
            SEVERITY_HIGH,
            actor_id,
            name or (records[0].get("actor_name") if records else None),
            (
                f"{size} failed event(s) clustered within "
                f"{FAILED_AUTH_BURST_WINDOW_MINUTES} minute(s) "
                f"({to_iso(start)} to {to_iso(end)}), at or above the "
                f"{FAILED_AUTH_BURST_COUNT}-failure burst threshold. "
                f"Total failures for this actor in the window: {len(stamped)}."
            ),
            {
                "burst_size": size,
                "burst_start": to_iso(start),
                "burst_end": to_iso(end),
                "total_failures_in_window": len(stamped),
                "source_ips": ips[:20],
                "actions": [
                    {"action": action, "count": n}
                    for action, n in Counter(
                        str(r.get("action")) for r in burst_records
                    ).most_common(5)
                ],
            },
            {
                "failed_auth_burst_count": FAILED_AUTH_BURST_COUNT,
                "failed_auth_burst_window_minutes": FAILED_AUTH_BURST_WINDOW_MINUTES,
            },
        )
    ]


def check_high_failure_rate(
    actor_id: str,
    records: Sequence[dict[str, Any]],
    baseline: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Flag a sustained majority-failure pattern even without a tight burst."""
    total = len(records)
    if total < HIGH_FAILURE_RATE_MIN_EVENTS:
        return []
    failures = sum(1 for r in records if r.get("is_failure"))
    rate = (failures / total) * 100
    if rate <= HIGH_FAILURE_RATE_PCT:
        return []
    return [
        _finding(
            FINDING_HIGH_FAILURE_RATE,
            SEVERITY_MEDIUM,
            actor_id,
            (baseline or {}).get("actor_name")
            or (records[0].get("actor_name") if records else None),
            (
                f"{failures} of {total} event(s) failed ({round(rate, 2)}%), above the "
                f"{HIGH_FAILURE_RATE_PCT}% sustained-failure threshold over at least "
                f"{HIGH_FAILURE_RATE_MIN_EVENTS} events."
            ),
            {
                "failure_count": failures,
                "event_count": total,
                "failure_rate_pct": round(rate, 2),
                "failed_actions": [
                    {"action": action, "count": n}
                    for action, n in Counter(
                        str(r.get("action")) for r in records if r.get("is_failure")
                    ).most_common(5)
                ],
            },
            {
                "high_failure_rate_pct": HIGH_FAILURE_RATE_PCT,
                "min_events": HIGH_FAILURE_RATE_MIN_EVENTS,
            },
        )
    ]


def _baseline_off_hours_ratio(baseline: dict[str, Any] | None) -> float | None:
    """Off-hours share of the baseline window, from its hour histogram."""
    if not baseline:
        return None
    histogram = baseline.get("baseline_hour_histogram") or baseline.get(
        "lifetime_hour_histogram"
    )
    if not histogram:
        return None
    total = 0
    off = 0
    for hour, count in histogram.items():
        try:
            hour_int = int(hour)
            count_int = int(count)
        except (TypeError, ValueError):
            continue
        total += count_int
        if is_off_hours(datetime(2000, 1, 1, hour_int)):
            off += count_int
    if total == 0:
        return None
    return off / total


def check_off_hours(
    actor_id: str,
    records: Sequence[dict[str, Any]],
    baseline: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Flag an off-hours share well above the actor's historical share."""
    stamps = _timestamps(records)
    if not stamps:
        return []
    off_records = [
        r
        for r in records
        if (parse_iso8601(r.get("received")) is not None)
        and is_off_hours(parse_iso8601(r.get("received")))  # type: ignore[arg-type]
    ]
    if len(off_records) < OFF_HOURS_MIN_EVENTS:
        return []
    window_ratio = len(off_records) / len(stamps)
    baseline_ratio = _baseline_off_hours_ratio(baseline)
    effective_baseline = max(
        baseline_ratio if baseline_ratio is not None else 0.0,
        OFF_HOURS_BASELINE_RATIO_FLOOR,
    )
    if window_ratio <= effective_baseline * OFF_HOURS_RATIO_MULTIPLIER:
        return []
    return [
        _finding(
            FINDING_OFF_HOURS,
            SEVERITY_MEDIUM,
            actor_id,
            (baseline or {}).get("actor_name")
            or (records[0].get("actor_name") if records else None),
            (
                f"{len(off_records)} of {len(stamps)} event(s) "
                f"({round(window_ratio * 100, 2)}%) landed in the off-hours band "
                f"{OFF_HOURS_START_HOUR:02d}:00-{OFF_HOURS_END_HOUR:02d}:00 UTC, versus a "
                f"baseline share of "
                f"{'unknown' if baseline_ratio is None else str(round(baseline_ratio * 100, 2)) + '%'}"
                f" (floor {round(OFF_HOURS_BASELINE_RATIO_FLOOR * 100, 2)}%) - more than "
                f"{OFF_HOURS_RATIO_MULTIPLIER}x the expected share."
            ),
            {
                "off_hours_event_count": len(off_records),
                "window_event_count": len(stamps),
                "off_hours_share_pct": round(window_ratio * 100, 2),
                "baseline_off_hours_share_pct": (
                    None if baseline_ratio is None else round(baseline_ratio * 100, 2)
                ),
                "hours_utc": [
                    {"hour": hour, "count": n}
                    for hour, n in sorted(
                        Counter(
                            (parse_iso8601(r.get("received")) or utc_now()).hour
                            for r in off_records
                        ).items()
                    )
                ],
                "source_ips": sorted(
                    {ip for r in off_records for ip in (r.get("source_ips") or [])}
                )[:20],
            },
            {
                "off_hours_utc": f"{OFF_HOURS_START_HOUR:02d}:00-{OFF_HOURS_END_HOUR:02d}:00",
                "off_hours_min_events": OFF_HOURS_MIN_EVENTS,
                "off_hours_ratio_multiplier": OFF_HOURS_RATIO_MULTIPLIER,
            },
        )
    ]


def check_new_actions(
    actor_id: str,
    records: Sequence[dict[str, Any]],
    baseline: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Flag action types this actor has never performed before."""
    if baseline is None:
        return []
    known = {str(a) for a in baseline.get("known_actions") or []}
    if len(known) < NEW_ACTION_MIN_KNOWN_ACTIONS:
        return []
    unseen = Counter(
        str(r.get("action")) for r in records if str(r.get("action")) not in known
    )
    if not unseen:
        return []
    return [
        _finding(
            FINDING_NEW_ACTION,
            SEVERITY_LOW,
            actor_id,
            baseline.get("actor_name"),
            (
                f"Actor performed {len(unseen)} action type(s) never seen in "
                f"{len(known)} historically observed action(s): "
                + ", ".join(sorted(unseen)[:NEW_ACTION_REPORT_LIMIT])
                + "."
            ),
            {
                "new_actions": [
                    {"action": action, "count": n}
                    for action, n in unseen.most_common(NEW_ACTION_REPORT_LIMIT)
                ],
                "known_action_count": len(known),
            },
            {"new_action_min_known_actions": NEW_ACTION_MIN_KNOWN_ACTIONS},
        )
    ]


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #


def detect_anomalies(
    records: Sequence[dict[str, Any]],
    baselines: dict[str, dict[str, Any]] | None = None,
    window_start: datetime | None = None,
    window_end: datetime | None = None,
    baseline_days: int = DEFAULT_BASELINE_DAYS,
) -> dict[str, Any]:
    """Run every check over classified events, grouped by actor.

    ``baselines`` maps actor id to the view produced by
    :meth:`src.state.StateStore.get_baselines`.  Actors missing from it are
    treated as new.
    """
    baselines = baselines or {}
    by_actor: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        by_actor[actor_label(record)].append(record)

    if window_start is None or window_end is None:
        stamps = _timestamps(records)
        window_start = window_start or (stamps[0] if stamps else None)
        window_end = window_end or (stamps[-1] if stamps else None)
    observed_days = window_days(window_start, window_end)

    findings: list[dict[str, Any]] = []
    for actor_id, actor_records in by_actor.items():
        baseline = baselines.get(actor_id)
        findings.extend(check_new_actor(actor_id, actor_records, baseline))
        findings.extend(check_volume_spike(actor_id, actor_records, baseline, observed_days))
        findings.extend(check_new_source_ips(actor_id, actor_records, baseline))
        findings.extend(check_failure_burst(actor_id, actor_records, baseline))
        findings.extend(check_high_failure_rate(actor_id, actor_records, baseline))
        findings.extend(check_off_hours(actor_id, actor_records, baseline))
        findings.extend(check_new_actions(actor_id, actor_records, baseline))

    findings.sort(
        key=lambda f: (SEVERITY_ORDER.get(f["severity"], 99), f["type"], str(f["actor_id"]))
    )

    return {
        "window": {
            "from": to_iso(window_start),
            "to": to_iso(window_end),
            "days": round(observed_days, 2),
        },
        "baseline_days": baseline_days,
        "events_analyzed": len(records),
        "actors_analyzed": len(by_actor),
        "actors_with_baseline": sum(1 for a in by_actor if a in baselines),
        "finding_count": len(findings),
        "findings_by_severity": dict(Counter(f["severity"] for f in findings)),
        "findings_by_type": dict(Counter(f["type"] for f in findings)),
        "thresholds": thresholds_snapshot(),
        "findings": findings,
    }
