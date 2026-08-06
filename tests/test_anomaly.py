"""Threshold and baseline-comparison tests for the anomaly detector.

Baselines are built through the real SQLite state store (in-memory) so the
detector is exercised against the same shape it sees in production.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from src.anomaly import (
    FAILED_AUTH_BURST_COUNT,
    FAILED_AUTH_BURST_WINDOW_MINUTES,
    FINDING_FAILURE_BURST,
    FINDING_HIGH_FAILURE_RATE,
    FINDING_NEW_ACTION,
    FINDING_NEW_ACTOR,
    FINDING_NEW_SOURCE_IP,
    FINDING_OFF_HOURS,
    FINDING_VOLUME_SPIKE,
    NEW_IP_LOOKBACK_DAYS,
    OFF_HOURS_MIN_EVENTS,
    SPIKE_MIN_WINDOW_EVENTS,
    SPIKE_MULTIPLIER,
    detect_anomalies,
    is_off_hours,
    thresholds_snapshot,
)
from src.classifier import classify_events
from src.state import StateStore

WINDOW_START = datetime(2024, 5, 10, 0, 0, tzinfo=timezone.utc)
WINDOW_END = datetime(2024, 5, 11, 0, 0, tzinfo=timezone.utc)
BASELINE_DAYS = 30
BASELINE_START = WINDOW_START - timedelta(days=BASELINE_DAYS)


def raw_event(
    when: datetime,
    actor_id: str = "actor-1",
    actor_name: str = "alice@example.com",
    action: str = "scan.launch",
    ip: str | None = "203.0.113.10",
    is_failure: bool = False,
    index: int = 0,
) -> dict:
    fields = [{"key": "access_method", "value": "apikey"}]
    if ip:
        fields.append({"key": "source_ip", "value": ip})
    return {
        "id": f"{actor_id}-{action}-{when.isoformat()}-{index}",
        "action": action,
        "crud": "create",
        "actor": {"id": actor_id, "name": actor_name, "type": "User"},
        "target": {"id": "t-1", "name": "scan", "type": "Scan"},
        "received": when.isoformat().replace("+00:00", "Z"),
        "is_failure": is_failure,
        "is_anonymous": False,
        "fields": fields,
    }


def series(
    count: int,
    start: datetime,
    step: timedelta = timedelta(hours=1),
    index: int = 0,
    **kwargs,
) -> list[dict]:
    """``count`` events spaced by ``step``; ``index`` offsets the synthetic ids."""
    return [raw_event(start + step * i, index=index + i, **kwargs) for i in range(count)]


@pytest.fixture()
def store():
    with StateStore(":memory:") as state:
        yield state


def seed_baseline(store: StateStore, events: list[dict], days: int = BASELINE_DAYS) -> dict:
    """Ingest baseline-window events and recompute baselines, as the tool does."""
    records = classify_events(events)
    store.record_events(records)
    store.refresh_baselines(
        records, window_days=days, window_start=BASELINE_START, window_end=WINDOW_START
    )
    return store.get_baselines(ip_lookback_days=NEW_IP_LOOKBACK_DAYS, now=WINDOW_END)


def run(records_raw: list[dict], baselines: dict) -> dict:
    return detect_anomalies(
        classify_events(records_raw),
        baselines=baselines,
        window_start=WINDOW_START,
        window_end=WINDOW_END,
        baseline_days=BASELINE_DAYS,
    )


def types_for(result: dict, actor_id: str | None = None) -> set[str]:
    return {
        f["type"]
        for f in result["findings"]
        if actor_id is None or f["actor_id"] == actor_id
    }


# --------------------------------------------------------------------------- #
# New actor
# --------------------------------------------------------------------------- #


def test_actor_with_no_history_is_flagged_as_new(store):
    baselines = seed_baseline(store, series(30, BASELINE_START))

    result = run(series(3, WINDOW_START, actor_id="actor-new"), baselines)

    findings = [f for f in result["findings"] if f["type"] == FINDING_NEW_ACTOR]
    assert len(findings) == 1
    assert findings[0]["actor_id"] == "actor-new"
    assert findings[0]["severity"] == "high"  # API-key driven
    assert "no recorded history" in findings[0]["reasoning"]
    assert findings[0]["evidence"]["window_event_count"] == 3


def test_known_actor_is_not_flagged_as_new(store):
    baselines = seed_baseline(store, series(30, BASELINE_START, step=timedelta(days=1)))

    result = run(series(2, WINDOW_START), baselines)

    assert FINDING_NEW_ACTOR not in types_for(result)


# --------------------------------------------------------------------------- #
# Volume spike
# --------------------------------------------------------------------------- #


def test_volume_above_spike_multiplier_is_flagged(store):
    # Baseline: 30 events over 30 days = 1.0/day.
    baselines = seed_baseline(store, series(30, BASELINE_START, step=timedelta(days=1)))

    # Window: 1 day, 40 events = 40/day = 40x baseline.
    result = run(series(40, WINDOW_START, step=timedelta(minutes=20)), baselines)

    findings = [f for f in result["findings"] if f["type"] == FINDING_VOLUME_SPIKE]
    assert len(findings) == 1
    evidence = findings[0]["evidence"]
    assert evidence["baseline_events_per_day"] == 1.0
    assert evidence["observed_events_per_day"] == 40.0
    assert evidence["ratio"] == 40.0
    assert findings[0]["severity"] == "high"
    assert str(SPIKE_MULTIPLIER) in findings[0]["reasoning"]


def test_volume_just_under_the_multiplier_is_not_flagged(store):
    # Baseline: 300 events over 30 days = 10/day. 3x threshold = 30/day.
    baselines = seed_baseline(
        store, series(300, BASELINE_START, step=timedelta(hours=2)), days=BASELINE_DAYS
    )

    result = run(series(29, WINDOW_START, step=timedelta(minutes=30)), baselines)

    assert FINDING_VOLUME_SPIKE not in types_for(result)


def test_small_windows_do_not_trip_the_spike_check(store):
    baselines = seed_baseline(store, series(30, BASELINE_START, step=timedelta(days=1)))

    result = run(series(SPIKE_MIN_WINDOW_EVENTS - 1, WINDOW_START), baselines)

    assert FINDING_VOLUME_SPIKE not in types_for(result)


# --------------------------------------------------------------------------- #
# New source IP
# --------------------------------------------------------------------------- #


def test_source_ip_outside_the_baseline_is_flagged(store):
    baselines = seed_baseline(store, series(30, BASELINE_START, step=timedelta(days=1)))

    result = run(series(2, WINDOW_START, ip="198.51.100.99"), baselines)

    findings = [f for f in result["findings"] if f["type"] == FINDING_NEW_SOURCE_IP]
    assert len(findings) == 1
    assert findings[0]["evidence"]["new_ip"] == "198.51.100.99"
    assert findings[0]["evidence"]["known_ips"] == ["203.0.113.10"]
    assert findings[0]["evidence"]["apikey_event_count"] == 2
    assert str(NEW_IP_LOOKBACK_DAYS) in findings[0]["reasoning"]


def test_known_source_ip_is_not_flagged(store):
    baselines = seed_baseline(store, series(30, BASELINE_START, step=timedelta(days=1)))

    result = run(series(2, WINDOW_START, ip="203.0.113.10"), baselines)

    assert FINDING_NEW_SOURCE_IP not in types_for(result)


def test_ips_older_than_the_lookback_no_longer_count_as_known(store):
    stale = WINDOW_START - timedelta(days=NEW_IP_LOOKBACK_DAYS + 10)
    records = classify_events(series(5, stale, step=timedelta(days=1)))
    store.record_events(records)
    store.refresh_baselines(records, window_days=BASELINE_DAYS)
    baselines = store.get_baselines(ip_lookback_days=NEW_IP_LOOKBACK_DAYS, now=WINDOW_END)

    assert baselines["actor-1"]["known_ips"] == []
    # With no recent known IPs the check stays quiet rather than crying wolf.
    result = run(series(2, WINDOW_START, ip="198.51.100.99"), baselines)
    assert FINDING_NEW_SOURCE_IP not in types_for(result)


# --------------------------------------------------------------------------- #
# Failure clustering
# --------------------------------------------------------------------------- #


def test_failed_event_burst_is_flagged(store):
    baselines = seed_baseline(store, series(30, BASELINE_START, step=timedelta(days=1)))

    burst = series(
        FAILED_AUTH_BURST_COUNT,
        WINDOW_START + timedelta(hours=2),
        step=timedelta(minutes=1),
        action="user.login",
        is_failure=True,
    )
    result = run(burst, baselines)

    findings = [f for f in result["findings"] if f["type"] == FINDING_FAILURE_BURST]
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert findings[0]["evidence"]["burst_size"] == FAILED_AUTH_BURST_COUNT
    assert str(FAILED_AUTH_BURST_WINDOW_MINUTES) in findings[0]["reasoning"]


def test_failures_spread_beyond_the_burst_window_are_not_a_burst(store):
    baselines = seed_baseline(store, series(30, BASELINE_START, step=timedelta(days=1)))

    spread = series(
        FAILED_AUTH_BURST_COUNT,
        WINDOW_START,
        step=timedelta(minutes=FAILED_AUTH_BURST_WINDOW_MINUTES + 5),
        action="user.login",
        is_failure=True,
    )
    result = run(spread, baselines)

    assert FINDING_FAILURE_BURST not in types_for(result)


def test_sustained_failure_rate_is_flagged_separately(store):
    baselines = seed_baseline(store, series(30, BASELINE_START, step=timedelta(days=1)))

    events = series(9, WINDOW_START, step=timedelta(hours=1), is_failure=True) + series(
        3, WINDOW_START + timedelta(hours=12), step=timedelta(hours=1), index=100
    )
    result = run(events, baselines)

    findings = [f for f in result["findings"] if f["type"] == FINDING_HIGH_FAILURE_RATE]
    assert len(findings) == 1
    assert findings[0]["evidence"]["failure_rate_pct"] == 75.0


# --------------------------------------------------------------------------- #
# Off hours
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("hour", [20, 22, 0, 3, 5])
def test_off_hours_band_includes_night_hours(hour):
    assert is_off_hours(datetime(2024, 5, 10, hour, tzinfo=timezone.utc))


@pytest.mark.parametrize("hour", [6, 9, 12, 17, 19])
def test_business_hours_are_not_off_hours(hour):
    assert not is_off_hours(datetime(2024, 5, 10, hour, tzinfo=timezone.utc))


def test_off_hours_concentration_is_flagged(store):
    # Baseline is entirely business hours (09:00 UTC daily).
    baselines = seed_baseline(
        store, series(30, BASELINE_START + timedelta(hours=9), step=timedelta(days=1))
    )

    night = series(
        OFF_HOURS_MIN_EVENTS,
        WINDOW_START + timedelta(hours=1),  # 01:00 UTC
        step=timedelta(minutes=5),
    )
    result = run(night, baselines)

    findings = [f for f in result["findings"] if f["type"] == FINDING_OFF_HOURS]
    assert len(findings) == 1
    assert findings[0]["evidence"]["off_hours_event_count"] == OFF_HOURS_MIN_EVENTS
    assert findings[0]["evidence"]["off_hours_share_pct"] == 100.0
    assert findings[0]["evidence"]["baseline_off_hours_share_pct"] == 0.0


def test_daytime_activity_is_not_flagged_as_off_hours(store):
    baselines = seed_baseline(
        store, series(30, BASELINE_START + timedelta(hours=9), step=timedelta(days=1))
    )

    day = series(
        OFF_HOURS_MIN_EVENTS, WINDOW_START + timedelta(hours=10), step=timedelta(minutes=5)
    )
    result = run(day, baselines)

    assert FINDING_OFF_HOURS not in types_for(result)


# --------------------------------------------------------------------------- #
# New actions / aggregation
# --------------------------------------------------------------------------- #


def test_unseen_action_type_is_flagged(store):
    baseline_events = (
        series(10, BASELINE_START, step=timedelta(days=1), action="scan.launch")
        + series(10, BASELINE_START, step=timedelta(days=1), action="scan.stop", index=50)
        + series(10, BASELINE_START, step=timedelta(days=1), action="user.login", index=90)
    )
    baselines = seed_baseline(store, baseline_events)

    result = run(series(2, WINDOW_START, action="user.apikeys.generate"), baselines)

    findings = [f for f in result["findings"] if f["type"] == FINDING_NEW_ACTION]
    assert len(findings) == 1
    assert findings[0]["evidence"]["new_actions"] == [
        {"action": "user.apikeys.generate", "count": 2}
    ]


def test_result_is_ordered_by_severity_and_carries_thresholds(store):
    baselines = seed_baseline(store, series(30, BASELINE_START, step=timedelta(days=1)))

    events = (
        series(40, WINDOW_START, step=timedelta(minutes=20), ip="198.51.100.99")
        + series(3, WINDOW_START, actor_id="actor-new", index=500)
    )
    result = run(events, baselines)

    severities = [f["severity"] for f in result["findings"]]
    assert severities == sorted(severities, key=lambda s: {"high": 0, "medium": 1, "low": 2}[s])
    assert result["finding_count"] == len(result["findings"])
    assert result["events_analyzed"] == 43
    assert result["actors_analyzed"] == 2
    assert result["thresholds"] == thresholds_snapshot()
    assert result["thresholds"]["spike_multiplier"] == SPIKE_MULTIPLIER
    assert result["findings_by_type"][FINDING_VOLUME_SPIKE] == 1


def test_empty_window_produces_no_findings(store):
    baselines = seed_baseline(store, series(30, BASELINE_START, step=timedelta(days=1)))

    result = run([], baselines)

    assert result["findings"] == []
    assert result["events_analyzed"] == 0


def test_baseline_refresh_is_idempotent(store):
    events = series(30, BASELINE_START, step=timedelta(days=1))
    first = seed_baseline(store, events)
    second = seed_baseline(store, events)

    assert first["actor-1"]["avg_events_per_day"] == second["actor-1"]["avg_events_per_day"]
    assert second["actor-1"]["lifetime_events"] == 30  # duplicates were not re-counted
