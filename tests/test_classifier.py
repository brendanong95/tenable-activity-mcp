"""API-key vs UI/session classification, redaction and rollup tests."""

from __future__ import annotations

import pytest

from src.classifier import (
    ACCESS_API_KEY,
    ACCESS_SESSION,
    ACCESS_SYSTEM,
    ACCESS_UNKNOWN,
    build_actor_usage,
    classify_access_method,
    classify_event,
    classify_events,
    extract_source_ips,
    redact_fields,
    redact_value,
    summarize_events,
)

TENABLE_STYLE_KEY = "a" * 64


def event(
    action: str = "scan.launch",
    fields: list[dict] | None = None,
    actor_id: str = "actor-1",
    actor_name: str = "alice@example.com",
    actor_type: str = "User",
    received: str = "2024-05-01T10:00:00Z",
    is_failure: bool = False,
    crud: str = "create",
) -> dict:
    return {
        "id": f"{action}-{received}",
        "action": action,
        "crud": crud,
        "actor": {"id": actor_id, "name": actor_name, "type": actor_type},
        "target": {"id": "target-1", "name": "scan-a", "type": "Scan"},
        "received": received,
        "is_failure": is_failure,
        "is_anonymous": False,
        "fields": fields if fields is not None else [],
    }


# --------------------------------------------------------------------------- #
# Access-method classification
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("key", "value", "expected"),
    [
        ("access_method", "API Key", ACCESS_API_KEY),
        ("access_method", "apikey", ACCESS_API_KEY),
        ("auth_method", "api_key", ACCESS_API_KEY),
        ("authentication_method", "session", ACCESS_SESSION),
        ("login_type", "password", ACCESS_SESSION),
        ("access_type", "SAML", ACCESS_SESSION),
    ],
)
def test_explicit_access_method_field_wins(key, value, expected):
    access_type, reason = classify_access_method(event(fields=[{"key": key, "value": value}]))
    assert access_type == expected
    assert key in reason and value in reason  # reasoning must cite the evidence


@pytest.mark.parametrize(
    ("user_agent", "expected"),
    [
        ("pyTenable/1.4.20 (Python/3.11)", ACCESS_API_KEY),
        ("python-requests/2.32.0", ACCESS_API_KEY),
        ("curl/8.4.0", ACCESS_API_KEY),
        ("PostmanRuntime/7.36.0", ACCESS_API_KEY),
        ("Mozilla/5.0 (Windows NT 10.0) Chrome/124.0", ACCESS_SESSION),
        ("Mozilla/5.0 (Macintosh) Safari/605.1.15", ACCESS_SESSION),
    ],
)
def test_user_agent_is_the_fallback_signal(user_agent, expected):
    access_type, reason = classify_access_method(
        event(fields=[{"key": "user_agent", "value": user_agent}])
    )
    assert access_type == expected
    assert "user agent" in reason


def test_real_tenable_x_access_type_field_is_recognised():
    """Tenable VM emits `X-Access-Type: apikey`, not a generic access_method."""
    access_type, reason = classify_access_method(
        event(fields=[{"key": "X-Access-Type", "value": "apikey"}])
    )
    assert access_type == ACCESS_API_KEY
    assert "x-access-type" in reason


def test_session_uuid_field_marks_an_interactive_session():
    access_type, reason = classify_access_method(
        event(fields=[{"key": "X-Session-Uuid", "value": "11c0055"}])
    )
    assert access_type == ACCESS_SESSION
    assert "session id" in reason


@pytest.mark.parametrize(
    ("action", "expected"),
    [
        ("user.authenticate.api_keys", ACCESS_API_KEY),
        ("user.authenticate.password", ACCESS_SESSION),
        ("user.authenticate.mfa", ACCESS_SESSION),
        ("session.create", ACCESS_SESSION),
        ("user.logout", ACCESS_SESSION),
    ],
)
def test_authentication_actions_name_their_own_mechanism(action, expected):
    access_type, reason = classify_access_method(event(action=action))
    assert access_type == expected
    assert action in reason


@pytest.mark.parametrize(
    "action", ["api-findings-vulnerabilities-host.create", "api-exports.assets.create"]
)
def test_generic_api_actions_stay_unknown(action):
    """The web UI calls the same REST endpoints, so `api-*` proves nothing."""
    access_type, _ = classify_access_method(event(action=action))
    assert access_type == ACCESS_UNKNOWN


def test_access_type_field_beats_the_action_name():
    access_type, reason = classify_access_method(
        event(action="session.create", fields=[{"key": "X-Access-Type", "value": "apikey"}])
    )
    assert access_type == ACCESS_API_KEY
    assert "x-access-type" in reason


def test_x_forwarded_for_is_read_as_the_source_ip():
    assert extract_source_ips(
        event(fields=[{"key": "X-Forwarded-For", "value": "203.0.113.10"}])
    ) == ["203.0.113.10"]


def test_access_method_field_beats_user_agent():
    access_type, _ = classify_access_method(
        event(
            fields=[
                {"key": "user_agent", "value": "Mozilla/5.0 Chrome/124.0"},
                {"key": "access_method", "value": "apikey"},
            ]
        )
    )
    assert access_type == ACCESS_API_KEY


def test_system_actor_is_not_reported_as_api_key_usage():
    access_type, reason = classify_access_method(event(actor_type="System"))
    assert access_type == ACCESS_SYSTEM
    assert "actor.type" in reason


def test_unknown_when_no_signal_is_present():
    access_type, reason = classify_access_method(event(actor_type="User"))
    assert access_type == ACCESS_UNKNOWN
    assert "no access-method" in reason


def test_boolean_api_key_marker_is_honoured():
    access_type, _ = classify_access_method(
        event(fields=[{"key": "api_key_used", "value": "true"}])
    )
    assert access_type == ACCESS_API_KEY


def test_fields_may_arrive_as_a_mapping():
    access_type, _ = classify_access_method(event(fields={"access_method": "apikey"}))
    assert access_type == ACCESS_API_KEY


# --------------------------------------------------------------------------- #
# Source IPs
# --------------------------------------------------------------------------- #


def test_source_ips_are_collected_and_deduplicated():
    ips = extract_source_ips(
        event(
            fields=[
                {"key": "source_ip", "value": "203.0.113.10"},
                {"key": "X-Forwarded-For", "value": "203.0.113.10, 198.51.100.7"},
                {"key": "unrelated", "value": "10.0.0.1"},
            ]
        )
    )
    assert ips == ["203.0.113.10", "198.51.100.7"]


def test_ipv6_source_is_extracted():
    assert extract_source_ips(
        event(fields=[{"key": "client_ip", "value": "2001:db8::42"}])
    ) == ["2001:db8::42"]


# --------------------------------------------------------------------------- #
# Redaction
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "key", ["secret_key", "accessKey", "api_key", "password", "authorization", "token"]
)
def test_credential_keys_are_redacted_to_last_four(key):
    assert redact_value(key, "SUPERSECRETVALUE1234") == "*" * 16 + "1234"


def test_credential_shaped_values_are_redacted_regardless_of_key():
    assert redact_value("note", TENABLE_STYLE_KEY).endswith("aaaa")
    assert redact_value("note", TENABLE_STYLE_KEY).count("*") == 60


def test_uuids_and_ips_are_not_mistaken_for_credentials():
    assert redact_value("target_id", "00000000-1111-4222-8333-444444444444") == (
        "00000000-1111-4222-8333-444444444444"
    )
    assert redact_value("source_ip", "203.0.113.10") == "203.0.113.10"


def test_redacted_fields_never_leak_the_original_secret():
    fields = redact_fields(
        event(fields=[{"key": "secret_key", "value": TENABLE_STYLE_KEY}])
    )
    assert fields[0]["value"] == "*" * 60 + "aaaa"
    assert TENABLE_STYLE_KEY not in fields[0]["value"]


def test_classify_event_output_is_redacted():
    record = classify_event(
        event(fields=[{"key": "api_key", "value": "0123456789abcdef0123456789abcdef"}])
    )
    assert record["fields"][0]["value"].endswith("cdef")
    assert "*" in record["fields"][0]["value"]


# --------------------------------------------------------------------------- #
# Normalisation
# --------------------------------------------------------------------------- #


def test_classify_event_flattens_actor_and_target():
    record = classify_event(
        event(fields=[{"key": "source_ip", "value": "203.0.113.10"}])
    )
    assert record["actor_id"] == "actor-1"
    assert record["actor_name"] == "alice@example.com"
    assert record["target_id"] == "target-1"
    assert record["received"] == "2024-05-01T10:00:00Z"
    assert record["source_ips"] == ["203.0.113.10"]


def test_events_without_an_id_get_a_stable_synthetic_key():
    raw = event()
    del raw["id"]
    first = classify_event(raw)["id"]
    second = classify_event(dict(raw))["id"]
    assert first == second
    assert first.startswith("sha1:")


# --------------------------------------------------------------------------- #
# Rollups (all arithmetic happens here, not in the LLM)
# --------------------------------------------------------------------------- #


def sample_records() -> list[dict]:
    return classify_events(
        [
            event(action="user.login", fields=[{"key": "access_method", "value": "apikey"}]),
            event(action="scan.launch", fields=[{"key": "access_method", "value": "apikey"}]),
            event(
                action="user.login",
                actor_id="actor-2",
                actor_name="bob@example.com",
                fields=[{"key": "user_agent", "value": "Mozilla/5.0 Chrome/124"}],
            ),
            event(
                action="user.login",
                actor_id="actor-2",
                actor_name="bob@example.com",
                is_failure=True,
                crud="read",
                fields=[{"key": "user_agent", "value": "Mozilla/5.0 Chrome/124"}],
            ),
        ]
    )


def test_summarize_counts_by_actor_action_crud_and_access_type():
    summary = summarize_events(sample_records())

    assert summary["total_events"] == 4
    assert summary["distinct_actors"] == 2
    assert summary["failure_count"] == 1
    assert summary["failure_rate_pct"] == 25.0
    assert {row["action"]: row["count"] for row in summary["by_action"]} == {
        "user.login": 3,
        "scan.launch": 1,
    }
    assert {row["crud"]: row["count"] for row in summary["by_crud"]} == {
        "create": 3,
        "read": 1,
    }
    assert {row["access_type"]: row["count"] for row in summary["by_access_type"]} == {
        ACCESS_API_KEY: 2,
        ACCESS_SESSION: 2,
    }
    actor_two = next(r for r in summary["by_actor"] if r["actor_id"] == "actor-2")
    assert actor_two["count"] == 2
    assert actor_two["failure_rate_pct"] == 50.0
    assert summary["first_event"] == "2024-05-01T10:00:00Z"


def test_summarize_handles_an_empty_window_without_dividing_by_zero():
    summary = summarize_events([])
    assert summary["total_events"] == 0
    assert summary["failure_rate_pct"] == 0.0
    assert summary["by_actor"] == []


def test_api_key_usage_excludes_session_activity():
    profiles = build_actor_usage(sample_records(), access_types=(ACCESS_API_KEY,))

    assert len(profiles) == 1
    profile = profiles[0]
    assert profile["actor_id"] == "actor-1"
    assert profile["event_count"] == 2
    assert {row["action"] for row in profile["action_breakdown"]} == {
        "user.login",
        "scan.launch",
    }
    assert profile["first_seen"] == "2024-05-01T10:00:00Z"


def test_actor_usage_tracks_distinct_source_ips():
    records = classify_events(
        [
            event(fields=[
                {"key": "access_method", "value": "apikey"},
                {"key": "source_ip", "value": "203.0.113.10"},
            ]),
            event(
                received="2024-05-02T11:00:00Z",
                fields=[
                    {"key": "access_method", "value": "apikey"},
                    {"key": "source_ip", "value": "198.51.100.7"},
                ],
            ),
            event(
                received="2024-05-03T11:00:00Z",
                fields=[
                    {"key": "access_method", "value": "apikey"},
                    {"key": "source_ip", "value": "203.0.113.10"},
                ],
            ),
        ]
    )
    profile = build_actor_usage(records, access_types=(ACCESS_API_KEY,))[0]

    assert profile["distinct_source_ip_count"] == 2
    assert profile["source_ips"][0] == {"ip": "203.0.113.10", "count": 2}
    assert profile["last_seen"] == "2024-05-03T11:00:00Z"


def test_actor_usage_can_cover_every_access_type_for_one_actor():
    profiles = build_actor_usage(sample_records(), access_types=(), actor_id="actor-2")
    assert len(profiles) == 1
    assert profiles[0]["event_count"] == 2
