"""Pagination, filter-building and rate-limit backoff tests.

All API traffic is faked through a stub transport - no live Tenable calls.
"""

from __future__ import annotations

import pytest

from src.tenable_client import (
    BASE_BACKOFF_SECONDS,
    DEFAULT_PAGE_LIMIT,
    MAX_PAGE_LIMIT,
    MAX_RATE_LIMIT_RETRIES,
    TenableAPIError,
    TenableAuditLogClient,
    TenableAuthError,
    TenablePermissionError,
    TenableRateLimitError,
    _translate_status,
    build_filters,
    clamp_page_limit,
    filter_events_by_window,
    parse_iso8601,
)


def make_event(index: int, received: str = "2024-05-01T10:00:00Z") -> dict:
    return {
        "id": f"event-{index}",
        "action": "user.login",
        "crud": "read",
        "actor": {"id": "actor-1", "name": "alice@example.com"},
        "target": {"id": "target-1", "name": "console"},
        "received": received,
        "is_failure": False,
        "is_anonymous": False,
        "fields": [],
    }


class FakeTransport:
    """Serves a scripted list of pages and records the params it was called with."""

    def __init__(self, pages: list[dict]) -> None:
        self.pages = pages
        self.calls: list[dict] = []

    def get_events(self, params: dict) -> dict:
        self.calls.append(dict(params))
        index = len(self.calls) - 1
        if index >= len(self.pages):
            return {"events": [], "pagination": {"next": None}}
        return self.pages[index]


def page(events: list[dict], next_token: str | None, total: int | None = None) -> dict:
    pagination: dict = {"next": next_token}
    if total is not None:
        pagination["total"] = total
    return {"events": events, "pagination": pagination}


def build_client(transport: FakeTransport) -> tuple[TenableAuditLogClient, list[float]]:
    slept: list[float] = []
    client = TenableAuditLogClient(transport=transport, sleep=slept.append)
    return client, slept


# --------------------------------------------------------------------------- #
# Cursor following
# --------------------------------------------------------------------------- #


def test_follows_next_cursor_until_exhausted():
    transport = FakeTransport(
        [
            page([make_event(1), make_event(2)], "cursor-2", total=5),
            page([make_event(3), make_event(4)], "cursor-3"),
            page([make_event(5)], None),
        ]
    )
    client, _ = build_client(transport)

    result = client.fetch_events(date_from="2024-05-01", date_to="2024-05-02")

    assert [e["id"] for e in result.events] == [f"event-{i}" for i in range(1, 6)]
    assert result.pages_fetched == 3
    assert result.next_token is None
    assert result.truncated is False
    assert result.total_available == 5
    # Page 2 and 3 must carry the cursor returned by the previous page.
    assert [call["next_token"] for call in transport.calls] == [None, "cursor-2", "cursor-3"]


def test_resumes_from_supplied_next_token():
    transport = FakeTransport([page([make_event(9)], None)])
    client, _ = build_client(transport)

    client.fetch_events(date_from="2024-05-01", date_to="2024-05-02", next_token="cursor-42")

    assert transport.calls[0]["next_token"] == "cursor-42"


def test_stops_at_page_cap_and_returns_resume_token():
    transport = FakeTransport([page([make_event(i)], f"cursor-{i + 1}") for i in range(10)])
    client, _ = build_client(transport)

    result = client.fetch_events(date_from="2024-05-01", date_to="2024-05-02", max_pages=3)

    assert result.pages_fetched == 3
    assert len(result.events) == 3
    assert result.truncated is True
    assert result.next_token == "cursor-3"
    assert "Pass next_token to continue" in result.truncation_reason


def test_stops_at_event_cap():
    transport = FakeTransport(
        [page([make_event(i) for i in range(5)], f"cursor-{p}") for p in range(10)]
    )
    client, _ = build_client(transport)

    result = client.fetch_events(date_from="2024-05-01", date_to="2024-05-02", max_events=7)

    assert len(result.events) == 10  # cap checked per page, never mid-page
    assert result.pages_fetched == 2
    assert result.truncated is True
    assert result.next_token == "cursor-1"


def test_empty_page_terminates_the_loop_even_with_a_cursor():
    transport = FakeTransport([page([], "cursor-loop"), page([make_event(1)], None)])
    client, _ = build_client(transport)

    result = client.fetch_events(date_from="2024-05-01", date_to="2024-05-02")

    assert result.pages_fetched == 1
    assert result.events == []


def test_stale_cursor_on_an_empty_final_page_is_not_truncation():
    """Tenable returns a non-null `next` even after the last real page."""
    transport = FakeTransport(
        [
            page([make_event(i) for i in range(500)], "cursor-2", total=704),
            page([make_event(i) for i in range(500, 704)], "cursor-3", total=704),
            page([], "cursor-3", total=704),  # same cursor, no events
        ]
    )
    client, _ = build_client(transport)

    result = client.fetch_events(date_from="2024-05-01", date_to="2024-05-02")

    assert len(result.events) == 704
    assert result.truncated is False
    assert result.next_token is None
    assert result.to_dict()["has_more"] is False


def test_reaching_the_reported_total_ends_the_fetch():
    transport = FakeTransport([page([make_event(i) for i in range(40)], "cursor-2", total=40)])
    client, _ = build_client(transport)

    result = client.fetch_events(date_from="2024-05-01", date_to="2024-05-02", max_pages=1)

    assert result.truncated is False
    assert result.next_token is None


@pytest.mark.parametrize("token", ["", "0", 0, None])
def test_sentinel_next_tokens_are_treated_as_end_of_results(token):
    transport = FakeTransport([{"events": [make_event(1)], "pagination": {"next": token}}])
    client, _ = build_client(transport)

    result = client.fetch_events(date_from="2024-05-01", date_to="2024-05-02")

    assert result.next_token is None
    assert result.truncated is False


def test_malformed_page_bodies_do_not_crash():
    transport = FakeTransport([{}, {"events": "nope", "pagination": "nope"}])
    client, _ = build_client(transport)

    result = client.fetch_events(date_from="2024-05-01", date_to="2024-05-02")

    assert result.events == []


# --------------------------------------------------------------------------- #
# Filters and page size
# --------------------------------------------------------------------------- #


def test_build_filters_uses_documented_operators():
    filters = build_filters(
        date_from="2024-05-01",
        date_to="2024-05-31T23:59:59Z",
        actor_id="abc-123",
        action="user.create",
        target_id="tgt-9",
    )
    assert filters == [
        ("date", "gte", "2024-05-01"),
        ("date", "lte", "2024-05-31T23:59:59Z"),
        ("actor_id", "eq", "abc-123"),
        ("target_id", "eq", "tgt-9"),
        ("action", "eq", "user.create"),
    ]


def test_filters_are_forwarded_to_the_transport():
    transport = FakeTransport([page([make_event(1)], None)])
    client, _ = build_client(transport)

    client.fetch_events(
        date_from="2024-05-01", date_to="2024-05-02", actor_id="a-1", action="scan.launch"
    )

    assert ("actor_id", "eq", "a-1") in transport.calls[0]["filters"]
    assert ("action", "eq", "scan.launch") in transport.calls[0]["filters"]


@pytest.mark.parametrize(
    ("supplied", "expected"),
    [(0, 1), (-5, 1), (250, 250), (99999, MAX_PAGE_LIMIT), ("bad", DEFAULT_PAGE_LIMIT)],
)
def test_page_limit_is_clamped_to_the_api_range(supplied, expected):
    assert clamp_page_limit(supplied) == expected


def test_client_side_window_filter_trims_out_of_range_events():
    events = [
        make_event(1, "2024-04-30T23:00:00Z"),
        make_event(2, "2024-05-01T12:00:00Z"),
        make_event(3, "2024-05-03T01:00:00Z"),
        {"id": "no-timestamp", "action": "x"},
    ]
    kept = filter_events_by_window(
        events, parse_iso8601("2024-05-01T00:00:00Z"), parse_iso8601("2024-05-02T00:00:00Z")
    )
    # Undated events are kept deliberately: an audit tool must not hide activity.
    assert [e["id"] for e in kept] == ["event-2", "no-timestamp"]


def test_fetch_applies_precise_window_to_day_granular_results():
    transport = FakeTransport(
        [
            page(
                [
                    make_event(1, "2024-05-01T01:00:00Z"),
                    make_event(2, "2024-05-01T23:00:00Z"),
                ],
                None,
            )
        ]
    )
    client, _ = build_client(transport)

    result = client.fetch_events(
        date_from="2024-05-01T00:00:00Z", date_to="2024-05-01T12:00:00Z"
    )

    assert [e["id"] for e in result.events] == ["event-1"]


# --------------------------------------------------------------------------- #
# Rate limiting / errors
# --------------------------------------------------------------------------- #


class FlakyTransport:
    """Raises a scripted sequence of errors before serving a page."""

    def __init__(self, errors: list[Exception]) -> None:
        self.errors = errors
        self.attempts = 0

    def get_events(self, params: dict) -> dict:
        self.attempts += 1
        if self.errors:
            raise self.errors.pop(0)
        return page([make_event(1)], None)


def test_rate_limit_backoff_prefers_the_reset_header():
    transport = FlakyTransport(
        [TenableRateLimitError("429", reset_seconds=7.0), TenableRateLimitError("429")]
    )
    client, slept = build_client(transport)

    result = client.fetch_events(date_from="2024-05-01", date_to="2024-05-02")

    assert transport.attempts == 3
    assert len(result.events) == 1
    # First retry honours X-RateLimit-Reset; second falls back to exponential.
    assert slept[0] == 7.0
    assert slept[1] == BASE_BACKOFF_SECONDS * 2


def test_rate_limit_gives_up_after_the_retry_cap():
    transport = FlakyTransport(
        [TenableRateLimitError("429") for _ in range(MAX_RATE_LIMIT_RETRIES + 1)]
    )
    client, slept = build_client(transport)

    with pytest.raises(TenableRateLimitError) as excinfo:
        client.fetch_events(date_from="2024-05-01", date_to="2024-05-02")

    assert len(slept) == MAX_RATE_LIMIT_RETRIES
    assert "Gave up after" in excinfo.value.message


def test_server_errors_are_retried_but_client_errors_are_not():
    transport = FlakyTransport([TenableAPIError("boom", status_code=503)])
    client, slept = build_client(transport)
    assert len(client.fetch_events(date_from="2024-05-01", date_to="2024-05-02").events) == 1
    assert len(slept) == 1

    transport = FlakyTransport([TenableAPIError("bad request", status_code=400)])
    client, _ = build_client(transport)
    with pytest.raises(TenableAPIError):
        client.fetch_events(date_from="2024-05-01", date_to="2024-05-02")


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (401, TenableAuthError),
        (403, TenablePermissionError),
        (429, TenableRateLimitError),
        (500, TenableAPIError),
    ],
)
def test_http_status_maps_to_typed_error(status, expected):
    assert isinstance(_translate_status(status, ""), expected)


def test_permission_error_names_the_required_role():
    error = _translate_status(403, "")
    assert "Administrator" in error.message
    assert "audit-log read permission" in error.message


def test_rate_limit_reset_header_accepts_epoch_and_delta():
    delta = _translate_status(429, "", {"X-RateLimit-Reset": "12"})
    assert delta.reset_seconds == 12.0

    epoch = _translate_status(429, "", {"X-RateLimit-Reset": "99999999999"})
    assert epoch.reset_seconds > 0


def test_check_access_reports_permission_failures_in_plain_language():
    class DeniedTransport:
        def get_events(self, params: dict) -> dict:
            raise TenablePermissionError("denied", status_code=403)

    client, _ = build_client(DeniedTransport())
    result = client.check_access()

    assert result["ok"] is False
    assert result["error"] == "permission_error"
    assert "Administrator" in result["remediation"]
