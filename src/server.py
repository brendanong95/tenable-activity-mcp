"""tenable-activity-mcp - MCP server over the Tenable VM audit/activity log.

Entrypoint and tool registration only.  Fetching lives in ``tenable_client``,
enrichment and rollups in ``classifier``, threshold logic in ``anomaly``, and
persistence in ``state``.  Tools return finished, pre-computed structures: no
tool ever hands back a raw event list expecting the caller to do the counting.

Run with stdio transport::

    uv run python -m src.server
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime, timedelta
from typing import Any

from dotenv import find_dotenv, load_dotenv

try:  # mcp >= 2.0 renamed FastMCP to MCPServer; the decorator API is unchanged
    from mcp.server.mcpserver import MCPServer as FastMCP
except ImportError:  # pragma: no cover - mcp 1.x
    from mcp.server.fastmcp import FastMCP  # type: ignore[no-redef]

from . import anomaly, classifier
from .state import DEFAULT_CURSOR_NAME, StateStore
from .tenable_client import (
    DEFAULT_PAGE_LIMIT,
    MAX_EVENTS_PER_CALL,
    MAX_PAGES_PER_CALL,
    TenableAuditLogClient,
    TenableClientError,
    TenableConfig,
    remediation_for,
    parse_iso8601,
    to_iso,
    utc_now,
)

# --------------------------------------------------------------------------- #
# Defaults
# --------------------------------------------------------------------------- #

SERVER_NAME = "tenable-activity-mcp"
SERVER_VERSION = "0.1.0"

#: Lookback used when a tool's date range is omitted.
DEFAULT_LOOKBACK_DAYS = 30
#: How far back ``get_actor_profile`` reaches when refreshing an actor's history.
PROFILE_LOOKBACK_DAYS = 365
#: Page size used by the aggregate tools (they always paginate to completion).
AGGREGATE_PAGE_LIMIT = 1000
#: How many enriched events ``list_activity_events`` returns inline per call.
MAX_INLINE_EVENTS = 1000

logging.basicConfig(
    stream=sys.stderr,  # stdout is the MCP transport - never log to it
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(SERVER_NAME)

mcp = FastMCP(
    SERVER_NAME,
    version=SERVER_VERSION,
    instructions=(
        "Query the Tenable Vulnerability Management audit/activity log. "
        "Counts, groupings, rates and anomaly thresholds are computed server-side "
        "and returned pre-aggregated - use the numbers as given rather than "
        "recomputing them from raw events. Start with check_permission_prereqs if "
        "any tool reports an authentication or permission error."
    ),
)

_client: TenableAuditLogClient | None = None
_state: StateStore | None = None


def get_client() -> TenableAuditLogClient:
    """Lazily build the API client so import never requires credentials."""
    global _client
    if _client is None:
        _client = TenableAuditLogClient(TenableConfig.from_env())
    return _client


def get_state() -> StateStore:
    """Lazily open ``state.db`` (created on first use)."""
    global _state
    if _state is None:
        _state = StateStore()
    return _state


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #


def _fail(exc: Exception) -> dict[str, Any]:
    """Turn any exception into a structured, human-readable tool result."""
    if isinstance(exc, TenableClientError):
        logger.warning("%s: %s", exc.kind, exc.message)
        payload = {"ok": False, **exc.to_dict(), "remediation": remediation_for(exc)}
        return payload
    logger.exception("Unexpected error in tool call")
    return {
        "ok": False,
        "error": "unexpected_error",
        "message": f"{type(exc).__name__}: {exc}",
        "remediation": "Check the server logs (stderr) for the full traceback.",
    }


def _require_window(date_from: str, date_to: str) -> tuple[datetime, datetime]:
    start = parse_iso8601(date_from)
    end = parse_iso8601(date_to)
    if start is None:
        raise TenableClientError(
            f"date_from='{date_from}' is not a valid ISO-8601 date "
            "(e.g. 2024-01-31 or 2024-01-31T00:00:00Z)"
        )
    if end is None:
        raise TenableClientError(
            f"date_to='{date_to}' is not a valid ISO-8601 date "
            "(e.g. 2024-02-01 or 2024-02-01T23:59:59Z)"
        )
    if end < start:
        raise TenableClientError(
            f"date_to ({date_to}) is earlier than date_from ({date_from})"
        )
    return start, end


def _default_window(
    date_from: str | None, date_to: str | None, lookback_days: int
) -> tuple[datetime, datetime]:
    end = parse_iso8601(date_to) if date_to else utc_now()
    start = parse_iso8601(date_from) if date_from else (end - timedelta(days=lookback_days))
    if start is None or end is None:
        raise TenableClientError("Could not parse the supplied date range")
    return start, end


def _fetch_classified(
    date_from: datetime | str,
    date_to: datetime | str,
    actor_id: str | None = None,
    action: str | None = None,
    limit: int = AGGREGATE_PAGE_LIMIT,
    next_token: str | None = None,
) -> tuple[list[dict[str, Any]], Any]:
    """Fetch + classify in one step; returns ``(records, fetch_result)``."""
    fetched = get_client().fetch_events(
        date_from=date_from,
        date_to=date_to,
        actor_id=actor_id,
        action=action,
        limit=limit,
        next_token=next_token,
    )
    return classifier.classify_events(fetched.events), fetched


def _pagination_block(fetched: Any) -> dict[str, Any]:
    block = fetched.to_dict()
    block["max_pages_per_call"] = MAX_PAGES_PER_CALL
    block["max_events_per_call"] = MAX_EVENTS_PER_CALL
    return block


# --------------------------------------------------------------------------- #
# Tools
# --------------------------------------------------------------------------- #


@mcp.tool()
def list_activity_events(
    date_from: str,
    date_to: str,
    actor_id: str | None = None,
    action: str | None = None,
    limit: int = DEFAULT_PAGE_LIMIT,
    next_token: str | None = None,
) -> dict[str, Any]:
    """List Tenable audit-log events for a date range, with optional filters.

    Pagination is handled internally (the ``next`` cursor is followed
    automatically) up to a safety cap of 20 pages / 100k events per call; if the
    cap is hit, ``pagination.next_token`` is returned so the next call resumes
    exactly where this one stopped. Every event is normalised, tagged with an
    access type (API key vs UI session), and has credential-looking field values
    redacted to their last 4 characters.

    Args:
        date_from: Start of the window, ISO-8601 (e.g. "2024-01-01" or
            "2024-01-01T00:00:00Z"). Inclusive.
        date_to: End of the window, ISO-8601. Inclusive.
        actor_id: Optional actor UUID to filter on (``actor_id.eq``).
        action: Optional exact action name, e.g. "user.create" (``action.eq``).
        limit: Page size sent to the API (1-5000).
        next_token: Opaque cursor from a previous call, to resume pagination.

    Returns:
        A dict with ``events`` (classified, redacted), a ``summary`` rollup of
        those events, and a ``pagination`` block.
    """
    try:
        start, end = _require_window(date_from, date_to)
        records, fetched = _fetch_classified(
            start, end, actor_id=actor_id, action=action, limit=limit, next_token=next_token
        )
        if fetched.next_token:
            get_state().save_cursor(
                fetched.next_token,
                last_event_time=records[-1].get("received") if records else None,
                name=DEFAULT_CURSOR_NAME,
            )
        truncated_inline = len(records) > MAX_INLINE_EVENTS
        return {
            "ok": True,
            "window": {"from": to_iso(start), "to": to_iso(end)},
            "filters": {"actor_id": actor_id, "action": action},
            "pagination": _pagination_block(fetched),
            "summary": classifier.summarize_events(records),
            "events_returned_inline": min(len(records), MAX_INLINE_EVENTS),
            "inline_truncated": truncated_inline,
            "inline_truncation_note": (
                f"Only the first {MAX_INLINE_EVENTS} of {len(records)} fetched events are "
                "included inline; the summary block covers all of them."
                if truncated_inline
                else None
            ),
            "events": records[:MAX_INLINE_EVENTS],
        }
    except Exception as exc:  # noqa: BLE001 - tools must not raise at the transport
        return _fail(exc)


@mcp.tool()
def summarize_activity(date_from: str, date_to: str) -> dict[str, Any]:
    """Summarise all audit-log activity in a window (counts computed in Python).

    Returns event counts by actor, by action, by CRUD type and by access type,
    plus failure and anonymous rates - all pre-computed. Use these numbers
    directly; do not re-derive them from raw events.

    Args:
        date_from: Start of the window, ISO-8601. Inclusive.
        date_to: End of the window, ISO-8601. Inclusive.

    Returns:
        A dict with a ``summary`` block (``total_events``, ``by_actor``,
        ``by_action``, ``by_crud``, ``by_access_type``, ``failure_rate_pct``,
        ``top_failed_actions``) and a ``pagination`` block describing coverage.
    """
    try:
        start, end = _require_window(date_from, date_to)
        records, fetched = _fetch_classified(start, end, limit=AGGREGATE_PAGE_LIMIT)
        summary = classifier.summarize_events(records)
        return {
            "ok": True,
            "window": {
                "from": to_iso(start),
                "to": to_iso(end),
                "days": round(anomaly.window_days(start, end), 2),
            },
            "summary": summary,
            "events_per_day": round(
                summary["total_events"] / max(anomaly.window_days(start, end), 1e-9), 2
            ),
            "pagination": _pagination_block(fetched),
        }
    except Exception as exc:  # noqa: BLE001
        return _fail(exc)


@mcp.tool()
def get_api_key_usage(
    actor_id: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
) -> dict[str, Any]:
    """Report API-key-driven activity per actor (UI/session activity excluded).

    Events are classified as API-key driven using the audit event's
    access/auth-method field, falling back to user-agent shape (scripted client
    vs browser). Each actor gets an action breakdown, distinct source IPs, and
    first/last seen timestamps - all pre-aggregated.

    Args:
        actor_id: Optional actor UUID. Omit to cover every actor with API-key
            activity in the window.
        date_from: Start of the window, ISO-8601. Defaults to 30 days ago.
        date_to: End of the window, ISO-8601. Defaults to now.

    Returns:
        A dict with ``actors`` (per-actor API-key usage profiles), an
        ``access_type_totals`` breakdown for context, and coverage metadata.
    """
    try:
        start, end = _default_window(date_from, date_to, DEFAULT_LOOKBACK_DAYS)
        records, fetched = _fetch_classified(
            start, end, actor_id=actor_id, limit=AGGREGATE_PAGE_LIMIT
        )
        profiles = classifier.build_actor_usage(
            records, access_types=(classifier.ACCESS_API_KEY,), actor_id=actor_id
        )
        apikey_events = sum(p["event_count"] for p in profiles)
        return {
            "ok": True,
            "window": {"from": to_iso(start), "to": to_iso(end)},
            "filters": {"actor_id": actor_id},
            "actor_count": len(profiles),
            "apikey_event_count": apikey_events,
            "total_event_count": len(records),
            "apikey_share_pct": (
                round(apikey_events / len(records) * 100, 2) if records else 0.0
            ),
            "access_type_totals": classifier.summarize_events(records)["by_access_type"],
            "classification_note": (
                "Access type is derived from the event's access/auth-method field when "
                "present, otherwise from the user agent. Events with neither signal are "
                "reported as 'unknown' and excluded from this API-key view."
            ),
            "actors": profiles,
            "pagination": _pagination_block(fetched),
        }
    except Exception as exc:  # noqa: BLE001
        return _fail(exc)


@mcp.tool()
def detect_anomalies(
    date_from: str,
    date_to: str,
    baseline_days: int = anomaly.DEFAULT_BASELINE_DAYS,
) -> dict[str, Any]:
    """Compare a window against each actor's stored baseline and flag outliers.

    Checks run: previously unseen actor, event volume above SPIKE_MULTIPLIER x
    the actor's historical daily average, source IPs absent from the baseline
    lookback, failed-event bursts, sustained high failure rate, off-hours
    activity spikes, and never-before-seen action types. Every finding includes
    the observed value, the threshold crossed, and a ``reasoning`` sentence.

    Baselines live in the local SQLite state file and are refreshed from the
    period immediately preceding the window when they are stale. Events in the
    analysed window itself are not folded into the baseline, so re-running the
    same window yields the same findings.

    Args:
        date_from: Start of the window under investigation, ISO-8601.
        date_to: End of the window under investigation, ISO-8601.
        baseline_days: Days of history preceding the window to baseline against.

    Returns:
        A dict with ``findings`` (severity-ordered, each with evidence and
        reasoning), ``findings_by_type``/``findings_by_severity`` counts, and
        the active ``thresholds``.
    """
    try:
        start, end = _require_window(date_from, date_to)
        baseline_days = max(1, int(baseline_days))
        state = get_state()

        baseline_start = start - timedelta(days=baseline_days)
        baseline_refreshed = False
        baseline_events = 0
        if not state.baselines_fresh(baseline_days, anomaly.BASELINE_REFRESH_MAX_AGE_HOURS):
            baseline_records, _ = _fetch_classified(
                baseline_start, start, limit=AGGREGATE_PAGE_LIMIT
            )
            state.record_events(baseline_records)
            state.refresh_baselines(
                baseline_records,
                window_days=baseline_days,
                window_start=baseline_start,
                window_end=start,
            )
            baseline_refreshed = True
            baseline_events = len(baseline_records)

        # "Known" IPs are judged relative to the window under investigation, not
        # to wall-clock now, so historical windows are analysed correctly.
        baselines = state.get_baselines(
            ip_lookback_days=anomaly.NEW_IP_LOOKBACK_DAYS, now=start
        )
        records, fetched = _fetch_classified(start, end, limit=AGGREGATE_PAGE_LIMIT)
        result = anomaly.detect_anomalies(
            records,
            baselines=baselines,
            window_start=start,
            window_end=end,
            baseline_days=baseline_days,
        )
        result.update(
            {
                "ok": True,
                "baseline_window": {
                    "from": to_iso(baseline_start),
                    "to": to_iso(start),
                    "refreshed_this_call": baseline_refreshed,
                    "events_ingested": baseline_events,
                    "actors_known": len(baselines),
                    "max_age_hours": anomaly.BASELINE_REFRESH_MAX_AGE_HOURS,
                },
                "pagination": _pagination_block(fetched),
            }
        )
        return result
    except Exception as exc:  # noqa: BLE001
        return _fail(exc)


@mcp.tool()
def get_actor_profile(
    actor_id: str,
    lookback_days: int = PROFILE_LOOKBACK_DAYS,
) -> dict[str, Any]:
    """Full historical view of one actor: roles, actions, access types, IPs.

    Combines a fresh audit-log fetch for the actor with everything previously
    persisted in the local state database, so IPs and actions seen in earlier
    sessions still show up. The Tenable role is resolved on a best-effort basis
    from the user directory and is omitted when the API keys cannot list users.

    Args:
        actor_id: The actor UUID (as it appears in ``actor.id`` on events).
        lookback_days: How far back to fetch fresh events for this actor.

    Returns:
        A dict with ``identity``, ``recent_activity`` (rollup over the lookback
        window), ``lifetime`` (accumulated state: all IPs, all actions, all
        access types, first/last seen) and ``pagination``.
    """
    try:
        if not actor_id or not str(actor_id).strip():
            raise TenableClientError("actor_id is required")
        actor_id = str(actor_id).strip()
        lookback_days = max(1, int(lookback_days))
        end = utc_now()
        start = end - timedelta(days=lookback_days)

        records, fetched = _fetch_classified(
            start, end, actor_id=actor_id, limit=AGGREGATE_PAGE_LIMIT
        )
        state = get_state()
        ingest = state.record_events(records)
        baseline = state.get_baseline(actor_id, ip_lookback_days=anomaly.NEW_IP_LOOKBACK_DAYS)
        profiles = classifier.build_actor_usage(records, access_types=(), actor_id=actor_id)
        recent = profiles[0] if profiles else None
        user = get_client().lookup_user(actor_id)

        return {
            "ok": True,
            "actor_id": actor_id,
            "window": {"from": to_iso(start), "to": to_iso(end), "days": lookback_days},
            "identity": {
                "actor_id": actor_id,
                "actor_name": (recent or {}).get("actor_name")
                or (baseline or {}).get("actor_name"),
                "actor_type": (recent or {}).get("actor_type")
                or (baseline or {}).get("actor_type"),
                "role": (user or {}).get("role"),
                "username": (user or {}).get("username"),
                "email": (user or {}).get("email"),
                "enabled": (user or {}).get("enabled"),
                "role_lookup": (
                    "resolved from the Tenable user directory"
                    if user
                    else "unavailable (user directory not readable with these keys, "
                    "or the actor is not a platform user)"
                ),
            },
            "recent_activity": recent
            or {
                "event_count": 0,
                "note": f"No audit events for this actor in the last {lookback_days} day(s).",
            },
            "lifetime": {
                "known_to_state": baseline is not None,
                "first_seen": (baseline or {}).get("first_seen"),
                "last_seen": (baseline or {}).get("last_seen"),
                "total_events": (baseline or {}).get("lifetime_events", 0),
                "total_failures": (baseline or {}).get("lifetime_failures", 0),
                "avg_events_per_day": (baseline or {}).get("avg_events_per_day", 0.0),
                "baseline_window_days": (baseline or {}).get("window_days"),
                "source_ips": (baseline or {}).get("all_ips", []),
                "actions": (baseline or {}).get("actions", []),
                "access_types": (baseline or {}).get("access_types", []),
                "hour_histogram_utc": (baseline or {}).get("lifetime_hour_histogram", {}),
                "events_ingested_this_call": ingest,
            },
            "pagination": _pagination_block(fetched),
        }
    except Exception as exc:  # noqa: BLE001
        return _fail(exc)


@mcp.tool()
def check_permission_prereqs() -> dict[str, Any]:
    """Verify the configured API keys can actually read the audit log.

    Makes one minimal audit-log request and reports pass/fail with a plain
    explanation and remediation steps. Run this first when another tool returns
    an authentication or permission error. No secret material is echoed - the
    access key is shown with only its last 4 characters.

    Returns:
        A dict with ``ok``, a human-readable ``message``, ``remediation`` when
        failing, plus configuration and local-state diagnostics.
    """
    try:
        config = TenableConfig.from_env()
        client = get_client()
        result = client.check_access()
        result["required_role"] = (
            "Administrator, or a custom role with explicit audit-log read permission"
        )
        result["configuration"] = {
            "base_url": config.base_url,
            "access_key": config.masked_access_key,
            "secret_key": "configured (never displayed)",
        }
        try:
            result["state"] = get_state().stats()
        except Exception as exc:  # noqa: BLE001 - state is optional for this check
            result["state"] = {"error": f"{type(exc).__name__}: {exc}"}
        return result
    except Exception as exc:  # noqa: BLE001
        return _fail(exc)


# --------------------------------------------------------------------------- #
# Entrypoint
# --------------------------------------------------------------------------- #


def main() -> None:
    """Load ``.env`` (if present) and serve over stdio."""
    dotenv_path = find_dotenv(usecwd=True)
    if dotenv_path:
        load_dotenv(dotenv_path)
        logger.info("Loaded environment from %s", dotenv_path)
    else:
        load_dotenv()
    logger.info("Starting %s v%s (stdio)", SERVER_NAME, SERVER_VERSION)
    mcp.run("stdio")


if __name__ == "__main__":
    main()

