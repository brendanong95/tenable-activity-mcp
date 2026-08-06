"""Tenable Vulnerability Management audit-log client.

Wraps ``GET https://cloud.tenable.com/audit-log/v1/events``.

Responsibilities kept in this module:

* credential loading (``TENABLE_ACCESS_KEY`` / ``TENABLE_SECRET_KEY`` / ``TENABLE_MCP_BASE_URL``)
* filter construction (``f=field.operator:value``)
* cursor pagination (``pagination.next``) with a hard safety cap
* rate-limit handling: HTTP 429 backoff keyed off ``X-RateLimit-Reset``
* mapping HTTP errors onto typed exceptions with human-readable messages

Transport is pluggable so that tests can drive the pagination loop without any
network access.  The default transport goes through pyTenable's ``TenableIO``
session (auth, user-agent, connection reuse); a plain ``requests`` transport is
used as a fallback if pyTenable is unavailable.
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Iterator, Protocol, Sequence

# --------------------------------------------------------------------------- #
# Tunable constants (no magic numbers inline)
# --------------------------------------------------------------------------- #

AUDIT_LOG_PATH = "audit-log/v1/events"
DEFAULT_BASE_URL = "https://cloud.tenable.com"

#: Largest page size the audit-log endpoint accepts.
MAX_PAGE_LIMIT = 5000
DEFAULT_PAGE_LIMIT = 500

#: Safety caps so a single tool call can never loop forever.
MAX_PAGES_PER_CALL = 20
MAX_EVENTS_PER_CALL = 100_000

#: 429 backoff.  The endpoint sends no Retry-After, only X-RateLimit-Reset.
MAX_RATE_LIMIT_RETRIES = 5
BASE_BACKOFF_SECONDS = 1.0
MAX_BACKOFF_SECONDS = 60.0
BACKOFF_MULTIPLIER = 2.0
#: Values above this are interpreted as an absolute epoch, below as a delta.
EPOCH_THRESHOLD_SECONDS = 1_000_000_000

#: Retries for transient 5xx responses.
MAX_SERVER_ERROR_RETRIES = 2

REQUEST_TIMEOUT_SECONDS = 60

FILTER_TYPE_AND = "and"

#: Tenable VM permission codes -> role names, used for best-effort actor roles.
TENABLE_ROLE_BY_PERMISSION = {
    16: "Basic",
    24: "Scan Operator",
    32: "Standard",
    40: "Scan Manager",
    64: "Administrator",
}

#: Non-secret user attributes safe to surface in an actor profile.
USER_PROFILE_FIELDS = (
    "id",
    "uuid",
    "username",
    "name",
    "email",
    "type",
    "permissions",
    "enabled",
    "login_fail_count",
    "last_login_attempt",
    "lastlogin",
)

#: Event field carrying the server-side timestamp.
TIMESTAMP_FIELDS = ("received", "date", "timestamp", "created")


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #


class TenableClientError(Exception):
    """Base error carrying a message safe to hand back to an MCP client."""

    kind = "client_error"

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code

    def to_dict(self) -> dict[str, Any]:
        return {"error": self.kind, "message": self.message, "status_code": self.status_code}


class TenableConfigError(TenableClientError):
    """Credentials or base URL missing/invalid."""

    kind = "configuration_error"


class TenableAuthError(TenableClientError):
    """401 - the API keys are wrong, disabled, or revoked."""

    kind = "authentication_error"


class TenablePermissionError(TenableClientError):
    """403 - keys are valid but lack audit-log read access."""

    kind = "permission_error"


class TenableRateLimitError(TenableClientError):
    """429 - rate limited."""

    kind = "rate_limit_error"

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = 429,
        reset_seconds: float | None = None,
    ) -> None:
        super().__init__(message, status_code=status_code)
        self.reset_seconds = reset_seconds

    def to_dict(self) -> dict[str, Any]:
        data = super().to_dict()
        data["reset_seconds"] = self.reset_seconds
        return data


class TenableAPIError(TenableClientError):
    """Any other non-2xx response."""

    kind = "api_error"


# --------------------------------------------------------------------------- #
# Timestamp helpers (shared by classifier / anomaly)
# --------------------------------------------------------------------------- #


def parse_iso8601(value: Any) -> datetime | None:
    """Parse an ISO-8601 string into a timezone-aware UTC datetime.

    Accepts ``2024-01-31``, ``2024-01-31T12:00:00Z`` and offset forms.  Returns
    ``None`` when the value cannot be parsed rather than raising, because audit
    events come from an external system and one bad row should not fail a whole
    report.
    """
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d"):
            try:
                parsed = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
        else:
            return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def event_timestamp(event: dict[str, Any]) -> datetime | None:
    """Best-effort extraction of an event's timestamp."""
    for key in TIMESTAMP_FIELDS:
        parsed = parse_iso8601(event.get(key))
        if parsed is not None:
            return parsed
    return None


def to_iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _format_filter_date(value: str | datetime) -> str:
    """Normalise a user-supplied date into what the API filter expects.

    Full ISO-8601 timestamps are passed through (normalised to UTC ``Z`` form);
    a bare date is passed through as-is.  Because the endpoint historically
    applies *date* granularity, callers additionally get client-side filtering
    (see :func:`filter_events_by_window`) so the returned window is always exact.
    """
    if isinstance(value, datetime):
        return to_iso(value) or ""
    text = str(value).strip()
    if not text:
        raise TenableClientError("Date filter value cannot be empty")
    parsed = parse_iso8601(text)
    if parsed is None:
        raise TenableClientError(
            f"Could not parse '{text}' as an ISO-8601 date "
            "(expected e.g. 2024-01-31 or 2024-01-31T00:00:00Z)"
        )
    if "T" not in text:
        return parsed.date().isoformat()
    return to_iso(parsed) or text


def build_filters(
    date_from: str | datetime | None = None,
    date_to: str | datetime | None = None,
    actor_id: str | None = None,
    action: str | None = None,
    target_id: str | None = None,
) -> list[tuple[str, str, str]]:
    """Build ``(field, operator, value)`` filter tuples for the audit-log API."""
    filters: list[tuple[str, str, str]] = []
    if date_from:
        filters.append(("date", "gte", _format_filter_date(date_from)))
    if date_to:
        filters.append(("date", "lte", _format_filter_date(date_to)))
    if actor_id:
        filters.append(("actor_id", "eq", str(actor_id)))
    if target_id:
        filters.append(("target_id", "eq", str(target_id)))
    if action:
        filters.append(("action", "eq", str(action)))
    return filters


def filter_events_by_window(
    events: Iterable[dict[str, Any]],
    window_start: datetime | None = None,
    window_end: datetime | None = None,
) -> list[dict[str, Any]]:
    """Client-side precision filter on the event timestamp.

    Events with an unparseable timestamp are kept: dropping them would silently
    hide activity, which is the opposite of what an audit tool should do.
    """
    if window_start is None and window_end is None:
        return list(events)
    kept: list[dict[str, Any]] = []
    for event in events:
        stamp = event_timestamp(event)
        if stamp is None:
            kept.append(event)
            continue
        if window_start is not None and stamp < window_start:
            continue
        if window_end is not None and stamp > window_end:
            continue
        kept.append(event)
    return kept


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

_KEY_PATTERN = re.compile(r"^[A-Za-z0-9]{32,}$")


@dataclass(frozen=True)
class TenableConfig:
    access_key: str
    secret_key: str
    base_url: str = DEFAULT_BASE_URL

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "TenableConfig":
        source = os.environ if env is None else env
        access_key = (source.get("TENABLE_ACCESS_KEY") or "").strip()
        secret_key = (source.get("TENABLE_SECRET_KEY") or "").strip()
        base_url = (source.get("TENABLE_MCP_BASE_URL") or DEFAULT_BASE_URL).strip().rstrip("/")
        missing = [
            name
            for name, value in (
                ("TENABLE_ACCESS_KEY", access_key),
                ("TENABLE_SECRET_KEY", secret_key),
            )
            if not value
        ]
        if missing:
            raise TenableConfigError(
                "Missing required environment variable(s): "
                + ", ".join(missing)
                + ". Copy .env.example to .env and fill in your Tenable API keys, "
                "or set them in your MCP client's server config."
            )
        if not base_url.startswith(("http://", "https://")):
            raise TenableConfigError(
                f"TENABLE_MCP_BASE_URL must start with http:// or https:// (got '{base_url}')"
            )
        return cls(access_key=access_key, secret_key=secret_key, base_url=base_url)

    @property
    def masked_access_key(self) -> str:
        """Access key with everything but the last 4 characters hidden."""
        return mask_secret(self.access_key)


def mask_secret(value: str | None, keep: int = 4) -> str:
    """Return ``value`` with all but the last ``keep`` characters replaced."""
    if not value:
        return ""
    text = str(value)
    if len(text) <= keep:
        return "*" * len(text)
    return "*" * (len(text) - keep) + text[-keep:]


def looks_like_credential(value: str) -> bool:
    """True when a value looks like a Tenable API key (32+ alphanumerics)."""
    return bool(_KEY_PATTERN.match(value.strip())) if isinstance(value, str) else False


# --------------------------------------------------------------------------- #
# Transports
# --------------------------------------------------------------------------- #


class Transport(Protocol):
    """Minimal contract the client needs from an HTTP layer."""

    def get_events(self, params: dict[str, Any]) -> dict[str, Any]:
        """Perform one audit-log request, returning the decoded JSON body.

        Implementations raise the typed errors declared in this module.
        """


def _plain(value: Any) -> Any:
    """Convert pyTenable ``Box``/``BoxList`` results into plain dict/list."""
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if hasattr(value, "to_list"):
        return value.to_list()
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_plain(v) for v in value]
    return value


def _reset_seconds_from_headers(headers: Any) -> float | None:
    """Read ``X-RateLimit-Reset`` as either a delta or an absolute epoch."""
    if not headers:
        return None
    try:
        raw = headers.get("X-RateLimit-Reset") or headers.get("x-ratelimit-reset")
    except AttributeError:
        return None
    if raw in (None, ""):
        return None
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    if value > EPOCH_THRESHOLD_SECONDS:
        value = value - time.time()
    return max(value, 0.0)


class PyTenableTransport:
    """Default transport: pyTenable's ``TenableIO`` audit-log endpoint.

    ``return_json=True`` gives us the raw page (including ``pagination.next``),
    which is what the tools need in order to expose an opaque ``next_token``.
    """

    def __init__(self, config: TenableConfig) -> None:
        from tenable.io import TenableIO  # imported lazily so tests stay offline

        self._config = config
        self._tio = TenableIO(
            access_key=config.access_key,
            secret_key=config.secret_key,
            url=config.base_url,
            vendor="tenable-activity-mcp",
            product="tenable-activity-mcp",
            build="0.1.0",
        )

    def get_events(self, params: dict[str, Any]) -> dict[str, Any]:
        from tenable.errors import APIError  # noqa: PLC0415 - lazy, optional dep

        filters: Sequence[tuple[str, str, str]] = params.get("filters") or ()
        try:
            response = self._tio.audit_log.events(
                *filters,
                limit=params.get("limit", DEFAULT_PAGE_LIMIT),
                filter_type=params.get("filter_type", FILTER_TYPE_AND),
                token=params.get("next_token") or "0",
                return_json=True,
            )
        except APIError as exc:  # pragma: no cover - exercised against live API
            raise _translate_status(
                getattr(exc, "code", None) or getattr(exc, "status_code", None),
                _response_text(getattr(exc, "response", None)),
                getattr(getattr(exc, "response", None), "headers", None),
            ) from exc
        return _plain(response) or {}

    def list_users(self) -> list[dict[str, Any]]:
        """Best-effort user directory lookup (used only to label actor roles)."""
        return [_plain(user) for user in self._tio.users.list()]


class RequestsTransport:
    """Fallback transport using ``requests`` directly with ``X-ApiKeys``."""

    def __init__(self, config: TenableConfig, session: Any | None = None) -> None:
        import requests  # noqa: PLC0415 - lazy import

        self._config = config
        self._session = session or requests.Session()
        self._session.headers.update(
            {
                "X-ApiKeys": f"accessKey={config.access_key};secretKey={config.secret_key}",
                "Accept": "application/json",
                "User-Agent": "tenable-activity-mcp/0.1.0",
            }
        )

    def get_events(self, params: dict[str, Any]) -> dict[str, Any]:
        filters: Sequence[tuple[str, str, str]] = params.get("filters") or ()
        query: dict[str, Any] = {
            "f": [f"{name}.{op}:{value}" for name, op, value in filters],
            "ft": params.get("filter_type", FILTER_TYPE_AND),
            "limit": params.get("limit", DEFAULT_PAGE_LIMIT),
        }
        token = params.get("next_token")
        if token:
            query["next"] = token
        response = self._session.get(
            f"{self._config.base_url}/{AUDIT_LOG_PATH}",
            params=query,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        if response.status_code >= 400:
            raise _translate_status(
                response.status_code, _response_text(response), response.headers
            )
        try:
            return response.json() or {}
        except ValueError as exc:
            raise TenableAPIError(
                "Tenable returned a non-JSON response for the audit-log endpoint"
            ) from exc

    def list_users(self) -> list[dict[str, Any]]:
        """Best-effort user directory lookup (used only to label actor roles)."""
        response = self._session.get(
            f"{self._config.base_url}/users", timeout=REQUEST_TIMEOUT_SECONDS
        )
        if response.status_code >= 400:
            raise _translate_status(
                response.status_code, _response_text(response), response.headers
            )
        return list((response.json() or {}).get("users") or [])


def _response_text(response: Any) -> str:
    if response is None:
        return ""
    text = getattr(response, "text", "") or ""
    return text[:500]


def _translate_status(
    status_code: int | None, body: str, headers: Any = None
) -> TenableClientError:
    """Map an HTTP status onto a typed error with actionable wording."""
    detail = f" Response: {body}" if body else ""
    if status_code == 401:
        return TenableAuthError(
            "Tenable rejected the API keys (HTTP 401). Check TENABLE_ACCESS_KEY / "
            "TENABLE_SECRET_KEY - the key may be mistyped, disabled, or regenerated."
            + detail,
            status_code=status_code,
        )
    if status_code == 403:
        return TenablePermissionError(
            "Tenable denied access to the audit log (HTTP 403). The API key's user "
            "needs the Administrator role, or a custom role that explicitly grants "
            "audit-log read permission." + detail,
            status_code=status_code,
        )
    if status_code == 429:
        return TenableRateLimitError(
            "Tenable rate limit hit (HTTP 429; 200 requests/min, 10 concurrent per key)."
            + detail,
            reset_seconds=_reset_seconds_from_headers(headers),
        )
    return TenableAPIError(
        f"Tenable audit-log request failed with HTTP {status_code}.{detail}",
        status_code=status_code,
    )


# --------------------------------------------------------------------------- #
# Client
# --------------------------------------------------------------------------- #


@dataclass
class Page:
    events: list[dict[str, Any]]
    next_token: str | None
    total: int | None = None


@dataclass
class FetchResult:
    """Outcome of a (possibly multi-page) fetch."""

    events: list[dict[str, Any]] = field(default_factory=list)
    next_token: str | None = None
    pages_fetched: int = 0
    truncated: bool = False
    truncation_reason: str | None = None
    total_available: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_count": len(self.events),
            "pages_fetched": self.pages_fetched,
            "next_token": self.next_token,
            "has_more": self.next_token is not None,
            "truncated": self.truncated,
            "truncation_reason": self.truncation_reason,
            "total_available": self.total_available,
        }


class TenableAuditLogClient:
    """Paginating, rate-limit-aware reader for the audit-log endpoint."""

    def __init__(
        self,
        config: TenableConfig | None = None,
        transport: Transport | None = None,
        sleep: Any = time.sleep,
    ) -> None:
        if transport is None and config is None:
            config = TenableConfig.from_env()
        self.config = config
        self._sleep = sleep
        self._transport = transport if transport is not None else _default_transport(config)

    # -- single page ------------------------------------------------------- #

    def fetch_page(
        self,
        filters: Sequence[tuple[str, str, str]] = (),
        limit: int = DEFAULT_PAGE_LIMIT,
        next_token: str | None = None,
    ) -> Page:
        """Fetch exactly one page, retrying on 429/5xx with backoff."""
        params = {
            "filters": list(filters),
            "limit": clamp_page_limit(limit),
            "filter_type": FILTER_TYPE_AND,
            "next_token": next_token,
        }
        body = self._request_with_backoff(params)
        return _parse_page(body)

    def _request_with_backoff(self, params: dict[str, Any]) -> dict[str, Any]:
        rate_limit_attempts = 0
        server_error_attempts = 0
        while True:
            try:
                return self._transport.get_events(params)
            except TenableRateLimitError as exc:
                rate_limit_attempts += 1
                if rate_limit_attempts > MAX_RATE_LIMIT_RETRIES:
                    raise TenableRateLimitError(
                        f"{exc.message} Gave up after {MAX_RATE_LIMIT_RETRIES} backoff "
                        "attempts - narrow the date range or retry later.",
                        reset_seconds=exc.reset_seconds,
                    ) from exc
                self._sleep(_backoff_delay(rate_limit_attempts, exc.reset_seconds))
            except TenableAPIError as exc:
                status = exc.status_code or 0
                server_error_attempts += 1
                if status < 500 or server_error_attempts > MAX_SERVER_ERROR_RETRIES:
                    raise
                self._sleep(_backoff_delay(server_error_attempts, None))

    # -- multi page -------------------------------------------------------- #

    def iter_pages(
        self,
        filters: Sequence[tuple[str, str, str]] = (),
        limit: int = DEFAULT_PAGE_LIMIT,
        next_token: str | None = None,
        max_pages: int = MAX_PAGES_PER_CALL,
        max_events: int = MAX_EVENTS_PER_CALL,
    ) -> Iterator[Page]:
        """Yield pages, following ``pagination.next`` until a cap is reached."""
        pages = 0
        collected = 0
        token = next_token
        page_cap = max(1, min(max_pages, MAX_PAGES_PER_CALL))
        event_cap = max(1, min(max_events, MAX_EVENTS_PER_CALL))
        while pages < page_cap and collected < event_cap:
            page = self.fetch_page(filters=filters, limit=limit, next_token=token)
            pages += 1
            collected += len(page.events)
            yield page
            token = page.next_token
            if not token or not page.events:
                return

    def fetch_events(
        self,
        date_from: str | datetime | None = None,
        date_to: str | datetime | None = None,
        actor_id: str | None = None,
        action: str | None = None,
        target_id: str | None = None,
        limit: int = DEFAULT_PAGE_LIMIT,
        next_token: str | None = None,
        max_pages: int = MAX_PAGES_PER_CALL,
        max_events: int = MAX_EVENTS_PER_CALL,
        precise_window: bool = True,
    ) -> FetchResult:
        """Fetch every event matching the filters, transparently paginating.

        The loop stops at ``max_pages``/``max_events`` and reports the stop in
        :attr:`FetchResult.truncated` plus a resumable ``next_token``.
        """
        filters = build_filters(
            date_from=date_from,
            date_to=date_to,
            actor_id=actor_id,
            action=action,
            target_id=target_id,
        )
        result = FetchResult()
        page_cap = max(1, min(max_pages, MAX_PAGES_PER_CALL))
        event_cap = max(1, min(max_events, MAX_EVENTS_PER_CALL))
        last_token: str | None = None
        last_page_empty = False
        hit_event_cap = False
        raw_collected = 0
        for page in self.iter_pages(
            filters=filters,
            limit=limit,
            next_token=next_token,
            max_pages=page_cap,
            max_events=event_cap,
        ):
            result.events.extend(page.events)
            raw_collected += len(page.events)
            result.pages_fetched += 1
            if page.total is not None:
                result.total_available = page.total
            last_token = page.next_token
            last_page_empty = not page.events
            if raw_collected >= event_cap:
                hit_event_cap = True
                break

        # The endpoint keeps handing back a non-null cursor after the last real
        # page, so a leftover token is NOT by itself evidence of more results.
        # Only a cap we actually hit means the caller has more to fetch.
        exhausted = (
            not last_token
            or last_page_empty
            or (
                result.total_available is not None
                and raw_collected >= result.total_available
            )
        )
        hit_page_cap = result.pages_fetched >= page_cap and not exhausted
        if exhausted or not (hit_page_cap or hit_event_cap):
            result.next_token = None
            result.truncated = False
        else:
            result.next_token = last_token
            result.truncated = True
            result.truncation_reason = (
                f"Stopped after {result.pages_fetched} page(s) / {raw_collected} events "
                f"(caps: {page_cap} pages, {event_cap} events). "
                "Pass next_token to continue, or narrow the date range."
            )
        if precise_window and (date_from or date_to):
            window_start = parse_iso8601(date_from) if date_from else None
            window_end = parse_iso8601(date_to) if date_to else None
            result.events = filter_events_by_window(result.events, window_start, window_end)
        return result

    # -- optional enrichment ----------------------------------------------- #

    def lookup_user(self, actor_id: str) -> dict[str, Any] | None:
        """Resolve an actor UUID to a user record, if the keys may list users.

        Returns ``None`` (never raises) when the directory is unavailable - a
        missing role label must not break an otherwise useful profile.
        """
        lister = getattr(self._transport, "list_users", None)
        if lister is None or not actor_id:
            return None
        try:
            users = lister()
        except Exception:  # noqa: BLE001 - enrichment is strictly best-effort
            return None
        wanted = str(actor_id).strip().lower()
        for user in users or []:
            if not isinstance(user, dict):
                continue
            candidates = {
                str(user.get("uuid") or "").lower(),
                str(user.get("id") or "").lower(),
                str(user.get("user_uuid") or "").lower(),
            }
            if wanted in candidates:
                profile = {
                    key: user.get(key) for key in USER_PROFILE_FIELDS if key in user
                }
                permission = user.get("permissions")
                if isinstance(permission, int):
                    profile["role"] = TENABLE_ROLE_BY_PERMISSION.get(
                        permission, f"Unknown ({permission})"
                    )
                return profile
        return None

    # -- prereq check ------------------------------------------------------ #

    def check_access(self) -> dict[str, Any]:
        """Cheapest possible audit-log call, used by ``check_permission_prereqs``."""
        started = time.monotonic()
        yesterday = (utc_now() - timedelta(days=1)).date().isoformat()
        try:
            page = self.fetch_page(filters=build_filters(date_from=yesterday), limit=1)
        except TenableClientError as exc:
            return {
                "ok": False,
                "check": "audit_log_read",
                "error": exc.kind,
                "status_code": exc.status_code,
                "message": exc.message,
                "remediation": remediation_for(exc),
                "base_url": getattr(self.config, "base_url", None),
                "access_key": getattr(self.config, "masked_access_key", None),
            }
        return {
            "ok": True,
            "check": "audit_log_read",
            "message": (
                "Credentials can read the Tenable audit log. "
                f"Sample request returned {len(page.events)} event(s)."
            ),
            "base_url": getattr(self.config, "base_url", None),
            "access_key": getattr(self.config, "masked_access_key", None),
            "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
        }


def remediation_for(exc: TenableClientError) -> str:
    if isinstance(exc, TenablePermissionError):
        return (
            "Assign the Administrator role to the user that owns these API keys, or "
            "create a custom role with audit-log read permission and regenerate the keys."
        )
    if isinstance(exc, TenableAuthError):
        return (
            "Regenerate the API keys in Tenable VM (Settings > My Account > API Keys) "
            "and update TENABLE_ACCESS_KEY / TENABLE_SECRET_KEY."
        )
    if isinstance(exc, TenableConfigError):
        return "Set TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY in the environment or .env file."
    if isinstance(exc, TenableRateLimitError):
        return "Wait for the rate-limit window to reset (200 requests/min per key) and retry."
    return "Check network access to the Tenable API base URL and retry."


def _default_transport(config: TenableConfig | None) -> Transport:
    if config is None:  # pragma: no cover - guarded by the caller
        raise TenableConfigError("A TenableConfig is required to build a transport")
    try:
        return PyTenableTransport(config)
    except ImportError:  # pragma: no cover - pyTenable is a pinned dependency
        return RequestsTransport(config)


def clamp_page_limit(limit: Any) -> int:
    """Coerce a caller-supplied page size into the API's accepted range."""
    try:
        value = int(limit)
    except (TypeError, ValueError):
        return DEFAULT_PAGE_LIMIT
    return max(1, min(value, MAX_PAGE_LIMIT))


def _parse_page(body: dict[str, Any]) -> Page:
    """Extract events and the ``next`` cursor from one API response body."""
    body = body or {}
    events = body.get("events")
    if events is None:
        events = body.get("data") if isinstance(body.get("data"), list) else []
    if not isinstance(events, list):
        events = []
    pagination = body.get("pagination") or {}
    if not isinstance(pagination, dict):
        pagination = {}
    token = pagination.get("next")
    if token in ("", "0", 0, None):
        token = None
    total = pagination.get("total")
    if not isinstance(total, int):
        total = None
    return Page(events=[e for e in events if isinstance(e, dict)], next_token=token, total=total)


def _backoff_delay(attempt: int, reset_seconds: float | None) -> float:
    """Exponential backoff, preferring the server's reset hint when present."""
    exponential = BASE_BACKOFF_SECONDS * (BACKOFF_MULTIPLIER ** (attempt - 1))
    delay = max(reset_seconds, exponential) if reset_seconds is not None else exponential
    return float(min(delay, MAX_BACKOFF_SECONDS))

