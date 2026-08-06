"""Event enrichment, redaction and deterministic rollups.

Everything in this module is pure Python over already-fetched events: no
network, no LLM.  Tools return the structures built here so the calling model
never has to count, group, or do arithmetic over raw event lists.

Two jobs:

1. **Classification** - decide whether an audit event came from an API key or
   from an interactive UI/session login, and pull out source IPs / user agents
   from the free-form ``fields[]`` array.
2. **Rollups** - counts by actor / action / crud / access type, failure rates,
   and per-actor usage profiles.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Iterable, Sequence

from .tenable_client import (
    event_timestamp,
    looks_like_credential,
    mask_secret,
    parse_iso8601,
    to_iso,
)

# --------------------------------------------------------------------------- #
# Access-method classification vocabulary
# --------------------------------------------------------------------------- #

ACCESS_API_KEY = "apikey"
ACCESS_SESSION = "session"
ACCESS_SYSTEM = "system"
ACCESS_UNKNOWN = "unknown"

#: ``fields[]`` keys that directly name the authentication/access method.
#: ``x-access-type`` is what Tenable VM actually emits (value ``apikey``).
ACCESS_METHOD_FIELD_KEYS = frozenset(
    {
        "x-access-type",
        "x_access_type",
        "xaccesstype",
        "access_method",
        "accessmethod",
        "access_type",
        "auth_method",
        "authmethod",
        "authentication_method",
        "auth_type",
        "authentication_type",
        "login_type",
        "method",
        "session_type",
    }
)

#: Presence of one of these keys proves an interactive session was in play.
SESSION_MARKER_FIELD_KEYS = frozenset(
    {"x-session-uuid", "x_session_uuid", "session_uuid", "session_id"}
)

#: Actions that name the authentication mechanism unambiguously. Used only when
#: no access-method field is present. Deliberately narrow: a generic ``api-*``
#: action proves nothing, because the web UI calls the same REST endpoints with
#: a session cookie.
ACCESS_TYPE_BY_ACTION = {
    "user.authenticate.api_keys": ACCESS_API_KEY,
    "user.authenticate.password": ACCESS_SESSION,
    "user.authenticate.mfa": ACCESS_SESSION,
    "user.logout": ACCESS_SESSION,
    "session.create": ACCESS_SESSION,
    "session.delete": ACCESS_SESSION,
}

#: Substrings in an access-method value that indicate API-key authentication.
API_KEY_VALUE_TOKENS = ("apikey", "api_key", "api-key", "api key", "accesskey", "keys")

#: Substrings in an access-method value that indicate an interactive session.
SESSION_VALUE_TOKENS = (
    "session",
    "cookie",
    "password",
    "ui",
    "web",
    "browser",
    "saml",
    "sso",
    "oidc",
    "mfa",
    "login",
)

#: ``fields[]`` keys that carry a user agent.
USER_AGENT_FIELD_KEYS = frozenset({"user_agent", "useragent", "user-agent", "ua", "client"})

#: User-agent substrings typical of scripted/API-key clients.
API_CLIENT_UA_TOKENS = (
    "pytenable",
    "python-requests",
    "python-urllib",
    "httpx",
    "curl",
    "wget",
    "postman",
    "insomnia",
    "go-http-client",
    "okhttp",
    "java/",
    "axios",
    "powershell",
    "restsharp",
    "terraform",
    "ansible",
    "libwww",
)

#: User-agent substrings typical of an interactive browser session.
BROWSER_UA_TOKENS = ("mozilla", "chrome", "safari", "firefox", "edg/", "gecko", "webkit")

#: ``fields[]`` keys that carry a source IP address.
SOURCE_IP_FIELD_KEYS = frozenset(
    {
        "source_ip",
        "sourceip",
        "src_ip",
        "ip",
        "ip_address",
        "ipaddress",
        "client_ip",
        "remote_addr",
        "remote_ip",
        "x-forwarded-for",
        "x_forwarded_for",
        "xforwardedfor",
        "forwarded_for",
    }
)

#: Actor types that mean "the platform did this", not a human or an API key.
SYSTEM_ACTOR_TYPES = frozenset({"system", "service", "internal", "tenable"})

#: Field-name fragments that mark an "was an API key used?" flag.
API_KEY_ACTION_TOKENS = ("apikey", "api_key", "api-key")
#: Values of such a flag that mean "yes".
API_KEY_TRUE_VALUES = frozenset({"true", "yes", "1"})

# --------------------------------------------------------------------------- #
# Redaction
# --------------------------------------------------------------------------- #

#: Substrings in a field key that mark the value as secret material.
SECRET_KEY_TOKENS = (
    "secret",
    "access_key",
    "accesskey",
    "api_key",
    "apikey",
    "password",
    "passwd",
    "token",
    "authorization",
    "credential",
    "private_key",
    "session_id",
    "cookie",
)

#: Keep this many trailing characters when redacting.
REDACTION_KEEP_CHARS = 4

#: Keys whose value is an opaque identifier we must not treat as a secret.
REDACTION_EXEMPT_KEYS = frozenset({"actor_id", "target_id", "id", "uuid"})

_IP_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"  # IPv4
    r"|\b(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}\b"  # IPv6 (loose)
)

# --------------------------------------------------------------------------- #
# Field helpers
# --------------------------------------------------------------------------- #


def _norm_key(key: Any) -> str:
    return str(key or "").strip().lower()


def field_pairs(event: dict[str, Any]) -> list[tuple[str, str]]:
    """Normalise ``fields[]`` into ``(lowercased key, string value)`` pairs.

    Tolerates the two shapes seen in the wild: a list of ``{key, value}``
    objects, and a plain ``{key: value}`` mapping.
    """
    raw = event.get("fields")
    pairs: list[tuple[str, str]] = []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                key = _norm_key(item.get("key") or item.get("name"))
                value = item.get("value")
                if key:
                    pairs.append((key, "" if value is None else str(value)))
    elif isinstance(raw, dict):
        for key, value in raw.items():
            pairs.append((_norm_key(key), "" if value is None else str(value)))
    return pairs


def field_map(event: dict[str, Any]) -> dict[str, str]:
    """Flatten ``fields[]`` into a dict (later duplicates win)."""
    return {key: value for key, value in field_pairs(event)}


def is_secret_key(key: str) -> bool:
    key = _norm_key(key)
    if key in REDACTION_EXEMPT_KEYS:
        return False
    return any(token in key for token in SECRET_KEY_TOKENS)


def redact_value(key: str, value: Any) -> str:
    """Redact a field value, keeping only the last :data:`REDACTION_KEEP_CHARS`.

    Applied when either the key names a credential or the value itself looks
    like Tenable key material.  Nothing that resembles a secret ever leaves this
    process intact.
    """
    text = "" if value is None else str(value)
    if is_secret_key(key) or looks_like_credential(text):
        return mask_secret(text, REDACTION_KEEP_CHARS)
    return text


def redact_fields(event: dict[str, Any]) -> list[dict[str, str]]:
    """Return the event's fields as redacted ``{key, value}`` dicts."""
    return [{"key": key, "value": redact_value(key, value)} for key, value in field_pairs(event)]


# --------------------------------------------------------------------------- #
# Access-method classification
# --------------------------------------------------------------------------- #


def _match_access_value(value: str) -> str | None:
    text = value.strip().lower()
    if not text:
        return None
    if any(token in text for token in API_KEY_VALUE_TOKENS):
        return ACCESS_API_KEY
    if any(token in text for token in SESSION_VALUE_TOKENS):
        return ACCESS_SESSION
    return None


def classify_access_method(event: dict[str, Any]) -> tuple[str, str]:
    """Tag an event as API-key driven vs UI/session driven.

    Returns ``(access_type, reason)``.  The reason string is carried through to
    tool output so a human can see *why* something was tagged the way it was
    instead of trusting an opaque label.

    Signals, in priority order:

    1. an explicit access/auth-method field in ``fields[]`` (``X-Access-Type``)
    2. the presence of a session identifier field (``X-Session-Uuid``)
    3. an action that names the mechanism (``user.authenticate.api_keys``)
    4. an explicit api-key boolean marker
    5. the user agent (scripted client vs browser)
    6. the actor type (``system``) / anonymous flag
    """
    fields = field_map(event)

    for key, value in fields.items():
        if key in ACCESS_METHOD_FIELD_KEYS:
            matched = _match_access_value(value)
            if matched:
                return matched, f"fields['{key}']='{value}'"

    for key in fields:
        if key in SESSION_MARKER_FIELD_KEYS:
            return ACCESS_SESSION, f"fields['{key}'] present (interactive session id)"

    action = str(event.get("action") or "").strip().lower()
    if action in ACCESS_TYPE_BY_ACTION:
        return ACCESS_TYPE_BY_ACTION[action], f"action='{action}' names the auth mechanism"

    # Some tenants surface a boolean-ish api_key marker instead of a method name.
    # Only an explicit true-ish value counts: a field that merely *names* an API
    # key (e.g. the target of a key-rotation event) says nothing about how the
    # request itself was authenticated.
    for key, value in fields.items():
        if any(token in key for token in API_KEY_ACTION_TOKENS):
            if value.strip().lower() in API_KEY_TRUE_VALUES:
                return ACCESS_API_KEY, f"fields['{key}']='{value}'"

    user_agent = ""
    for key in USER_AGENT_FIELD_KEYS:
        if fields.get(key):
            user_agent = fields[key]
            break
    if user_agent:
        lowered = user_agent.lower()
        if any(token in lowered for token in API_CLIENT_UA_TOKENS):
            return ACCESS_API_KEY, f"user agent looks scripted: '{user_agent[:80]}'"
        if any(token in lowered for token in BROWSER_UA_TOKENS):
            return ACCESS_SESSION, f"user agent looks like a browser: '{user_agent[:80]}'"

    actor_type = _norm_key((event.get("actor") or {}).get("type"))
    if actor_type in SYSTEM_ACTOR_TYPES:
        return ACCESS_SYSTEM, f"actor.type='{actor_type}'"

    if event.get("is_anonymous") is True:
        return ACCESS_UNKNOWN, "event is anonymous; no access-method field present"

    return ACCESS_UNKNOWN, "no access-method, user-agent or actor-type signal in the event"


def extract_source_ips(event: dict[str, Any]) -> list[str]:
    """Collect every source IP referenced by the event, de-duplicated.

    ``X-Forwarded-For`` style comma lists are split so proxy chains do not hide
    the real client address.
    """
    found: list[str] = []
    for key, value in field_pairs(event):
        if key not in SOURCE_IP_FIELD_KEYS:
            continue
        for candidate in str(value).split(","):
            candidate = candidate.strip()
            if not candidate:
                continue
            if _IP_PATTERN.fullmatch(candidate) or _IP_PATTERN.search(candidate):
                match = _IP_PATTERN.search(candidate)
                found.append(match.group(0) if match else candidate)
            else:
                found.append(candidate)
    seen: set[str] = set()
    ordered: list[str] = []
    for ip in found:
        if ip not in seen:
            seen.add(ip)
            ordered.append(ip)
    return ordered


def extract_user_agent(event: dict[str, Any]) -> str | None:
    fields = field_map(event)
    for key in USER_AGENT_FIELD_KEYS:
        if fields.get(key):
            return fields[key]
    return None


def event_key(event: dict[str, Any]) -> str:
    """Stable identity for an event, for de-duplicating repeated ingests."""
    raw_id = event.get("id") or event.get("event_id")
    if raw_id:
        return str(raw_id)
    actor = event.get("actor") or {}
    target = event.get("target") or {}
    seed = "|".join(
        str(part)
        for part in (
            event.get("received"),
            event.get("action"),
            actor.get("id"),
            target.get("id"),
        )
    )
    return "sha1:" + hashlib.sha1(seed.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# Normalisation
# --------------------------------------------------------------------------- #


def classify_event(event: dict[str, Any]) -> dict[str, Any]:
    """Normalise + enrich one raw audit event.

    The returned record is flat, redacted, and safe to hand to an LLM.
    """
    actor = event.get("actor") or {}
    target = event.get("target") or {}
    access_type, access_reason = classify_access_method(event)
    stamp = event_timestamp(event)
    return {
        "id": event_key(event),
        "received": to_iso(stamp),
        "action": event.get("action"),
        "crud": event.get("crud"),
        "actor_id": actor.get("id"),
        "actor_name": actor.get("name"),
        "actor_type": actor.get("type"),
        "target_id": target.get("id"),
        "target_name": target.get("name"),
        "target_type": target.get("type"),
        "is_anonymous": bool(event.get("is_anonymous")),
        "is_failure": bool(event.get("is_failure")),
        "access_type": access_type,
        "access_reason": access_reason,
        "source_ips": extract_source_ips(event),
        "user_agent": extract_user_agent(event),
        "fields": redact_fields(event),
    }


def classify_events(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return [classify_event(event) for event in events]


def actor_label(record: dict[str, Any]) -> str:
    """Grouping key for an actor: the UUID when present, else the name."""
    return str(record.get("actor_id") or record.get("actor_name") or "unknown")


# --------------------------------------------------------------------------- #
# Deterministic rollups
# --------------------------------------------------------------------------- #


def _counter_to_sorted_list(counter: Counter, key_name: str) -> list[dict[str, Any]]:
    return [
        {key_name: key, "count": count}
        for key, count in sorted(counter.items(), key=lambda kv: (-kv[1], str(kv[0])))
    ]


def _percent(part: int, whole: int) -> float:
    return round((part / whole) * 100, 2) if whole else 0.0


def summarize_events(records: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """Full deterministic rollup of classified events.

    All counting, grouping and percentage math happens here so that tools return
    finished numbers.
    """
    by_actor: Counter = Counter()
    by_action: Counter = Counter()
    by_crud: Counter = Counter()
    by_access: Counter = Counter()
    actor_names: dict[str, str | None] = {}
    actor_failures: Counter = Counter()
    failure_actions: Counter = Counter()
    failures = 0
    anonymous = 0
    timestamps: list[datetime] = []

    for record in records:
        actor = actor_label(record)
        by_actor[actor] += 1
        actor_names.setdefault(actor, record.get("actor_name"))
        by_action[record.get("action") or "unknown"] += 1
        by_crud[record.get("crud") or "unknown"] += 1
        by_access[record.get("access_type") or ACCESS_UNKNOWN] += 1
        if record.get("is_failure"):
            failures += 1
            actor_failures[actor] += 1
            failure_actions[record.get("action") or "unknown"] += 1
        if record.get("is_anonymous"):
            anonymous += 1
        stamp = parse_iso8601(record.get("received"))
        if stamp:
            timestamps.append(stamp)

    total = len(records)
    return {
        "total_events": total,
        "distinct_actors": len(by_actor),
        "distinct_actions": len(by_action),
        "first_event": to_iso(min(timestamps)) if timestamps else None,
        "last_event": to_iso(max(timestamps)) if timestamps else None,
        "failure_count": failures,
        "failure_rate_pct": _percent(failures, total),
        "anonymous_count": anonymous,
        "anonymous_rate_pct": _percent(anonymous, total),
        "by_actor": [
            {
                "actor_id": actor,
                "actor_name": actor_names.get(actor),
                "count": count,
                "share_pct": _percent(count, total),
                "failure_count": actor_failures.get(actor, 0),
                "failure_rate_pct": _percent(actor_failures.get(actor, 0), count),
            }
            for actor, count in sorted(by_actor.items(), key=lambda kv: (-kv[1], kv[0]))
        ],
        "by_action": _counter_to_sorted_list(by_action, "action"),
        "by_crud": _counter_to_sorted_list(by_crud, "crud"),
        "by_access_type": _counter_to_sorted_list(by_access, "access_type"),
        "top_failed_actions": _counter_to_sorted_list(failure_actions, "action")[:10],
    }


def group_by_actor(records: Iterable[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        grouped[actor_label(record)].append(record)
    return dict(grouped)


def build_actor_usage(
    records: Sequence[dict[str, Any]],
    access_types: Sequence[str] = (ACCESS_API_KEY,),
    actor_id: str | None = None,
) -> list[dict[str, Any]]:
    """Per-actor usage profile, optionally restricted to certain access types.

    Used by ``get_api_key_usage`` (API-key access only) and by
    ``get_actor_profile`` (all access types for a single actor).
    """
    wanted = set(access_types) if access_types else None
    filtered = [
        record
        for record in records
        if (wanted is None or record.get("access_type") in wanted)
        and (actor_id is None or actor_label(record) == actor_id)
    ]

    profiles: list[dict[str, Any]] = []
    for actor, actor_records in sorted(
        group_by_actor(filtered).items(), key=lambda kv: (-len(kv[1]), kv[0])
    ):
        actions: Counter = Counter()
        cruds: Counter = Counter()
        access_counter: Counter = Counter()
        ips: Counter = Counter()
        agents: Counter = Counter()
        stamps: list[datetime] = []
        failures = 0
        name = None
        actor_type = None
        for record in actor_records:
            actions[record.get("action") or "unknown"] += 1
            cruds[record.get("crud") or "unknown"] += 1
            access_counter[record.get("access_type") or ACCESS_UNKNOWN] += 1
            for ip in record.get("source_ips") or []:
                ips[ip] += 1
            if record.get("user_agent"):
                agents[record["user_agent"]] += 1
            if record.get("is_failure"):
                failures += 1
            stamp = parse_iso8601(record.get("received"))
            if stamp:
                stamps.append(stamp)
            name = name or record.get("actor_name")
            actor_type = actor_type or record.get("actor_type")

        profiles.append(
            {
                "actor_id": actor,
                "actor_name": name,
                "actor_type": actor_type,
                "event_count": len(actor_records),
                "failure_count": failures,
                "failure_rate_pct": _percent(failures, len(actor_records)),
                "first_seen": to_iso(min(stamps)) if stamps else None,
                "last_seen": to_iso(max(stamps)) if stamps else None,
                "action_breakdown": _counter_to_sorted_list(actions, "action"),
                "crud_breakdown": _counter_to_sorted_list(cruds, "crud"),
                "access_type_breakdown": _counter_to_sorted_list(access_counter, "access_type"),
                "source_ips": [
                    {"ip": ip, "count": count}
                    for ip, count in sorted(ips.items(), key=lambda kv: (-kv[1], kv[0]))
                ],
                "distinct_source_ip_count": len(ips),
                "user_agents": _counter_to_sorted_list(agents, "user_agent")[:10],
            }
        )
    return profiles
