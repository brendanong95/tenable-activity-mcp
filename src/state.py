"""SQLite persistence for cursors and per-actor baselines.

Two kinds of state live here:

* **Accumulating history** (``actor_history``, ``actor_ips``, ``actor_actions``,
  ``actor_access_types``, ``actor_hours``) - everything ever observed for an
  actor, upserted with first/last seen timestamps.  Backs ``get_actor_profile``
  and supplies the "known IPs / known actions" sets used by anomaly detection.
* **Computed baselines** (``actor_baselines``) - the rolling N-day averages,
  recomputed wholesale from a baseline-window fetch so repeated runs cannot
  inflate the numbers.

Ingestion is de-duplicated on event id (``ingested_events``) so re-reading an
overlapping window never double-counts.

Plain stdlib ``sqlite3``; the database file is created on first use.
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

from .classifier import ACCESS_UNKNOWN, actor_label
from .tenable_client import parse_iso8601, to_iso, utc_now

DEFAULT_DB_FILENAME = "state.db"
SCHEMA_VERSION = 1

#: Cursor row used by the tools to remember the newest page they have read.
DEFAULT_CURSOR_NAME = "audit_log"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cursors (
    name            TEXT PRIMARY KEY,
    next_token      TEXT,
    last_event_time TEXT,
    updated_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS actor_history (
    actor_id     TEXT PRIMARY KEY,
    actor_name   TEXT,
    actor_type   TEXT,
    total_events INTEGER NOT NULL DEFAULT 0,
    failures     INTEGER NOT NULL DEFAULT 0,
    first_seen   TEXT,
    last_seen    TEXT,
    updated_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS actor_ips (
    actor_id   TEXT NOT NULL,
    ip         TEXT NOT NULL,
    count      INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT,
    last_seen  TEXT,
    PRIMARY KEY (actor_id, ip)
);

CREATE TABLE IF NOT EXISTS actor_actions (
    actor_id   TEXT NOT NULL,
    action     TEXT NOT NULL,
    count      INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT,
    last_seen  TEXT,
    PRIMARY KEY (actor_id, action)
);

CREATE TABLE IF NOT EXISTS actor_access_types (
    actor_id    TEXT NOT NULL,
    access_type TEXT NOT NULL,
    count       INTEGER NOT NULL DEFAULT 0,
    first_seen  TEXT,
    last_seen   TEXT,
    PRIMARY KEY (actor_id, access_type)
);

CREATE TABLE IF NOT EXISTS actor_hours (
    actor_id TEXT NOT NULL,
    hour     INTEGER NOT NULL,
    count    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (actor_id, hour)
);

CREATE TABLE IF NOT EXISTS actor_baselines (
    actor_id            TEXT PRIMARY KEY,
    actor_name          TEXT,
    window_days         INTEGER NOT NULL,
    window_start        TEXT,
    window_end          TEXT,
    total_events        INTEGER NOT NULL DEFAULT 0,
    observed_days       INTEGER NOT NULL DEFAULT 0,
    avg_events_per_day  REAL NOT NULL DEFAULT 0,
    failure_events      INTEGER NOT NULL DEFAULT 0,
    hour_histogram      TEXT,
    computed_at         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ingested_events (
    event_id    TEXT PRIMARY KEY,
    actor_id    TEXT,
    received    TEXT,
    ingested_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ingested_received ON ingested_events (received);
"""


def default_db_path() -> Path:
    """Where ``state.db`` lives: ``TENABLE_MCP_STATE_DB`` or the project root."""
    configured = (os.environ.get("TENABLE_MCP_STATE_DB") or "").strip()
    if configured:
        return Path(configured).expanduser()
    return Path(__file__).resolve().parent.parent / DEFAULT_DB_FILENAME


class StateStore:
    """Thin SQLite wrapper. Safe to construct repeatedly; schema is idempotent."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        self.db_path = Path(db_path) if db_path is not None else default_db_path()
        if str(self.db_path) != ":memory:":
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema()

    # -- lifecycle --------------------------------------------------------- #

    def _init_schema(self) -> None:
        with self._conn:
            self._conn.executescript(_SCHEMA)
            self._conn.execute(
                "INSERT INTO meta (key, value) VALUES ('schema_version', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(SCHEMA_VERSION),),
            )

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "StateStore":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # -- cursors ----------------------------------------------------------- #

    def save_cursor(
        self,
        next_token: str | None,
        last_event_time: str | None = None,
        name: str = DEFAULT_CURSOR_NAME,
    ) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO cursors (name, next_token, last_event_time, updated_at) "
                "VALUES (?, ?, ?, ?) ON CONFLICT(name) DO UPDATE SET "
                "next_token=excluded.next_token, "
                "last_event_time=COALESCE(excluded.last_event_time, cursors.last_event_time), "
                "updated_at=excluded.updated_at",
                (name, next_token, last_event_time, to_iso(utc_now())),
            )

    def get_cursor(self, name: str = DEFAULT_CURSOR_NAME) -> dict[str, Any] | None:
        row = self._conn.execute("SELECT * FROM cursors WHERE name = ?", (name,)).fetchone()
        return dict(row) if row else None

    # -- ingestion --------------------------------------------------------- #

    def record_events(self, records: Sequence[dict[str, Any]]) -> dict[str, int]:
        """Fold classified events into the accumulating history tables.

        Events already ingested (matched on ``id``) are skipped, so calling this
        with overlapping windows is safe.
        """
        ingested = 0
        skipped = 0
        with self._conn:
            for record in records:
                event_id = str(record.get("id") or "")
                if not event_id:
                    skipped += 1
                    continue
                actor = actor_label(record)
                received = record.get("received")
                cursor = self._conn.execute(
                    "INSERT OR IGNORE INTO ingested_events "
                    "(event_id, actor_id, received, ingested_at) VALUES (?, ?, ?, ?)",
                    (event_id, actor, received, to_iso(utc_now())),
                )
                if cursor.rowcount == 0:
                    skipped += 1
                    continue
                ingested += 1
                self._apply_record(actor, record, received)
        return {"ingested": ingested, "skipped_duplicates": skipped}

    def _apply_record(self, actor: str, record: dict[str, Any], received: str | None) -> None:
        conn = self._conn
        conn.execute(
            "INSERT INTO actor_history "
            "(actor_id, actor_name, actor_type, total_events, failures, "
            " first_seen, last_seen, updated_at) "
            "VALUES (?, ?, ?, 1, ?, ?, ?, ?) "
            "ON CONFLICT(actor_id) DO UPDATE SET "
            "actor_name=COALESCE(excluded.actor_name, actor_history.actor_name), "
            "actor_type=COALESCE(excluded.actor_type, actor_history.actor_type), "
            "total_events=actor_history.total_events + 1, "
            "failures=actor_history.failures + excluded.failures, "
            "first_seen=MIN(COALESCE(actor_history.first_seen, excluded.first_seen), "
            "               COALESCE(excluded.first_seen, actor_history.first_seen)), "
            "last_seen=MAX(COALESCE(actor_history.last_seen, excluded.last_seen), "
            "              COALESCE(excluded.last_seen, actor_history.last_seen)), "
            "updated_at=excluded.updated_at",
            (
                actor,
                record.get("actor_name"),
                record.get("actor_type"),
                1 if record.get("is_failure") else 0,
                received,
                received,
                to_iso(utc_now()),
            ),
        )

        for ip in record.get("source_ips") or []:
            _upsert_counter(conn, "actor_ips", "ip", actor, str(ip), received)
        _upsert_counter(conn, "actor_actions", "action", actor, record.get("action"), received)
        _upsert_counter(
            conn,
            "actor_access_types",
            "access_type",
            actor,
            record.get("access_type") or ACCESS_UNKNOWN,
            received,
        )

        stamp = parse_iso8601(received)
        if stamp is not None:
            conn.execute(
                "INSERT INTO actor_hours (actor_id, hour, count) VALUES (?, ?, 1) "
                "ON CONFLICT(actor_id, hour) DO UPDATE SET count = actor_hours.count + 1",
                (actor, stamp.astimezone(timezone.utc).hour),
            )

    # -- baselines --------------------------------------------------------- #

    def refresh_baselines(
        self,
        records: Sequence[dict[str, Any]],
        window_days: int,
        window_start: datetime | None = None,
        window_end: datetime | None = None,
        now: datetime | None = None,
    ) -> dict[str, int]:
        """Recompute ``actor_baselines`` from a baseline-window event set.

        Rows are replaced (not accumulated) for every actor present in
        ``records``, so running this twice over the same window is a no-op.
        """
        now = now or utc_now()
        window_days = max(1, int(window_days))
        per_actor: dict[str, dict[str, Any]] = {}
        for record in records:
            actor = actor_label(record)
            bucket = per_actor.setdefault(
                actor,
                {
                    "actor_name": record.get("actor_name"),
                    "total": 0,
                    "failures": 0,
                    "days": set(),
                    "hours": {},
                },
            )
            bucket["total"] += 1
            if record.get("is_failure"):
                bucket["failures"] += 1
            stamp = parse_iso8601(record.get("received"))
            if stamp is not None:
                utc = stamp.astimezone(timezone.utc)
                bucket["days"].add(utc.date().isoformat())
                bucket["hours"][str(utc.hour)] = bucket["hours"].get(str(utc.hour), 0) + 1
            if not bucket["actor_name"]:
                bucket["actor_name"] = record.get("actor_name")

        with self._conn:
            for actor, bucket in per_actor.items():
                self._conn.execute(
                    "INSERT INTO actor_baselines "
                    "(actor_id, actor_name, window_days, window_start, window_end, "
                    " total_events, observed_days, avg_events_per_day, failure_events, "
                    " hour_histogram, computed_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(actor_id) DO UPDATE SET "
                    "actor_name=excluded.actor_name, window_days=excluded.window_days, "
                    "window_start=excluded.window_start, window_end=excluded.window_end, "
                    "total_events=excluded.total_events, observed_days=excluded.observed_days, "
                    "avg_events_per_day=excluded.avg_events_per_day, "
                    "failure_events=excluded.failure_events, "
                    "hour_histogram=excluded.hour_histogram, computed_at=excluded.computed_at",
                    (
                        actor,
                        bucket["actor_name"],
                        window_days,
                        to_iso(window_start),
                        to_iso(window_end),
                        bucket["total"],
                        len(bucket["days"]),
                        round(bucket["total"] / window_days, 4),
                        bucket["failures"],
                        json.dumps(bucket["hours"]),
                        to_iso(now),
                    ),
                )
        return {"actors_updated": len(per_actor)}

    def baselines_fresh(
        self,
        window_days: int,
        max_age_hours: float,
        now: datetime | None = None,
    ) -> bool:
        """True when stored baselines already cover ``window_days`` recently enough."""
        row = self._conn.execute(
            "SELECT MAX(computed_at) AS newest FROM actor_baselines WHERE window_days = ?",
            (int(window_days),),
        ).fetchone()
        newest = parse_iso8601(row["newest"]) if row and row["newest"] else None
        if newest is None:
            return False
        return (now or utc_now()) - newest <= timedelta(hours=max_age_hours)

    def get_baseline(
        self,
        actor_id: str,
        ip_lookback_days: int = 30,
        now: datetime | None = None,
    ) -> dict[str, Any] | None:
        """Baseline view for one actor, or ``None`` if the actor is unknown."""
        row = self._conn.execute(
            "SELECT * FROM actor_baselines WHERE actor_id = ?", (actor_id,)
        ).fetchone()
        history = self._conn.execute(
            "SELECT * FROM actor_history WHERE actor_id = ?", (actor_id,)
        ).fetchone()
        if row is None and history is None:
            return None
        return self._baseline_view(actor_id, row, history, ip_lookback_days, now)

    def get_baselines(
        self,
        ip_lookback_days: int = 30,
        now: datetime | None = None,
    ) -> dict[str, dict[str, Any]]:
        """Baseline views keyed by actor id, for every actor ever observed."""
        rows = {
            r["actor_id"]: r for r in self._conn.execute("SELECT * FROM actor_baselines")
        }
        histories = {
            r["actor_id"]: r for r in self._conn.execute("SELECT * FROM actor_history")
        }
        actors = set(rows) | set(histories)
        return {
            actor: self._baseline_view(
                actor, rows.get(actor), histories.get(actor), ip_lookback_days, now
            )
            for actor in actors
        }

    def _baseline_view(
        self,
        actor_id: str,
        row: sqlite3.Row | None,
        history: sqlite3.Row | None,
        ip_lookback_days: int,
        now: datetime | None,
    ) -> dict[str, Any]:
        now = now or utc_now()
        cutoff = to_iso(now - timedelta(days=max(1, int(ip_lookback_days))))
        recent_ips = [
            r["ip"]
            for r in self._conn.execute(
                "SELECT ip FROM actor_ips WHERE actor_id = ? "
                "AND (last_seen IS NULL OR last_seen >= ?) ORDER BY ip",
                (actor_id, cutoff),
            )
        ]
        all_ips = [
            {
                "ip": r["ip"],
                "count": r["count"],
                "first_seen": r["first_seen"],
                "last_seen": r["last_seen"],
            }
            for r in self._conn.execute(
                "SELECT * FROM actor_ips WHERE actor_id = ? ORDER BY count DESC, ip",
                (actor_id,),
            )
        ]
        actions = [
            {"action": r["action"], "count": r["count"], "last_seen": r["last_seen"]}
            for r in self._conn.execute(
                "SELECT * FROM actor_actions WHERE actor_id = ? ORDER BY count DESC, action",
                (actor_id,),
            )
        ]
        access_types = [
            {"access_type": r["access_type"], "count": r["count"], "last_seen": r["last_seen"]}
            for r in self._conn.execute(
                "SELECT * FROM actor_access_types WHERE actor_id = ? ORDER BY count DESC",
                (actor_id,),
            )
        ]
        hours = {
            str(r["hour"]): r["count"]
            for r in self._conn.execute(
                "SELECT hour, count FROM actor_hours WHERE actor_id = ?", (actor_id,)
            )
        }
        histogram: dict[str, int] = {}
        if row is not None and row["hour_histogram"]:
            try:
                histogram = json.loads(row["hour_histogram"])
            except (TypeError, ValueError):
                histogram = {}

        return {
            "actor_id": actor_id,
            "actor_name": (row["actor_name"] if row else None)
            or (history["actor_name"] if history else None),
            "actor_type": history["actor_type"] if history else None,
            "has_baseline": row is not None,
            "window_days": row["window_days"] if row else None,
            "window_start": row["window_start"] if row else None,
            "window_end": row["window_end"] if row else None,
            "baseline_total_events": row["total_events"] if row else 0,
            "observed_days": row["observed_days"] if row else 0,
            "avg_events_per_day": row["avg_events_per_day"] if row else 0.0,
            "baseline_failures": row["failure_events"] if row else 0,
            "baseline_hour_histogram": histogram,
            "computed_at": row["computed_at"] if row else None,
            "known_ips": recent_ips,
            "all_ips": all_ips,
            "known_actions": [a["action"] for a in actions],
            "actions": actions,
            "access_types": access_types,
            "lifetime_hour_histogram": hours,
            "lifetime_events": history["total_events"] if history else 0,
            "lifetime_failures": history["failures"] if history else 0,
            "first_seen": history["first_seen"] if history else None,
            "last_seen": history["last_seen"] if history else None,
        }

    # -- maintenance ------------------------------------------------------- #

    def prune_ingested_events(self, older_than_days: int = 400) -> int:
        """Drop de-duplication rows past their usefulness to bound the DB size."""
        cutoff = to_iso(utc_now() - timedelta(days=max(1, int(older_than_days))))
        with self._conn:
            cursor = self._conn.execute(
                "DELETE FROM ingested_events WHERE received IS NOT NULL AND received < ?",
                (cutoff,),
            )
        return cursor.rowcount or 0

    def stats(self) -> dict[str, Any]:
        def count(table: str) -> int:
            return int(self._conn.execute(f"SELECT COUNT(*) AS c FROM {table}").fetchone()["c"])

        return {
            "db_path": str(self.db_path),
            "schema_version": SCHEMA_VERSION,
            "actors_tracked": count("actor_history"),
            "actors_with_baseline": count("actor_baselines"),
            "events_ingested": count("ingested_events"),
        }


def _upsert_counter(
    conn: sqlite3.Connection,
    table: str,
    column: str,
    actor_id: str,
    value: Any,
    received: str | None,
) -> None:
    """Increment a per-actor counter row, maintaining first/last seen."""
    if value in (None, ""):
        return
    conn.execute(
        f"INSERT INTO {table} (actor_id, {column}, count, first_seen, last_seen) "  # noqa: S608
        "VALUES (?, ?, 1, ?, ?) "
        f"ON CONFLICT(actor_id, {column}) DO UPDATE SET "
        f"count = {table}.count + 1, "
        f"first_seen = MIN(COALESCE({table}.first_seen, excluded.first_seen), "
        f"                 COALESCE(excluded.first_seen, {table}.first_seen)), "
        f"last_seen = MAX(COALESCE({table}.last_seen, excluded.last_seen), "
        f"                COALESCE(excluded.last_seen, {table}.last_seen))",
        (actor_id, str(value), received, received),
    )


def summarize_ingest(results: Iterable[dict[str, int]]) -> dict[str, int]:
    """Combine several :meth:`StateStore.record_events` results."""
    total = {"ingested": 0, "skipped_duplicates": 0}
    for result in results:
        total["ingested"] += result.get("ingested", 0)
        total["skipped_duplicates"] += result.get("skipped_duplicates", 0)
    return total
