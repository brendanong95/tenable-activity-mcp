"""Smoke-test the tools against your real Tenable tenant (read-only).

Reads credentials from .env or the environment, verifies audit-log access, then
runs a short summary / API-key / anomaly pass over a recent window.

    uv run python scripts/live_check.py [days]

`days` defaults to 7. Every call is a GET against the audit-log endpoint; nothing
is written to Tenable. Baselines are written to the local state.db.
"""

from __future__ import annotations

import json
import sys
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import find_dotenv, load_dotenv  # noqa: E402

load_dotenv(find_dotenv(usecwd=True))

from src import server  # noqa: E402
from src.tenable_client import to_iso, utc_now  # noqa: E402

DAYS = int(sys.argv[1]) if len(sys.argv) > 1 else 7
END = utc_now()
START = END - timedelta(days=DAYS)
date_from, date_to = to_iso(START), to_iso(END)


def show(title: str, payload: dict, keys: list[str]) -> None:
    print(f"\n=== {title} (ok={payload.get('ok')}) ===")
    if not payload.get("ok"):
        print("  error:", payload.get("error"), "-", payload.get("message"))
        print("  remediation:", payload.get("remediation"))
        return
    for key in keys:
        print(f"  {key}: {json.dumps(payload.get(key), indent=2, default=str)[:1500]}")


print(f"Window: {date_from} -> {date_to} ({DAYS} day(s))")

prereq = server.check_permission_prereqs()
show("check_permission_prereqs", prereq, ["message", "configuration", "state"])
if not prereq.get("ok"):
    print("\nStopping: fix credentials/permissions first.")
    sys.exit(1)

show(
    "summarize_activity",
    server.summarize_activity(date_from, date_to),
    ["summary", "events_per_day", "pagination"],
)
show(
    "get_api_key_usage",
    server.get_api_key_usage(date_from=date_from, date_to=date_to),
    ["actor_count", "apikey_event_count", "apikey_share_pct", "access_type_totals"],
)

anomalies = server.detect_anomalies(date_from, date_to, baseline_days=30)
show(
    "detect_anomalies",
    anomalies,
    ["baseline_window", "actors_analyzed", "findings_by_severity", "findings_by_type"],
)
for finding in anomalies.get("findings", [])[:10]:
    print(f"  [{finding['severity']}] {finding['type']} / {finding['actor_name'] or finding['actor_id']}")
    print(f"      {finding['reasoning']}")

top = (server.summarize_activity(date_from, date_to).get("summary") or {}).get("by_actor") or []
if top:
    show(
        f"get_actor_profile ({top[0]['actor_name'] or top[0]['actor_id']})",
        server.get_actor_profile(top[0]["actor_id"], lookback_days=90),
        ["identity", "lifetime"],
    )

print("\nLive check complete.")
