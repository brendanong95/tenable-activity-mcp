"""Offline end-to-end exercise of all six tools. No credentials, no network.

Serves scripted audit-log pages through a fake transport, calls every tool, and
asserts the invariants that matter (secrets redacted, anomalies flagged, errors
returned as structured results rather than raised).

    uv run python scripts/smoke_local.py
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Fake credentials + a throwaway state DB, set before importing the server.
os.environ["TENABLE_ACCESS_KEY"] = "a" * 64
os.environ["TENABLE_SECRET_KEY"] = "b" * 64
os.environ["TENABLE_MCP_STATE_DB"] = str(Path(tempfile.mkdtemp()) / "state.db")

from src import server  # noqa: E402
from src.tenable_client import TenableAuditLogClient  # noqa: E402

PLANTED_SECRET = "c" * 64
BASELINE_IP = "203.0.113.10"
WINDOW_IP = "198.51.100.99"
WINDOW_FROM = "2024-05-10"
WINDOW_TO = "2024-05-11"


def event(index: int, when: datetime, ip: str, failure: bool = False) -> dict:
    return {
        "id": f"event-{index}",
        "action": "scan.launch",
        "crud": "create",
        "actor": {"id": "actor-1", "name": "alice@example.com", "type": "User"},
        "target": {"id": "target-1", "name": "nightly-scan", "type": "Scan"},
        "received": when.isoformat().replace("+00:00", "Z"),
        "is_failure": failure,
        "is_anonymous": False,
        "fields": [
            {"key": "access_method", "value": "apikey"},
            {"key": "source_ip", "value": ip},
            {"key": "user_agent", "value": "pyTenable/1.4.20"},
            # Planted on purpose: this must never survive into tool output.
            {"key": "secret_key", "value": PLANTED_SECRET},
        ],
    }


class FakeTenable:
    """Quiet baseline month, then a noisy night from a brand-new IP."""

    def get_events(self, params: dict) -> dict:
        start = dict((f"{f[0]}.{f[1]}", f[2]) for f in params["filters"]).get("date.gte", "")
        if start.startswith("2024-04"):  # baseline window: 1 scan/day at 09:00
            events = [
                event(i, datetime(2024, 4, 11, 9, tzinfo=timezone.utc) + timedelta(days=i),
                      BASELINE_IP)
                for i in range(29)
            ]
        else:  # investigation window: 40 events overnight, new IP, some failures
            events = [
                event(100 + i,
                      datetime(2024, 5, 10, 2, tzinfo=timezone.utc) + timedelta(minutes=2 * i),
                      WINDOW_IP, failure=i % 4 == 0)
                for i in range(40)
            ]
        return {"events": events, "pagination": {"next": None, "total": len(events)}}

    def list_users(self) -> list[dict]:
        return [{"uuid": "actor-1", "username": "alice@example.com", "permissions": 64,
                 "email": "alice@example.com", "enabled": True}]


server._client = TenableAuditLogClient(transport=FakeTenable(), sleep=lambda _: None)

failures: list[str] = []


def check(label: str, condition: bool, detail: str = "") -> None:
    print(f"  [{'PASS' if condition else 'FAIL'}] {label}{f' - {detail}' if detail else ''}")
    if not condition:
        failures.append(label)


print("\n1. check_permission_prereqs")
prereq = server.check_permission_prereqs()
check("credentials accepted", prereq["ok"] is True)
check("access key masked", prereq["configuration"]["access_key"].endswith("aaaa")
      and "*" in prereq["configuration"]["access_key"])

print("\n2. list_activity_events")
listing = server.list_activity_events(WINDOW_FROM, WINDOW_TO)
check("events returned", listing["events_returned_inline"] == 40)
check("access type classified", listing["events"][0]["access_type"] == "apikey",
      listing["events"][0]["access_reason"])
check("planted secret redacted", PLANTED_SECRET not in json.dumps(listing))

print("\n3. summarize_activity")
summary = server.summarize_activity(WINDOW_FROM, WINDOW_TO)["summary"]
check("total events", summary["total_events"] == 40)
check("failure rate precomputed", summary["failure_rate_pct"] == 25.0,
      f"{summary['failure_count']} failures")

print("\n4. get_api_key_usage")
usage = server.get_api_key_usage(date_from=WINDOW_FROM, date_to=WINDOW_TO)
check("one actor with api-key activity", usage["actor_count"] == 1)
check("source IP tracked", usage["actors"][0]["source_ips"][0]["ip"] == WINDOW_IP)

print("\n5. detect_anomalies (baseline rebuilt from the preceding 30 days)")
result = server.detect_anomalies(WINDOW_FROM, WINDOW_TO, baseline_days=30)
kinds = result["findings_by_type"]
for finding in result["findings"]:
    print(f"      [{finding['severity']}] {finding['type']}: {finding['reasoning'][:150]}")
check("volume spike flagged", kinds.get("volume_spike") == 1)
check("new source IP flagged", kinds.get("new_source_ip") == 1)
check("off-hours spike flagged", kinds.get("off_hours_spike") == 1)
check("thresholds echoed", result["thresholds"]["spike_multiplier"] == 3.0)

print("\n6. get_actor_profile")
profile = server.get_actor_profile("actor-1", lookback_days=60)
check("role resolved", profile["identity"]["role"] == "Administrator")
check("lifetime history persisted", profile["lifetime"]["known_to_state"] is True,
      f"{profile['lifetime']['total_events']} events in state.db")

print("\n7. error handling")
bad_date = server.summarize_activity("not-a-date", WINDOW_TO)
check("bad date returns a result, not an exception", bad_date["ok"] is False)
check("message is actionable", "ISO-8601" in bad_date["message"])
os.environ.pop("TENABLE_ACCESS_KEY")
server._client = None
missing = server.check_permission_prereqs()
check("missing credentials explained", missing["ok"] is False
      and "TENABLE_ACCESS_KEY" in missing["message"])

print(f"\n{'FAILED: ' + ', '.join(failures) if failures else 'All local smoke checks passed.'}")
sys.exit(1 if failures else 0)
