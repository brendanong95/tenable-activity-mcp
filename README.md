# tenable-activity-mcp

[![Tests](https://github.com/brendanong95/tenable-activity-mcp/actions/workflows/tests.yml/badge.svg)](https://github.com/brendanong95/tenable-activity-mcp/actions/workflows/tests.yml)

An MCP server that exposes the **Tenable Vulnerability Management audit/activity log**
(`GET /audit-log/v1/events`) as a small set of tools, so any MCP client can ask about
platform activity, API-key usage, and anomalous behaviour on demand.

The server does the analysis. Counting, grouping, rate math and threshold comparisons
all happen in Python; tools return finished, structured results (`failure_rate_pct`,
`by_actor`, `findings` with reasoning) rather than dumping raw events for the model to
add up.

## What it gives you

| Tool | Purpose |
| --- | --- |
| `list_activity_events` | Event feed for a window, with actor/action filters. Pagination is followed automatically; returns a resumable `next_token` if a safety cap is hit. |
| `summarize_activity` | Deterministic rollup for a window: counts by actor, action, CRUD type and access type, plus failure/anonymous rates. |
| `get_api_key_usage` | API-key-driven activity only, grouped by actor: action breakdown, distinct source IPs, first/last seen. |
| `detect_anomalies` | Compares a window against each actor's stored baseline. Flags new actors, volume spikes, unseen source IPs, failed-event bursts, sustained failure rates, off-hours spikes and never-before-seen actions - each with evidence and a reasoning sentence. |
| `get_actor_profile` | One actor's full picture: role (best effort), all-time action breakdown, access types, every source IP seen. |
| `check_permission_prereqs` | Pass/fail on whether the configured keys can actually read the audit log, with remediation text. |

Safety properties worth knowing:

- **Nothing that looks like a credential is ever returned.** Field values whose key names
  a secret (`secret_key`, `api_key`, `token`, `password`, ...) or whose value looks like
  Tenable key material are masked to their last 4 characters.
- **Pagination is capped** at 20 pages / 100k events per tool call; hitting the cap is
  reported explicitly along with the cursor needed to continue.
- **429s back off** using the `X-RateLimit-Reset` header (the endpoint sends no
  `Retry-After`), with exponential fallback and a retry ceiling.

## Requirements

- Python 3.11+
- [uv](https://docs.astral.sh/uv/)
- Tenable VM API keys whose owner can read the audit log

### Tenable role / permissions

Reading `audit-log/v1/events` requires the **Administrator** role, or a custom role with
explicit audit-log read permission, on the user that owns the API keys. Anything less
gets HTTP 403; `check_permission_prereqs` reports that in plain language.

Generate keys in Tenable VM under **Settings → My Account → API Keys**. The keys inherit
the permissions of the user that created them.

`get_actor_profile` additionally tries to resolve an actor's role from the user
directory. If the keys cannot list users, the profile is still returned - just without
the role label.

## Setup

```bash
uv sync --extra dev
```

Then copy `.env.example` to `.env` and fill in your keys:

```bash
cp .env.example .env
```

Verify credentials and permissions before wiring it into a client:

```bash
uv run python -c "from dotenv import load_dotenv; load_dotenv(); from src.server import check_permission_prereqs; print(check_permission_prereqs())"
```

Run the server directly (it speaks MCP over stdio, so it will just sit there waiting for
a client - that is the correct behaviour):

```bash
uv run python -m src.server
```

## Connecting a client

Use the **absolute path** to your clone in the config below.

### Claude Desktop

Edit `claude_desktop_config.json`:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "tenable-activity": {
      "command": "uv",
      "args": [
        "--directory",
        "C:\\path\\to\\tenable-activity-mcp",
        "run",
        "python",
        "-m",
        "src.server"
      ],
      "env": {
        "TENABLE_ACCESS_KEY": "your_access_key",
        "TENABLE_SECRET_KEY": "your_secret_key",
        "TENABLE_MCP_BASE_URL": "https://cloud.tenable.com"
      }
    }
  }
}
```

Restart Claude Desktop afterwards. On macOS/Linux use a POSIX path
(`/Users/you/tenable-activity-mcp`).

If `uv` is not on the launcher's `PATH`, use its absolute path (`which uv` /
`(Get-Command uv).Source`) as `command`.

### Claude Code

```bash
claude mcp add tenable-activity --env TENABLE_ACCESS_KEY=your_access_key --env TENABLE_SECRET_KEY=your_secret_key -- uv --directory /absolute/path/to/tenable-activity-mcp run python -m src.server
```

Or add the same block as above to a project-level `.mcp.json`.

Credentials passed via `env` take precedence over `.env`; the `.env` file is a
local-development convenience, and either mechanism works.

## Example questions to ask once connected

- *"Check whether my Tenable credentials can read the audit log."*
- *"Summarise Tenable platform activity for the last 7 days - who was most active, and what's the failure rate?"*
- *"Which API keys were used against Tenable in the last 30 days, and from which source IPs?"*
- *"Look for anomalies in Tenable activity over the past 3 days against a 30-day baseline, and explain anything you flag."*
- *"Show me everything actor 00000000-1111-4222-8333-444444444444 has ever done - actions, access types, and IPs."*

## How anomaly detection works

`detect_anomalies` needs history to compare against, which lives in a local SQLite file
(`state.db`, created automatically):

1. If stored baselines are older than `BASELINE_REFRESH_MAX_AGE_HOURS` (12), the server
   fetches the `baseline_days` immediately preceding your window and recomputes
   per-actor averages, known IPs, known actions and an hour-of-day histogram.
2. Your window is fetched and compared against those baselines.
3. Events in the analysed window are **not** folded into the baseline, so re-running the
   same window returns the same findings.

Every threshold is a named constant at the top of `src/anomaly.py` and is echoed back in
each result under `thresholds`:

| Constant | Default | Meaning |
| --- | --- | --- |
| `SPIKE_MULTIPLIER` | `3.0` | Window events/day must exceed this multiple of the baseline average |
| `SPIKE_MIN_WINDOW_EVENTS` | `20` | Floor before a spike can be flagged at all |
| `NEW_IP_LOOKBACK_DAYS` | `30` | How recently an IP must have been seen to count as "known" |
| `FAILED_AUTH_BURST_COUNT` / `FAILED_AUTH_BURST_WINDOW_MINUTES` | `5` / `10` | Failure-clustering trigger |
| `HIGH_FAILURE_RATE_PCT` | `50.0` | Sustained failure-rate trigger (over at least 10 events) |
| `OFF_HOURS_START_HOUR` / `OFF_HOURS_END_HOUR` | `20` / `6` (UTC) | Off-hours band |
| `OFF_HOURS_RATIO_MULTIPLIER` | `2.0` | Off-hours share must exceed this multiple of the actor's baseline share |

Baselines are per actor, so a service account that legitimately runs 500 scans a day does
not get flagged for doing exactly that.

## Layout

```
src/
  server.py          MCP entrypoint (FastMCP-style) + the six tool definitions
  tenable_client.py  Auth, filter building, cursor pagination, 429 backoff, typed errors
  classifier.py      API-key vs UI/session tagging, IP extraction, redaction, rollups
  anomaly.py         Thresholds and the individual anomaly checks
  state.py           SQLite: cursors, accumulated actor history, computed baselines
tests/
  test_pagination.py test_classifier.py test_anomaly.py
```

Dependency direction is one-way: `server → {anomaly, classifier, state} → tenable_client`.

## Testing

Three levels, in the order you should run them.

### 1. Unit tests (no credentials, no network)

```bash
uv run pytest -q
```

105 tests covering pagination/cursor handling, rate-limit backoff, API-key vs session
classification, redaction, and every anomaly threshold. Every API response is faked
through a stub transport, so the suite never touches a live tenant.

### 2. Offline end-to-end (no credentials, no network)

```bash
uv run python scripts/smoke_local.py
```

Runs all six tools against a scripted fake Tenable (a quiet baseline month, then a noisy
night from a new IP) and asserts the results: anomalies flagged, planted secrets
redacted, bad input returned as a structured error instead of an exception. Exits
non-zero on any failure, so it works as a pre-commit or CI gate.

### 3. Live check against your tenant (read-only)

With `.env` filled in:

```bash
uv run python scripts/live_check.py 7
```

Verifies audit-log permissions first and stops with remediation text if they are wrong,
then prints a real summary, API-key usage breakdown, anomaly findings, and the busiest
actor's profile for the last N days (default 7). All calls are GETs; nothing is written
to Tenable.

### 4. Through an MCP client

Any MCP client works. To poke at the tools interactively without a chat client:

```bash
npx @modelcontextprotocol/inspector uv --directory . run python -m src.server
```

Or wire it into Claude Desktop / Claude Code (above) and ask one of the example
questions. `check_permission_prereqs` is the right first call - it confirms the server
started, found its credentials, and can reach the audit log.

### Inspecting local state

```bash
uv run python -c "from src.state import StateStore; print(StateStore().stats())"
```

Delete `state.db` to reset baselines; the next `detect_anomalies` call rebuilds them.

## Notes

- Built against `mcp==2.0.0`, where the SDK renamed `FastMCP` to `MCPServer`. `server.py`
  imports whichever name the installed SDK provides, so it also works on `mcp` 1.x.
- Event fetching goes through pyTenable's `TenableIO` session
  (`audit_log.events(..., return_json=True)`), which keeps auth and connection handling
  in the maintained library while leaving the `pagination.next` cursor visible to us. If
  pyTenable is unavailable, an equivalent `requests` transport using the
  `X-ApiKeys: accessKey=...;secretKey=...` header takes over.
- Timestamps are UTC everywhere, including the off-hours band.
- `state.db` accumulates per-actor history. Delete it to reset all baselines; the next
  `detect_anomalies` call rebuilds them.
