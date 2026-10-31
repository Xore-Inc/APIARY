# Port smoke suite (#1608 / #1610 / #1616)

Live-data smoke tests for the modernization port: the Rust service tier
(`backend-service/`) and the worker loops. The frontend suites left with
`frontend-next` (#3749); the dashboard is Xore-Inc/apiary-dashboard and
carries its own tests. Every check runs against the **real** Elasticsearch,
so results reflect actual parity, not fixtures.

## Prerequisites

- Elasticsearch reachable (default `http://127.0.0.1:19200`). On the
  devbox that's a tunnel: `ssh -N -L 19200:172.16.1.16:9200 xore@$HOMESERVER_HOST &`
  (it dies occasionally — restart it before blaming a failure on code; the
  target is Docker-assigned, so if the tunnel lands but ES doesn't answer,
  re-check `docker inspect hp-elasticsearch` for the current address).
- Rust toolchain (`cargo`).

## Scripts

| script | covers | writes to live ES? |
| --- | --- | --- |
| `backend-api.sh` | every `/api/v1` endpoint: KPIs, dashboard aggregation, events + filters + q, stores, charts, session/ip/payload/replay details, artifacts, SSE, report PDF | ip-block round trip on the TEST-NET-3 address `203.0.113.99` (restored) |
| `worker-notifier.sh` | `WORKER_LOOPS=alert-notifier` baseline pass | yes — upserts `dashboard-alert-state-v1` on the same key/shape contract as the Go alertManager (safe alongside it) |
| `worker-reports-scheduler.sh` | `WORKER_LOOPS=reports-scheduler` scheduled-tick parity against the old Go `reportScheduleLoop`'s own test contract (success path + #1340 no-hot-loop failure path) | yes — two throwaway definitions in `dashboard-reports-definitions-v1` + one generated doc in `dashboard-generated-reports-v1`, all deleted at the end |

Run one: `bash port-tests/backend-api.sh`
Run all: `for s in port-tests/{backend-api,worker-notifier,worker-reports-scheduler}.sh; do bash "$s" || exit 1; done`

Env knobs: `ES_URL`, `BE_PORT` (18081),
`PORT_TESTS_MAX_SKIPS=N` to fail a run whose skip count exceeds N
(default: skips stay exit-zero — but they are always counted and listed).

## Conventions for new tests

- Source `lib.sh`; use `check` / `check_http` / `check_json` + `summary`
  so scripts exit non-zero on any failure.
- Discover test keys (session ids, hashes, report ids) from live data —
  never hardcode ids that rot.
- Gate detail checks on discovered keys explicitly (#2184): if found, run
  the check; if not, call `skip <label> <kind>` so the summary names the
  unexercised family instead of shrinking silently behind
  `[ -n "$VAR" ] &&`. Use `discover_key` for the discovery itself — it
  tolerates empty/broken ES responses without stack-tracing between PASS
  lines.
- Anything that writes must use reserved/test values (TEST-NET-3 IPs) and
  restore state before exiting.
- Never pipe a test command through `| tail` without capturing the exit
  code — that pattern has silently hidden failures before.
