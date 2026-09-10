# WeSheildSiem — Design & Architecture

## Context

A SIEM built from scratch to **learn how one works internally** (portfolio project), in
**Python**, with events stored in **OpenSearch**.

**v1 targets ingestion + normalization only** — the data pipeline, which is the hardest and
most educational part of a SIEM. Detection, UI, and alerting are designed into the
architecture now but built in later phases so v1 stays finishable.

**v1 outcome:** point real logs (syslog, nginx, sshd, JSON) at the system, watch them get
parsed, enriched, normalized to a common schema, and land searchable in OpenSearch — with
malformed events routed to a dead-letter index instead of being lost.

---

## Architecture

```
                 ┌───────────┐
  syslog UDP/TCP →│           │
  file tail      →│  Inputs   │→ raw envelope →┐
  HTTP JSON API  →│           │                │
                 └───────────┘                 ▼
                                        Redis Stream  siem:raw
                                                │  (consumer group)
                                                ▼
                                        ┌───────────────┐
                                        │ Pipeline      │  parse → enrich → normalize (ECS)
                                        │ workers (N)   │
                                        └───────┬───────┘
                                     ok │               │ parse/validate failure
                                        ▼               ▼
                              OpenSearch bulk      siem:deadletter stream
                              data stream           → siem-deadletter index
                              logs-*  (ECS)
                                        ▲
                              OpenSearch Dashboards (Discover / viz)
```

### Data flow contract

- Every input produces a uniform **raw envelope**:
  `{raw, source, transport, received_at, labels, host}`.
- Workers pull from a Redis **consumer group** (at-least-once), ack on success.
- Document `_id` = hash of normalized content → **idempotent** re-delivery (dedupe).
- Output target is an OpenSearch **data stream** `logs-*` with an ECS index template and an
  **ISM retention policy** (delete after 30d for the lab).
- Anything that fails parsing/validation → dead-letter stream + `siem-deadletter` index
  with the error and original raw text. **Nothing is silently dropped.**

### Why these choices

| Decision | Rationale | Later swap |
|---|---|---|
| **Redis Streams** as the buffer | Teaches consumer groups / acks / backpressure with one lightweight container | Kafka behind the same `queue/` interface |
| **ECS** as the normalized schema | Well-documented, maps cleanly onto OpenSearch, what real SIEMs converge on | OCSF |
| **Data stream + ISM** (not hand-rolled daily indices) | Teaches index lifecycle — the thing that actually bites SIEM operators (mapping explosion, retention, rollover) | — |
| **Split inputs from workers via the queue** | Ingestion never blocks on OpenSearch being slow/down; workers scale independently | — |

---

## Tech stack

| Concern | Choice |
|---|---|
| Language | Python 3.12, `asyncio` for inputs + I/O |
| Dep management | `uv` + `pyproject.toml` |
| Models / validation | `pydantic` v2 (config + event schema) |
| HTTP ingest API | `FastAPI` + `uvicorn` |
| Queue | `redis` (redis-py) Redis Streams |
| OpenSearch client | `opensearch-py` (bulk helpers) |
| Parsing | native JSON; `regex`; `pygrok` for grok patterns; `python-dateutil` for timestamps |
| Enrichment | `geoip2` + MaxMind GeoLite2 |
| CLI | `typer` |
| Lint / type / test | `ruff`, `mypy`, `pytest`, `testcontainers` |
| Local env | `docker-compose`: opensearch (single node), opensearch-dashboards, redis |

---

## Module responsibilities

| Module | Responsibility |
|---|---|
| `schema.py` | `RawEnvelope` and `Event` (ECS subset). Validation. `to_bulk_action()` producing a deterministic `_id`. |
| `config.py` | pydantic models for `config/pipeline.yml` + loader. Powers `siem check-config`. |
| `queue/streams.py` | Redis Streams producer (`xadd`); consumer wrapper: group create, `xreadgroup`, `xack`, `xautoclaim` for stuck messages; pending/lag metric. |
| `inputs/base.py` | `Input` ABC — async iterator yielding `RawEnvelope`. |
| `inputs/syslog.py` | RFC3164 + RFC5424 framing, UDP + TCP. |
| `inputs/filetail.py` | Tail files with persisted byte offsets (survives restart). |
| `inputs/http_api.py` | FastAPI app, `POST /ingest?source=<name>`. |
| `parsers/base.py` | `Parser` ABC: `raw str -> dict` of ECS-ish fields. |
| `parsers/{json,regex,grok}_parser.py` | Generic parser implementations. |
| `parsers/builtin/*.yml` | Declarative parser definitions (sshd, nginx access, generic syslog). |
| `pipeline/registry.py` | Route `source` → parser using `config.routing`. |
| `enrich/geoip.py` | `source.ip` / `destination.ip` → `*.geo.*`. |
| `enrich/asset.py` | Static host/IP → `host.name`, `labels` from config. Populates `related.*`. |
| `output/bootstrap.py` | Apply index template + ISM policy + create data stream. |
| `output/opensearch.py` | Bulk indexer: batching, retry/backoff, backpressure signal. |
| `output/deadletter.py` | Write failures to `siem:deadletter` stream + `siem-deadletter` index. |
| `pipeline/worker.py` | The loop: consume → parse → enrich → normalize → output / dead-letter → ack. |
| `observability/metrics.py` | Prometheus text endpoint: received, parsed, failed, indexed, stream lag, bulk latency. |
| `cli.py` | `bootstrap-opensearch`, `run`, `replay`, `check-config`. |
| `tools/loggen.py` | Replay `sample-data/*` to syslog / HTTP at a target events-per-second. |

---

## Build phases

### Phase 0 — Scaffold  *(done: skeleton + infra files exist)*
`pyproject.toml`, `docker-compose.yml`, ruff/mypy/pytest config, `.pre-commit-config.yaml`,
CI, `README`.

### Phase 1 — Ingestion + normalization  *(v1 — see BUILD_GUIDE.md for the ordered steps)*
Schema → config → queue → inputs → parser framework → enrichment → output → dead-letter →
worker → CLI → metrics + loggen → tests.

**Definition of done for v1:**
- syslog / file / HTTP inputs all land events in `logs-*` with populated ECS fields
- GeoIP + asset enrichment applied
- malformed input visible in `siem-deadletter` with an error reason
- worker restart mid-load ⇒ no lost events, no duplicates
- `pytest` green (parser units + one testcontainers integration test)
- `/metrics` shows throughput and near-zero stream lag at steady state

### Phase 2 — Detection engine
`pySigma` with an OpenSearch backend; scheduled query-rules; stateful windowed correlation;
`alerts` index + alert model.

### Phase 3 — Search + triage UI
Start with OpenSearch Dashboards; then a small FastAPI + React app for alert triage and
saved searches.

### Phase 4 — Notifications + response
Notifier framework (email / Slack / webhook); alert dedup + grouping; lightweight case
tracking.

### Phase 5 — Agents + scale
Endpoint agent or Fluent Bit / Vector integration; Windows Event Log; multi-node
OpenSearch; auth / RBAC.

---

## Learning concepts this project exercises

Backpressure & flow control · at-least-once delivery + idempotent writes · consumer groups
& redelivery · schema normalization tradeoffs · timestamp/timezone parsing pitfalls ·
index lifecycle management & mapping explosion / field cardinality · dead-lettering ·
throughput vs. enrichment cost · grok/regex parser design.

---

## Verification (end-to-end, after Phase 1)

1. `docker compose up -d` → OpenSearch green, Dashboards on :5601, Redis up.
2. `uv run siem bootstrap-opensearch` → verify `curl localhost:9200/_index_template/ecs-logs`
   and `curl localhost:9200/_plugins/_ism/policies/siem-logs-retention`.
3. `uv run siem run`.
4. `uv run python tools/loggen.py --source sshd --transport syslog-udp --eps 50`.
5. `curl 'localhost:9200/logs-*/_search?q=event.category:authentication&size=1&pretty'` →
   doc with `source.ip`, `source.geo.country_name`, `user.name`, UTC `@timestamp`.
6. `printf '<13>not a real log line\n' | nc -u -w1 localhost 514` →
   `curl 'localhost:9200/siem-deadletter/_search?pretty'` shows it with an error reason.
7. Dashboards → Discover on `logs-*` → events filterable.
8. `curl localhost:8000/metrics` → non-zero `siem_events_indexed_total`, `siem_stream_lag` ≈ 0.
9. `uv run pytest` → green.
10. Restart workers mid-replay → no duplicate docs (idempotent `_id`), no lost events.

---

## Open questions to settle during implementation

- **GeoLite2** requires a free MaxMind account/license key. `enrich.geoip.enabled` is
  `false` by default — enable once `GeoLite2-City.mmdb` is present, or skip geo for v1.
- **OpenSearch security**: disabled in `docker-compose.yml` for lab simplicity. Turn on
  TLS + basic auth before this is anything but a local toy.
- **Target throughput**: 1k eps is plenty for a lab. Affects `workers.count` and whether
  bulk batching needs tuning.
