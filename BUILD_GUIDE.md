# WeSheildSiem — Build Guide (write the code yourself)

This is the order to implement Phase 1. Each step is small, ends with something you can
**run and see working**, and only depends on steps above it. Don't skip ahead — the value
is in watching each layer light up.

> **Where to start:** `src/siem/schema.py`. It has zero dependencies and everything else
> imports it.

---

## 0. One-time setup

```bash
cd WeSheildSiem
uv sync --extra dev          # install deps into .venv
docker compose up -d         # OpenSearch :9200, Dashboards :5601, Redis :6379
curl localhost:9200/_cluster/health   # expect status green/yellow
```

Keep a scratch REPL open for testing: `uv run python`.

---

## Module dependency graph (implement bottom-up)

```
schema.py
  ├─ config.py
  ├─ queue/streams.py ──────────────┐
  ├─ parsers/base.py                │
  │    ├─ parsers/json_parser.py    │
  │    ├─ parsers/regex_parser.py   │
  │    ├─ parsers/grok_parser.py    │
  │    └─ pipeline/registry.py  (uses config + parsers)
  ├─ enrich/geoip.py                │
  ├─ enrich/asset.py                │
  └─ output/bootstrap.py           │
       └─ output/opensearch.py     │
       └─ output/deadletter.py     │
                                   │
inputs/base.py ─ inputs/syslog.py ─┤  (all inputs produce RawEnvelope -> queue)
                 inputs/filetail.py│
                 inputs/http_api.py│
                                   ▼
                        pipeline/worker.py   (consume -> parse -> enrich -> normalize -> output)
                                   │
                                 cli.py      (wires inputs + workers + metrics)
                                   │
        observability/metrics.py ──┘        tools/loggen.py   tests/
```

---

## Step 1 — `src/siem/schema.py`  *(the foundation)*

**Goal:** typed models for a raw event and a normalized ECS event.

**Implement:**
- `class RawEnvelope(BaseModel)` — what an input emits:
  - `raw: str` (the original line/payload)
  - `source: str` (routing key, e.g. `"sshd"`)
  - `transport: str` (`"syslog-udp"`, `"file"`, `"http"`, …)
  - `received_at: datetime` (UTC, default `now`)
  - `host: str | None` (the collector host / sender IP)
  - `labels: dict[str, str] = {}`
  - `.to_stream_fields() -> dict[str, str]` — flat string dict for Redis `xadd`
  - `.from_stream_fields(d) -> RawEnvelope` classmethod
- `class Event(BaseModel)` — ECS subset. Use nested sub-models or a flat model with
  `alias="@timestamp"` etc. Fields to cover (see `templates/ecs-index-template.json` for
  the full list): `@timestamp`, `message`, `tags`, `labels`, `event.*`, `log.*`, `host.*`,
  `source.*` (+ `source.geo.*`), `destination.*`, `user.*`, `network.*`, `http.*`, `url.*`,
  `user_agent.original`, `related.*`, `observer.*`, `ecs.version = "8.11"`.
  - `model_config = ConfigDict(populate_by_name=True, extra="allow")` — extra allowed so
    parsers can add fields OpenSearch will map dynamically.
  - `.to_doc() -> dict` — `model_dump(by_alias=True, exclude_none=True)`, dotted keys.
  - `.doc_id() -> str` — `sha256` of a canonical JSON dump of the doc. This is the
    idempotency key.
  - `.to_bulk_action(data_stream: str) -> dict` — opensearch-py bulk action:
    `{"_op_type": "create", "_index": data_stream, "_id": ..., "_source": ...}`.

**Test:**
```python
from siem.schema import Event
e = Event.model_validate({"@timestamp": "2026-09-10T00:00:00Z", "message": "hi",
                          "source": {"ip": "8.8.8.8"}})
print(e.to_doc()); print(e.doc_id())
```
Same input twice ⇒ same `doc_id()`.

---

## Step 2 — `src/siem/config.py`

**Goal:** load + validate `config/pipeline.yml` into typed models.

**Implement:** pydantic models mirroring the YAML: `QueueConfig`, `OutputConfig`,
`WorkersConfig`, `MetricsConfig`, `EnrichConfig` (with `GeoipConfig`, assets map),
`InputConfig` (discriminated union on `type`: `SyslogInput`, `FileTailInput`,
`HttpApiInput`), `RoutingRule` (`match: dict`, `parser: ParserSpec`), and a top-level
`PipelineConfig`.
- `load_config(path: str | Path) -> PipelineConfig` — read YAML, `model_validate`.
- Raise a clear error on unknown keys (`extra="forbid"` on these models).

**Test:** `uv run siem check-config config/pipeline.yml` (after Step 9) or in the REPL:
`from siem.config import load_config; load_config("config/pipeline.yml")`.

---

## Step 3 — `src/siem/queue/streams.py`

**Goal:** thin wrapper over Redis Streams for producer + consumer-group semantics.

**Implement:**
- `class RawQueue` built from `QueueConfig`, holding an async `redis.asyncio.Redis`.
- `async produce(env: RawEnvelope) -> None` → `xadd(raw_stream, env.to_stream_fields())`.
- `async ensure_group() -> None` → `xgroup_create(raw_stream, group, id="0", mkstream=True)`
  swallowing `BUSYGROUP`.
- `async consume(consumer: str, count: int, block_ms: int) -> list[tuple[msg_id, RawEnvelope]]`
  → `xreadgroup(group, consumer, {raw_stream: ">"}, count=count, block=block_ms)`.
- `async ack(msg_id: str) -> None` → `xack`.
- `async reclaim(consumer: str, min_idle_ms: int) -> list[...]` → `xautoclaim` for messages
  a dead worker never acked.
- `async pending_count() -> int` → `xpending` summary (for backpressure + the lag metric).
- `async deadletter(env, stage, error) -> None` → `xadd(deadletter_stream, {...})`.

**Test:**
```python
q = RawQueue(cfg.queue); await q.ensure_group()
await q.produce(RawEnvelope(raw="test", source="sshd", transport="manual"))
print(await q.consume("c1", 10, 100))
```

---

## Step 4 — Inputs  (`inputs/base.py`, then `syslog.py`, `filetail.py`, `http_api.py`)

**Goal:** each input reads from the outside world and calls `queue.produce(...)`.

**`inputs/base.py`:**
- `class Input(ABC)` with `name: str` and `async def run(self, queue: RawQueue) -> None`
  (runs forever). Optionally an `async def stop()`.

**`inputs/syslog.py`:** UDP (`asyncio.DatagramProtocol`) and TCP
(`asyncio.start_server`, newline-framed) listeners. Minimal PRI parsing:
strip `<PRI>`, derive `log.syslog.facility/severity` later in the parser — here just set
`source` (from `default_source` or config), `transport="syslog-udp"/"syslog-tcp"`,
`host` = sender IP.

**`inputs/filetail.py`:** open file, `seek` to stored offset, read new lines, persist the
new offset to `offset_store` after each batch. Handle truncation (size < offset ⇒ seek 0)
and missing file (retry). One `RawEnvelope` per line.

**`inputs/http_api.py`:** FastAPI app; `POST /ingest?source=<name>` accepts a raw body
(newline-delimited ⇒ one envelope per line) or `application/json` (one or an array).
Run with uvicorn programmatically from `run()`.

**Test:** start just one input from a tiny script, then:
```bash
printf '<34>Oct 11 22:14:15 host sshd[1]: test\n' | nc -u -w1 localhost 514
redis-cli XRANGE siem:raw - +        # see the envelope
```

---

## Step 5 — Parser framework  (`parsers/`)

**Goal:** turn `raw: str` into a dict of ECS-ish fields.

**`parsers/base.py`:** `class Parser(ABC)` → `def parse(self, raw: str) -> dict`. Raise
`ParseError` on no match.

**`parsers/json_parser.py`:** `json.loads`; optionally map common keys to ECS
(`timestamp`/`ts`/`time` → `@timestamp`, `msg` → `message`). Pass unknown keys through.

**`parsers/regex_parser.py`:** compiled named-group pattern → dict from `groupdict()`;
a `field_map` to rename groups to dotted ECS paths; type coercion hints.

**`parsers/grok_parser.py`:** wrap `pygrok.Grok`; support a list of patterns tried in
order; same `field_map` mechanism.

**`parsers/builtin/*.yml`:** declarative — each file is `{type: grok|regex, patterns: [...],
field_map: {...}, add: {event.category: [...], observer.product: ...}, timestamp_field: ...,
timestamp_formats: [...]}`. Write a small loader that turns one of these into a configured
`GrokParser`/`RegexParser`.
- `sshd.yml`: `Failed password for <user> from <ip> port <port>`,
  `Accepted publickey for <user> from <ip>`, invalid user, etc. →
  `event.category: [authentication]`, `event.outcome`, `user.name`, `source.ip`,
  `source.port`.
- `nginx_access.yml`: combined log format → `source.ip`, `http.request.method`,
  `url.original`, `http.response.status_code`, `http.response.body.bytes`,
  `user_agent.original`, `http.request.referrer`.
- `syslog_generic.yml`: RFC3164/5424 header → `@timestamp`, `host.hostname`,
  `process.name`, `process.pid`, `message`.

**Common post-parse normalization** (do this once, in the worker or a helper):
parse `timestamp_field` with `dateutil` → UTC `@timestamp`; ensure `event.kind = "event"`;
copy `source.ip`/`destination.ip` into `related.ip`, `user.name` into `related.user`.

**`pipeline/registry.py`:** `build_router(config) -> Router`; `Router.parser_for(source)`
walks `config.routing`, matching `match` dicts (support `"*"` wildcard), returns a
constructed `Parser`. Cache constructed parsers.

**Test:** this is where unit tests start — see Step 11. Quick check:
```python
from siem.parsers.builtin import load_builtin
p = load_builtin("sshd")
print(p.parse("Failed password for root from 8.8.8.8 port 22 ssh2"))
```

---

## Step 6 — Enrichment  (`enrich/geoip.py`, `enrich/asset.py`)

**Goal:** add context to a partially-normalized dict/Event.

**`enrich/geoip.py`:** `class GeoIpEnricher` opens `geoip2.database.Reader`; `enrich(event)`
looks up `source.ip` and `destination.ip`, sets `*.geo.country_iso_code`,
`*.geo.country_name`, `*.geo.city_name`, `*.geo.location = {lat, lon}`. No-op if disabled
or the IP is private/not found.

**`enrich/asset.py`:** `class AssetEnricher(assets: dict)` — if `host`, `source.ip`, or
`host.name` matches a key, merge the mapped fields (`host.name`, `labels`). Also finalize
`related.hosts`.

**Test:**
```python
GeoIpEnricher(cfg.enrich.geoip).enrich(evt_with_source_ip_8_8_8_8)
```

---

## Step 7 — Output  (`output/bootstrap.py`, `output/opensearch.py`, `output/deadletter.py`)

**`output/bootstrap.py`:** `bootstrap(output_cfg)`:
1. PUT ISM policy from `templates/ism-policy.json` to
   `_plugins/_ism/policies/siem-logs-retention` (skip if exists).
2. PUT index template from `templates/ecs-index-template.json` as `ecs-logs`.
3. Create the data stream `logs-generic-default` (ignore "already exists").
4. Create the `siem-deadletter` index with a minimal mapping.

**`output/opensearch.py`:** `class BulkIndexer`:
- buffers bulk actions; flushes on `bulk_max_actions` or `bulk_flush_interval_seconds`.
- uses `opensearchpy.helpers.async_bulk` (or `streaming_bulk`) with retry/backoff up to
  `retry_max_attempts`.
- `create` op-type ⇒ duplicate `_id` returns a 409 that you count as "already indexed",
  not an error (idempotency).
- exposes `inflight()` / a backpressure flag the worker checks before consuming more.

**`output/deadletter.py`:** `deadletter(env, stage, error)` → index a doc into
`siem-deadletter` (`{"@timestamp", "raw", "source", "transport", "stage", "error"}`) **and**
`queue.deadletter(...)` for replay tooling later.

**Test:**
```bash
uv run siem bootstrap-opensearch
curl localhost:9200/_index_template/ecs-logs?pretty
curl 'localhost:9200/_plugins/_ism/policies/siem-logs-retention?pretty'
```

---

## Step 8 — `src/siem/pipeline/worker.py`  *(ties it together)*

**Goal:** the pipeline loop.

**Implement** `class Worker(id, queue, router, enrichers, indexer, metrics)` with
`async run()`:
```
loop:
  if indexer.backpressured(): await sleep(small); continue
  batch = await queue.consume(consumer=f"w{id}", count=N, block_ms=1000)
  for msg_id, env in batch:
    try:
      fields = router.parser_for(env.source).parse(env.raw)
      event  = normalize(fields, env)          # -> Event, UTC @timestamp, related.*
      for en in enrichers: en.enrich(event)
      await indexer.add(event.to_bulk_action(data_stream))
      metrics.parsed.inc(); 
    except ParseError | ValidationError as exc:
      await deadletter(env, stage, str(exc)); metrics.failed.inc()
    finally:
      await queue.ack(msg_id)                   # ack after dead-letter, never lose it
  metrics.received.inc(len(batch))
periodically: await queue.reclaim(consumer, min_idle_ms=60000)
```
Ack only after the event is either handed to the indexer buffer *and that buffer is
durable enough for your taste* or dead-lettered. Simplest correct choice for v1: flush the
indexer before acking the batch (at-least-once, occasional dupes handled by `_id`).

**Test:** run a script that starts one input + one worker, send a line, see a doc:
```bash
curl 'localhost:9200/logs-*/_search?size=1&pretty'
```

---

## Step 9 — `src/siem/cli.py`

**Goal:** the `siem` command (Typer app).

- `siem check-config [PATH]` — load + print a summary, exit non-zero on error.
- `siem bootstrap-opensearch` — call `output.bootstrap.bootstrap`.
- `siem run [--config PATH] [--workers N]` — build queue, router, enrichers, indexer,
  metrics server; start every configured input + N workers with `asyncio.TaskGroup`;
  graceful shutdown on SIGINT/SIGTERM (drain indexer).
- `siem replay FILE --source S` — read a file and `queue.produce` each line (offline
  ingestion without a listener).

**Test:** `uv run siem --help`, then `uv run siem run`.

---

## Step 10 — `observability/metrics.py` + `tools/loggen.py`

**`metrics.py`:** `prometheus_client` counters/gauges/histograms:
`siem_events_received_total`, `siem_events_parsed_total`, `siem_events_failed_total`,
`siem_events_indexed_total`, `siem_stream_lag` (gauge, from `queue.pending_count()`),
`siem_bulk_flush_seconds` (histogram). Start `start_http_server(port)` from `siem run`.

**`tools/loggen.py`:** Typer script. `--source`, `--transport {syslog-udp,syslog-tcp,http}`,
`--eps`, `--count`, `--file` (defaults to `sample-data/<source>.*`). Sleeps to hold the
target rate. Populate `sample-data/sshd.log`, `nginx-access.log`, `firewall.json` with
~50 realistic lines each (include a couple of malformed lines to exercise dead-lettering).

**Test:** full end-to-end from `PLAN.md` §Verification.

---

## Step 11 — Tests  (`tests/`)

**`tests/test_parsers.py`:** table-driven — for each builtin parser, a list of
`(raw_line, expected_subset_of_fields)`; assert `parser.parse(raw)` is a superset.
Include failure cases asserting `ParseError`.

**`tests/test_pipeline_integration.py`:** `testcontainers` spins up OpenSearch + Redis;
`bootstrap`; push ~20 sample lines (1 malformed) via `queue.produce`; run one `Worker`
until the stream drains; assert:
- N-1 docs in `logs-*` with expected ECS fields,
- 1 doc in `siem-deadletter`,
- re-running the worker over the same messages creates **no** duplicates.

Run: `uv run pytest -q`.

---

## Definition of done (Phase 1)

- [ ] `siem check-config` passes on `config/pipeline.yml`
- [ ] `siem bootstrap-opensearch` is idempotent
- [ ] syslog UDP+TCP, file tail, and HTTP inputs each land ECS docs in `logs-*`
- [ ] sshd / nginx / generic-syslog builtin parsers populate the right ECS fields
- [ ] GeoIP + asset enrichment applied (or GeoIP cleanly skipped when disabled)
- [ ] malformed line ⇒ `siem-deadletter` doc with an error reason, still acked
- [ ] worker restart mid-load ⇒ no lost events, no duplicate docs
- [ ] `/metrics` shows throughput and near-zero `siem_stream_lag` at steady state
- [ ] `pytest` green (parser units + integration)
- [ ] end-to-end verification steps in `PLAN.md` all pass
