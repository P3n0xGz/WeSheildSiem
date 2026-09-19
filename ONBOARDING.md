# ONBOARDING.md — Developer Onboarding, Code Analysis & Team Deliverables

Welcome to the **WeShieldSIEM** engineering team! This guide is designed to get you up to speed immediately, provide a comprehensive deep-dive code analysis of what has already been built, and define assignable work packages/deliverables so we can collaboratively build out the remaining components of Phase 1.

---

## Table of Contents

1. [Project Overview & Core Mission](#1-project-overview--core-mission)
2. [Architecture & Data Pipeline Flow](#2-architecture--data-pipeline-flow)
3. [Developer Setup & Environment Verification](#3-developer-setup--environment-verification)
4. [Full Code Analysis: What is Built & How it Works](#4-full-code-analysis-what-is-built--how-it-works)
   - [Layer 1: Schema & Data Contracts (`src/siem/schema.py`)](#layer-1-schema--data-contracts-srcsiemschemapy)
   - [Layer 2: Configuration & Validation (`src/siem/config.py`)](#layer-2-configuration--validation-srcsiemconfigpy)
   - [Layer 3: Buffer & Redis Streams Layer (`src/siem/queue/streams.py`)](#layer-3-buffer--redis-streams-layer-srcsiemqueuestreamspy)
   - [Layer 4: Planning Blueprints](#layer-4-planning-blueprints)
   - [Current Test Suite Status](#current-test-suite-status)
5. [Gap Analysis: What Remains to be Built](#5-gap-analysis-what-remains-to-be-built)
6. [Team Deliverables & Work Packages (Assignable Tasks)](#6-team-deliverables--work-packages-assignable-tasks)
   - [Work Package 1: Ingestion Collectors (`inputs/`)](#work-package-1-ingestion-collectors-srcsieminputs)
   - [Work Package 2: Parser Framework & Signatures (`parsers/` & `registry.py`)](#work-package-2-parser-framework--signatures-srcsiemparsers)
   - [Work Package 3: Contextual Enrichment (`enrich/`)](#work-package-3-contextual-enrichment-srcsiemenrich)
   - [Work Package 4: OpenSearch Bootstrap & Bulk Storage (`output/`)](#work-package-4-opensearch-bootstrap--bulk-storage-srcsiemoutput)
   - [Work Package 5: Pipeline Worker & Typer CLI (`worker.py` & `cli.py`)](#work-package-5-pipeline-worker--typer-cli)
   - [Work Package 6: Observability, Tooling & Integration Testing](#work-package-6-observability-tooling--integration-testing)
7. [Cross-Module Interface Contracts](#7-cross-module-interface-contracts)
8. [Developer Standards & Definition of Done](#8-developer-standards--definition-of-done)
9. [Quick Reference & Command Cheat Sheet](#9-quick-reference--command-cheat-sheet)

---

## 1. Project Overview & Core Mission

**WeShieldSIEM** is a lightweight, educational Security Information and Event Management (SIEM) system built in Python 3.12+ and asyncio, storing normalized events in OpenSearch.

### Why Are We Building This?
Commercial and enterprise SIEMs (Splunk, Elastic, Sentinel) abstract away the most educational and failure-prone layer in cybersecurity operations: the **data pipeline**. We are building WeShieldSIEM from scratch to master:
- High-throughput asynchronous log ingestion across multiple transports (UDP/TCP syslog, file tailing, HTTP APIs).
- Stream buffering, consumer groups, and backpressure management.
- Schema normalization to the industry-standard **Elastic Common Schema (ECS 8.11)**.
- Dead-letter routing ensuring **zero silent log loss**.
- Idempotent writes ensuring duplicate ingestion does not corrupt security analytics.
- Modern index lifecycle management (Data Streams + Index State Management retention).

### Core Architectural Principles
1. **Never Drop Logs Silently:** If a log line fails parsing or schema validation, it is routed to `siem:deadletter` and stored in `siem-deadletter` with the original payload, stage, and error reason preserved.
2. **At-Least-Once Delivery with Idempotency:** Redis consumer group acknowledgments (`XACK`) occur only after events are securely buffered for bulk indexing or dead-lettered. Duplicate deliveries are safely rejected by OpenSearch via deterministic content-hash document IDs (`_id = sha256(...)`).
3. **Decoupled Ingestion & Processing:** Collectors write to a Redis Stream buffer (`siem:raw`). Processing workers scale independently from network listeners.

---

## 2. Architecture & Data Pipeline Flow

```
                      ┌─────────────────────────────────┐
                      │ Log Collectors (Inputs)         │
                      │ • Syslog UDP/TCP (:514)         │
                      │ • FileTail (/var/log/*.log)     │
                      │ • HTTP JSON/NDJSON API (:9000)  │
                      └────────────────┬────────────────┘
                                       │ RawEnvelope (raw, source, transport, host, labels)
                                       │ await queue.produce() -> XADD
                                       ▼
                       ┌────────────────────────────────┐
                       │ Redis Stream: siem:raw         │
                       │ Consumer Group: pipeline       │
                       └───────────────┬────────────────┘
                                       │ XREADGROUP (count=N, block=1000ms)
                                       ▼
                       ┌────────────────────────────────┐
                       │ Pipeline Worker Loop           │
                       │ 1. Router.parser_for(source)   │
                       │ 2. parser.parse(raw)           │
                       │ 3. normalize() -> Event (ECS)  │
                       │ 4. enrichers.enrich(event)     │
                       └───────┬────────────────┬───────┘
                     [Success] │                │ [ParseError / ValidationError]
                               ▼                ▼
         ┌─────────────────────────┐    ┌───────────────────────────┐
         │ OpenSearch Bulk Indexer │    │ Dead-letter Queue         │
         │ Target: logs-*          │    │ Redis: siem:deadletter    │
         │ Op: create (_id=hash)   │    │ OpenSearch: siem-deadletter
         └─────────────┬───────────┘    └─────────────┬─────────────┘
                       │                              │
                       └──────────────┬───────────────┘
                                      │ await queue.ack(msg_id) -> XACK
                                      ▼
                       ┌────────────────────────────────┐
                       │ OpenSearch Dashboards (:5601)  │
                       │ • Discover / Logs Search       │
                       │ • Authentication & Web Panels  │
                       └────────────────────────────────┘
```

---

## 3. Developer Setup & Environment Verification

### 3.1 Prerequisites
- **Linux / macOS / WSL2**
- **Python 3.12+** (3.14 compatible)
- **uv** (recommended: `curl -LsSf https://astral.sh/uv/install.sh | sh`) or standard Python `venv`
- **Docker & Docker Compose**

### 3.2 Setup Commands

```bash
# 1. Clone & enter repository
git clone https://github.com/P3n0xGz/WeSheildSiem.git
cd WeSheildSiem

# 2. Synchronize virtual environment & dev dependencies
uv sync --extra dev
# Alternatively with python3 -m venv:
# python3 -m venv .venv && source .venv/bin/activate && pip install -e ".[dev]"

# 3. Spin up local container infrastructure
docker compose up -d

# 4. Verify containers are healthy
docker compose ps
```

The stack provides:
| Service | Internal Port | Host Port | Purpose | Health Check |
|---|---|---|---|---|
| `siem-opensearch` | 9200 | 127.0.0.1:9200 | Single-node OpenSearch 2.15 (security plugin disabled for lab) | `curl -sf http://localhost:9200/_cluster/health` |
| `siem-dashboards` | 5601 | 127.0.0.1:5601 | OpenSearch Dashboards UI | Browser: `http://localhost:5601` |
| `siem-redis` | 6379 | 127.0.0.1:6379 | Redis 7.4 Streams message buffer with AOF persistence | `redis-cli ping` |

### 3.3 Running Quality & Verification Checks

```bash
# Run the complete test suite (147 existing tests)
./.venv/bin/pytest -v

# Run linting
./.venv/bin/ruff check src tests

# Run strict type checking
./.venv/bin/mypy src/siem/schema.py src/siem/config.py
```

---

## 4. Full Code Analysis: What is Built & How it Works

The foundation layers of the system are 100% complete, thoroughly documented, and protected by unit test suites.

### Layer 1: Schema & Data Contracts (`src/siem/schema.py`)
*Lines of code: 445 | Covered by: 78 tests in `tests/test_schema.py`*

`schema.py` defines the two canonical data structures that flow through the entire system.

#### 1. `RawEnvelope` (Pydantic Model)
The boundary contract produced by all input collectors and consumed by the Redis queue.
```python
class RawEnvelope(BaseModel):
    raw: str                      # Original raw log string (e.g., syslog line)
    source: str                   # Routing key (e.g., "sshd", "nginx_access")
    transport: str                # Transport protocol ("syslog-udp", "syslog-tcp", "file", "http")
    received_at: str              # ISO-8601 UTC timestamp of collector arrival
    host: str | None = None       # Collector host or client IP
    labels: dict[str, str] = {}   # Collector-attached tags
```
- **Serialization Methods:**
  - `to_stream_fields() -> dict[str, str]`: Serializes fields into a flat string dictionary suitable for Redis `XADD` (e.g. `labels` is stored as canonical JSON).
  - `from_stream_fields(fields: dict[str, str]) -> RawEnvelope`: Reconstructs the typed envelope directly from Redis stream responses with zero manual decoding loops.
- **Validators:** Strict whitespace stripping on `source`/`transport`; automatic coercion of non-string label values to string; `to_utc` validation on timestamps.

#### 2. `Event` (ECS 8.11 Normalized Model)
The core normalized security event stored in OpenSearch `logs-*`.
- **Field Hierarchy:**
  - `@timestamp`: Timezone-aware UTC `datetime` (aliased to `@timestamp`).
  - `message`: Human-readable summary or primary log message.
  - `tags`: List of classification flags and sanitization warnings.
  - `labels`: Arbitrary key-value strings.
  - Nested Sub-Models: `Source`, `Destination`, `Host`, `User`, `EventMeta`, `LogMeta`, `HttpRequest`, `HttpResponse`, `Http`, `Url`, `UserAgent`, `Network`, `Related`, `Observer`.
- **Key Architectural Features in `Event`:**
  - **Graceful Raw Input Sanitization (`sanitize_raw_input` validator):**
    If a parser passes an invalid IP (e.g., `"999.999.999.999"`) or non-integer port, `Event` **does not crash or discard the record**. Instead, it nullifies the invalid field and appends an informative tag (e.g. `_source_ip_invalid`, `_http_status_code_invalid`).
  - **Automated Pivot Entity Aggregation (`populate_related_fields` validator):**
    Automatically extracts, deduplicates, and populates pivot fields into `related.ip`, `related.user`, and `related.hosts` across source, destination, host, and user fields.
  - **Deterministic Idempotency Key (`doc_id()`):**
    Computes `sha256(event.original \x00 event.dataset \x00 host.name \x00 @timestamp)`.
    Reprocessing the exact same raw event generates the identical `doc_id`.
  - **OpenSearch Bulk Generation (`to_bulk_action(data_stream)`):**
    Produces `{"_op_type": "create", "_index": data_stream, "_id": self.doc_id(), "_source": self.to_doc()}`.
    Because `_op_type` is `"create"`, OpenSearch safely returns an HTTP 409 Conflict if the document was already indexed, guaranteeing deduplication on worker crash recovery.

---

### Layer 2: Configuration & Validation (`src/siem/config.py`)
*Lines of code: 154 | Covered by: 46 tests in `tests/test_config.py`*

`config.py` provides strongly-typed models mirroring [`config/pipeline.yml`](file:///home/shady/Projects/WeSheildSiem/config/pipeline.yml).

- **Strict Validation Policy (`_StrictModel`):**
  Every configuration model enforces `extra="forbid"`. A misspelled configuration key (such as `max_pendign: 5000`) fails loudly during startup rather than causing silent pipeline misbehavior.
- **Discriminated Input Union:**
  `InputConfig` is defined as:
  ```python
  InputConfig = Annotated[
      Union[SyslogInputConfig, FileTailInputConfig, HttpApiInputConfig],
      Field(discriminator="type"),
  ]
  ```
  Pydantic validates each list item against the precise input model based on `type: syslog | filetail | http_api`.
- **Dotted YAML Key Aliasing:**
  `AssetEntry` maps dotted YAML keys like `host.name` directly to Python attribute `host_name` using `Field(alias="host.name")` and `populate_by_name=True`.
- **Routing Rules:**
  `RoutingRule` pairs a `MatchSpec(source=...)` with a `ParserSpec(type=builtin|json|regex|grok, name=...)`, validating that `name` is provided whenever `type == "builtin"`.

---

### Layer 3: Buffer & Redis Streams Layer (`src/siem/queue/streams.py`)
*Lines of code: 124 | Covered by: 5 tests in `tests/test_streams.py`*

`RawQueue` provides high-performance asynchronous Redis Streams operations.

| Method | Redis Command | Behavior & Resilience |
|---|---|---|
| `ensure_group()` | `XGROUP CREATE ... id="0" mkstream=True` | Creates consumer group from beginning of stream. Catches and swallows `BUSYGROUP` `ResponseError`, making startup idempotent. |
| `produce(env)` | `XADD siem:raw ...` | Serializes `RawEnvelope.to_stream_fields()` and appends to the stream. Returns generated Redis ID (`<timestamp>-<seq>`). |
| `consume(consumer, count, block_ms)` | `XREADGROUP group consumer STREAMS siem:raw >` | Reads new messages using cursor `">"`. Parses nested Redis responses into `list[tuple[msg_id, RawEnvelope]]`. |
| `ack(msg_id)` | `XACK siem:raw group msg_id` | Clears processed entry from the Pending Entries List (PEL). |
| `reclaim(consumer, min_idle_ms)` | `XAUTOCLAIM siem:raw group consumer min_idle_ms 0-0` | Reclaims abandoned messages from crashed workers whose idle duration exceeds `min_idle_ms`. |
| `pending_count()` | `XPENDING siem:raw group` | Queries stream backlog to signal backpressure to input collectors and report Prometheus lag metrics. |
| `deadletter(env, stage, error)` | `XADD siem:deadletter ...` | Adds `stage` and `error` metadata to envelope fields and appends to fallback stream for inspection and replay. |
| `close()` | `aclose()` | Cleanly shuts down Redis client connection pools. |

---

### Layer 4: Planning Blueprints

Detailed architectural specifications have been created at the root of the repository:
- [`schemaPlanning.md`](file:///home/shady/Projects/WeSheildSiem/schemaPlanning.md): Deep-dive reference for ECS data modeling and Pydantic validation.
- [`configPlanning.md`](file:///home/shady/Projects/WeSheildSiem/configPlanning.md): Guide to strict schema validation and YAML configuration loading.
- [`streamPlanning.md`](file:///home/shady/Projects/WeSheildSiem/streamPlanning.md): Architecture of Redis Streams buffer, PEL semantics, and crash recovery.
- [`parserPlanning.md`](file:///home/shady/Projects/WeSheildSiem/parserPlanning.md): Blueprint for building the Parser Framework, Grok/Regex engines, builtins, and normalizer.

### Current Test Suite Status

```
============================= test session starts ==============================
collected 147 items

tests/test_config.py ..............................................      [ 31%]
tests/test_schema.py ................................................... [ 65%]
.............................................                            [ 96%]
tests/test_streams.py .....                                              [100%]

============================= 147 passed in 0.37s ==============================
```

---

## 5. Gap Analysis: What Remains to be Built

Here is the exact status of each module across Phase 1:

```
[X] Step 1: src/siem/schema.py            - COMPLETE (445 LOC, 78 tests)
[X] Step 2: src/siem/config.py            - COMPLETE (154 LOC, 46 tests)
[X] Step 3: src/siem/queue/streams.py     - COMPLETE (124 LOC, 5 tests)
[ ] Step 4: src/siem/inputs/              - EMPTY (base.py, syslog.py, filetail.py, http_api.py)
[ ] Step 5: src/siem/parsers/             - EMPTY (base.py, json, regex, grok, builtins, registry.py)
[ ] Step 6: src/siem/enrich/              - EMPTY (geoip.py, asset.py)
[ ] Step 7: src/siem/output/              - EMPTY (bootstrap.py, opensearch.py, deadletter.py)
[ ] Step 8: src/siem/pipeline/worker.py   - EMPTY
[ ] Step 9: src/siem/cli.py               - EMPTY
[ ] Step 10: src/siem/observability/      - EMPTY (metrics.py, tools/loggen.py)
[ ] Step 11: tests/                       - PARTIAL (test_parsers.py & test_pipeline_integration.py pending)
```

---

## 6. Team Deliverables & Work Packages (Assignable Tasks)

To distribute work effectively among team members, the remaining engineering tasks are broken down into **6 modular Work Packages**. Each package has clearly defined file targets, input/output interfaces, and acceptance criteria.

---

### Work Package 1: Ingestion Collectors (`src/siem/inputs/`)
**Target Files:**
- [`src/siem/inputs/base.py`](file:///home/shady/Projects/WeSheildSiem/src/siem/inputs/base.py)
- [`src/siem/inputs/syslog.py`](file:///home/shady/Projects/WeSheildSiem/src/siem/inputs/syslog.py)
- [`src/siem/inputs/filetail.py`](file:///home/shady/Projects/WeSheildSiem/src/siem/inputs/filetail.py)
- [`src/siem/inputs/http_api.py`](file:///home/shady/Projects/WeSheildSiem/src/siem/inputs/http_api.py)
- `tests/test_inputs.py`

**Scope & Responsibilities:**
1. **Base Class (`base.py`):** Define `Input(ABC)` with `name: str`, `async def run(self, queue: RawQueue) -> None`, and `async def stop() -> None`.
2. **Syslog Listener (`syslog.py`):**
   - Implement UDP listener using `asyncio.DatagramProtocol`.
   - Implement TCP listener using `asyncio.start_server` with newline framing.
   - Strip leading `<PRI>` headers.
   - Construct `RawEnvelope(raw=payload, source=default_source or "syslog", transport="syslog-udp"|"syslog-tcp", host=sender_ip)` and push via `await queue.produce(env)`.
3. **File Tailer (`filetail.py`):**
   - Asynchronously tail log files. Persist read byte offsets to `offset_store` after each batch.
   - Handle truncation/rotation (if `file_size < offset`, seek to 0). Retry with backoff if the targeted file does not exist yet.
4. **HTTP API Ingest (`http_api.py`):**
   - Embedded FastAPI app with endpoint `POST /ingest?source=<name>`.
   - Support `text/plain` (newline-delimited) and `application/json` (single object or array).
   - Run programmatically via `uvicorn.Server`.

**Acceptance Criteria:**
- `echo '<34>Oct 11 22:14:15 host sshd[1]: test' | nc -u -w1 localhost 514` results in a new entry in Redis `siem:raw`.
- File tailer resumes from saved offset after restart without duplicate emission.
- HTTP endpoint returns `{"status": "accepted", "count": N}` and produces envelopes to the queue.

---

### Work Package 2: Parser Framework & Signatures (`src/siem/parsers/`)
**Target Files:**
- [`src/siem/parsers/base.py`](file:///home/shady/Projects/WeSheildSiem/src/siem/parsers/base.py)
- [`src/siem/parsers/json_parser.py`](file:///home/shady/Projects/WeSheildSiem/src/siem/parsers/json_parser.py)
- [`src/siem/parsers/regex_parser.py`](file:///home/shady/Projects/WeSheildSiem/src/siem/parsers/regex_parser.py)
- [`src/siem/parsers/grok_parser.py`](file:///home/shady/Projects/WeSheildSiem/src/siem/parsers/grok_parser.py)
- [`src/siem/parsers/builtin/`](file:///home/shady/Projects/WeSheildSiem/src/siem/parsers/builtin/) (`sshd.yml`, `nginx_access.yml`, `syslog_generic.yml`, `__init__.py`)
- [`src/siem/pipeline/registry.py`](file:///home/shady/Projects/WeSheildSiem/src/siem/pipeline/registry.py)
- [`tests/test_parsers.py`](file:///home/shady/Projects/WeSheildSiem/tests/test_parsers.py)

**Scope & Responsibilities:**
*Refer directly to [`parserPlanning.md`](file:///home/shady/Projects/WeSheildSiem/parserPlanning.md) for full implementation templates.*
1. Define `Parser(ABC)` and `ParseError(Exception)` in `base.py`.
2. Implement `JsonParser` with key mapping (`timestamp`/`msg` -> `@timestamp`/`message`).
3. Implement `RegexParser` with compiled named groups, `field_map`, and type coercions.
4. Implement `GrokParser` wrapping `pygrok.Grok` with multi-pattern sequential fallback.
5. Create builtin declarative signatures in `builtin/*.yml` for `sshd`, `nginx_access`, and `syslog_generic`. Implement `load_builtin(name)` with caching.
6. Implement `Router` and `build_router(config)` in `registry.py` with exact source match and `*` wildcard fallback.

**Acceptance Criteria:**
- All tests specified in `parserPlanning.md` Section 5 pass in `tests/test_parsers.py`.
- Mismatched log lines raise `ParseError` (never return `None` or `{}`).
- Parsers compile patterns once at startup; router lookup is $O(1)$.

---

### Work Package 3: Contextual Enrichment (`src/siem/enrich/`)
**Target Files:**
- [`src/siem/enrich/geoip.py`](file:///home/shady/Projects/WeSheildSiem/src/siem/enrich/geoip.py)
- [`src/siem/enrich/asset.py`](file:///home/shady/Projects/WeSheildSiem/src/siem/enrich/asset.py)
- `tests/test_enrich.py`

**Scope & Responsibilities:**
1. **GeoIP Enricher (`geoip.py`):**
   - `class GeoIpEnricher(config: GeoipConfig)`:
   - If `config.enabled == False` or database file is missing, act as a clean no-op.
   - Open MaxMind `geoip2.database.Reader`.
   - Inspect `event.source.ip` and `event.destination.ip`.
   - For public IPs, populate `geo.country_iso_code`, `geo.country_name`, `geo.city_name`, and `geo.location = {"lat": ..., "lon": ...}`.
   - Silently skip private/bogon/loopback IP ranges (`10.0.0.0/8`, `192.168.0.0/16`, etc.) and `AddressNotFoundError`.
2. **Asset Enricher (`asset.py`):**
   - `class AssetEnricher(assets: dict[str, AssetEntry])`:
   - Match `event.host.name`, `event.host.hostname`, `event.source.ip`, or `envelope.host` against static asset mapping from `config.enrich.assets`.
   - On match, merge metadata into `host.name` and append labels.
   - Trigger `event.populate_related_fields()` to synchronize `related.hosts`.

**Acceptance Criteria:**
- Given `8.8.8.8` on `source.ip`, `source.geo.country_name` is populated with `"United States"`.
- Private IPs (e.g. `192.168.1.1`) do not throw errors and leave `geo` empty.
- Configured asset hostname matches update `host.name` and `labels`.

---

### Work Package 4: OpenSearch Bootstrap & Bulk Storage (`src/siem/output/`)
**Target Files:**
- [`src/siem/output/bootstrap.py`](file:///home/shady/Projects/WeSheildSiem/src/siem/output/bootstrap.py)
- [`src/siem/output/opensearch.py`](file:///home/shady/Projects/WeSheildSiem/src/siem/output/opensearch.py)
- [`src/siem/output/deadletter.py`](file:///home/shady/Projects/WeSheildSiem/src/siem/output/deadletter.py)
- `tests/test_output.py`

**Scope & Responsibilities:**
1. **Bootstrap (`bootstrap.py`):**
   - `async def bootstrap(config: OutputConfig) -> None`:
   - PUT ISM policy from [`templates/ism-policy.json`](file:///home/shady/Projects/WeSheildSiem/templates/ism-policy.json) to `_plugins/_ism/policies/siem-logs-retention`.
   - PUT index template from [`templates/ecs-index-template.json`](file:///home/shady/Projects/WeSheildSiem/templates/ecs-index-template.json) as `ecs-logs`.
   - Initialize data stream `logs-generic-default` (ignore `resource_already_exists_exception`).
   - Create `siem-deadletter` index with minimal error mapping.
2. **Bulk Indexer (`opensearch.py`):**
   - `class BulkIndexer`:
   - Buffer bulk actions generated by `event.to_bulk_action()`.
   - Flush automatically when batch size reaches `bulk_max_actions` or timeout hits `bulk_flush_interval_seconds`.
   - Use `opensearchpy.helpers.async_bulk` with exponential backoff up to `retry_max_attempts`.
   - Treat HTTP 409 Conflict as successful deduplication (increment metric `dedup_count`, not error).
   - Expose `backpressured() -> bool` based on inflight batches.
3. **Dead-letter Output (`deadletter.py`):**
   - Dual-write failure handler:
   - Index document into `siem-deadletter` (`@timestamp`, `raw`, `source`, `transport`, `stage`, `error`).
   - Simultaneously call `await queue.deadletter(env, stage, error)` for Redis replay tooling.

**Acceptance Criteria:**
- Bootstrap creates data stream and ISM policy idempotently on fresh or existing OpenSearch instances.
- Re-indexing identical events returns 409 and does not generate duplicate documents in OpenSearch.
- Flushing handles temporary OpenSearch connection drops via retries.

---

### Work Package 5: Pipeline Worker & Typer CLI
**Target Files:**
- [`src/siem/pipeline/worker.py`](file:///home/shady/Projects/WeSheildSiem/src/siem/pipeline/worker.py)
- [`src/siem/cli.py`](file:///home/shady/Projects/WeSheildSiem/src/siem/cli.py)
- `src/siem/parsers/normalizer.py`

**Scope & Responsibilities:**
1. **Pipeline Worker (`worker.py`):**
   - Implement `class Worker(id, queue, router, enrichers, indexer, metrics)`:
   - Asynchronous loop:
     1. Check `indexer.backpressured()`; sleep briefly if throttled.
     2. `batch = await queue.consume(consumer=f"w-{id}", count=N, block_ms=1000)`
     3. For each `(msg_id, env)`:
        - `fields = router.parser_for(env.source).parse(env.raw)`
        - `event = normalize(fields, env)`
        - For each enricher: `enricher.enrich(event)`
        - `await indexer.add(event.to_bulk_action(config.output.data_stream))`
        - On `ParseError` or `ValidationError`: write to `output.deadletter(...)`
        - In `finally`: `await queue.ack(msg_id)`
     4. Periodically invoke `await queue.reclaim(consumer, min_idle_ms=60000)`
2. **Typer CLI (`cli.py`):**
   - `siem check-config [PATH]` — load config, print summary, exit non-zero on error.
   - `siem bootstrap-opensearch` — execute output bootstrap.
   - `siem run [--config PATH] [--workers N]` — orchestrate inputs, worker task group, and metrics server with graceful shutdown on SIGINT/SIGTERM.
   - `siem replay FILE --source S` — read local log file and push directly to `queue.produce()` for offline testing.

**Acceptance Criteria:**
- `siem check-config config/pipeline.yml` exits with code 0.
- `siem run` starts all configured inputs and worker threads under an `asyncio.TaskGroup`.
- Process handles `SIGINT` gracefully by draining in-flight index batches before exiting.

---

### Work Package 6: Observability, Tooling & Integration Testing
**Target Files:**
- [`src/siem/observability/metrics.py`](file:///home/shady/Projects/WeSheildSiem/src/siem/observability/metrics.py)
- `tools/loggen.py`
- `sample-data/` (`sshd.log`, `nginx-access.log`, `firewall.json`)
- `tests/test_pipeline_integration.py`

**Scope & Responsibilities:**
1. **Prometheus Metrics (`metrics.py`):**
   - Expose Prometheus endpoint on `config.metrics.port` (default `:8000`).
   - Define:
     - `siem_events_received_total` (Counter by source, transport)
     - `siem_events_parsed_total` (Counter by source)
     - `siem_events_failed_total` (Counter by stage, error_type)
     - `siem_events_indexed_total` (Counter by data_stream)
     - `siem_stream_lag` (Gauge updated via `queue.pending_count()`)
     - `siem_bulk_flush_duration_seconds` (Histogram)
2. **Log Generator Tool (`tools/loggen.py`):**
   - CLI tool accepting `--source`, `--transport {syslog-udp,syslog-tcp,http}`, `--eps <rate>`, `--file`.
   - Populate `sample-data/` with 50 realistic log lines for SSH, Nginx, and Syslog (including deliberate malformed lines to test deadlettering).
3. **End-to-End Integration Test (`tests/test_pipeline_integration.py`):**
   - Full pipeline test:
     1. Produce 20 logs (19 valid, 1 malformed).
     2. Run worker until queue drains.
     3. Verify 19 documents in OpenSearch `logs-*`.
     4. Verify 1 document in `siem-deadletter`.
     5. Re-run worker over the same data; verify count remains 19 (idempotency).

**Acceptance Criteria:**
- `curl localhost:8000/metrics` returns valid Prometheus metrics format.
- `python tools/loggen.py --source sshd --transport syslog-udp --eps 50` generates verifiable log stream.
- Integration test passes end-to-end against local docker stack.

---

## 7. Cross-Module Interface Contracts

To avoid integration mismatches between team members working on different packages, strictly adhere to these data contracts:

```
[Inputs]
   │
   ▼ RawEnvelope(raw: str, source: str, transport: str, received_at: str, host: str | None, labels: dict[str, str])
[Redis Queue: streams.py]
   │
   ▼ tuple[msg_id: str, env: RawEnvelope]
[Parsers]
   │
   ▼ dict[str, Any] (flat or dotted ECS-mapped keys, e.g. {"source.ip": "1.2.3.4"})
[Normalizer]
   │
   ▼ Event (Pydantic model, populated @timestamp, event.original, related.*)
[Enrichers]
   │
   ▼ Event (mutated in-place: geo.*, asset labels)
[Bulk Indexer]
   │
   ▼ dict[str, Any] via event.to_bulk_action(data_stream)
[OpenSearch Engine]
```

---

## 8. Developer Standards & Definition of Done

### Code Style & Type Safety
- **Python Version:** 3.12+ features (use `|` for unions, built-in generics `list[str]`, `dict[str, Any]`).
- **Async Hygiene:** Never call blocking I/O (e.g. `requests`, `time.sleep()`, synchronous `open()` in high-rate loops) inside the async event loop. Use `asyncio.sleep()`, non-blocking clients, or run in executor threads if necessary.
- **Type Annotations:** All functions and methods must have full type annotations. Run `mypy` before committing.
- **Linting:** Code must pass `ruff check` with zero warnings.

### Definition of Done for any Pull Request
1. **Target Module Implemented:** Code satisfies the module specification.
2. **Unit Tests Added:** Every new class or method has unit tests covering happy path and edge/failure cases.
3. **Existing Tests Pass:** `pytest` passes with 0 failures (minimum 147 tests passing).
4. **Linter & Typing Clean:** `ruff check .` and `mypy` return clean exits.
5. **No Silent Exceptions:** Every `try...except` either handles the error, logs at appropriate level, re-raises, or routes to dead-lettering.

---

## 9. Quick Reference & Command Cheat Sheet

### Common Development Tasks

```bash
# Start infrastructure
docker compose up -d

# Stop infrastructure
docker compose down

# Check OpenSearch cluster health
curl -s http://localhost:9200/_cluster/health | jq

# Search recent indexed events
curl -s 'http://localhost:9200/logs-*/_search?size=5&pretty'

# Search dead-lettered events
curl -s 'http://localhost:9200/siem-deadletter/_search?pretty'

# Check Redis stream depth & pending entries
redis-cli XLEN siem:raw
redis-cli XPENDING siem:raw pipeline

# Inspect Redis dead-letter stream
redis-cli XRANGE siem:deadletter - + COUNT 5

# Run a specific test module
./.venv/bin/pytest tests/test_streams.py -v

# Run all tests with short summary
./.venv/bin/pytest -q
```

---

*This document serves as the team onboarding handbook. For architectural rationale, consult [PLAN.md](PLAN.md); for the ordered build sequence, consult [BUILD_GUIDE.md](BUILD_GUIDE.md); for parser specifications, consult [parserPlanning.md](parserPlanning.md).*
