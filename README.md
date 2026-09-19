# WeShieldSIEM

**WeShieldSIEM** is a lightweight, educational Security Information and Event Management (SIEM) log ingestion, normalization, and storage engine built from scratch in Python 3.12+ using `asyncio`, Redis Streams, and OpenSearch.

---

## Purpose & Core Mission

Commercial and enterprise SIEMs (Splunk, Microsoft Sentinel, Elastic SIEM) abstract away the most critical, educationally rich, and failure-prone layer in cybersecurity operations: **the underlying data pipeline**. 

WeShieldSIEM was created to demystify and implement the core engineering principles of security data processing from first principles:
- **High-Throughput Asynchronous Ingestion:** Handling concurrent log streams across diverse network transports (Syslog UDP/TCP, file tailing, HTTP APIs) without blocking or dropping packets.
- **Resilient Buffering & Consumer Groups:** Decoupling ingestion network collectors from downstream compute and database backends using Redis Streams and consumer groups with backpressure management.
- **Strict Schema Normalization:** Unifying noisy, disparate security events into the industry-standard **Elastic Common Schema (ECS 8.11)** for consistent cross-source querying and correlation.
- **Zero Silent Log Loss:** Guaranteeing that unparseable or malformed logs are never quietly discarded; they are quarantined in a dedicated Dead-Letter Queue (DLQ) with raw payloads and error context preserved for debugging and replay.
- **At-Least-Once Processing with Idempotent Storage:** Protecting security analytics against duplicate events using deterministic SHA-256 content-hash document IDs (`_id = sha256(...)`).
- **Modern Index Lifecycle Management:** Organizing storage using OpenSearch Data Streams backed by automated Index State Management (ISM) retention policies.

---

## What the Code Does (End-to-End Pipeline)

WeShieldSIEM processes security logs through a multi-stage asynchronous pipeline:

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
         │ OpenSearch Bulk Indexer │    │ Dead-Letter Queue         │
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
                       │ • Security Panels & Analytics  │
                       └────────────────────────────────┘
```

### 1. Ingestion (Inputs Layer)
Asynchronous network and file listeners ingest raw logs from multiple sources:
- **Syslog (`src/siem/inputs/syslog.py`):** RFC 3164 (BSD syslog) and RFC 5424 over UDP and TCP.
- **File Tailer (`src/siem/inputs/filetail.py`):** Non-blocking file tailing with persisted byte offsets to survive application restarts.
- **HTTP Ingest API (`src/siem/inputs/http_api.py`):** FastAPI endpoint (`POST /ingest?source=<name>`) accepting JSON and NDJSON batches.

### 2. Buffering (Redis Streams Layer)
All inputs package incoming data into a uniform `RawEnvelope` contract (`raw`, `source`, `transport`, `host`, `received_at`, `labels`) and push it to Redis Streams (`siem:raw`). This buffers bursts, enables horizontal scaling of worker processes, and allows failed or crashed workers' jobs to be automatically reclaimed via `XAUTOCLAIM`.

### 3. Routing & Parsing (Parser Layer)
Worker consumers read batches from the `pipeline` consumer group. The router dispatches each envelope to its registered parser:
- **JSON Parser:** Direct key-path mapping.
- **Regex Parser:** Named capture groups with type coercions.
- **Grok Parser:** Pattern-based extraction wrapping `pygrok`.
- **Declarative Signatures:** Pre-configured YAML parser definitions for common security logs (e.g. OpenSSH authentication, Nginx web access, generic syslog).

### 4. Schema Normalization (ECS Layer)
Parsed dictionaries are validated and converted into typed, nested Pydantic v2 `Event` models conforming to **ECS 8.11**. Fields are standardized under common namespaces:
- `event` (kind, category, type, outcome, dataset, ingested)
- `host` (name, hostname, ip, architecture)
- `source` / `destination` (ip, port, bytes, packets, geo)
- `user` (name, domain, id)
- `http` (request.method, response.status_code)
- `log` (level, logger, syslog)

### 5. Contextual Enrichment (Enrichment Layer)
Events are enriched before storage:
- **GeoIP:** Translates public IP addresses into geographical locations (city, country, coordinates).
- **Asset Inventory:** Maps internal IPs and hostnames against known inventory metadata (criticality, department, environment).

### 6. Storage & Lifecycle (Output Layer)
- **Bulk Indexing:** Successfully processed events are serialized to bulk indexing actions targeting an OpenSearch data stream (`logs-*`).
- **Idempotency:** The OpenSearch document ID (`_id`) is computed as a SHA-256 hash of normalized event properties (`@timestamp`, `event.dataset`, `host.name`, `log.file.path`, `message`). Re-delivered messages are rejected with HTTP 409, preventing duplicate data.
- **Data Streams & Retention:** OpenSearch Data Streams partition time-series logs into backing indices managed by an Index State Management (ISM) policy (e.g., 30-day retention).

### 7. Dead-Letter Quarantine
When a log line cannot be parsed or fails schema validation, it is routed to `siem:deadletter` in Redis and indexed into `siem-deadletter` in OpenSearch. The quarantined record preserves:
- Original raw log string
- Failed processing stage (`parse` or `normalize`)
- Exact error message and traceback
- Ingestion metadata (source, transport, timestamp)

---

## Current Project Status

| Component | Module | Status | Description |
|---|---|---|---|
| **Schema & Contracts** | `src/siem/schema.py` | ✅ **Complete** | ECS 8.11 `Event` model, `RawEnvelope`, SHA-256 doc ID generator, UTC timestamp helpers, and validators. |
| **Pipeline Config** | `src/siem/config.py` | ✅ **Complete** | Pydantic v2 models validating `config/pipeline.yml` (inputs, queue, routing, enrichment, output, workers). |
| **Stream Queue Buffer** | `src/siem/queue/streams.py` | ✅ **Complete** | Async Redis Streams queue supporting `produce`, `consume`, `ack`, `reclaim` (PEL recovery), and `deadletter`. |
| **Automated Test Suite** | `tests/` | ✅ **Passing** | 147 unit tests passing across schema, config validation, and stream queues. |
| **Ingestion Inputs** | `src/siem/inputs/` | 🚧 In Development | Syslog (UDP/TCP), FileTail, and HTTP collectors. |
| **Parser Framework** | `src/siem/parsers/` | 🚧 In Development | Base parser, JSON/Regex/Grok parsers, and YAML signatures (`sshd.yml`, `nginx_access.yml`, `syslog_generic.yml`). |
| **Context Enrichment** | `src/siem/enrich/` | 🚧 In Development | MaxMind GeoIP and static asset inventory enrichers. |
| **Output Storage** | `src/siem/output/` | 🚧 In Development | OpenSearch bootstrap (templates, ISM policy), bulk indexer, and dead-letter sink. |
| **Worker & CLI** | `src/siem/pipeline/worker.py`, `src/siem/cli.py` | 🚧 In Development | Pipeline worker processing loop and Typer CLI commands (`siem run`, `siem check-config`). |

---

## Project Structure

```
WeSheildSiem/
├── config/
│   └── pipeline.yml              # Pipeline configuration (inputs, routing, output, workers)
├── templates/
│   ├── ecs-index-template.json   # OpenSearch composable template matching ECS 8.11 mappings
│   └── ism-retention-policy.json # OpenSearch Index State Management 30-day rollover/delete policy
├── src/siem/
│   ├── schema.py                 # Core data contracts (RawEnvelope, Event, ECS models, doc_id)
│   ├── config.py                 # Pydantic configuration loader & validation rules
│   ├── queue/
│   │   └── streams.py            # Redis Streams async producer, consumer groups, deadletter
│   ├── inputs/                   # Ingestion collectors (Syslog, FileTail, HTTP API)
│   ├── parsers/                  # Parsing framework (JSON, Regex, Grok, Builtin YAMLs)
│   │   └── builtin/              # Declarative log signatures (sshd, nginx, syslog)
│   ├── enrich/                   # GeoIP and asset metadata enrichment
│   ├── output/                   # OpenSearch bulk indexer, bootstrap, and deadletter sink
│   ├── pipeline/
│   │   ├── registry.py           # Log routing engine (source -> parser)
│   │   └── worker.py             # Main consumer loop (pull -> parse -> enrich -> index)
│   └── cli.py                    # Typer command-line interface (`siem`)
├── tools/
│   └── loggen.py                 # Synthetic security log generator & replayer
├── tests/
│   ├── test_schema.py            # Unit tests for ECS models, idempotency, and type coercions
│   ├── test_config.py            # Unit tests for YAML configuration validation
│   ├── test_streams.py           # Unit tests for Redis Streams queue and PEL recovery
│   └── test_parsers.py           # Parser framework test suite
├── docker-compose.yml            # Local development infrastructure (OpenSearch, Dashboards, Redis)
├── pyproject.toml                # Project metadata, dependencies, and tooling configuration
└── graphify-out/                 # Knowledge graph and architectural audits
```

---

## Quickstart & Development

### 1. Prerequisites
- Python 3.12+
- [uv](https://docs.astral.sh/uv/) (recommended package manager)
- Docker & Docker Compose

### 2. Environment Setup
```bash
# Clone the repository
git clone https://github.com/shady/WeSheildSiem.git
cd WeSheildSiem

# Install dependencies and development tools
uv sync --extra dev
```

### 3. Start Local Infrastructure
Launch single-node OpenSearch 2.13, OpenSearch Dashboards, and Redis:
```bash
docker compose up -d
```

### 4. Run the Test Suite
Verify that the core schema, configuration, and queue components pass all checks:
```bash
uv run pytest -v
```

### 5. Check Pipeline Configuration
Validate your `config/pipeline.yml`:
```bash
uv run python -c "from siem.config import load_config; print(load_config('config/pipeline.yml'))"
```

---

## Architectural & Planning References

- **[ONBOARDING.md](ONBOARDING.md):** Comprehensive developer onboarding, deep-dive code analysis of built layers, and assignable work packages.
- **[PLAN.md](PLAN.md):** Core architecture design, technical trade-offs, and technology selection rationale.
- **[BUILD_GUIDE.md](BUILD_GUIDE.md):** Step-by-step implementation roadmap for remaining components.
- **[schemaPlanning.md](schemaPlanning.md):** Detailed design and field specification for ECS 8.11 schema mapping.
- **[configPlanning.md](configPlanning.md):** Specification for pipeline configuration models.
- **[streamPlanning.md](streamPlanning.md):** Specification for Redis Streams buffer, PEL recovery, and dead-lettering.
- **[parserPlanning.md](parserPlanning.md):** Parser framework design, Grok integration, and signature definitions.
