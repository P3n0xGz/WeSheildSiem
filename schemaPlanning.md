# schemaPlanning.md — `src/siem/schema.py`

A full design + implementation plan for the first file of WeSheildSiem, plus curated
online resources. Follow this top-to-bottom; write the code yourself.

---

## 1. Purpose & scope

`schema.py` defines the **two data shapes** that flow through the whole pipeline. It has
**zero project dependencies** — every other module imports from it.

| Model | Represents | Produced by | Consumed by |
|---|---|---|---|
| `RawEnvelope` | An unparsed log line + collection metadata | `inputs/*` | `queue/streams.py`, `pipeline/worker.py` |
| `Event` | A parsed, enriched, ECS-normalized event | `pipeline/worker.py` (via parsers + enrichers) | `output/opensearch.py` |

**In scope for this file:** the models, their field definitions, serialization
(`to_doc`, `to_bulk_action`), the idempotency key (`doc_id`), a UTC timestamp helper, and
validators. **Out of scope:** parsing, enrichment, transport, I/O.

**Non-goal:** implementing the *entire* ECS. Implement the subset in §5 that the v1
parsers actually populate. `extra="allow"` lets parsers add more fields that OpenSearch
maps dynamically.

---

## 2. Key design decisions (decide these before coding)

| Decision | Recommendation | Why |
|---|---|---|
| **Nested sub-models vs. flat dotted keys** | **Nested** (`Event.source.geo.country_name`) | Mirrors `templates/ecs-index-template.json`; OpenSearch accepts nested-object JSON natively; easier validation per fieldset. `model_dump` emits nested dicts. |
| **Alias strategy** | `alias="@timestamp"` + `model_config.populate_by_name=True`; dump with `by_alias=True` | ECS uses `@timestamp` and dotted names that aren't valid Python identifiers. `populate_by_name` lets tests pass either `timestamp=` or `{"@timestamp": ...}`. |
| **Unknown fields** | `model_config.extra="allow"` on `Event` | Parsers legitimately produce ECS fields beyond our subset; OpenSearch dynamic mapping handles them. Keep `extra="forbid"` on `RawEnvelope` (its shape is fixed). |
| **ECS version pin** | Module constant `ECS_VERSION = "8.11"`, emitted as `ecs.version` | Declares which ECS the docs conform to. Bump deliberately. (Latest ECS is 9.x; 8.11 is a safe, widely-tooled baseline for the subset here.) |
| **Timestamp type** | `datetime` (timezone-aware, coerced to UTC) internally; ISO-8601 `...Z` string on the wire | ES `date` fields want ISO-8601 or epoch millis; tz-aware avoids the classic "logged in local time" bug. |
| **`doc_id` basis** | Hash of `raw` + `source` + `host` + `@timestamp` (NOT the whole normalized doc) | Stable across parser/enricher changes — reprocessing the same input yields the same id, so `_op_type: create` dedupes instead of duplicating. See §7. |
| **Ports / numeric fields** | Coerce `"22"` → `22` with validators | Regex/grok parsers yield strings; ES mapping expects `long`. |

---

## 3. Module layout

```python
# src/siem/schema.py
from __future__ import annotations
import hashlib, json
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

ECS_VERSION = "8.11"
RAW_STREAM_FIELDS = ("raw", "source", "transport", "received_at", "host", "labels")

def now_utc() -> datetime: ...
def to_utc(value: str | datetime | int | float) -> datetime: ...   # dateutil-free helper OK here
def canonical_json(obj: Any) -> str: ...                           # sort_keys, compact, str default

class RawEnvelope(BaseModel): ...
class Geo(BaseModel): ...
class Source(BaseModel): ...
class Destination(BaseModel): ...
class Host(BaseModel): ...
class User(BaseModel): ...
class EventMeta(BaseModel): ...      # the ECS `event.*` fieldset
class LogMeta(BaseModel): ...        # `log.*` incl. log.syslog.*
class Http(BaseModel): ...
class Url(BaseModel): ...
class Related(BaseModel): ...
class Observer(BaseModel): ...
class Event(BaseModel): ...
```

Keep helpers (`now_utc`, `to_utc`, `canonical_json`) at module top — they're reused by
tests and `worker.py`.

---

## 4. `RawEnvelope` — full spec

```
raw          : str                     # original line/payload, unmodified. REQUIRED.
source       : str                     # routing key: "sshd", "nginx_access", "syslog". REQUIRED.
transport    : str                     # "syslog-udp" | "syslog-tcp" | "file" | "http" | "replay". REQUIRED.
received_at  : datetime = now_utc()    # when the collector received it (UTC, tz-aware)
host         : str | None = None       # sender IP or collector hostname
labels       : dict[str, str] = {}     # free-form collector tags (e.g. {"input":"syslog-udp"})
```

- `model_config = ConfigDict(extra="forbid")` — envelope shape is fixed.
- `@field_validator("received_at")` → coerce to UTC tz-aware via `to_utc`.
- `@field_validator("source", "transport")` → `str.strip()`, reject empty.

### Redis Streams serialization (important constraint)

Redis stream entries are **flat maps of string→string**. `raw` can contain newlines and
arbitrary bytes — that's fine for a Redis field value, but `labels` (a dict) and
`received_at` (a datetime) must be encoded.

```python
def to_stream_fields(self) -> dict[str, str]:
    # every value must be str
    return {
        "raw": self.raw,
        "source": self.source,
        "transport": self.transport,
        "received_at": self.received_at.isoformat(),
        "host": self.host or "",
        "labels": json.dumps(self.labels, separators=(",", ":")),
    }

@classmethod
def from_stream_fields(cls, d: dict[str, str]) -> "RawEnvelope":
    # redis-py may hand back bytes keys/values depending on decode_responses;
    # normalize to str first (decide: set decode_responses=True in streams.py)
    return cls(
        raw=d["raw"],
        source=d["source"],
        transport=d["transport"],
        received_at=d["received_at"],
        host=d.get("host") or None,
        labels=json.loads(d.get("labels") or "{}"),
    )
```

**Edge cases to handle / test:**
- `raw` containing NUL bytes or invalid UTF-8 → decide policy (store `errors="replace"`
  at the input layer; `schema.py` assumes valid `str`).
- Empty `host` string ↔ `None` round-trip.
- `labels` with non-str values → validator should `str()` them or reject.
- Very large `raw` (multi-MB stack trace) → not schema's job to truncate, but note it.

---

## 5. `Event` — ECS subset to implement

Cross-reference every field against `templates/ecs-index-template.json` (same names/types)
and the ECS field reference (§9). Types below: **ES type** → **Python type**.

### Top level
| Field (alias) | ES type | Python | Notes |
|---|---|---|---|
| `@timestamp` | date | `datetime` | REQUIRED. tz-aware UTC. Field name `timestamp`, `alias="@timestamp"`. |
| `message` | match_only_text | `str \| None` | Human-readable summary / log body. |
| `tags` | keyword | `list[str]` = [] | Pipeline markers, e.g. `["_geoip_lookup_failure"]`. |
| `labels` | object | `dict[str, str]` = {} | Carried from envelope + asset enrichment. |
| `ecs.version` | keyword | const `ECS_VERSION` | Emit as nested `{"ecs": {"version": ...}}`. |

### `event.*` (EventMeta)
| Field | Allowed values | Notes |
|---|---|---|
| `event.kind` | see §8 | Default `"event"`. |
| `event.category` | see §8 (array) | `list[str]`. |
| `event.type` | see §8 (array) | `list[str]`. |
| `event.action` | free | e.g. `"logon-failed"`, `"http-request"`. |
| `event.outcome` | `success \| failure \| unknown` | |
| `event.dataset` | free | e.g. `"sshd.auth"`, `"nginx.access"`. |
| `event.module` | free | e.g. `"sshd"`. |
| `event.provider` | free | source system. |
| `event.severity` | long | numeric severity (from syslog etc.). |
| `event.original` | keyword (not indexed) | **= `RawEnvelope.raw`.** Always set. |
| `event.created` | date | when the pipeline built the Event. Set in `worker.py`, **excluded from `doc_id`**. |
| `event.ingested` | date | when written to OpenSearch. Set at output, **excluded from `doc_id`**. |

### `log.*` (LogMeta)
| Field | Notes |
|---|---|
| `log.level` | `"info"`, `"error"`, … (string) |
| `log.syslog.facility.code` / `.name` | from PRI |
| `log.syslog.severity.code` / `.name` | from PRI |
| `log.syslog.priority` | the raw PRI int |

### `host.*` (Host)
`host.name` (keyword), `host.hostname` (keyword), `host.ip` (`list[IPvAnyAddress]`).

### `source.*` / `destination.*` (Source / Destination)
`ip` (`IPvAnyAddress`), `port` (int), `bytes` (int), `domain` (str),
`source.geo.*` (Geo: `country_iso_code`, `country_name`, `city_name`,
`location` = `{"lat": float, "lon": float}`).

### `user.*` (User)
`user.name` (keyword), `user.id` (keyword), `user.domain` (keyword).

### `network.*`
`network.transport` (`"tcp"`/`"udp"`), `network.protocol` (`"ssh"`, `"http"`).

### `http.*` (Http) / `url.*` (Url) / `user_agent.original`
`http.request.method`, `http.request.referrer`, `http.response.status_code` (int),
`http.response.body.bytes` (int), `http.version`;
`url.original`, `url.path`, `url.query`;
`user_agent.original` (keyword).

### `related.*` (Related) — SIEM pivot fields, populate in a `model_validator`
`related.ip` (`list[IPvAnyAddress]`), `related.user` (`list[str]`),
`related.hosts` (`list[str]`). De-duplicated. See §6.

### `observer.*` (Observer)
`observer.vendor`, `observer.product`, `observer.type` — set by builtin parsers
(e.g. nginx → `{vendor: "nginx", product: "nginx", type: "web"}`).

> **Implementation tip:** every sub-model gets
> `model_config = ConfigDict(extra="allow", populate_by_name=True)` and all fields
> `Optional` with default `None`. Serialize the whole `Event` with
> `model_dump(by_alias=True, exclude_none=True)` so absent fieldsets don't emit empty
> objects.

---

## 6. Methods to implement

### `to_doc() -> dict[str, Any]`
```python
def to_doc(self) -> dict[str, Any]:
    doc = self.model_dump(by_alias=True, exclude_none=True, mode="json")
    doc.setdefault("ecs", {})["version"] = ECS_VERSION
    return doc
```
`mode="json"` makes `datetime` → ISO string, `IPvAnyAddress` → str, etc. Verify
`@timestamp` comes out as `"...Z"` or `"+00:00"` (both valid ES date input).

### `doc_id() -> str`  (idempotency key — see §7)
```python
def doc_id(self) -> str:
    basis = "\x00".join([
        self.event.original or "",             # the raw line
        self.event.dataset or self.__source_hint or "",
        (self.host.name if self.host else "") or "",
        self.timestamp.isoformat(),
    ])
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()
```
Decide where the "source" string comes from — simplest is to keep a private
`_source: str` on the Event set by `worker.py` from the envelope, or fold `source` into
`event.dataset` early. **Do not** hash `to_doc()` — parser changes would change the id.

### `to_bulk_action(data_stream: str) -> dict[str, Any]`
```python
def to_bulk_action(self, data_stream: str) -> dict[str, Any]:
    return {
        "_op_type": "create",          # 409 on duplicate _id => idempotent
        "_index": data_stream,
        "_id": self.doc_id(),
        "_source": self.to_doc(),
    }
```

### Helpers
- `now_utc()` → `datetime.now(timezone.utc)`.
- `to_utc(value)` → accepts `datetime` (assume UTC if naive, else convert),
  ISO string, or epoch seconds/millis (disambiguate by magnitude). Raise on garbage.
  (In `schema.py` keep it dependency-light; the parsers use `dateutil` for messy formats.)
- `canonical_json(obj)` → `json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)`.
  Keep it even though `doc_id` doesn't hash the doc — dead-letter records and tests use it.

---

## 7. Idempotency & the dedup key (read carefully)

**Goal:** if the same log line is delivered twice (Redis at-least-once redelivery, a worker
crash between index and ack, a `siem replay` re-run), it must land as **one** document.

**Mechanism:** deterministic `_id` + `_op_type: "create"`. On a duplicate id OpenSearch
returns HTTP 409; `output/opensearch.py` counts that as "already indexed", not an error.

**What to hash — trade-off:**

| Basis | Pro | Con |
|---|---|---|
| Whole normalized `to_doc()` | Any real content difference ⇒ new doc | Parser/enricher/GeoIP-DB change ⇒ new id ⇒ **duplicates on reprocess** |
| `raw + source + host + @timestamp` (**recommended**) | Stable across code changes; reprocessing is safe | Two *identical* lines in the same second/host collapse into one (minor undercount) |
| Include a monotonic counter / Redis msg-id | Never collapses | Not deterministic across redelivery — **breaks the whole point** |

**Pitfalls:**
- `event.created` / `event.ingested` are set *after* the Event is built — never feed them
  into `doc_id()`.
- `@timestamp` must already be normalized to UTC before hashing, or the same event parsed
  under two server timezones gets two ids.
- If `@timestamp` falls back to `received_at` (parser found no timestamp), replay at a
  later time changes the id. Mitigation: when no timestamp is parsed, hash `received_at`
  from the envelope (which is persisted in the Redis entry), not "now".

---

## 8. ECS categorization reference (embed as module constants / `Literal`s)

Use these to validate `event.kind/category/type/outcome`. Treat unknown values as a
warning (append a `tag`), not a hard failure — you don't want to dead-letter a real event
over a categorization typo.

**`event.kind`** (single value): `alert`, `asset`, `enrichment`, `event`, `metric`,
`pipeline_error`, `signal`, `state`
*(verify against the allowed-values page — this list is from ECS 8.x.)*

**`event.outcome`** (single value): `failure`, `success`, `unknown`

**`event.category`** (array) — 20 values:
`api`, `authentication`, `configuration`, `database`, `driver`, `email`, `file`, `host`,
`iam`, `intrusion_detection`, `library`, `malware`, `network`, `package`, `process`,
`registry`, `session`, `threat`, `vulnerability`, `web`

**`event.type`** (array) — 18 values:
`access`, `admin`, `allowed`, `change`, `connection`, `creation`, `deletion`, `denied`,
`device`, `end`, `error`, `group`, `indicator`, `info`, `installation`, `protocol`,
`start`, `user`

**Worked mappings for the v1 parsers:**
| Source | kind | category | type | outcome |
|---|---|---|---|---|
| sshd failed password | `event` | `[authentication]` | `[start, denied]` | `failure` |
| sshd accepted | `event` | `[authentication]` | `[start, allowed]` | `success` |
| nginx access (2xx/3xx) | `event` | `[web]` | `[access]` | `success` |
| nginx access (4xx/5xx) | `event` | `[web]` | `[access, error]` | `failure` |
| generic syslog | `event` | `[]` | `[info]` | `unknown` |

---

## 9. Validators to write (`@field_validator` / `@model_validator`)

1. **`@timestamp` → UTC tz-aware** (`mode="before"`): route through `to_utc`.
2. **IP fields**: use `pydantic.IPvAnyAddress` for `source.ip`, `destination.ip`,
   `host.ip[]`, `related.ip[]`. Invalid IP in a parsed field ⇒ drop the field + add a tag,
   don't raise (parsers occasionally mis-capture).
3. **Port / bytes / status_code**: `mode="before"` coerce `str`→`int`; non-numeric ⇒ `None` + tag.
4. **`labels` values → `str`**: coerce or reject non-string values.
5. **`model_validator(mode="after")` — populate `related.*`**:
   collect non-null `source.ip`, `destination.ip`, `host.ip` into `related.ip`;
   `user.name` into `related.user`; `host.name`/`host.hostname` into `related.hosts`;
   dedupe each list; only set if non-empty.
6. **`event.category` / `event.type` membership check**: warn-tag on unknown values.
7. **Default `event.kind="event"`** if unset.

---

## 10. Testing plan (`tests/test_schema.py` — add it now)

- `RawEnvelope` round-trips through `to_stream_fields` / `from_stream_fields` (incl.
  `host=None`, multi-line `raw`, unicode, `labels` non-empty).
- `received_at` naive datetime → becomes tz-aware UTC.
- `Event` minimal (`@timestamp` + `message`) validates; `to_doc()` has no `None`s and no
  empty sub-objects; `@timestamp` serializes to ISO-8601 with offset/Z.
- `Event.model_validate({"@timestamp": ..., "source": {"ip": "8.8.8.8"}})` **and**
  `Event(timestamp=..., ...)` both work (`populate_by_name`).
- `doc_id()` is **stable**: same inputs → same id across two constructions.
- `doc_id()` **ignores** `event.created` / `event.ingested` / enrichment fields
  (`source.geo.*`) — set them, id unchanged.
- `doc_id()` **changes** when `raw`, `source`, `host`, or `@timestamp` changes.
- `related.ip` / `related.user` auto-populated and de-duplicated.
- Port `"22"` → `22`; port `"notaport"` → `None` + tag present.
- Invalid `source.ip` `"999.1.1.1"` → field dropped, tag present, no exception.
- `to_bulk_action("logs-generic-default")` shape: `_op_type=create`, `_id=doc_id()`,
  `_source=to_doc()`.
- Unknown extra field on `Event` survives into `to_doc()` (`extra="allow"`).
- Unknown extra field on `RawEnvelope` raises (`extra="forbid"`).

Run: `uv run pytest tests/test_schema.py -q`.

---

## 11. Implementation checklist (do in this order)

- [ ] Module constants: `ECS_VERSION`, categorization tuples/`Literal`s.
- [ ] Helpers: `now_utc`, `to_utc`, `canonical_json`.
- [ ] `RawEnvelope` + validators + `to_stream_fields` / `from_stream_fields`.
- [ ] Write the `RawEnvelope` tests; make them pass.
- [ ] Leaf sub-models: `Geo`, `Related`, `Observer`, `LogMeta`, `EventMeta`, `Http`, `Url`.
- [ ] Composite sub-models: `Source`, `Destination`, `Host`, `User`.
- [ ] `Event` with all fieldsets, `model_config`, aliases.
- [ ] `Event` validators (timestamp, IPs, numeric coercion, `related.*`, categorization).
- [ ] `to_doc`, `doc_id`, `to_bulk_action`.
- [ ] Write the `Event` tests; make them pass.
- [ ] `ruff check` + `mypy src/siem/schema.py` clean.
- [ ] Commit: `feat(schema): RawEnvelope + ECS Event models`.

---

## 12. Resources

### ECS (field definitions — the source of truth for §5 and §8)
- **ECS field reference (latest)** — every fieldset, field, type, example:
  https://www.elastic.co/docs/reference/ecs/ecs-field-reference
- **ECS reference home / guide index**: https://www.elastic.co/guide/en/ecs/index.html
- **Using the categorization fields** (how kind/category/type/outcome relate):
  https://www.elastic.co/docs/reference/ecs/ecs-using-categorization-fields
- **Allowed values — `event.category`**:
  https://www.elastic.co/docs/reference/ecs/ecs-allowed-values-event-category
- **Allowed values — `event.type`**:
  https://www.elastic.co/docs/reference/ecs/ecs-allowed-values-event-type
- **Allowed values — `event.outcome`**:
  https://www.elastic.co/docs/reference/ecs/ecs-allowed-values-event-outcome
- **Allowed values — `event.kind`**: linked from the categorization reference:
  https://www.elastic.co/docs/reference/ecs/ecs-category-field-values-reference
- **ECS GitHub** (YAML field definitions you can script against, `generated/ecs/`):
  https://github.com/elastic/ecs
- **`ecs-logging-python`** (Elastic's ECS-shaped logging lib — reference for field
  naming, not a schema/validation lib): https://github.com/elastic/ecs-logging-python

### Pydantic v2 (how to build the models)
- **Models** (config, `extra`, nested models):
  https://docs.pydantic.dev/latest/concepts/models/
- **Fields** (`Field`, defaults, `alias`):
  https://docs.pydantic.dev/latest/concepts/fields/
- **Alias** (`alias` vs `validation_alias` vs `serialization_alias`, `populate_by_name`):
  https://docs.pydantic.dev/latest/concepts/alias/
- **Serialization** (`model_dump`, `by_alias`, `exclude_none`, `mode="json"`):
  https://docs.pydantic.dev/latest/concepts/serialization/
- **Validators** (`field_validator`, `model_validator`, `mode="before"/"after"`):
  https://docs.pydantic.dev/latest/concepts/validators/
- **Standard library & network types** (`IPvAnyAddress`, `datetime` handling):
  https://docs.pydantic.dev/latest/api/networks/ ·
  https://docs.pydantic.dev/latest/concepts/types/
- **`ConfigDict` API** (all `model_config` options):
  https://docs.pydantic.dev/latest/api/config/

### OpenSearch (what `to_doc` / `to_bulk_action` must produce)
- **`opensearch-py` bulk guide** (`bulk`, `streaming_bulk`, action dict format):
  https://github.com/opensearch-project/opensearch-py/blob/main/guides/bulk.md
- **`helpers/actions.py` source** (exact `_op_type` / `_id` / `_source` handling):
  https://github.com/opensearch-project/opensearch-py/blob/main/opensearchpy/helpers/actions.py
- **Bulk API reference** (`create` vs `index`, 409 on duplicate):
  https://docs.opensearch.org/latest/api-reference/document-apis/bulk/
- **Data streams** (why `create` op-type, template `data_stream: {}`):
  https://opensearch.org/docs/latest/im-plugin/data-streams/
- **Date field types** (accepted `@timestamp` formats):
  https://opensearch.org/docs/latest/field-types/supported-field-types/date/

### Syslog (fields for `log.syslog.*`, used by `syslog_generic` parser but modeled here)
- **RFC 5424 — The Syslog Protocol** (PRI, VERSION, structured data):
  https://datatracker.ietf.org/doc/html/rfc5424
- **RFC 3164 — BSD syslog** (the legacy `<PRI>TIMESTAMP HOST TAG: MSG` format):
  https://datatracker.ietf.org/doc/html/rfc3164
- **Facility / severity code tables** (RFC 5424 §6.2.1): in the RFC above; quick reference:
  https://en.wikipedia.org/wiki/Syslog#Facility · https://en.wikipedia.org/wiki/Syslog#Severity_level

### Idempotency / hashing
- `hashlib` — https://docs.python.org/3/library/hashlib.html
- Canonical JSON discussion (why `sort_keys` + fixed separators):
  https://datatracker.ietf.org/doc/html/rfc8785 (JCS — informational; we use a simpler form)

---

## 13. Open questions to resolve while coding

- **`decode_responses` in `streams.py`**: set `True` so `from_stream_fields` gets `str`,
  or handle `bytes` in the schema? → Recommend `decode_responses=True`, document it here.
- **Where does the routing `source` live on the `Event`?** Private `_source` attr vs.
  folding into `event.dataset` immediately in `worker.py`. → Recommend `event.dataset`
  set early (e.g. `"sshd.auth"`), and `doc_id` uses it.
- **Categorization enforcement**: warn-tag (recommended) vs. reject. Confirm.
- **ECS version**: stay on `8.11`, or target `9.x` and update the index template mappings
  to match? → v1 stays `8.11`.
- **`message` max length**: truncate oversized `message` in the schema, or leave it? →
  Leave for v1; revisit if mapping/İndex size becomes an issue.
