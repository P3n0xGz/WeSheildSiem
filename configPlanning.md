# configPlanning.md — src/siem/config.py

A full design + implementation plan for the second file of WeSheildSiem, plus curated online
resources. Follow this top-to-bottom; write the code yourself.

---

## 1. Purpose & scope

`config.py` defines the **typed models for `config/pipeline.yml`** and the loader that turns
it into a validated `PipelineConfig`. Every other pipeline module (queue, inputs, parsers,
enrich, output, worker, metrics, cli) is *configured by* this file but this file imports
**nothing** from them — it only depends on `pydantic` and `pyyaml`.

| Model | Represents | Produced by | Consumed by |
|---|---|---|---|
| `PipelineConfig` | The whole validated `pipeline.yml` | `load_config()` | `cli.py` (`siem run`, `siem check-config`), `worker.py` |
| `QueueConfig` | `queue:` section | `load_config()` | `queue/streams.py` |
| `OutputConfig` | `output:` section | `load_config()` | `output/opensearch.py` |
| `WorkersConfig` | `workers:` section | `load_config()` | `worker.py`, `cli.py --workers` override |
| `MetricsConfig` | `metrics:` section | `load_config()` | `metrics.py` |
| `EnrichConfig` (+ `GeoipConfig`, `AssetEntry`) | `enrich:` section | `load_config()` | `enrich/geoip.py`, `enrich/asset.py` |
| `InputConfig` union (`SyslogInputConfig` / `FileTailInputConfig` / `HttpApiInputConfig`) | one entry of `inputs:` | `load_config()` | `inputs/syslog.py`, `inputs/filetail.py`, `inputs/http_api.py` |
| `RoutingRule` (+ `MatchSpec`, `ParserSpec`) | one entry of `routing:` | `load_config()` | `parsers/registry.py` (`build_router`) |

**In scope for this file:** the models, their field definitions, `extra="forbid"`
enforcement, the `InputConfig` discriminated union, the `assets` map's dotted-key handling,
and `load_config()`. **Out of scope:** actually constructing queues/inputs/parsers/outputs
from the config (that's Steps 3–9 reading the validated objects), CLI argument parsing
(Step 9 owns the `typer` app), connectivity checks (config.py never opens a socket, a Redis
connection, or an OpenSearch client — it only validates shape).

**Non-goal:** supporting hot-reload, environment-variable interpolation inside the YAML, or
a general-purpose settings framework. `pipeline.yml` is read once at process startup;
`config.py`'s only job is to make sure that one read either produces a fully-typed,
internally-consistent `PipelineConfig` or fails loudly before any input/output is opened.

---

## 2. Key design decisions (decide these before coding)

| Decision | Recommendation | Why |
|---|---|---|
| **`BaseModel` vs `pydantic-settings` `BaseSettings`** | Plain `pydantic.BaseModel` for every model, including `PipelineConfig` | `pipeline.yml` is the single source of truth today; `BaseSettings` exists to layer env vars / secrets / multiple sources, which isn't a requirement yet. Keep `pydantic-settings` as an unused-for-now dependency (see §12). |
| **Unknown fields** | `model_config = ConfigDict(extra="forbid")` on **every** model, including `PipelineConfig` and each section/leaf model | BUILD_GUIDE says so explicitly, and it's the right call for a startup-once config: a mistyped key (`max_pendign`) must crash `siem check-config`, not silently fall back to a default. Contrast with `Event`'s `extra="allow"` in `schema.py` — that's for per-event data where losing one field is cheap; a misconfigured pipeline is not cheap. |
| **`InputConfig` shape** | `Annotated[Union[SyslogInputConfig, FileTailInputConfig, HttpApiInputConfig], Field(discriminator="type")]`, each member a `Literal["syslog"/"filetail"/"http_api"]` tag on its own `type` field | Pydantic v2's tagged-union support: validates each list item against exactly the right model (no "tried all 3, here are 15 confusing errors"), and gives mypy-strict-friendly concrete types instead of `Any`/`dict`. |
| **`assets` dotted key (`host.name`)** | `AssetEntry` model with `host_name: str = Field(alias="host.name")` + `model_config` adds `populate_by_name=True`; `assets: dict[str, AssetEntry]` keyed by a plain `str` (hostname or IP, unvalidated) | Exactly the `@timestamp` pattern already used in `schema.py` — Python identifiers can't contain dots, so alias in from YAML / attribute name in Python. The map keys themselves (`"web-01"`, `"10.0.0.5"`) are used as opaque lookup keys by `enrich/asset.py`, not validated as IPs. |
| **`RoutingRule.match` typing** | A real `MatchSpec` model (`source: str`, `extra="forbid"`), not a bare `dict[str, str]` | BUILD_GUIDE calls it `match: dict`, but every current YAML entry only ever has `source`. A typed model catches typos (`sourse: "sshd"`) at load time; a bare dict would silently accept anything. Widen `MatchSpec` (add fields) rather than loosen its type when a second match dimension is needed — see §12. |
| **`ParserSpec.type`** | `Literal["builtin", "json", "regex", "grok"]`, plus `name: str \| None = None`, plus a `model_validator(mode="after")` requiring `name` when `type == "builtin"` | Matches every current use in `pipeline.yml`: `builtin` entries always carry a `name` (`"sshd"`, `"nginx_access"`, `"syslog_generic"`); the `json` fallback never does. `regex`/`grok` don't have real config yet (Step 5 will define what they need) — don't over-design them now. |
| **Filesystem-path fields** (`enrich.geoip.database_path`, `filetail.path`, `filetail.offset_store`) | Type them as `Path`, not `str` | These are genuinely paths that Steps 4/6 will `open()`/`stat()`; `Path` is the more honest type and pydantic serializes it to a plain string in `mode="json"` dumps, so nothing downstream breaks. |
| **Network-identity fields** (`queue.url`, `output.hosts`, `*.host`) | Keep as plain `str`, **not** `RedisDsn` / `HttpUrl` / `AnyUrl` | Pydantic's URL types normalize (e.g. can append trailing slashes, reorder query params). `redis-py` and `opensearch-py` want the exact string the operator wrote; over-validating here risks silent mutation. |
| **Numeric tuning fields** (`max_pending`, `bulk_max_actions`, `bulk_flush_interval_seconds`, `retry_max_attempts`, `workers.count`, all `port`s) | `Field(gt=0)` (ports additionally `lt=65536`) | Declarative range constraints catch nonsensical `0`/negative tuning values or out-of-range ports at load time instead of at a confusing runtime failure three modules downstream. |
| **`bulk_flush_interval_seconds` numeric type** | `float`, even though the YAML currently has an int (`2`) | Pydantic coerces `2` → `2.0` for free; using `float` up front avoids a breaking model change the day someone writes `1.5`. |
| **Validation error surfacing** | `load_config()` lets `pydantic.ValidationError` propagate unmodified; no custom exception wrapper in `config.py` | Keeps `config.py` dependency-free of any CLI/formatting concerns and trivially testable with `pytest.raises(ValidationError)`. Step 9's `siem check-config` is where a human-friendly `for err in e.errors(): ...` printer belongs. |
| **DRY `extra="forbid"`** | A tiny `_StrictModel(BaseModel)` base with `model_config = ConfigDict(extra="forbid")`; every model subclasses it (pydantic v2 merges child `model_config` into the parent's, so `AssetEntry` only needs to add `populate_by_name=True`) | Avoids repeating `ConfigDict(extra="forbid")` on a dozen classes and avoids someone forgetting it on a new model later. |

---

## 3. Module layout

```python
# src/siem/config.py
from __future__ import annotations

from pathlib import Path
from typing import Annotated, Literal, Union

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

INPUT_TYPES = ("syslog", "filetail", "http_api")
PARSER_TYPES = ("builtin", "json", "regex", "grok")
SYSLOG_PROTOCOLS = ("udp", "tcp")


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class QueueConfig(_StrictModel): ...
class OutputConfig(_StrictModel): ...
class WorkersConfig(_StrictModel): ...
class MetricsConfig(_StrictModel): ...

class GeoipConfig(_StrictModel): ...
class AssetEntry(_StrictModel): ...
class EnrichConfig(_StrictModel): ...

class BaseInputConfig(_StrictModel): ...
class SyslogInputConfig(BaseInputConfig): ...
class FileTailInputConfig(BaseInputConfig): ...
class HttpApiInputConfig(BaseInputConfig): ...
InputConfig = Annotated[
    Union[SyslogInputConfig, FileTailInputConfig, HttpApiInputConfig],
    Field(discriminator="type"),
]

class MatchSpec(_StrictModel): ...
class ParserSpec(_StrictModel): ...
class RoutingRule(_StrictModel): ...

class PipelineConfig(_StrictModel): ...


def load_config(path: str | Path) -> PipelineConfig: ...
```

Keep the input-variant classes and the `InputConfig` union defined top-to-bottom right above
`RoutingRule`/`PipelineConfig` — no forward refs are needed, and `from __future__ import
annotations` plus this ordering is what keeps `mypy --strict` happy with the discriminated
union.

---

## 4. Deep-dive specs

### `QueueConfig`
| Field | Type | Notes |
|---|---|---|
| `url` | `str` | Redis DSN, e.g. `"redis://localhost:6379/0"`. REQUIRED, plain str (see §2). |
| `raw_stream` | `str` | REQUIRED. |
| `deadletter_stream` | `str` | REQUIRED. |
| `consumer_group` | `str` | REQUIRED. |
| `max_pending` | `int = Field(gt=0)` | Backpressure threshold consumed by `queue/streams.py`. |

`model_config` inherited (`extra="forbid"`) from `_StrictModel`.

### `OutputConfig`
| Field | Type | Notes |
|---|---|---|
| `hosts` | `list[str] = Field(min_length=1)` | Raw OpenSearch base URLs, not `HttpUrl` (see §2). |
| `data_stream` | `str` | REQUIRED. |
| `deadletter_index` | `str` | REQUIRED. |
| `bulk_max_actions` | `int = Field(gt=0)` | |
| `bulk_flush_interval_seconds` | `float = Field(gt=0)` | Accepts YAML's `2` as `2.0`. |
| `retry_max_attempts` | `int = Field(ge=0)` | `0` is a legal ("no retries") value, hence `ge` not `gt`. |

### `WorkersConfig`
`count: int = Field(gt=0)` — the only field. `siem run --workers N` (Step 9) overrides this
at the CLI layer; `config.py` doesn't need to know about that override.

### `MetricsConfig`
`host: str`, `port: int = Field(gt=0, lt=65536)`.

### `EnrichConfig`, `GeoipConfig`, `AssetEntry`

```python
class GeoipConfig(_StrictModel):
    enabled: bool = False
    database_path: Path


class AssetEntry(_StrictModel):
    model_config = ConfigDict(populate_by_name=True)  # merges with _StrictModel's extra="forbid"

    host_name: str = Field(alias="host.name")
    labels: dict[str, str] = Field(default_factory=dict)


class EnrichConfig(_StrictModel):
    geoip: GeoipConfig
    assets: dict[str, AssetEntry] = Field(default_factory=dict)
```

#### The `host.name` dotted key (read this before coding)

`assets` in the YAML is a map keyed by arbitrary strings (`"web-01"`, `"10.0.0.5"`), and each
*value* is itself an object with a literal dot in one of its keys:

```yaml
"web-01":
  host.name: "web-01.corp.local"
  labels: { env: "prod", role: "web" }
```

`host.name` cannot be a Python attribute name, so `AssetEntry.host_name` carries
`Field(alias="host.name")`. Because `model_config.populate_by_name=True` is also set,
`AssetEntry(host_name="web-01.corp.local", labels={})` works too (handy in tests). Dumping
with `model_dump(by_alias=True)` re-emits `"host.name"` — always dump `AssetEntry`/`EnrichConfig`
with `by_alias=True` if you ever need to round-trip it back to YAML-shaped data.

Do **not** model `assets` as `dict[str, AssetEntry]` with a *validated* key type (e.g. trying
to enforce "key is an IP or a hostname") — `enrich/asset.py` looks keys up as opaque strings
against whatever `event.host.name` or `source.ip` string it has; adding format validation
here only creates false rejections.

**Edge cases to handle / test:**
- `assets: {}` (no assets configured) must validate — it's not in the current YAML but should
  be legal.
- An asset entry missing `labels` should default to `{}`, not error.
- An asset entry using `host_name` (Python name) instead of `host.name` (YAML alias) should
  also validate, given `populate_by_name=True`.
- `geoip.enabled: true` with a `database_path` that doesn't exist on disk must **still
  validate** — see §6, filesystem existence is explicitly not this file's job.

### `InputConfig` discriminated union

```python
class BaseInputConfig(_StrictModel):
    name: str


class SyslogInputConfig(BaseInputConfig):
    type: Literal["syslog"]
    protocol: Literal["udp", "tcp"]
    host: str
    port: int = Field(gt=0, lt=65536)
    default_source: str | None = None


class FileTailInputConfig(BaseInputConfig):
    type: Literal["filetail"]
    path: Path
    source: str
    offset_store: Path


class HttpApiInputConfig(BaseInputConfig):
    type: Literal["http_api"]
    host: str
    port: int = Field(gt=0, lt=65536)


InputConfig = Annotated[
    Union[SyslogInputConfig, FileTailInputConfig, HttpApiInputConfig],
    Field(discriminator="type"),
]
```

`BaseInputConfig` isn't part of the `Union` itself (it's not concrete/taggable on its own) —
only the three tagged subclasses are, which is exactly the supported pydantic v2 pattern for
mixing shared fields (`name`) into a discriminated union.

**Edge cases to handle / test:**
- `type: "kafka"` (or any value outside `INPUT_TYPES`) must raise a `ValidationError` whose
  message names the bad tag and the valid ones — this is the main payoff of using
  `discriminator="type"` instead of a bare `Union` (which instead produces one confusing
  error per union member tried).
- An input entry with no `type` key at all → error (discriminator field itself is required).
- `syslog-tcp`'s missing `default_source` (present in the real YAML) must validate with
  `default_source is None`, not error.
- `filetail.path` / `filetail.offset_store` as `Path` must still accept the plain YAML
  strings (`"/var/log/nginx/access.log"`, `".state/nginx-access.offset"`) — pydantic coerces
  `str` → `Path` automatically.

### `RoutingRule` (`MatchSpec` + `ParserSpec`)

```python
class MatchSpec(_StrictModel):
    source: str


class ParserSpec(_StrictModel):
    type: Literal["builtin", "json", "regex", "grok"]
    name: str | None = None

    @model_validator(mode="after")
    def _builtin_requires_name(self) -> "ParserSpec":
        if self.type == "builtin" and not self.name:
            raise ValueError("parser.name is required when parser.type == 'builtin'")
        return self


class RoutingRule(_StrictModel):
    match: MatchSpec
    parser: ParserSpec
```

The `{"source": "*"}` wildcard is **not** special-cased in `config.py` — it's stored as an
ordinary `MatchSpec(source="*")`; matching `"*"` against an incoming event's source is
`parsers/registry.py`'s (Step 5) job at dispatch time, not a config-loading concern.

**Edge cases to handle / test:**
- `parser: {type: json}` (no `name`) validates.
- `parser: {type: builtin}` (no `name`) raises.
- `parser: {type: builtin, name: "sshd"}` validates.

### `PipelineConfig`

```python
class PipelineConfig(_StrictModel):
    queue: QueueConfig
    output: OutputConfig
    workers: WorkersConfig
    metrics: MetricsConfig
    enrich: EnrichConfig
    inputs: list[InputConfig] = Field(min_length=1)
    routing: list[RoutingRule] = Field(min_length=1)

    @model_validator(mode="after")
    def _routing_has_wildcard_fallback(self) -> "PipelineConfig":
        if not any(rule.match.source == "*" for rule in self.routing):
            raise ValueError('routing must include a wildcard fallback rule: {"source": "*"}')
        return self

    @model_validator(mode="after")
    def _input_names_are_unique(self) -> "PipelineConfig":
        names = [i.name for i in self.inputs]
        if len(names) != len(set(names)):
            raise ValueError(f"input names must be unique, got: {names}")
        return self
```

**Edge cases to handle / test:**
- A `routing` list with no `{"source": "*"}` entry must raise, even if every named source is
  otherwise covered — an unmatched-at-runtime event has nowhere to go.
- Two inputs both named `"syslog-udp"` must raise (would otherwise be indistinguishable in
  logs/metrics).

---

## 5. Methods to implement

### `load_config`

```python
def load_config(path: str | Path) -> PipelineConfig:
    text = Path(path).read_text(encoding="utf-8")
    raw = yaml.safe_load(text)
    if raw is None:
        raise ValueError(f"config file is empty: {path}")
    return PipelineConfig.model_validate(raw)
```

Tricky open decisions:
- **`yaml.safe_load`, never `yaml.load`** with the default `Loader` — the default loader can
  instantiate arbitrary Python objects from `!!python/object:...` tags, which is a real
  deserialization-of-untrusted-input risk even for a config file an operator controls.
- **Path-not-found and empty-file behavior**: let `Path.read_text()` raise its natural
  `FileNotFoundError` (don't catch and rewrap it — it's already clear); explicitly guard the
  "YAML parses to `None`" case (e.g. an empty or all-comments file) with a clear `ValueError`
  instead of letting `PipelineConfig.model_validate(None)` produce a confusing pydantic error
  about the top level not being a mapping.
- **Accept a pre-parsed dict too?** Recommend **no** — keep `load_config` single-purpose
  (file I/O + parse + validate). Unit tests that only care about model behavior should call
  `PipelineConfig.model_validate(some_dict)` directly; reserve `load_config(path)` for
  file-level tests (real YAML text via `tmp_path`, syntax errors, missing files).
- **Should this function catch `pydantic.ValidationError` and reformat it?** No — see §2 and
  §12; let it propagate raw, format it in `cli.py`.

---

## 6. Fail-fast validation and clear error messages (why this matters)

**Goal:** a broken or typo'd `pipeline.yml` must never let the process start half-configured.
Redis, OpenSearch, and every input socket are opened *after* `load_config()` succeeds — if
validation is loose, the failure mode becomes a mysterious crash (or worse, silent data loss)
minutes or hours into running, instead of an immediate, readable error at `siem check-config`
or `siem run` time.

**Mechanism:** `extra="forbid"` on every model (typos and stray keys are rejected, not
ignored), no silent defaults on required operational fields, the `InputConfig` discriminated
union (a bad `type` produces one precise error instead of a wall of per-branch Union noise),
and two `PipelineConfig`-level `model_validator`s that encode business rules types alone can't
express (a wildcard routing fallback must exist; input names must be unique). Pydantic
aggregates *all* violations found in a single `model_validate()` call into one
`ValidationError`, so an operator sees every problem in the file at once, not one-at-a-time
across repeated retries.

**What to enforce — trade-off:**

| Approach | Pro | Con |
|---|---|---|
| `extra="forbid"` everywhere (**recommended**) | Typos/renamed keys caught immediately at startup | Every new YAML key needs a matching model field — slightly more maintenance |
| `extra="allow"` (schema.py's `Event` philosophy) | Forward/backward compatible with newer YAML without code changes | A misspelled `max_pendign` silently vanishes; the process starts with a wrong/default value and fails cryptically deep inside a worker — the opposite of what a one-time startup config should do |
| `extra="ignore"` | Never errors on unknown keys | Strictly worse than `allow` — it hides operator typos with *zero* signal at all |

**Pitfalls:**
- **Don't reuse `schema.py`'s "warn-tag, don't reject" philosophy here.** That's correct for
  per-event data, where dropping one malformed field from one log line is an acceptable
  trade-off against a dead-lettered pipeline. Config is loaded once; there is no analogous
  "just skip this one bad section and keep going."
- **Discriminated unions only pay off if you actually set the discriminator.** A bare
  `Union[SyslogInputConfig, FileTailInputConfig, HttpApiInputConfig]` without
  `Field(discriminator="type")` still validates, but a bad `type: "kafka"` produces three
  separate "field required" errors (one per model pydantic tried), not one clear "unknown
  input type" error.
- **YAML quoting quirks.** `port: "514"` (quoted) must still coerce to `int` — pydantic v2's
  non-strict mode does this by default, but it's worth an explicit test since operators
  sometimes quote numeric-looking values out of habit.
- **`bulk_flush_interval_seconds` as `int` would silently truncate** a future `1.5` to `1` —
  use `float` from the start (see §2).
- **Don't add a `database_path` existence check inside `GeoipConfig`.** That would make
  `load_config()` — and therefore `siem check-config` in CI, before any real `.mmdb` file is
  fetched — fail even when `enabled: false`. Filesystem/reachability checks belong at
  *runtime*, gated on the relevant `enabled`/feature flag, inside the module that actually
  uses the resource (`enrich/geoip.py`), not in `config.py`.

---

## 7. Closed vocabularies (module constants)

Unlike ECS's `event.category`/`event.type` (an external, versioned spec with hundreds of
allowed values — see `schemaPlanning.md` §8), the vocabularies here are entirely **internal**:
they're just the set of input/parser engines this project has implemented. Keep them as the
single source of truth so adding a new engine is an explicit, greppable two-step (add the
pydantic model *and* add its tag here), not an accidental typo that slips past validation.

```python
INPUT_TYPES = ("syslog", "filetail", "http_api")       # SyslogInputConfig / FileTailInputConfig / HttpApiInputConfig
PARSER_TYPES = ("builtin", "json", "regex", "grok")     # ParserSpec.type
SYSLOG_PROTOCOLS = ("udp", "tcp")                       # SyslogInputConfig.protocol
```

These tuples are documentation/reference constants; the actual enforcement is the `Literal[...]`
type on each field (Pydantic validates against the `Literal`, not against the tuple — keep
them in sync manually, there's no need for a `Literal[*INPUT_TYPES]` trick that fights mypy).

---

## 8. Validators to write

1. **`PipelineConfig` — `@model_validator(mode="after")`, wildcard fallback required**: at
   least one `routing` entry must have `match.source == "*"`. Rationale: without a fallback,
   `parsers/registry.py` has no safe default at dispatch time and an unmatched source would
   have to be a runtime error per-event instead of a load-time error once.
2. **`PipelineConfig` — `@model_validator(mode="after")`, unique input names**: `inputs[*].name`
   values must be distinct. Rationale: names are the only human-readable handle for
   distinguishing inputs in logs/metrics; duplicates make troubleshooting impossible.
3. **`ParserSpec` — `@model_validator(mode="after")`, builtin requires name**: `type ==
   "builtin"` implies `name is not None`. Rationale: `registry.py`'s builtin dispatch is a
   name → callable lookup; a nameless builtin entry can never resolve to a parser.
4. **Port fields** (`SyslogInputConfig.port`, `HttpApiInputConfig.port`, `MetricsConfig.port`)
   — declarative `Field(gt=0, lt=65536)`, not a custom validator; rejects out-of-range ports
   with a standard pydantic message.
5. **Numeric tuning fields** (`max_pending`, `bulk_max_actions`, `bulk_flush_interval_seconds`,
   `workers.count`) — `Field(gt=0)`; `retry_max_attempts` — `Field(ge=0)` (zero retries is
   legal). Rationale: reject nonsensical zero/negative operational tuning at load time.
6. **`AssetEntry` dotted key** — no custom validator needed; the `Field(alias="host.name")` +
   `populate_by_name=True` combination handles it declaratively (see §4). Explicitly *not*
   writing a validator here is itself the decision worth documenting.
7. **`GeoipConfig.database_path`** — explicitly **no** existence-check validator (see §6);
   this bullet exists so a future contributor doesn't "helpfully" add one.

---

## 9. Testing plan (`tests/test_config.py` — add it now)

- `load_config()` loads the real, checked-in `config/pipeline.yml` end-to-end without
  raising, and spot-checks a few values (`queue.url`, `workers.count == 4`,
  `output.bulk_max_actions == 500`) — ties `config.py` directly to the reference file so a
  model change that breaks the real config is caught immediately.
- Missing a required top-level section (delete `workers:`) raises `ValidationError`.
- An unknown top-level key raises `ValidationError` (`extra="forbid"` on `PipelineConfig`).
- An unknown key nested inside a known section (e.g. `queue: {..., bogus_key: 1}`) raises
  `ValidationError`.
- Each of the three `inputs` entries in the real YAML parses into the correct concrete class
  (`isinstance`/`type(x) is SyslogInputConfig`, etc.).
- The `syslog-tcp` entry (no `default_source` in the YAML) validates with
  `default_source is None`.
- An input with `type: "kafka"` raises `ValidationError` naming the bad tag.
- An input entry with no `type` key raises `ValidationError`.
- `AssetEntry` round-trips the dotted key: constructing from
  `{"host.name": "web-01.corp.local", "labels": {...}}` populates `.host_name`; constructing
  via `AssetEntry(host_name=..., labels=...)` also works (`populate_by_name`); dumping with
  `model_dump(by_alias=True)` re-emits `"host.name"`.
- `EnrichConfig.assets` accepts `{}` (no assets configured).
- `ParserSpec(type="builtin")` with no `name` raises; `ParserSpec(type="json")` with no `name`
  is valid.
- A `routing` list with no `{"source": "*"}` entry raises (`PipelineConfig`-level validator).
- Two inputs with the same `name` raises.
- `bulk_flush_interval_seconds` accepts YAML's int `2` and stores/dumps it as `2.0`.
- A quoted numeric string port (`port: "514"`) still coerces to `int`.
- Port `0` and port `70000` are both rejected.
- `load_config()` on a nonexistent path raises `FileNotFoundError`.
- `load_config()` on an empty (or comments-only) YAML file raises a clear `ValueError`, not a
  confusing `AttributeError`/pydantic error about `None`.
- Round trip: `PipelineConfig.model_validate(raw_dict)` then `.model_dump(by_alias=True)` then
  re-`model_validate()` produces an equal model (idempotent load).

Run: `uv run pytest tests/test_config.py -q`.

---

## 10. Implementation checklist (do in this order)

- [ ] Module constants: `INPUT_TYPES`, `PARSER_TYPES`, `SYSLOG_PROTOCOLS`.
- [ ] `_StrictModel` base (`extra="forbid"`).
- [ ] Leaf config models: `QueueConfig`, `OutputConfig`, `WorkersConfig`, `MetricsConfig`.
- [ ] `GeoipConfig`, `AssetEntry` (alias + `populate_by_name`), `EnrichConfig`.
- [ ] `BaseInputConfig` + `SyslogInputConfig`, `FileTailInputConfig`, `HttpApiInputConfig`;
      the `InputConfig` discriminated union.
- [ ] `MatchSpec`, `ParserSpec` (+ builtin-requires-name validator), `RoutingRule`.
- [ ] `PipelineConfig` (+ wildcard-fallback validator, + unique-input-name validator).
- [ ] `load_config(path)`.
- [ ] Write `tests/test_config.py` against both synthetic dicts and the real
      `config/pipeline.yml`; make them pass.
- [ ] `ruff check src/siem/config.py` + `mypy --strict src/siem/config.py` clean — pay
      particular attention to the discriminated union and the `Field(alias=...)` on
      `AssetEntry` under the pydantic mypy plugin.
- [ ] Confirm `config.py` has zero imports from any other `siem.*` submodule.
- [ ] Commit: `feat(config): pydantic models + loader for pipeline.yml`.

---

## 11. Resources

### Pydantic v2 — discriminated unions
- **Discriminated unions** (`Field(discriminator=...)`, tagged unions):
  https://docs.pydantic.dev/latest/concepts/unions/#discriminated-unions
- **Models** (`ConfigDict`, `extra`, nested models, config inheritance/merging):
  https://docs.pydantic.dev/latest/concepts/models/
- **Fields** (`Field()`, numeric constraints `gt`/`lt`/`ge`/`le`, `min_length`):
  https://docs.pydantic.dev/latest/concepts/fields/
- **Alias** (`alias` vs `validation_alias`, `populate_by_name`):
  https://docs.pydantic.dev/latest/concepts/alias/
- **Validators** (`model_validator`, `mode="after"`):
  https://docs.pydantic.dev/latest/concepts/validators/
- **`ConfigDict` API** (all `model_config` options):
  https://docs.pydantic.dev/latest/api/config/
- **Mypy plugin** (strict-mode compatibility, required for `[tool.mypy] strict = true`):
  https://docs.pydantic.dev/latest/integrations/mypy/

### PyYAML
- **PyYAML documentation** (`safe_load` vs `load`, `Loader` classes):
  https://pyyaml.org/wiki/PyYAMLDocumentation
- **Why `safe_load`** (arbitrary-object deserialization risk of the default `Loader`):
  https://pyyaml.org/wiki/PyYAMLDocumentation#loading-yaml

### pydantic-settings (evaluate, likely deferred — see §12)
- **pydantic-settings overview** (env var + file source layering):
  https://docs.pydantic.dev/latest/concepts/pydantic_settings/
- **YAML config source** (if env-var overrides of `pipeline.yml` are ever wanted):
  https://docs.pydantic.dev/latest/concepts/pydantic_settings/#other-settings-source

### Typer (consumer, Step 9)
- **Typer docs home**: https://typer.tiangolo.com/
- **Handling exceptions / exit codes** (for formatting `ValidationError` in `check-config`):
  https://typer.tiangolo.com/tutorial/exceptions/

---

## 12. Open questions to resolve while coding

- **`pydantic-settings` vs plain `BaseModel`?** → Recommend plain `BaseModel` +
  `PipelineConfig` for v1. `pydantic-settings` stays an unused dependency until there's a real
  need for env-var overrides (e.g. `SIEM_QUEUE__URL` in a containerized deploy) — revisit then,
  not preemptively.
- **How to type the `assets` map given the dotted `"host.name"` key?** → Recommend
  `AssetEntry.host_name: str = Field(alias="host.name")` + `ConfigDict(populate_by_name=True)`
  (merged onto `_StrictModel`'s `extra="forbid"`); `assets: dict[str, AssetEntry]` keyed by a
  plain, unvalidated `str`.
- **Should `RoutingRule.match` support more than exact `source` equality later (glob, regex,
  additional match keys)?** → Recommend keeping `MatchSpec` as just `source: str` for v1 (it
  covers every current YAML use, including the literal `"*"` wildcard string, which
  `parsers/registry.py` interprets, not `config.py`). When a second match dimension is
  needed, extend `MatchSpec` with an additional optional field rather than loosening it to a
  bare `dict[str, str]`, to keep typo-catching.
- **Should config validation errors be user-friendly-formatted or the raw pydantic
  `ValidationError`?** → Recommend `load_config()` re-raises the raw `ValidationError`
  unmodified; `cli.py`'s `siem check-config` (Step 9) is the right place to iterate
  `e.errors()` and pretty-print, keeping `config.py` free of CLI/formatting concerns and easy
  to unit test with `pytest.raises`.
- **Should `load_config` also accept an already-parsed `dict` (for tests)?** → Recommend no;
  reserve `load_config(path)` for file-level tests (real YAML text, syntax errors, missing
  files) and have unit tests call `PipelineConfig.model_validate(dict)` directly.
- **Should `GeoipConfig` validate that `database_path` exists on disk?** → Recommend no (see
  §6/§8); existence checks belong in `enrich/geoip.py` at runtime, gated on `enabled`, so
  `check-config`/tests don't require a real `.mmdb` file to be present.
- **`bulk_flush_interval_seconds`: `int` or `float`?** → Recommend `float` (accepts today's
  YAML `2` as `2.0`; allows `1.5` later with no breaking model change).
- **Should `ParserSpec` eventually become its own discriminated union (like `InputConfig`),
  once `regex`/`grok` need type-specific fields such as a pattern string?** → Recommend not
  yet: v1 `pipeline.yml` only exercises `builtin` and `json`. Keep `ParserSpec` a single flat
  model with optional `name` (plus the builtin-requires-name validator) until Step 5 defines
  what `regex`/`grok` actually need, then convert to a discriminated union at that point.
