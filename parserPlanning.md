# parserPlanning.md — src/siem/parsers/ & src/siem/pipeline/registry.py

A complete architectural and implementation plan for the fifth component of WeSheildSiem: the **Parser Framework & Event Normalization Layer**. Follow this guide top-to-bottom to build high-performance, declarative, and extensible parsers that turn unstructured log lines into structured Elastic Common Schema (ECS) events.

---

## 1. Purpose & Scope

The parser framework sits directly between the Redis queue buffer (`siem:raw`) and the worker/output pipeline. Its sole responsibility is transforming raw, unparsed log strings (`RawEnvelope.raw`) into structured dictionaries adhering to the Elastic Common Schema (ECS), which are then converted into typed [`Event`](file:///home/shady/Projects/WeSheildSiem/src/siem/schema.py#L294) instances.

```
                    ┌─────────────────────────┐
                    │ Redis Stream: siem:raw  │
                    └────────────┬────────────┘
                                 │ consume() -> (msg_id, RawEnvelope)
                                 ▼
                     Worker Consumer Process
                                 │
                 ┌───────────────┴───────────────┐
                 │ Router.parser_for(env.source) │
                 └───────────────┬───────────────┘
                                 │
          ┌──────────────────────┼──────────────────────┐
          ▼                      ▼                      ▼
    JsonParser              RegexParser             GrokParser
(native JSON / APIs)     (high throughput)      (complex logs / SSH / Syslog)
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │ dict[str, Any] (ECS-mapped fields)
                                 ▼
                    normalize(parsed, envelope)
                 • Unflatten dotted keys (`source.ip` -> nested)
                 • Parse timestamps to UTC datetime (@timestamp)
                 • Populate event.original, host, labels, kind
                 • Validate via Event.model_validate()
                                 │
                ┌────────────────┴────────────────┐
                │                                 │
           [Success]                         [ParseError]
                ▼                                 ▼
     OpenSearch Bulk Indexer             Dead-letter Stream
        (data stream logs-*)              (siem:deadletter)
```

### Module Responsibilities

| Module | Purpose | Depends On |
|---|---|---|
| `src/siem/parsers/base.py` | `Parser` abstract base class and `ParseError` exception | None |
| `src/siem/parsers/json_parser.py` | Native JSON parser with automatic ECS timestamp/message key mapping | `base.py` |
| `src/siem/parsers/regex_parser.py` | High-throughput regex parser supporting named groups, field mapping, and type coercion | `base.py`, `regex` / `re` |
| `src/siem/parsers/grok_parser.py` | Pattern-matching parser wrapping `pygrok.Grok` with multi-pattern fallback | `base.py`, `pygrok` |
| `src/siem/parsers/builtin/*.yml` | Declarative YAML definitions for common log sources (`sshd.yml`, `nginx_access.yml`, `syslog_generic.yml`) | None |
| `src/siem/parsers/builtin/__init__.py` | Builtin parser loader (`load_builtin(name)`) compiling YAML into configured parser instances | `pyyaml`, `regex_parser.py`, `grok_parser.py` |
| `src/siem/parsers/normalizer.py` | Post-parse normalization: unflattening dotted keys, robust timestamp parsing, and `Event` instantiation | `schema.py`, `python-dateutil` |
| `src/siem/pipeline/registry.py` | `Router` implementation matching `RawEnvelope.source` against `config.routing` rules with wildcard fallback | `config.py`, all parsers |

---

## 2. Key Design Decisions

| Decision | Recommendation | Rationale |
|---|---|---|
| **Separation of Extraction vs Normalization** | Two distinct steps: Parsers extract key-values; `normalize()` creates `Event` | Keeps parsers fast, simple, and testable without Pydantic overhead. Parsers output `dict[str, Any]`; `normalize()` handles date parsing, key nesting, and validation. |
| **Exception on Mismatch** | Raise `ParseError` on unparseable lines (never return `None` or `{}`) | In a SIEM pipeline, silent failures cause undetected data loss. A raised `ParseError` is caught by the worker and routed directly to the dead-letter queue (`siem:deadletter`). |
| **Multi-Pattern Fallback** | Parsers evaluate a sequence of candidate patterns in order | Services emit varying line formats for the same source (e.g., SSH password failures vs. accepted public keys vs. disconnects). First matching pattern wins. |
| **Declarative YAML Specs** | Store parser definitions in YAML files under `parsers/builtin/` | Security engineers can add or modify log parsers without touching Python code. Patterns, field mappings, and static categories remain data-driven. |
| **Dotted-Key Output & Recursive Unflattening** | Parsers emit flat dotted keys (`source.ip: "10.0.0.1"`); a helper unflattens to nested dicts | Named regex capture groups and Grok patterns cannot emit nested dictionaries. Unflattening before `Event.model_validate()` satisfies Pydantic nested models. |
| **Timestamp Ingestion & UTC Guarantee** | Support format lists with fallback to `dateutil.parser.parse`, always converted to UTC | Logs arrive in ISO 8601, RFC 3339, or legacy syslog (RFC 3164) lacking years. Normalizer handles the missing-year boundary condition safely. |
| **Router Caching** | Instantiate each parser once and cache by rule / source | Compiling regexes and Grok patterns per message kills throughput. Parsers are stateless and thread/coroutine-safe; compile once at router build time. |

---

## 3. Module Specifications & Interfaces

### 3.1 Base Parser & Exceptions (`src/siem/parsers/base.py`)

```python
# src/siem/parsers/base.py
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any

class ParseError(Exception):
    """Raised when a parser fails to match or parse the raw log line."""
    def __init__(self, message: str, raw: str = "", parser_name: str = "") -> None:
        super().__init__(message)
        self.message = message
        self.raw = raw
        self.parser_name = parser_name

    def __str__(self) -> str:
        prefix = f"[{self.parser_name}] " if self.parser_name else ""
        return f"{prefix}{self.message}: {self.raw[:100]!r}"

class Parser(ABC):
    """Abstract interface for all log parsers."""
    name: str = "base"

    @abstractmethod
    def parse(self, raw: str) -> dict[str, Any]:
        """Parse raw log text into a dictionary of fields.
        
        Raises:
            ParseError: If the raw payload cannot be parsed or matched.
        """
        ...
```

---

### 3.2 JSON Parser (`src/siem/parsers/json_parser.py`)

Handles structured JSON logs (e.g., firewall logs, Kubernetes logs, application JSON streams).

#### Specification
- Parse `raw` with `json.loads`. Raise `ParseError` on `json.JSONDecodeError` or if root is not a dictionary.
- Map common timestamp aliases (`timestamp`, `time`, `ts`, `@timestamp`) to `@timestamp`.
- Map common message aliases (`message`, `msg`, `log`) to `message`.
- Support optional `field_map: dict[str, str]` to rename fields.
- Retain unknown extra fields so they land in OpenSearch dynamic mappings.

```python
# src/siem/parsers/json_parser.py
from __future__ import annotations
import json
from typing import Any
from siem.parsers.base import Parser, ParseError

class JsonParser(Parser):
    name = "json"

    def __init__(
        self,
        field_map: dict[str, str] | None = None,
        static_fields: dict[str, Any] | None = None,
    ) -> None:
        self.field_map = field_map or {}
        self.static_fields = static_fields or {}

    def parse(self, raw: str) -> dict[str, Any]:
        try:
            data = json.loads(raw)
        except Exception as exc:
            raise ParseError(f"Malformed JSON: {exc}", raw=raw, parser_name=self.name) from exc

        if not isinstance(data, dict):
            raise ParseError("JSON root must be an object/dict", raw=raw, parser_name=self.name)

        result: dict[str, Any] = {}
        for k, v in data.items():
            target_key = self.field_map.get(k, k)
            result[target_key] = v

        # Normalize common timestamp keys to @timestamp if not set
        if "@timestamp" not in result:
            for ts_key in ("timestamp", "time", "ts", "datetime"):
                if ts_key in result:
                    result["@timestamp"] = result.pop(ts_key)
                    break

        # Normalize common message keys to message if not set
        if "message" not in result:
            for msg_key in ("msg", "log", "body"):
                if msg_key in result:
                    result["message"] = result.pop(msg_key)
                    break

        if self.static_fields:
            result.update(self.static_fields)

        return result
```

---

### 3.3 Regex Parser (`src/siem/parsers/regex_parser.py`)

High-performance parser for formats with fixed, known patterns using named capture groups.

#### Specification
- Accepts `patterns: list[str]`. Compiles with `re.compile()` or `regex.compile()`.
- Iterates patterns sequentially; the first matching regex extracts `match.groupdict()`.
- Strips any groups that returned `None`.
- Renames keys using `field_map` (e.g. `src_ip` -> `source.ip`).
- Converts types according to `type_coercions` (e.g. `"source.port": int`, `"http.response.status_code": int`).
- Injects `static_fields` (e.g. `event.category: ["authentication"]`).
- Raises `ParseError` if no pattern matches.

```python
# src/siem/parsers/regex_parser.py
from __future__ import annotations
import re
from typing import Any, Callable
from siem.parsers.base import Parser, ParseError

COERCION_REGISTRY: dict[str, Callable[[Any], Any]] = {
    "int": int,
    "float": float,
    "str": str,
    "bool": lambda v: str(v).lower() in ("true", "1", "yes"),
}

class RegexParser(Parser):
    name = "regex"

    def __init__(
        self,
        patterns: list[str],
        field_map: dict[str, str] | None = None,
        static_fields: dict[str, Any] | None = None,
        type_coercions: dict[str, str] | None = None,
        parser_name: str = "regex",
    ) -> None:
        self.name = parser_name
        self.patterns = [re.compile(p) for p in patterns]
        self.field_map = field_map or {}
        self.static_fields = static_fields or {}
        self.type_coercions = type_coercions or {}

    def parse(self, raw: str) -> dict[str, Any]:
        match_dict: dict[str, Any] | None = None

        for pattern in self.patterns:
            m = pattern.search(raw)
            if m:
                match_dict = {k: v for k, v in m.groupdict().items() if v is not None}
                break

        if match_dict is None:
            raise ParseError("No pattern matched the raw input", raw=raw, parser_name=self.name)

        result: dict[str, Any] = {}
        for k, v in match_dict.items():
            target_key = self.field_map.get(k, k)
            if target_key in self.type_coercions:
                coercer = COERCION_REGISTRY.get(self.type_coercions[target_key], int)
                try:
                    v = coercer(v)
                except (ValueError, TypeError):
                    pass
            result[target_key] = v

        if self.static_fields:
            for sk, sv in self.static_fields.items():
                result[sk] = sv

        return result
```

---

### 3.4 Grok Parser (`src/siem/parsers/grok_parser.py`)

Wraps `pygrok.Grok` for expressive, composable pattern matching using standard logstash/grok libraries (e.g. `%{IP:source_ip}`, `%{NUMBER:source_port}`).

#### Specification
- Precompiles a list of `Grok` instances with optional custom pattern definitions.
- Evaluates patterns in declaration order.
- Extracts values, handles pygrok returning `None` for unmatched optional groups.
- Applies `field_map`, `type_coercions`, and merges `static_fields`.
- Raises `ParseError` if all grok patterns fail to match.

```python
# src/siem/parsers/grok_parser.py
from __future__ import annotations
from typing import Any
import pygrok
from siem.parsers.base import Parser, ParseError
from siem.parsers.regex_parser import COERCION_REGISTRY

class GrokParser(Parser):
    name = "grok"

    def __init__(
        self,
        patterns: list[str],
        custom_patterns: dict[str, str] | None = None,
        field_map: dict[str, str] | None = None,
        static_fields: dict[str, Any] | None = None,
        type_coercions: dict[str, str] | None = None,
        parser_name: str = "grok",
    ) -> None:
        self.name = parser_name
        self.field_map = field_map or {}
        self.static_fields = static_fields or {}
        self.type_coercions = type_coercions or {}
        
        # Precompile grok patterns
        self.groks = [
            pygrok.Grok(p, custom_patterns=custom_patterns or {})
            for p in patterns
        ]

    def parse(self, raw: str) -> dict[str, Any]:
        matched: dict[str, Any] | None = None

        for grok_inst in self.groks:
            res = grok_inst.match(raw)
            if res is not None:
                matched = {k: v for k, v in res.items() if v is not None}
                break

        if matched is None:
            raise ParseError("No grok pattern matched the input", raw=raw, parser_name=self.name)

        result: dict[str, Any] = {}
        for k, v in matched.items():
            target_key = self.field_map.get(k, k)
            if target_key in self.type_coercions:
                coercer = COERCION_REGISTRY.get(self.type_coercions[target_key], int)
                try:
                    v = coercer(v)
                except (ValueError, TypeError):
                    pass
            result[target_key] = v

        if self.static_fields:
            for sk, sv in self.static_fields.items():
                result[sk] = sv

        return result
```

---

### 3.5 Declarative Builtin Parser Loader (`src/siem/parsers/builtin/`)

The declarative loader reads YAML files under `src/siem/parsers/builtin/*.yml` and returns preconfigured `RegexParser` or `GrokParser` instances.

#### Schema for Builtin YAML Files
```yaml
name: sshd
type: grok   # or "regex"
patterns:
  - "Failed %{WORD:auth_method} for (?<user_invalid>invalid user )?%{USER:user} from %{IP:src_ip} port %{POSINT:src_port} ssh2"
  - "Accepted %{WORD:auth_method} for %{USER:user} from %{IP:src_ip} port %{POSINT:src_port} ssh2"
field_map:
  src_ip: "source.ip"
  src_port: "source.port"
  user: "user.name"
add:
  event.category: ["authentication"]
  observer.product: "OpenSSH"
coercions:
  source.port: int
timestamp_field: "timestamp"
```

#### Builtin Definitions to Implement

##### 1. `sshd.yml`
Handles SSH authentication events:
```yaml
name: sshd
type: regex
patterns:
  - '^Failed (?P<auth_method>\S+) for invalid user (?P<user>\S+) from (?P<src_ip>\S+) port (?P<src_port>\d+) ssh2$'
  - '^Failed (?P<auth_method>\S+) for (?P<user>\S+) from (?P<src_ip>\S+) port (?P<src_port>\d+) ssh2$'
  - '^Accepted (?P<auth_method>\S+) for (?P<user>\S+) from (?P<src_ip>\S+) port (?P<src_port>\d+) ssh2'
  - '^Invalid user (?P<user>\S+) from (?P<src_ip>\S+) port (?P<src_port>\d+)$'
field_map:
  src_ip: "source.ip"
  src_port: "source.port"
  user: "user.name"
add:
  event.category: ["authentication"]
  observer.product: "OpenSSH"
coercions:
  source.port: int
```

##### 2. `nginx_access.yml`
Handles Combined Log Format:
```yaml
name: nginx_access
type: regex
patterns:
  - '^(?P<client_ip>\S+) \S+ (?P<remote_user>\S+) \[(?P<timestamp>[^\]]+)\] "(?P<http_method>[A-Z]+) (?P<url_path>\S+) [^"]*" (?P<status_code>\d{3}) (?P<body_bytes>\d+) "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"'
field_map:
  client_ip: "source.ip"
  remote_user: "user.name"
  timestamp: "@timestamp"
  http_method: "http.request.method"
  url_path: "url.original"
  status_code: "http.response.status_code"
  body_bytes: "http.response.body.bytes"
  referrer: "http.request.referrer"
  user_agent: "user_agent.original"
add:
  event.category: ["web"]
coercions:
  http.response.status_code: int
  http.response.body.bytes: int
```

##### 3. `syslog_generic.yml`
Handles RFC 3164 (legacy BSD syslog) and RFC 5424 headers:
```yaml
name: syslog_generic
type: regex
patterns:
  # RFC 3164: <PRI>MMM DD HH:MM:SS hostname tag[pid]: message
  - '^(?:<(?P<priority>\d{1,3})>)?(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+(?P<process_name>[a-zA-Z0-9_\.\-]+)(?:\[(?P<process_pid>\d+)\])?:\s+(?P<message>.*)$'
  # RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
  - '^(?:<(?P<priority>\d{1,3})>)?1\s+(?P<timestamp>\S+)\s+(?P<hostname>\S+)\s+(?P<process_name>\S+)\s+(?P<process_pid>\S+)\s+(?P<msg_id>\S+)\s+(?P<structured_data>\[.*?\]|-)\s+(?P<message>.*)$'
field_map:
  hostname: "host.hostname"
  process_name: "process.name"
  process_pid: "process.pid"
coercions:
  priority: int
  process.pid: int
```

#### Loader Implementation (`src/siem/parsers/builtin/__init__.py`)
```python
# src/siem/parsers/builtin/__init__.py
from __future__ import annotations
from pathlib import Path
from typing import Any
import yaml

from siem.parsers.base import Parser
from siem.parsers.regex_parser import RegexParser
from siem.parsers.grok_parser import GrokParser

BUILTIN_DIR = Path(__file__).parent
_BUILTIN_CACHE: dict[str, Parser] = {}

def load_builtin(name: str) -> Parser:
    """Load and compile a declarative parser definition by name."""
    if name in _BUILTIN_CACHE:
        return _BUILTIN_CACHE[name]

    yaml_path = BUILTIN_DIR / f"{name}.yml"
    if not yaml_path.is_file():
        raise FileNotFoundError(f"Builtin parser definition not found: {yaml_path}")

    with open(yaml_path, "r", encoding="utf-8") as f:
        config: dict[str, Any] = yaml.safe_load(f)

    parser_type = config.get("type", "regex")
    patterns = config.get("patterns", [])
    field_map = config.get("field_map", {})
    static_fields = config.get("add", {})
    coercions = config.get("coercions", {})

    parser: Parser
    if parser_type == "regex":
        parser = RegexParser(
            patterns=patterns,
            field_map=field_map,
            static_fields=static_fields,
            type_coercions=coercions,
            parser_name=name,
        )
    elif parser_type == "grok":
        parser = GrokParser(
            patterns=patterns,
            field_map=field_map,
            static_fields=static_fields,
            type_coercions=coercions,
            parser_name=name,
        )
    else:
        raise ValueError(f"Unknown parser type: {parser_type}")

    _BUILTIN_CACHE[name] = parser
    return parser
```

---

### 3.6 Post-Parse Normalization (`src/siem/parsers/normalizer.py`)

The normalizer bridges parsed dictionaries and the typed Pydantic [`Event`](file:///home/shady/Projects/WeSheildSiem/src/siem/schema.py#L294).

#### Responsibilities
1. **Unflatten Dotted Keys**: Recursively turn `{"source.ip": "1.1.1.1", "http.response.status_code": 200}` into `{"source": {"ip": "1.1.1.1"}, "http": {"response": {"status_code": 200}}}`.
2. **Timestamp Parsing**: Parse strings via `dateutil.parser.parse`, convert to UTC. For RFC 3164 (e.g. `Oct 11 22:14:15`), assign current year and handle year boundary rollbacks. Fall back to `envelope.received_at` if missing.
3. **Envelope Metadata Inheritance**:
   - `event.original = envelope.raw`
   - `host.name = envelope.host` (if host not extracted)
   - `labels = {**envelope.labels, **parsed_labels}`
   - `event.kind = "event"` by default.
4. **Instantiate `Event`**: Validate via `Event.model_validate()`.

```python
# src/siem/parsers/normalizer.py
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any
from dateutil import parser as date_parser

from siem.schema import Event, RawEnvelope, to_utc

def unflatten(flat_dict: dict[str, Any]) -> dict[str, Any]:
    """Turn dotted keys into a nested dictionary."""
    nested: dict[str, Any] = {}
    for key, val in flat_dict.items():
        parts = key.split(".")
        current = nested
        for part in parts[:-1]:
            if part not in current or not isinstance(current[part], dict):
                current[part] = {}
            current = current[part]
        current[parts[-1]] = val
    return nested

def parse_log_timestamp(ts_val: Any, default_dt: datetime | None = None) -> datetime:
    """Parse log timestamp strings into timezone-aware UTC datetime."""
    if isinstance(ts_val, datetime):
        return datetime.fromisoformat(to_utc(ts_val))

    if isinstance(ts_val, (int, float)):
        return datetime.fromisoformat(to_utc(ts_val))

    if isinstance(ts_val, str):
        # RFC 3164 Syslog format check: "Oct 11 22:14:15" has no year
        try:
            dt = date_parser.parse(ts_val)
            if dt.year == 1900:  # dateutil default year
                now = default_dt or datetime.now(timezone.utc)
                dt = dt.replace(year=now.year)
                # If log appears in future by more than 2 days, roll back one year
                if (dt.replace(tzinfo=timezone.utc) - now).days > 2:
                    dt = dt.replace(year=now.year - 1)
            return datetime.fromisoformat(to_utc(dt))
        except Exception:
            pass

    return default_dt or datetime.now(timezone.utc)

def normalize(parsed: dict[str, Any], envelope: RawEnvelope) -> Event:
    """Transform parsed dictionary and RawEnvelope into a validated Event."""
    # 1. Resolve @timestamp
    raw_ts = parsed.pop("@timestamp", None)
    fallback_dt = datetime.fromisoformat(envelope.received_at)
    event_timestamp = parse_log_timestamp(raw_ts, default_dt=fallback_dt)

    # 2. Unflatten dotted keys
    nested = unflatten(parsed)

    # 3. Ensure mandatory sections
    nested.setdefault("event", {})
    nested["event"].setdefault("kind", "event")
    nested["event"]["original"] = envelope.raw

    # 4. Propagate host from envelope if absent
    if envelope.host and "host" not in nested:
        nested["host"] = {"name": envelope.host}

    # 5. Merge labels
    labels = {**envelope.labels, **nested.get("labels", {})}
    nested["labels"] = labels

    # 6. Set timestamp and construct Event
    nested["@timestamp"] = event_timestamp.isoformat()

    return Event.model_validate(nested)
```

---

### 3.7 Routing Registry (`src/siem/pipeline/registry.py`)

The router binds incoming log sources to the correct parser instance based on `config.routing`.

#### Routing Algorithm
1. Exact match on `rule.match.source == envelope.source`.
2. Fallback match on `rule.match.source == "*"`.
3. If no rule matches, raise `ValueError` (caught as unroutable and deadlettered).
4. All parsers are instantiated once and cached inside `Router`.

```python
# src/siem/pipeline/registry.py
from __future__ import annotations
from typing import Any
from siem.config import PipelineConfig, ParserSpec
from siem.parsers.base import Parser
from siem.parsers.json_parser import JsonParser
from siem.parsers.builtin import load_builtin

class Router:
    """Routes log sources to precompiled Parser instances."""

    def __init__(self) -> None:
        self._exact_routes: dict[str, Parser] = {}
        self._fallback_parser: Parser | None = None

    def register(self, source: str, parser: Parser) -> None:
        if source == "*":
            self._fallback_parser = parser
        else:
            self._exact_routes[source] = parser

    def parser_for(self, source: str) -> Parser:
        """Find the matching parser for a given source key."""
        if source in self._exact_routes:
            return self._exact_routes[source]
        if self._fallback_parser is not None:
            return self._fallback_parser
        raise ValueError(f"No parser configured for source: {source!r}")

def create_parser_from_spec(spec: ParserSpec) -> Parser:
    """Instantiate a parser from a ParserSpec configuration."""
    if spec.type == "builtin":
        if not spec.name:
            raise ValueError("ParserSpec type 'builtin' requires a name")
        return load_builtin(spec.name)
    if spec.type == "json":
        return JsonParser()
    raise NotImplementedError(f"Direct '{spec.type}' parser specification not yet supported; use 'builtin' or 'json'")

def build_router(config: PipelineConfig) -> Router:
    """Build and prime a Router from PipelineConfig."""
    router = Router()
    for rule in config.routing:
        parser = create_parser_from_spec(rule.parser)
        router.register(rule.match.source, parser)
    return router
```

---

## 4. Failure Modes & Edge Cases

| Scenario | Behavior | Mitigation |
|---|---|---|
| **Non-matching log line** | Parser raises `ParseError` | Worker catches `ParseError`, writes to `queue.deadletter()`, and calls `queue.ack()` so the pipeline never blocks. |
| **Malformed JSON** | `json.loads` fails | `JsonParser` wraps `JSONDecodeError` into `ParseError` with original string snippet. |
| **Syslog without year (`Oct 11 22:14:15`)** | Missing year | `parse_log_timestamp()` assigns current UTC year; handles New Year's Eve rollover window. |
| **Invalid IP or Port in parsed data** | Field fails validation | Handled gracefully by `Event.sanitize_raw_input()`: bad IP is dropped and tagged with `_source_ip_invalid` instead of dropping the whole event. |
| **Unmapped source key** | `Router.parser_for()` called with unknown source | Fallback rule `match: { source: "*" }` routes to `JsonParser`. If no fallback defined, `ParseError` is raised. |

---

## 5. Comprehensive Testing Plan (`tests/test_parsers.py`)

The test suite must cover unit parsing, builtin log validation, normalization, and routing.

```python
# tests/test_parsers.py
import pytest
from datetime import datetime, timezone
from siem.parsers.base import ParseError
from siem.parsers.json_parser import JsonParser
from siem.parsers.regex_parser import RegexParser
from siem.parsers.builtin import load_builtin
from siem.parsers.normalizer import unflatten, normalize
from siem.pipeline.registry import build_router
from siem.schema import RawEnvelope, Event
from siem.config import load_config

class TestParsers:
    def test_json_parser_success(self):
        p = JsonParser()
        data = p.parse('{"timestamp": "2026-09-10T12:00:00Z", "src_ip": "1.2.3.4", "msg": "auth failure"}')
        assert data["@timestamp"] == "2026-09-10T12:00:00Z"
        assert data["message"] == "auth failure"
        assert data["src_ip"] == "1.2.3.4"

    def test_json_parser_malformed(self):
        p = JsonParser()
        with pytest.raises(ParseError):
            p.parse("{not valid json}")

    def test_sshd_builtin_failed_password(self):
        p = load_builtin("sshd")
        raw = "Failed password for invalid user admin from 192.168.1.50 port 54321 ssh2"
        data = p.parse(raw)
        assert data["source.ip"] == "192.168.1.50"
        assert data["source.port"] == 54321
        assert data["user.name"] == "admin"
        assert data["event.category"] == ["authentication"]

    def test_sshd_builtin_accepted_pubkey(self):
        p = load_builtin("sshd")
        raw = "Accepted publickey for root from 10.0.0.1 port 2222 ssh2: RSA SHA256:abc123xyz"
        data = p.parse(raw)
        assert data["source.ip"] == "10.0.0.1"
        assert data["source.port"] == 2222
        assert data["user.name"] == "root"

    def test_nginx_access_builtin(self):
        p = load_builtin("nginx_access")
        raw = '127.0.0.1 - frank [10/Oct/2026:13:55:36 +0000] "GET /api/v1/health HTTP/1.1" 200 2326 "https://ref.com" "Mozilla/5.0"'
        data = p.parse(raw)
        assert data["source.ip"] == "127.0.0.1"
        assert data["user.name"] == "frank"
        assert data["http.response.status_code"] == 200
        assert data["http.response.body.bytes"] == 2326
        assert data["http.request.method"] == "GET"
        assert data["url.original"] == "/api/v1/health"

    def test_syslog_generic_builtin(self):
        p = load_builtin("syslog_generic")
        raw = "<34>Oct 11 22:14:15 myhost sshd[1234]: session opened for user test"
        data = p.parse(raw)
        assert data["host.hostname"] == "myhost"
        assert data["process.name"] == "sshd"
        assert data["process.pid"] == 1234
        assert data["message"] == "session opened for user test"

    def test_unflatten_nested_keys(self):
        flat = {"source.ip": "1.1.1.1", "http.response.status_code": 200}
        nested = unflatten(flat)
        assert nested == {"source": {"ip": "1.1.1.1"}, "http": {"response": {"status_code": 200}}}

    def test_normalize_to_event(self):
        env = RawEnvelope(
            raw="sample log",
            source="sshd",
            transport="syslog-udp",
            host="collector-1",
            labels={"cluster": "prod"},
        )
        parsed = {
            "source.ip": "192.168.1.1",
            "source.port": 22,
            "user.name": "deploy",
            "event.category": ["authentication"],
        }
        event = normalize(parsed, env)
        assert isinstance(event, Event)
        assert str(event.source.ip) == "192.168.1.1"
        assert event.source.port == 22
        assert event.user.name == "deploy"
        assert event.host.name == "collector-1"
        assert event.labels["cluster"] == "prod"
        assert event.event.original == "sample log"
        assert event.related.ip == [event.source.ip]

    def test_router_resolution(self):
        config = load_config("config/pipeline.yml")
        router = build_router(config)
        
        sshd_parser = router.parser_for("sshd")
        assert sshd_parser.name == "sshd"
        
        fallback = router.parser_for("some_unregistered_json_source")
        assert fallback.name == "json"
```

---

## 6. Implementation Checklist

Follow this checklist in sequence to complete the parser framework:

- [ ] **Base Parser**: Implement `Parser` and `ParseError` in `src/siem/parsers/base.py`.
- [ ] **JSON Parser**: Implement `JsonParser` with key mapping in `src/siem/parsers/json_parser.py`.
- [ ] **Regex Parser**: Implement `RegexParser` with named group extraction and type coercions in `src/siem/parsers/regex_parser.py`.
- [ ] **Grok Parser**: Implement `GrokParser` wrapping `pygrok.Grok` in `src/siem/parsers/grok_parser.py`.
- [ ] **Builtin Declarations**:
  - [ ] Write `src/siem/parsers/builtin/sshd.yml` (SSH auth patterns).
  - [ ] Write `src/siem/parsers/builtin/nginx_access.yml` (Combined Log Format).
  - [ ] Write `src/siem/parsers/builtin/syslog_generic.yml` (RFC 3164 / 5424).
- [ ] **Builtin Loader**: Implement `load_builtin()` with caching in `src/siem/parsers/builtin/__init__.py`.
- [ ] **Normalizer**: Implement `unflatten()`, `parse_log_timestamp()`, and `normalize()` in `src/siem/parsers/normalizer.py`.
- [ ] **Registry & Router**: Implement `Router` and `build_router()` in `src/siem/pipeline/registry.py`.
- [ ] **Export Symbols**: Update `src/siem/parsers/__init__.py` with all public classes.
- [ ] **Verification**: Run `pytest tests/test_parsers.py` to confirm all unit and integration tests pass.
