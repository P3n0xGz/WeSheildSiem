from __future__ import annotations
import hashlib, json
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any, Optional, Literal, List
from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator, model_validator

ECS_VERSION = "8.11"
RAW_STREAM_FIELDS = ("raw", "source", "transport", "received_at", "host", "labels")

# ECS categorization reference (schemaPlanning.md §8). These are membership
# lists for a future warn-tag validator on Event, NOT Literal types on the
# fields below — an unrecognized value must warn (append a tag), not hard-fail.
EVENT_KINDS = ("alert", "asset", "enrichment", "event", "metric", "pipeline_error", "signal", "state")
EVENT_OUTCOMES = ("failure", "success", "unknown")
EVENT_CATEGORIES = (
    "api", "authentication", "configuration", "database", "driver", "email", "file",
    "host", "iam", "intrusion_detection", "library", "malware", "network", "package",
    "process", "registry", "session", "threat", "vulnerability", "web",
)
EVENT_TYPES = (
    "access", "admin", "allowed", "change", "connection", "creation", "deletion",
    "denied", "device", "end", "error", "group", "indicator", "info", "installation",
    "protocol", "start", "user",
)

def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()

def to_utc(value: str | datetime | int | float) -> str:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc).isoformat()
        return value.astimezone(timezone.utc).isoformat()
    if isinstance(value, (int, (int,float))):
        if value > 1e11:
            value = value / 1000
        return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()
    if isinstance(value, (int, str)):
        cleaned_value = value.replace("Z","+00:00")
        dt = datetime.fromisoformat(cleaned_value)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc).isoformat()
        return dt.astimezone(timezone.utc).isoformat()
    raise ValueError(f"Invalid value for to_utc: {value}")
    
def canonical_json(obj: Any) -> str:
    """Produces sorted, deterministic JSON text with no extra spaces."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)

class RawEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    raw : str
    source : str
    transport : str
    received_at : str = Field(default_factory=now_utc)
    host : str | None = None
    labels       : dict[str, str] = {}

    @field_validator('source', 'transport', mode='before')
    @classmethod
    def strip_reject_empty(cls, value: str) -> str:
        if isinstance(value, str):
            value = value.strip()

        if not value:
            raise ValueError("Field cannot be empty or solely whitespace.")

        return value

    @field_validator('received_at', mode='before')
    @classmethod
    def validate_received_at(cls, value: str | datetime | int | float) -> str:
        try:
            return to_utc(value)
        except ValueError as e:
            raise ValueError(f"Invalid value for received_at: {value}. Error: {e}")

    @field_validator('labels', mode='before')
    @classmethod
    def coerce_labels_to_str(cls, value: Any) -> Any:
        # Policy: coerce non-str keys/values rather than reject, so collectors
        # can attach numeric/bool tags without needing to pre-stringify them.
        if isinstance(value, dict):
            return {str(k): str(v) for k, v in value.items()}
        return value

    def to_stream_fields(self) -> dict[str, str]:
        return {
            "raw": self.raw,
            "source": self.source,
            "transport": self.transport,
            "received_at": self.received_at,
            "host": self.host or "",
            "labels": canonical_json(self.labels),
        }

    @classmethod
    def from_stream_fields(cls, fields: dict[str, str]) -> RawEnvelope:
        return cls(
            raw=fields["raw"],
            source=fields["source"],
            transport=fields["transport"],
            received_at=fields.get("received_at") or now_utc(),
            host=fields.get("host") or None,
            labels=json.loads(fields.get("labels") or "{}"),
        )


class Geo(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    country_iso_code: Optional[str] = Field(default=None, max_length=2, description="Two-letter ISO country code")
    country_name: Optional[str] = Field(default=None, description="Full country name")
    city_name: Optional[str] = Field(default=None, description="City name")
    location: Optional[dict[str, float]] = Field(default=None, description="Location coordinates")


class Source(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    ip: Optional[IPvAnyAddress] = Field(default=None)
    port: Optional[int] = Field(default=None)
    bytes: Optional[int] = Field(default=None)
    domain: Optional[str] = Field(default=None)
    geo: Optional[Geo] = Field(default=None)  # Geo


class Destination(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    ip: Optional[IPvAnyAddress] = Field(default=None)
    port: Optional[int] = Field(default=None)
    bytes: Optional[int] = Field(default=None)
    domain: Optional[str] = Field(default=None)


class Host(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    name: Optional[str] = Field(default=None)
    hostname: Optional[str] = Field(default=None)
    ip: Optional[list[IPvAnyAddress]] = Field(default=None)  # list[IPvAnyAddress]


class User(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    name: Optional[str] = Field(default=None)
    id: Optional[str] = Field(default=None)
    domain: Optional[str] = Field(default=None)


class EventMeta(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    # kind/category/type/outcome are plain str/list[str], NOT Literal — an
    # unrecognized value must warn-tag, not hard-reject (schemaPlanning.md §8-9).
    # Membership checking against EVENT_KINDS/EVENT_OUTCOMES/etc. belongs in a
    # model_validator on Event (needs access to Event.tags to append warnings).
    kind: Optional[str] = Field(default="event", description="Highest tier schema classification archetype")
    category: Optional[List[str]] = Field(default=None, description="Broad categorization e.g., ['network', 'web']")
    type: Optional[List[str]] = Field(default=None, description="Event sub-type detail e.g., ['access', 'allowed']")
    action: Optional[str] = Field(default=None, description="The concrete action executed")
    outcome: Optional[str] = Field(default="unknown", description="success | failure | unknown")

    dataset: Optional[str] = Field(default=None, description="The specific log stream dataset identifier")
    module: Optional[str] = Field(default=None, description="The integration or source platform module name")
    provider: Optional[str] = Field(default=None, description="The application, service, or vendor creating the log")
    severity: Optional[int] = Field(default=None, description="Numeric event severity layer")

    # Internal Pipeline Metadata
    original: Optional[str] = Field(default=None, description="RawEnvelope.raw, always set on ingest")
    created: Optional[datetime] = Field(default=None, description="Timestamp when event was created, excluded from doc_id")
    ingested: Optional[datetime] = Field(default=None, description="Timestamp when event hit pipeline, excluded from doc_id")



class SyslogFacility(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    code: Optional[int] = Field(default=None, description="Syslog facility code", le=23, ge=0)
    name: Optional[str] = Field(default=None, description="Syslog facility name")


class SyslogSeverity(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    code: Optional[int] = Field(default=None, description="Syslog severity code", le=7, ge=0)
    name: Optional[str] = Field(default=None, description="Syslog severity name")


class Syslog(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    facility: Optional[SyslogFacility] = Field(default=None, description="Syslog facility")
    severity: Optional[SyslogSeverity] = Field(default=None, description="Syslog severity")
    priority: Optional[int] = Field(default=None, description="raw PRI int")


class LogMeta(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    level: Optional[str] = Field(default=None, description='"info", "error", ...')
    syslog: Optional[Syslog] = None


class HttpRequest(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    method: Optional[str] = None
    referrer: Optional[str] = None


class HttpResponseBody(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    bytes: Optional[int] = None


class HttpResponse(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    status_code: Optional[int] = None
    body: Optional[HttpResponseBody] = None


class Http(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    request: Optional[HttpRequest] = None
    response: Optional[HttpResponse] = None
    version: Optional[str] = None


class Url(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    original: Optional[str] = None
    path: Optional[str] = None
    query: Optional[str] = None


class UserAgent(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    original: Optional[str] = None


class Network(BaseModel):
    # Not explicitly listed as a top-level class in schemaPlanning.md §3,
    # but network.transport / network.protocol need a home per §5.
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    transport: Optional[str] = Field(default=None, description='"tcp" | "udp"')
    protocol: Optional[str] = Field(default=None, description='"ssh" | "http" | ...')


class Related(BaseModel):
    # Populated by Event.populate_related_fields, not passed in directly — see §6.
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    ip: Optional[List[IPvAnyAddress]] = None
    user: Optional[List[str]] = None
    hosts: Optional[List[str]] = None


class Observer(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    vendor: Optional[str] = None
    product: Optional[str] = None
    type: Optional[str] = None


def _coerce_int_or_none(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _is_valid_ip(value: Any) -> bool:
    try:
        ip_address(value)
        return True
    except (TypeError, ValueError):
        return False


class Event(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    timestamp: datetime = Field(alias="@timestamp")
    message: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    labels: dict[str, str] = Field(default_factory=dict)

    event: EventMeta = Field(default_factory=EventMeta)
    log: Optional[LogMeta] = None
    host: Optional[Host] = None
    source: Optional[Source] = None
    destination: Optional[Destination] = None
    user: Optional[User] = None
    network: Optional[Network] = None
    http: Optional[Http] = None
    url: Optional[Url] = None
    user_agent: Optional[UserAgent] = None
    related: Optional[Related] = None
    observer: Optional[Observer] = None

    @model_validator(mode='before')
    @classmethod
    def sanitize_raw_input(cls, data: Any) -> Any:
        # §9.2-3: invalid ip/port/bytes/status_code must drop the field and
        # add a tag instead of raising. Only applies when the caller handed
        # us raw dicts (e.g. straight from a parser) — an already-constructed
        # sub-model instance has already passed its own type validation.
        if not isinstance(data, dict):
            return data

        tags = list(data.get('tags') or [])

        def sanitize_ip(container: dict, field: str, tag: str) -> None:
            value = container.get(field)
            if value is None or not isinstance(value, (str, bytes)):
                return
            if not _is_valid_ip(value):
                container[field] = None
                tags.append(tag)

        def sanitize_int(container: dict, field: str, tag: str) -> None:
            value = container.get(field)
            if value is None:
                return
            coerced = _coerce_int_or_none(value)
            if coerced is None:
                tags.append(tag)
            container[field] = coerced

        for section in ("source", "destination"):
            block = data.get(section)
            if isinstance(block, dict):
                sanitize_ip(block, "ip", f"_{section}_ip_invalid")
                sanitize_int(block, "port", f"_{section}_port_invalid")
                sanitize_int(block, "bytes", f"_{section}_bytes_invalid")

        host = data.get("host")
        if isinstance(host, dict) and host.get("ip") is not None:
            raw_ips = host["ip"] if isinstance(host["ip"], list) else [host["ip"]]
            valid_ips = [ip for ip in raw_ips if _is_valid_ip(ip)]
            if len(valid_ips) != len(raw_ips):
                tags.append("_host_ip_invalid")
            host["ip"] = valid_ips or None

        http = data.get("http")
        if isinstance(http, dict):
            response = http.get("response")
            if isinstance(response, dict):
                sanitize_int(response, "status_code", "_http_status_code_invalid")
                body = response.get("body")
                if isinstance(body, dict):
                    sanitize_int(body, "bytes", "_http_response_bytes_invalid")

        data["tags"] = tags
        return data

    @field_validator('timestamp', mode='before')
    @classmethod
    def validate_timestamp(cls, value: str | datetime | int | float) -> datetime:
        try:
            return datetime.fromisoformat(to_utc(value))
        except ValueError as e:
            raise ValueError(f"Invalid value for timestamp: {value}. Error: {e}")

    @field_validator('labels', mode='before')
    @classmethod
    def coerce_labels_to_str(cls, value: Any) -> Any:
        if isinstance(value, dict):
            return {str(k): str(v) for k, v in value.items()}
        return value

    @model_validator(mode='after')
    def populate_related_fields(self) -> Event:
        # De-duplicated pivot fields from source/destination/user/host — §6.
        ips: list[IPvAnyAddress] = []
        if self.source and self.source.ip is not None:
            ips.append(self.source.ip)
        if self.destination and self.destination.ip is not None:
            ips.append(self.destination.ip)
        if self.host and self.host.ip:
            ips.extend(self.host.ip)

        users: list[str] = []
        if self.user and self.user.name:
            users.append(self.user.name)

        hosts: list[str] = []
        if self.host:
            if self.host.name:
                hosts.append(self.host.name)
            if self.host.hostname:
                hosts.append(self.host.hostname)

        deduped_ips = list(dict.fromkeys(ips))
        deduped_users = list(dict.fromkeys(users))
        deduped_hosts = list(dict.fromkeys(hosts))

        if deduped_ips or deduped_users or deduped_hosts:
            self.related = Related(
                ip=deduped_ips or None,
                user=deduped_users or None,
                hosts=deduped_hosts or None,
            )

        return self

    def to_doc(self) -> dict[str, Any]:
        doc = self.model_dump(by_alias=True, exclude_none=True, mode="json")
        doc.setdefault("ecs", {})["version"] = ECS_VERSION
        return doc

    def doc_id(self) -> str:
        # Do NOT hash to_doc() — parser/enrichment changes would change the
        # id. event.created/event.ingested are deliberately excluded so
        # reprocessing the same input yields the same id (§7).
        basis = "\x00".join([
            self.event.original or "",
            self.event.dataset or "",
            (self.host.name if self.host else "") or "",
            self.timestamp.isoformat(),
        ])
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()

    def to_bulk_action(self, data_stream: str) -> dict[str, Any]:
        return {
            "_op_type": "create",  # 409 on duplicate _id => idempotent
            "_index": data_stream,
            "_id": self.doc_id(),
            "_source": self.to_doc(),
        }
