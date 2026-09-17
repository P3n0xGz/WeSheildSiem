from __future__ import annotations

from pathlib import Path
from typing import Annotated, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

# See configPlanning.md for the full design rationale behind every decision
# below (extra="forbid" everywhere, the InputConfig discriminated union, the
# AssetEntry dotted-key alias, plain str for URLs, etc.) before filling in
# the validator/method bodies left as `...`.

INPUT_TYPES = ("syslog", "filetail", "http_api")
PARSER_TYPES = ("builtin", "json", "regex", "grok")
SYSLOG_PROTOCOLS = ("udp", "tcp")


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class QueueConfig(_StrictModel):
    url: str
    raw_stream: str
    deadletter_stream: str
    consumer_group: str
    max_pending: int = Field(gt=0)


class OutputConfig(_StrictModel):
    hosts: list[str] = Field(min_length=1)
    data_stream: str
    deadletter_index: str
    bulk_max_actions: int = Field(gt=0)
    bulk_flush_interval_seconds: float = Field(gt=0)
    retry_max_attempts: int = Field(ge=0)


class WorkersConfig(_StrictModel):
    count: int = Field(gt=0)


class MetricsConfig(_StrictModel):
    host: str
    port: int = Field(gt=0, lt=65536)


class GeoipConfig(_StrictModel):
    enabled: bool = False
    database_path: Path


class AssetEntry(_StrictModel):
    model_config = ConfigDict(populate_by_name=True)

    host_name: str = Field(alias="host.name")
    labels: dict[str, str] = Field(default_factory=dict)


class EnrichConfig(_StrictModel):
    geoip: GeoipConfig
    assets: dict[str, AssetEntry] = Field(default_factory=dict)


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
    SyslogInputConfig | FileTailInputConfig | HttpApiInputConfig,
    Field(discriminator="type"),
]


class MatchSpec(_StrictModel):
    source: str


class ParserSpec(_StrictModel):
    type: Literal["builtin", "json", "regex", "grok"]
    name: str | None = None

    @model_validator(mode="after")
    def _builtin_requires_name(self) -> ParserSpec:
        if self.type == "builtin" and not self.name:
            raise ValueError("parser.name is required when parser.type == 'builtin'")
        return self


class RoutingRule(_StrictModel):
    match: MatchSpec
    parser: ParserSpec


class PipelineConfig(_StrictModel):
    queue: QueueConfig
    output: OutputConfig
    workers: WorkersConfig
    metrics: MetricsConfig
    enrich: EnrichConfig
    inputs: list[InputConfig] = Field(min_length=1)
    routing: list[RoutingRule] = Field(min_length=1)

    @model_validator(mode="after")
    def _routing_has_wildcard_fallback(self) -> PipelineConfig:
        if not any(rule.match.source == "*" for rule in self.routing):
            raise ValueError(
                'routing must include a wildcard fallback rule: {"source": "*"}'
            )
        return self

    @model_validator(mode="after")
    def _input_names_are_unique(self) -> PipelineConfig:
        names = [i.name for i in self.inputs]
        if len(names) != len(set(names)):
            raise ValueError(f"input names must be unique, got: {names}")
        return self


def load_config(path: str | Path) -> PipelineConfig:
    """Read, parse, and validate a pipeline.yml file into a PipelineConfig.

    Raises FileNotFoundError for a missing path, ValueError for an empty
    (or comments-only) file, and pydantic.ValidationError for any shape
    violation. Error formatting belongs to the CLI, not here.
    """
    text = Path(path).read_text(encoding="utf-8")
    raw = yaml.safe_load(text)
    if raw is None:
        raise ValueError(f"config file is empty: {path}")
    return PipelineConfig.model_validate(raw)
