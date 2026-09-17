"""Tests for src/siem/config.py.

Covers the test-case list in configPlanning.md §9: end-to-end loading of the
real config/pipeline.yml, extra="forbid" strictness, the InputConfig
discriminated union, the AssetEntry dotted-key alias, the pipeline-level
validators, numeric constraints, and load_config() file-level behavior.
"""

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from siem.config import (
    AssetEntry,
    EnrichConfig,
    FileTailInputConfig,
    HttpApiInputConfig,
    ParserSpec,
    PipelineConfig,
    SyslogInputConfig,
    load_config,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
PIPELINE_YML = REPO_ROOT / "config" / "pipeline.yml"


def minimal_config() -> dict:
    """A smallest-valid config dict; each test mutates its own fresh copy."""
    return {
        "queue": {
            "url": "redis://localhost:6379/0",
            "raw_stream": "siem:raw",
            "deadletter_stream": "siem:deadletter",
            "consumer_group": "pipeline",
            "max_pending": 100,
        },
        "output": {
            "hosts": ["http://localhost:9200"],
            "data_stream": "logs-generic-default",
            "deadletter_index": "siem-deadletter",
            "bulk_max_actions": 500,
            "bulk_flush_interval_seconds": 2,
            "retry_max_attempts": 5,
        },
        "workers": {"count": 4},
        "metrics": {"host": "0.0.0.0", "port": 8000},
        "enrich": {
            "geoip": {"enabled": False, "database_path": "./GeoLite2-City.mmdb"},
            "assets": {},
        },
        "inputs": [
            {
                "type": "syslog",
                "name": "syslog-udp",
                "protocol": "udp",
                "host": "0.0.0.0",
                "port": 514,
            }
        ],
        "routing": [
            {"match": {"source": "sshd"}, "parser": {"type": "builtin", "name": "sshd"}},
            {"match": {"source": "*"}, "parser": {"type": "json"}},
        ],
    }


def validate(data: dict) -> PipelineConfig:
    return PipelineConfig.model_validate(data)


class TestLoadConfigRealPipelineYml:
    def test_real_yaml_loads_end_to_end(self):
        assert isinstance(load_config(PIPELINE_YML), PipelineConfig)

    def test_spot_check_values(self):
        cfg = load_config(PIPELINE_YML)
        assert cfg.queue.url == "redis://localhost:6379/0"
        assert cfg.workers.count == 4
        assert cfg.output.bulk_max_actions == 500

    def test_each_input_parses_into_correct_concrete_class(self):
        by_name = {i.name: i for i in load_config(PIPELINE_YML).inputs}
        assert type(by_name["syslog-udp"]) is SyslogInputConfig
        assert type(by_name["syslog-tcp"]) is SyslogInputConfig
        assert type(by_name["nginx-access"]) is FileTailInputConfig
        assert type(by_name["http-ingest"]) is HttpApiInputConfig

    def test_syslog_tcp_entry_has_none_default_source(self):
        by_name = {i.name: i for i in load_config(PIPELINE_YML).inputs}
        assert by_name["syslog-tcp"].default_source is None
        assert by_name["syslog-udp"].default_source == "syslog"

    def test_assets_load_with_dotted_host_name_key(self):
        cfg = load_config(PIPELINE_YML)
        assert set(cfg.enrich.assets) == {"web-01", "10.0.0.5"}
        assert cfg.enrich.assets["web-01"].host_name == "web-01.corp.local"
        assert cfg.enrich.assets["web-01"].labels == {"env": "prod", "role": "web"}

    def test_real_yaml_has_wildcard_fallback_rule(self):
        cfg = load_config(PIPELINE_YML)
        assert any(r.match.source == "*" for r in cfg.routing)


class TestLoadConfigFileErrors:
    def test_nonexistent_path_raises_file_not_found(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_config(tmp_path / "nope.yml")

    def test_empty_file_raises_clear_value_error(self, tmp_path):
        p = tmp_path / "empty.yml"
        p.write_text("", encoding="utf-8")
        with pytest.raises(ValueError, match="empty"):
            load_config(p)

    def test_comments_only_file_raises_clear_value_error(self, tmp_path):
        p = tmp_path / "comments.yml"
        p.write_text("# just a comment\n# another one\n", encoding="utf-8")
        with pytest.raises(ValueError, match="empty"):
            load_config(p)

    def test_invalid_yaml_syntax_propagates_as_yaml_error(self, tmp_path):
        p = tmp_path / "broken.yml"
        p.write_text("queue: [unclosed\n", encoding="utf-8")
        with pytest.raises(yaml.YAMLError):
            load_config(p)


class TestStrictness:
    def test_missing_top_level_section_raises(self):
        data = minimal_config()
        del data["workers"]
        with pytest.raises(ValidationError):
            validate(data)

    def test_unknown_top_level_key_raises(self):
        data = minimal_config()
        data["bogus"] = {}
        with pytest.raises(ValidationError):
            validate(data)

    def test_unknown_nested_key_raises(self):
        data = minimal_config()
        data["queue"]["bogus_key"] = 1
        with pytest.raises(ValidationError):
            validate(data)

    def test_typoed_key_is_rejected_not_silently_defaulted(self):
        # The canonical typo configPlanning.md §2 warns about: a mistyped
        # max_pending must crash validation, not fall back to a default.
        data = minimal_config()
        del data["queue"]["max_pending"]
        data["queue"]["max_pendign"] = 100
        with pytest.raises(ValidationError):
            validate(data)


class TestInputDiscriminatedUnion:
    def test_unknown_type_kafka_raises_naming_the_bad_tag(self):
        data = minimal_config()
        data["inputs"][0]["type"] = "kafka"
        with pytest.raises(ValidationError, match="kafka"):
            validate(data)

    def test_input_without_type_key_raises(self):
        data = minimal_config()
        del data["inputs"][0]["type"]
        with pytest.raises(ValidationError):
            validate(data)

    def test_quoted_numeric_port_coerces_to_int(self):
        data = minimal_config()
        data["inputs"][0]["port"] = "514"
        port = validate(data).inputs[0].port
        assert port == 514
        assert isinstance(port, int)

    def test_filetail_string_paths_coerce_to_path(self):
        data = minimal_config()
        data["inputs"] = [
            {
                "type": "filetail",
                "name": "nginx-access",
                "path": "/var/log/nginx/access.log",
                "source": "nginx_access",
                "offset_store": ".state/nginx-access.offset",
            }
        ]
        inp = validate(data).inputs[0]
        assert isinstance(inp, FileTailInputConfig)
        assert inp.path == Path("/var/log/nginx/access.log")
        assert inp.offset_store == Path(".state/nginx-access.offset")


class TestNumericConstraints:
    @pytest.mark.parametrize("port", [0, -1, 70000])
    def test_out_of_range_input_port_rejected(self, port):
        data = minimal_config()
        data["inputs"][0]["port"] = port
        with pytest.raises(ValidationError):
            validate(data)

    @pytest.mark.parametrize("port", [0, 70000])
    def test_out_of_range_metrics_port_rejected(self, port):
        data = minimal_config()
        data["metrics"]["port"] = port
        with pytest.raises(ValidationError):
            validate(data)

    def test_bulk_flush_interval_int_is_coerced_to_float(self):
        interval = validate(minimal_config()).output.bulk_flush_interval_seconds
        assert interval == 2.0
        assert isinstance(interval, float)

    def test_bulk_flush_interval_accepts_fractional_value(self):
        data = minimal_config()
        data["output"]["bulk_flush_interval_seconds"] = 1.5
        assert validate(data).output.bulk_flush_interval_seconds == 1.5

    def test_zero_retry_max_attempts_is_legal(self):
        data = minimal_config()
        data["output"]["retry_max_attempts"] = 0
        assert validate(data).output.retry_max_attempts == 0

    @pytest.mark.parametrize("section", ["queue", "output"])
    def test_zero_bulk_tuning_values_rejected(self, section):
        data = minimal_config()
        key = "max_pending" if section == "queue" else "bulk_max_actions"
        data[section][key] = 0
        with pytest.raises(ValidationError):
            validate(data)


class TestAssetEntryDottedKey:
    def test_yaml_style_dotted_key_populates_host_name(self):
        entry = AssetEntry.model_validate(
            {"host.name": "web-01.corp.local", "labels": {"env": "prod"}}
        )
        assert entry.host_name == "web-01.corp.local"

    def test_python_name_construction_also_works(self):
        entry = AssetEntry(host_name="web-01.corp.local", labels={})
        assert entry.host_name == "web-01.corp.local"

    def test_missing_labels_defaults_to_empty_dict(self):
        entry = AssetEntry.model_validate({"host.name": "web-01.corp.local"})
        assert entry.labels == {}

    def test_dump_by_alias_re_emits_dotted_key(self):
        dumped = AssetEntry(host_name="x", labels={"a": "b"}).model_dump(by_alias=True)
        assert dumped["host.name"] == "x"
        assert "host_name" not in dumped

    def test_enrich_assets_accepts_empty_map(self):
        enrich = EnrichConfig.model_validate(
            {"geoip": {"database_path": "./GeoLite2-City.mmdb"}}
        )
        assert enrich.assets == {}

    def test_geoip_enabled_with_missing_database_file_still_validates(self):
        # config.py must not stat the filesystem — existence checks belong to
        # enrich/geoip.py at runtime, gated on enabled (configPlanning.md §6).
        data = minimal_config()
        data["enrich"]["geoip"] = {
            "enabled": True,
            "database_path": "/nonexistent/GeoLite2-City.mmdb",
        }
        cfg = validate(data)
        assert cfg.enrich.geoip.enabled is True


class TestParserSpec:
    def test_builtin_without_name_raises(self):
        with pytest.raises(ValidationError):
            ParserSpec(type="builtin")

    def test_builtin_with_name_validates(self):
        assert ParserSpec(type="builtin", name="sshd").name == "sshd"

    def test_json_without_name_validates(self):
        assert ParserSpec(type="json").name is None

    @pytest.mark.parametrize("parser_type", ["regex", "grok"])
    def test_regex_and_grok_without_name_validate_for_now(self, parser_type):
        assert ParserSpec(type=parser_type).name is None

    def test_unknown_parser_type_raises(self):
        with pytest.raises(ValidationError):
            ParserSpec(type="llm_magic")


class TestPipelineLevelValidators:
    def test_routing_without_wildcard_fallback_raises(self):
        data = minimal_config()
        data["routing"] = [
            {"match": {"source": "sshd"}, "parser": {"type": "builtin", "name": "sshd"}}
        ]
        with pytest.raises(ValidationError, match="wildcard"):
            validate(data)

    def test_duplicate_input_names_raise(self):
        data = minimal_config()
        data["inputs"] = [
            {
                "type": "syslog",
                "name": "same-name",
                "protocol": "udp",
                "host": "0.0.0.0",
                "port": 514,
            },
            {
                "type": "syslog",
                "name": "same-name",
                "protocol": "tcp",
                "host": "0.0.0.0",
                "port": 514,
            },
        ]
        with pytest.raises(ValidationError, match="unique"):
            validate(data)

    def test_empty_inputs_list_raises(self):
        data = minimal_config()
        data["inputs"] = []
        with pytest.raises(ValidationError):
            validate(data)

    def test_empty_routing_list_raises(self):
        data = minimal_config()
        data["routing"] = []
        with pytest.raises(ValidationError):
            validate(data)


class TestRoundTripIdempotence:
    def test_minimal_config_round_trips_to_an_equal_model(self):
        cfg = validate(minimal_config())
        dumped = cfg.model_dump(mode="json", by_alias=True)
        assert validate(dumped) == cfg

    def test_real_yaml_round_trips_to_an_equal_model(self):
        cfg = load_config(PIPELINE_YML)
        dumped = cfg.model_dump(mode="json", by_alias=True)
        assert validate(dumped) == cfg
