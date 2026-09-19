"""Comprehensive test suite for WeShieldSIEM Parser Framework.

Covers:
- Parser ABC and ParseError exception
- JsonParser happy paths, aliases, field mapping, static fields, and edge cases
- RegexParser pattern matching, multi-pattern fallbacks, field mapping,
  type coercions, None-omissions, static fields, and real-world signatures
"""

from __future__ import annotations

from typing import Any

import pytest

from siem.parsers.base import ParseError, Parser
from siem.parsers.grok_parser import GrokParser
from siem.parsers.json_parser import JsonParser
from siem.parsers.regex_parser import RegexParser


class DummyParser(Parser):
    name = "dummy"

    def parse(self, raw: str) -> dict[str, Any]:
        if not raw:
            raise ParseError("Empty log", raw=raw, parser_name=self.name)
        return {"raw": raw}


# =====================================================================
# Base Parser Tests
# =====================================================================


class TestBaseParser:
    def test_parser_cannot_be_instantiated_directly(self) -> None:
        with pytest.raises(TypeError):
            Parser()  # type: ignore[abstract]

    def test_dummy_parser_success(self) -> None:
        p = DummyParser()
        assert p.name == "dummy"
        res = p.parse("hello world")
        assert res == {"raw": "hello world"}

    def test_dummy_parser_raises_parse_error(self) -> None:
        p = DummyParser()
        with pytest.raises(ParseError) as exc_info:
            p.parse("")
        err = exc_info.value
        assert err.message == "Empty log"
        assert err.raw == ""
        assert err.parser_name == "dummy"
        assert str(err) == "[dummy] Empty log"

    def test_parse_error_string_representation(self) -> None:
        err1 = ParseError("syntax error", raw="bad data here", parser_name="json")
        assert str(err1) == "[json] syntax error: 'bad data here'"

        err2 = ParseError("failed to match")
        assert str(err2) == "failed to match"

        long_raw = "x" * 200
        err3 = ParseError("too long", raw=long_raw, parser_name="regex")
        assert len(err3.raw[:100]) == 100
        assert str(err3).startswith("[regex] too long: '")


# =====================================================================
# JsonParser Tests & Edge Cases
# =====================================================================


class TestJsonParser:
    def test_json_parser_basic_dict(self) -> None:
        p = JsonParser()
        data = p.parse('{"user": "alice", "action": "login", "status": "ok"}')
        assert data == {"user": "alice", "action": "login", "status": "ok"}
        assert p.name == "json"

    @pytest.mark.parametrize("ts_key", ["timestamp", "time", "ts", "datetime"])
    def test_json_parser_timestamp_aliases_mapped_to_at_timestamp(self, ts_key: str) -> None:
        p = JsonParser()
        raw = f'{{"{ts_key}": "2026-09-19T03:00:00Z", "event": "audit"}}'
        data = p.parse(raw)
        assert data["@timestamp"] == "2026-09-19T03:00:00Z"
        assert ts_key not in data
        assert data["event"] == "audit"

    def test_json_parser_preserves_existing_at_timestamp(self) -> None:
        p = JsonParser()
        raw = (
            '{"@timestamp": "2026-09-19T03:00:00Z", '
            '"timestamp": "2026-01-01T00:00:00Z", '
            '"time": "2025-01-01T00:00:00Z"}'
        )
        data = p.parse(raw)
        assert data["@timestamp"] == "2026-09-19T03:00:00Z"
        assert data.get("@timestamp") == "2026-09-19T03:00:00Z"

    def test_json_parser_timestamp_alias_priority(self) -> None:
        p = JsonParser()
        raw = '{"timestamp": "2026-09-19T03:00:00Z", "ts": "2026-01-01T00:00:00Z"}'
        data = p.parse(raw)
        assert data["@timestamp"] == "2026-09-19T03:00:00Z"

    @pytest.mark.parametrize("msg_key", ["msg", "log", "body"])
    def test_json_parser_message_aliases_mapped_to_message(self, msg_key: str) -> None:
        p = JsonParser()
        raw = f'{{"{msg_key}": "Failed connection attempt", "code": 403}}'
        data = p.parse(raw)
        assert data["message"] == "Failed connection attempt"
        assert msg_key not in data
        assert data["code"] == 403

    def test_json_parser_preserves_existing_message(self) -> None:
        p = JsonParser()
        raw = '{"message": "canonical message", "msg": "alias msg", "log": "alias log"}'
        data = p.parse(raw)
        assert data["message"] == "canonical message"

    def test_json_parser_field_map_renaming(self) -> None:
        p = JsonParser(
            field_map={
                "src_ip": "source.ip",
                "dst_ip": "destination.ip",
                "dport": "destination.port",
                "proto": "network.transport",
            }
        )
        raw = (
            '{"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", '
            '"dport": 443, "proto": "tcp", "unmapped": "keep_me"}'
        )
        data = p.parse(raw)
        assert data["source.ip"] == "10.0.0.1"
        assert data["destination.ip"] == "10.0.0.2"
        assert data["destination.port"] == 443
        assert data["network.transport"] == "tcp"
        assert data["unmapped"] == "keep_me"
        assert "src_ip" not in data

    def test_json_parser_static_fields(self) -> None:
        p = JsonParser(
            static_fields={
                "event.kind": "event",
                "event.category": ["network"],
                "observer.product": "suricata",
            }
        )
        raw = '{"alert": "SYN flood detected"}'
        data = p.parse(raw)
        assert data["alert"] == "SYN flood detected"
        assert data["event.kind"] == "event"
        assert data["event.category"] == ["network"]
        assert data["observer.product"] == "suricata"

    def test_json_parser_combined_features(self) -> None:
        p = JsonParser(
            field_map={"client_ip": "source.ip", "bytes_sent": "http.response.body.bytes"},
            static_fields={"observer.type": "proxy"},
        )
        raw = (
            '{"client_ip": "192.168.1.100", "ts": "2026-09-19T01:00:00Z", '
            '"msg": "GET /index.html", "bytes_sent": 1024}'
        )
        data = p.parse(raw)
        assert data["source.ip"] == "192.168.1.100"
        assert data["@timestamp"] == "2026-09-19T01:00:00Z"
        assert data["message"] == "GET /index.html"
        assert data["http.response.body.bytes"] == 1024
        assert data["observer.type"] == "proxy"
        assert "client_ip" not in data
        assert "ts" not in data
        assert "msg" not in data

    def test_json_parser_complex_and_nested_types(self) -> None:
        p = JsonParser()
        raw = """{
            "id": 12345,
            "ratio": 3.14159,
            "active": true,
            "metadata": null,
            "tags": ["prod", "dmz", "pci"],
            "geo": {"city": "New York", "coords": [-74.006, 40.7128]},
            "nested": {"level2": {"level3": "deep"}}
        }"""
        data = p.parse(raw)
        assert data["id"] == 12345
        assert data["ratio"] == 3.14159
        assert data["active"] is True
        assert data["metadata"] is None
        assert data["tags"] == ["prod", "dmz", "pci"]
        assert data["geo"] == {"city": "New York", "coords": [-74.006, 40.7128]}
        assert data["nested"]["level2"]["level3"] == "deep"

    def test_json_parser_unicode_escapes_and_special_characters(self) -> None:
        p = JsonParser()
        raw = (
            '{"user": "Günther Müller 🚀", '
            '"path": "C:\\\\Windows\\\\System32\\\\cmd.exe", '
            '"quote": "He said \\"hello\\""}'
        )
        data = p.parse(raw)
        assert data["user"] == "Günther Müller 🚀"
        assert data["path"] == "C:\\Windows\\System32\\cmd.exe"
        assert data["quote"] == 'He said "hello"'

    @pytest.mark.parametrize(
        "invalid_json",
        [
            "{not valid json}",
            "{'single_quotes': 'invalid'}",
            '{"unclosed": "string',
            '{"trailing": "comma",}',
            '{"missing_colon" "value"}',
            "",
            "   ",
            "\n\t",
        ],
    )
    def test_json_parser_malformed_syntax_raises_parse_error(self, invalid_json: str) -> None:
        p = JsonParser()
        with pytest.raises(ParseError) as exc_info:
            p.parse(invalid_json)
        err = exc_info.value
        assert err.parser_name == "json"
        assert err.raw == invalid_json
        assert "Malformed JSON" in err.message or "JSON" in err.message

    @pytest.mark.parametrize(
        "non_dict_root",
        [
            "[1, 2, 3]",
            '[{"nested": "dict"}]',
            '"just a json string"',
            "12345",
            "-42.5",
            "true",
            "false",
            "null",
        ],
    )
    def test_json_parser_non_dict_root_raises_parse_error(self, non_dict_root: str) -> None:
        p = JsonParser()
        with pytest.raises(ParseError) as exc_info:
            p.parse(non_dict_root)
        err = exc_info.value
        assert err.parser_name == "json"
        assert err.raw == non_dict_root
        assert "root must be an object/dict" in err.message.lower() or "object" in (
            err.message.lower()
        )

    def test_json_parser_truncated_and_trailing_garbage_raises(self) -> None:
        p = JsonParser()
        with pytest.raises(ParseError):
            p.parse('{"valid": true} trailing garbage after json')

        with pytest.raises(ParseError):
            p.parse('{"valid": true')


# =====================================================================
# RegexParser Tests & Edge Cases
# =====================================================================


class TestRegexParser:
    def test_regex_parser_single_pattern_match(self) -> None:
        p = RegexParser(patterns=[r"^User (?P<user>\w+) logged in from (?P<ip>\S+)$"])
        raw = "User alice logged in from 10.0.0.1"
        data = p.parse(raw)
        assert data == {"user": "alice", "ip": "10.0.0.1"}
        assert p.name == "regex"

    def test_regex_parser_multi_pattern_sequential_fallback(self) -> None:
        patterns = [
            r"^Failed password for (?P<user>\w+) from (?P<ip>\S+) port (?P<port>\d+)$",
            r"^Accepted publickey for (?P<user>\w+) from (?P<ip>\S+) port (?P<port>\d+)$",
            r"^Received disconnect from (?P<ip>\S+) port (?P<port>\d+)$",
        ]
        p = RegexParser(patterns=patterns)

        # Match pattern 1
        res1 = p.parse("Failed password for bob from 192.168.1.10 port 2222")
        assert res1 == {"user": "bob", "ip": "192.168.1.10", "port": "2222"}

        # Match pattern 2 (fallback from 1)
        res2 = p.parse("Accepted publickey for charlie from 192.168.1.20 port 3333")
        assert res2 == {"user": "charlie", "ip": "192.168.1.20", "port": "3333"}

        # Match pattern 3 (fallback from 1 & 2)
        res3 = p.parse("Received disconnect from 192.168.1.30 port 4444")
        assert res3 == {"ip": "192.168.1.30", "port": "4444"}
        assert "user" not in res3

    def test_regex_parser_omits_none_groups(self) -> None:
        pattern = r"^User (?P<user>\w+)(?:@(?P<domain>[\w\.]+))? connected$"
        p = RegexParser(patterns=[pattern])

        # Match with optional group present
        res_with = p.parse("User alice@corp.local connected")
        assert res_with == {"user": "alice", "domain": "corp.local"}

        # Match without optional group: groupdict() returns {"user": "alice", "domain": None}
        # RegexParser must strip "domain": None
        res_without = p.parse("User alice connected")
        assert res_without == {"user": "alice"}
        assert "domain" not in res_without

    def test_regex_parser_field_map(self) -> None:
        pattern = r"^auth: user=(?P<usr>\S+) src=(?P<src_ip>\S+) dst_port=(?P<port>\d+)$"
        p = RegexParser(
            patterns=[pattern],
            field_map={
                "usr": "user.name",
                "src_ip": "source.ip",
                "port": "destination.port",
            },
        )
        data = p.parse("auth: user=david src=172.16.0.5 dst_port=8080")
        assert data["user.name"] == "david"
        assert data["source.ip"] == "172.16.0.5"
        assert data["destination.port"] == "8080"
        assert "usr" not in data
        assert "src_ip" not in data
        assert "port" not in data

    def test_regex_parser_type_coercions(self) -> None:
        pattern = (
            r"^stat: code=(?P<code>\d+) latency=(?P<latency>[\d\.]+) "
            r"active=(?P<active>\w+) id=(?P<id>\d+)$"
        )
        p = RegexParser(
            patterns=[pattern],
            field_map={
                "code": "http.response.status_code",
                "latency": "event.duration",
                "active": "service.state",
            },
            type_coercions={
                "http.response.status_code": "int",
                "event.duration": "float",
                "service.state": "bool",
                "id": "str",
            },
        )
        data = p.parse("stat: code=200 latency=0.045 active=true id=999")
        assert data["http.response.status_code"] == 200
        assert isinstance(data["http.response.status_code"], int)
        assert data["event.duration"] == 0.045
        assert isinstance(data["event.duration"], float)
        assert data["service.state"] is True
        assert data["id"] == "999"

    @pytest.mark.parametrize(
        "bool_str,expected",
        [
            ("true", True),
            ("True", True),
            ("1", True),
            ("yes", True),
            ("false", False),
            ("False", False),
            ("0", False),
            ("no", False),
        ],
    )
    def test_regex_parser_bool_coercion_values(self, bool_str: str, expected: bool) -> None:
        p = RegexParser(
            patterns=[r"^flag=(?P<flag>\w+)$"],
            type_coercions={"flag": "bool"},
        )
        data = p.parse(f"flag={bool_str}")
        assert data["flag"] is expected

    def test_regex_parser_coercion_failure_resilience(self) -> None:
        p = RegexParser(
            patterns=[r"^val=(?P<num>\S+)$"],
            type_coercions={"num": "int"},
        )
        data = p.parse("val=not_a_number")
        assert data["num"] == "not_a_number"

    def test_regex_parser_static_fields(self) -> None:
        p = RegexParser(
            patterns=[r"^login (?P<user>\w+)$"],
            static_fields={
                "event.category": ["authentication"],
                "event.kind": "event",
                "observer.product": "custom-auth",
            },
        )
        data = p.parse("login eve")
        assert data["user"] == "eve"
        assert data["event.category"] == ["authentication"]
        assert data["event.kind"] == "event"
        assert data["observer.product"] == "custom-auth"

    def test_regex_parser_real_world_sshd_failed_password(self) -> None:
        pattern = (
            r"^Failed (?P<auth_method>\S+) for invalid user (?P<user>\S+) "
            r"from (?P<src_ip>\S+) port (?P<src_port>\d+) ssh2$"
        )
        p = RegexParser(
            patterns=[pattern],
            field_map={"src_ip": "source.ip", "src_port": "source.port", "user": "user.name"},
            static_fields={"event.category": ["authentication"], "event.outcome": "failure"},
            type_coercions={"source.port": "int"},
            parser_name="sshd",
        )
        raw = "Failed password for invalid user admin from 192.168.1.50 port 54321 ssh2"
        data = p.parse(raw)
        assert data["source.ip"] == "192.168.1.50"
        assert data["source.port"] == 54321
        assert data["user.name"] == "admin"
        assert data["auth_method"] == "password"
        assert data["event.category"] == ["authentication"]
        assert data["event.outcome"] == "failure"
        assert p.name == "sshd"

    def test_regex_parser_real_world_sshd_accepted_pubkey(self) -> None:
        pattern = (
            r"^Accepted (?P<auth_method>\S+) for (?P<user>\S+) "
            r"from (?P<src_ip>\S+) port (?P<src_port>\d+) ssh2"
        )
        p = RegexParser(
            patterns=[pattern],
            field_map={"src_ip": "source.ip", "src_port": "source.port", "user": "user.name"},
            static_fields={"event.category": ["authentication"], "event.outcome": "success"},
            type_coercions={"source.port": "int"},
            parser_name="sshd",
        )
        raw = "Accepted publickey for root from 10.0.0.1 port 2222 ssh2: RSA SHA256:abc123xyz"
        data = p.parse(raw)
        assert data["source.ip"] == "10.0.0.1"
        assert data["source.port"] == 2222
        assert data["user.name"] == "root"
        assert data["auth_method"] == "publickey"
        assert data["event.category"] == ["authentication"]
        assert data["event.outcome"] == "success"

    def test_regex_parser_real_world_nginx_combined_access(self) -> None:
        pattern = (
            r'^(?P<client_ip>\S+) \S+ (?P<remote_user>\S+) \[(?P<timestamp>[^\]]+)\] '
            r'"(?P<http_method>[A-Z]+) (?P<url_path>\S+) [^"]*" '
            r'(?P<status_code>\d{3}) (?P<body_bytes>\d+) '
            r'"(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"'
        )
        p = RegexParser(
            patterns=[pattern],
            field_map={
                "client_ip": "source.ip",
                "remote_user": "user.name",
                "timestamp": "@timestamp",
                "http_method": "http.request.method",
                "url_path": "url.original",
                "status_code": "http.response.status_code",
                "body_bytes": "http.response.body.bytes",
                "referrer": "http.request.referrer",
                "user_agent": "user_agent.original",
            },
            type_coercions={
                "http.response.status_code": "int",
                "http.response.body.bytes": "int",
            },
            static_fields={"event.category": ["web"]},
            parser_name="nginx_access",
        )
        raw = (
            '127.0.0.1 - frank [10/Oct/2026:13:55:36 +0000] "GET /api/v1/health HTTP/1.1" '
            '200 2326 "https://ref.com" "Mozilla/5.0"'
        )
        data = p.parse(raw)
        assert data["source.ip"] == "127.0.0.1"
        assert data["user.name"] == "frank"
        assert data["@timestamp"] == "10/Oct/2026:13:55:36 +0000"
        assert data["http.request.method"] == "GET"
        assert data["url.original"] == "/api/v1/health"
        assert data["http.response.status_code"] == 200
        assert data["http.response.body.bytes"] == 2326
        assert data["http.request.referrer"] == "https://ref.com"
        assert data["user_agent.original"] == "Mozilla/5.0"
        assert data["event.category"] == ["web"]

    def test_regex_parser_real_world_syslog_rfc3164(self) -> None:
        pattern = (
            r"^(?:<(?P<priority>\d{1,3})>)?"
            r"(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
            r"(?P<hostname>\S+)\s+"
            r"(?P<process_name>[a-zA-Z0-9_\.\-]+)(?:\[(?P<process_pid>\d+)\])?:\s+"
            r"(?P<message>.*)$"
        )
        p = RegexParser(
            patterns=[pattern],
            field_map={
                "hostname": "host.hostname",
                "process_name": "process.name",
                "process_pid": "process.pid",
            },
            type_coercions={"priority": "int", "process.pid": "int"},
            parser_name="syslog_generic",
        )
        raw = "<34>Oct 11 22:14:15 myhost sshd[1234]: session opened for user test"
        data = p.parse(raw)
        assert data["priority"] == 34
        assert data["host.hostname"] == "myhost"
        assert data["process.name"] == "sshd"
        assert data["process.pid"] == 1234
        assert data["message"] == "session opened for user test"

    def test_regex_parser_no_match_raises_parse_error(self) -> None:
        p = RegexParser(
            patterns=[r"^Expected format: (?P<data>\d+)$"],
            parser_name="test_regex",
        )
        raw = "Completely unexpected log string"
        with pytest.raises(ParseError) as exc_info:
            p.parse(raw)
        err = exc_info.value
        assert err.parser_name == "test_regex"
        assert err.raw == raw
        assert "No pattern matched" in err.message or "matched" in err.message

    def test_regex_parser_empty_raw_raises_parse_error(self) -> None:
        p = RegexParser(patterns=[r"^User (?P<user>\w+)$"])
        with pytest.raises(ParseError) as exc_info:
            p.parse("")
        assert exc_info.value.raw == ""

    def test_regex_parser_empty_patterns_list_raises_parse_error(self) -> None:
        p = RegexParser(patterns=[], parser_name="empty_regex")
        with pytest.raises(ParseError) as exc_info:
            p.parse("any string")
        assert exc_info.value.parser_name == "empty_regex"


# =====================================================================
# GrokParser Tests & Edge Cases
# =====================================================================


class TestGrokParser:
    def test_grok_parser_basic_match(self) -> None:
        p = GrokParser(patterns=["%{IP:src_ip} %{WORD:method} %{URIPATHPARAM:request}"])
        raw = "192.168.1.50 GET /api/v1/users?role=admin"
        data = p.parse(raw)
        assert data["src_ip"] == "192.168.1.50"
        assert data["method"] == "GET"
        assert data["request"] == "/api/v1/users?role=admin"
        assert p.name == "grok"

    def test_grok_parser_multi_pattern_sequential_fallback(self) -> None:
        patterns = [
            (
                "Failed %{WORD:auth_method} for invalid user %{USER:user} "
                "from %{IP:src_ip} port %{POSINT:src_port}"
            ),
            "Failed %{WORD:auth_method} for %{USER:user} from %{IP:src_ip} port %{POSINT:src_port}",
            (
                "Accepted %{WORD:auth_method} for %{USER:user} "
                "from %{IP:src_ip} port %{POSINT:src_port}"
            ),
        ]
        p = GrokParser(patterns=patterns)

        # Match pattern 1
        res1 = p.parse("Failed password for invalid user admin from 10.0.0.1 port 5555")
        assert res1["user"] == "admin"
        assert res1["src_ip"] == "10.0.0.1"

        # Match pattern 2 (fallback from 1)
        res2 = p.parse("Failed password for root from 10.0.0.2 port 6666")
        assert res2["user"] == "root"
        assert res2["src_ip"] == "10.0.0.2"

        # Match pattern 3 (fallback from 1 & 2)
        res3 = p.parse("Accepted publickey for deploy from 10.0.0.3 port 7777")
        assert res3["user"] == "deploy"
        assert res3["auth_method"] == "publickey"

    def test_grok_parser_custom_patterns(self) -> None:
        custom = {"TRANSACTION_ID": r"TX-[A-Z0-9]{8}"}
        pattern = "%{USER:user} processed %{TRANSACTION_ID:tx_id}"
        p = GrokParser(patterns=[pattern], custom_patterns=custom)
        raw = "alice processed TX-AB12CD34"
        data = p.parse(raw)
        assert data["user"] == "alice"
        assert data["tx_id"] == "TX-AB12CD34"

    def test_grok_parser_field_map_and_coercions(self) -> None:
        pattern = (
            "src=%{IP:src} dst_port=%{NUMBER:port} latency=%{NUMBER:lat} "
            "active=%{WORD:act}"
        )
        p = GrokParser(
            patterns=[pattern],
            field_map={
                "src": "source.ip",
                "port": "destination.port",
                "lat": "event.duration",
            },
            type_coercions={
                "destination.port": "int",
                "event.duration": "float",
                "act": "bool",
            },
            static_fields={"event.kind": "event"},
            parser_name="custom_grok",
        )
        raw = "src=172.16.1.1 dst_port=443 latency=0.012 active=true"
        data = p.parse(raw)
        assert data["source.ip"] == "172.16.01.1" or data["source.ip"] == "172.16.1.1"
        assert data["destination.port"] == 443
        assert isinstance(data["destination.port"], int)
        assert data["event.duration"] == 0.012
        assert isinstance(data["event.duration"], float)
        assert data["act"] is True
        assert data["event.kind"] == "event"
        assert p.name == "custom_grok"
        assert "src" not in data
        assert "port" not in data

    def test_grok_parser_coercion_failure_resilience(self) -> None:
        pattern = "val=%{WORD:val}"
        p = GrokParser(patterns=[pattern], type_coercions={"val": "int"})
        data = p.parse("val=non_numeric")
        assert data["val"] == "non_numeric"

    def test_grok_parser_no_match_raises_parse_error(self) -> None:
        p = GrokParser(patterns=["%{IP:ip}"], parser_name="ip_grok")
        with pytest.raises(ParseError) as exc_info:
            p.parse("not an ip address")
        err = exc_info.value
        assert err.parser_name == "ip_grok"
        assert "No grok pattern matched" in err.message or "matched" in err.message

    def test_grok_parser_empty_raw_raises_parse_error(self) -> None:
        p = GrokParser(patterns=["%{WORD:w}"])
        with pytest.raises(ParseError):
            p.parse("")


# =====================================================================
# Advanced JsonParser Edge Cases & Security Scenarios
# =====================================================================


class TestJsonParserAdvanced:
    def test_json_empty_object(self) -> None:
        p = JsonParser()
        assert p.parse("{}") == {}

    def test_json_null_values_preserved(self) -> None:
        p = JsonParser()
        raw = '{"user": null, "action": "logout", "error_code": null}'
        data = p.parse(raw)
        assert data["user"] is None
        assert data["action"] == "logout"
        assert data["error_code"] is None

    def test_json_epoch_numeric_timestamps(self) -> None:
        p = JsonParser()
        raw = '{"timestamp": 1726718400, "ts_float": 1726718400.123456}'
        data = p.parse(raw)
        assert data["@timestamp"] == 1726718400
        assert data["ts_float"] == 1726718400.123456
        assert "timestamp" not in data

    def test_json_keys_with_special_characters(self) -> None:
        p = JsonParser(
            field_map={
                "client ip": "source.ip",
                "x-request-id": "http.request.id",
                "event:type": "event.action",
            }
        )
        raw = '{"client ip": "1.1.1.1", "x-request-id": "req-123", "event:type": "click"}'
        data = p.parse(raw)
        assert data["source.ip"] == "1.1.1.1"
        assert data["http.request.id"] == "req-123"
        assert data["event.action"] == "click"

    def test_json_static_fields_override_parsed(self) -> None:
        p = JsonParser(static_fields={"service.name": "override_svc", "env": "prod"})
        raw = '{"service.name": "original_svc", "user": "alice"}'
        data = p.parse(raw)
        assert data["service.name"] == "override_svc"
        assert data["env"] == "prod"
        assert data["user"] == "alice"

    def test_json_multiline_strings_and_escapes(self) -> None:
        p = JsonParser()
        raw = (
            '{"message": "Exception in thread main:\\n\\tat com.example.Main(Main.java:42)\\n", '
            '"tabbed": "col1\\tcol2\\tcol3"}'
        )
        data = p.parse(raw)
        assert "\tat com.example.Main" in data["message"]
        assert "col1\tcol2" in data["tabbed"]

    def test_json_aws_cloudtrail_style_event(self) -> None:
        p = JsonParser(
            field_map={
                "eventTime": "@timestamp",
                "eventName": "event.action",
                "eventSource": "service.name",
                "sourceIPAddress": "source.ip",
            },
            static_fields={"cloud.provider": "aws"},
        )
        raw = (
            '{"eventVersion": "1.08", "eventTime": "2026-09-19T02:00:00Z", '
            '"eventSource": "iam.amazonaws.com", "eventName": "CreateUser", '
            '"sourceIPAddress": "203.0.113.25", "userAgent": "aws-cli/2.15.0", '
            '"requestParameters": {"userName": "new-developer"}}'
        )
        data = p.parse(raw)
        assert data["@timestamp"] == "2026-09-19T02:00:00Z"
        assert data["event.action"] == "CreateUser"
        assert data["service.name"] == "iam.amazonaws.com"
        assert data["source.ip"] == "203.0.113.25"
        assert data["cloud.provider"] == "aws"
        assert data["requestParameters"]["userName"] == "new-developer"

    def test_json_large_payload_handling(self) -> None:
        p = JsonParser()
        large_text = "x" * 20000
        raw = f'{{"query": "{large_text}", "status": 200}}'
        data = p.parse(raw)
        assert len(data["query"]) == 20000
        assert data["status"] == 200


# =====================================================================
# Advanced RegexParser Edge Cases & Security Signatures
# =====================================================================


class TestRegexParserAdvanced:
    def test_regex_cisco_asa_firewall_log(self) -> None:
        pattern = (
            r"^%ASA-(?P<severity>\d)-(?P<msg_id>\d+): Built (?P<direction>\w+) "
            r"(?P<proto>\w+) connection \d+ for (?P<src_zone>\w+):(?P<src_ip>\S+)/"
            r"(?P<src_port>\d+) \([^)]+\) to (?P<dst_zone>\w+):(?P<dst_ip>\S+)/"
            r"(?P<dst_port>\d+)"
        )
        p = RegexParser(
            patterns=[pattern],
            field_map={
                "src_ip": "source.ip",
                "src_port": "source.port",
                "dst_ip": "destination.ip",
                "dst_port": "destination.port",
                "proto": "network.transport",
            },
            type_coercions={
                "source.port": "int",
                "destination.port": "int",
                "severity": "int",
            },
            static_fields={"observer.vendor": "Cisco", "observer.product": "ASA"},
        )
        raw = (
            "%ASA-6-302013: Built inbound TCP connection 987654 for "
            "outside:198.51.100.20/443 (198.51.100.20/443) "
            "to inside:10.0.1.5/51234 (10.0.1.5/51234)"
        )
        data = p.parse(raw)
        assert data["source.ip"] == "198.51.100.20"
        assert data["source.port"] == 443
        assert data["destination.ip"] == "10.0.1.5"
        assert data["destination.port"] == 51234
        assert data["network.transport"] == "TCP"
        assert data["severity"] == 6
        assert data["observer.vendor"] == "Cisco"

    def test_regex_suricata_ids_alert(self) -> None:
        pattern = (
            r"^\[\*\*\] \[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\] (?P<signature>[^\[]+) "
            r"\[\*\*\] \[Classification: (?P<category>[^\]]+)\] \[Priority: (?P<priority>\d+)\] "
            r"\{(?P<proto>\w+)\} (?P<src_ip>\S+):(?P<src_port>\d+) -> "
            r"(?P<dst_ip>\S+):(?P<dst_port>\d+)"
        )
        p = RegexParser(
            patterns=[pattern],
            field_map={
                "src_ip": "source.ip",
                "src_port": "source.port",
                "dst_ip": "destination.ip",
                "dst_port": "destination.port",
                "signature": "rule.name",
            },
            type_coercions={
                "source.port": "int",
                "destination.port": "int",
                "priority": "int",
                "sid": "int",
            },
            static_fields={"event.kind": "alert"},
        )
        raw = (
            "[**] [1:2001219:1] ET SCAN Potential SSH Scan [**] "
            "[Classification: Attempted Information Leak] [Priority: 2] "
            "{TCP} 192.168.1.100:45678 -> 10.0.0.1:22"
        )
        data = p.parse(raw)
        assert data["rule.name"].strip() == "ET SCAN Potential SSH Scan"
        assert data["source.ip"] == "192.168.1.100"
        assert data["source.port"] == 45678
        assert data["destination.ip"] == "10.0.0.1"
        assert data["destination.port"] == 22
        assert data["priority"] == 2
        assert data["sid"] == 2001219
        assert data["event.kind"] == "alert"

    def test_regex_ipv6_addresses_full_and_compressed(self) -> None:
        pattern = r"^conn from \[(?P<ip>[a-fA-F0-9:]+)\]:(?P<port>\d+)$"
        p = RegexParser(
            patterns=[pattern],
            type_coercions={"port": "int"},
        )
        # Compressed IPv6
        res1 = p.parse("conn from [2001:db8::1]:8080")
        assert res1["ip"] == "2001:db8::1"
        assert res1["port"] == 8080

        # Full IPv6
        res2 = p.parse("conn from [2001:0db8:85a3:0000:0000:8a2e:0370:7334]:443")
        assert res2["ip"] == "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        assert res2["port"] == 443

        # Loopback IPv6
        res3 = p.parse("conn from [::1]:22")
        assert res3["ip"] == "::1"
        assert res3["port"] == 22

    def test_regex_negative_numbers_and_scientific_coercions(self) -> None:
        pattern = r"^metrics: delta=(?P<delta>[-\d]+) rate=(?P<rate>[-\d\.eE]+)$"
        p = RegexParser(
            patterns=[pattern],
            type_coercions={"delta": "int", "rate": "float"},
        )
        data = p.parse("metrics: delta=-42 rate=-1.25e-3")
        assert data["delta"] == -42
        assert isinstance(data["delta"], int)
        assert data["rate"] == -0.00125
        assert isinstance(data["rate"], float)

    def test_regex_multiline_dotall_matching(self) -> None:
        pattern = r"(?s)^FATAL: (?P<error_msg>.*?) at (?P<location>\S+)$"
        p = RegexParser(patterns=[pattern])
        raw = "FATAL: NullPointerException\n  in Thread-1\n  details: timeout at Server.py:100"
        data = p.parse(raw)
        assert "NullPointerException\n  in Thread-1" in data["error_msg"]
        assert data["location"] == "Server.py:100"


# =====================================================================
# Advanced GrokParser Edge Cases & Network Formats
# =====================================================================


class TestGrokParserAdvanced:
    def test_grok_apache_combined_log_format(self) -> None:
        pattern = (
            '%{IPORHOST:client_ip} %{USER:ident} %{USER:auth} \\[%{HTTPDATE:timestamp}\\] '
            '"%{WORD:verb} %{DATA:request} HTTP/%{NUMBER:httpversion}" '
            '%{NUMBER:response:int} (?:%{NUMBER:bytes:int}|-) "%{DATA:referrer}" "%{DATA:agent}"'
        )
        p = GrokParser(
            patterns=[pattern],
            field_map={
                "client_ip": "source.ip",
                "auth": "user.name",
                "response": "http.response.status_code",
                "bytes": "http.response.body.bytes",
            },
            type_coercions={"http.response.status_code": "int"},
        )
        raw = (
            '10.1.2.3 - admin [19/Sep/2026:04:15:30 +0000] "POST /login HTTP/1.1" '
            '401 512 "https://example.com/portal" "curl/8.5.0"'
        )
        data = p.parse(raw)
        assert data["source.ip"] == "10.1.2.3"
        assert data["user.name"] == "admin"
        assert data["http.response.status_code"] == 401
        assert data["verb"] == "POST"

    def test_grok_syslog_rfc5424_with_iso8601(self) -> None:
        pattern = (
            "^<%{POSINT:priority}>1 %{TIMESTAMP_ISO8601:timestamp} %{HOSTNAME:hostname} "
            "%{WORD:app_name} %{POSINT:proc_id:int} %{WORD:msg_id} - %{GREEDYDATA:message}$"
        )
        p = GrokParser(
            patterns=[pattern],
            field_map={"hostname": "host.hostname", "app_name": "process.name"},
            type_coercions={"priority": "int"},
        )
        raw = (
            "<165>1 2026-09-19T04:20:00.123Z host.corp.internal "
            "auditd 1234 ID47 - user root granted sudo"
        )
        data = p.parse(raw)
        assert data["priority"] == 165
        assert data["host.hostname"] == "host.corp.internal"
        assert data["process.name"] == "auditd"
        assert data["message"] == "user root granted sudo"

    def test_grok_mac_address_and_email_patterns(self) -> None:
        pattern = "DHCPACK on %{IP:ip} to %{MAC:mac} via %{EMAILADDRESS:admin}"
        p = GrokParser(patterns=[pattern])
        raw = "DHCPACK on 192.168.1.150 to 00:11:22:33:44:55 via noc@corp.com"
        data = p.parse(raw)
        assert data["ip"] == "192.168.1.150"
        assert data["mac"] == "00:11:22:33:44:55"
        assert data["admin"] == "noc@corp.com"

    def test_grok_interdependent_custom_patterns(self) -> None:
        custom = {
            "CLUSTER_NAME": r"[a-z0-9\-]+",
            "POD_NAME": r"%{CLUSTER_NAME:cluster}\.[a-z0-9]+",
        }
        pattern = "Pod %{POD_NAME:pod} crashed with %{INT:exit_code:int}"
        p = GrokParser(
            patterns=[pattern],
            custom_patterns=custom,
            type_coercions={"exit_code": "int"},
        )
        raw = "Pod prod-us-east-1.frontend99 crashed with 137"
        data = p.parse(raw)
        assert data["cluster"] == "prod-us-east-1"
        assert data["pod"] == "prod-us-east-1.frontend99"
        assert data["exit_code"] == 137
        assert isinstance(data["exit_code"], int)
