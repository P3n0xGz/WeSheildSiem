"""Tests for parsing realistic sample log data in sample-data/."""

from __future__ import annotations

from pathlib import Path

from siem.parsers.base import ParseError
from siem.parsers.grok_parser import GrokParser
from siem.parsers.json_parser import JsonParser
from siem.parsers.regex_parser import RegexParser

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "sample-data"


class TestSampleDataParsing:
    def test_sample_firewall_json(self) -> None:
        file_path = SAMPLE_DIR / "firewall.json"
        assert file_path.exists(), f"Missing sample file: {file_path}"

        parser = JsonParser(
            field_map={
                "src_ip": "source.ip",
                "dst_ip": "destination.ip",
                "src_port": "source.port",
                "dst_port": "destination.port",
                "proto": "network.transport",
                "action": "event.action",
            },
            static_fields={"event.category": ["network"]},
        )

        success_count = 0
        error_count = 0

        with open(file_path, encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    event = parser.parse(line)
                    success_count += 1
                    assert "@timestamp" in event
                    assert "source.ip" in event
                    assert "destination.ip" in event
                    assert "event.action" in event
                    assert event["event.category"] == ["network"]
                except ParseError:
                    error_count += 1

        assert success_count >= 90
        assert error_count == 3  # exactly 3 malformed lines at end of file

    def test_sample_nginx_access_regex(self) -> None:
        file_path = SAMPLE_DIR / "nginx-access.log"
        assert file_path.exists(), f"Missing sample file: {file_path}"

        pattern = (
            r'^(?P<client_ip>\S+) \S+ (?P<remote_user>\S+) \[(?P<timestamp>[^\]]+)\] '
            r'"(?P<http_method>[A-Z]+) (?P<url_path>\S+) [^"]*" '
            r'(?P<status_code>\d{3}) (?P<body_bytes>\d+) '
            r'"(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"'
        )
        parser = RegexParser(
            patterns=[pattern],
            field_map={
                "client_ip": "source.ip",
                "remote_user": "user.name",
                "timestamp": "@timestamp",
                "http_method": "http.request.method",
                "url_path": "url.original",
                "status_code": "http.response.status_code",
                "body_bytes": "http.response.body.bytes",
            },
            type_coercions={
                "http.response.status_code": "int",
                "http.response.body.bytes": "int",
            },
        )

        success_count = 0
        error_count = 0

        with open(file_path, encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    event = parser.parse(line)
                    success_count += 1
                    assert "source.ip" in event
                    assert "http.request.method" in event
                    assert isinstance(event["http.response.status_code"], int)
                    assert isinstance(event["http.response.body.bytes"], int)
                except ParseError:
                    error_count += 1

        assert success_count == 96
        assert error_count == 6  # 6 malformed lines

    def test_sample_nginx_access_grok(self) -> None:
        file_path = SAMPLE_DIR / "nginx-access.log"
        pattern = (
            "%{IPORHOST:client_ip} %{USER:ident} %{USER:auth} \\[%{HTTPDATE:timestamp}\\] "
            '"%{WORD:verb} %{DATA:request} HTTP/%{NUMBER:httpversion}" '
            '%{NUMBER:response:int} (?:%{NUMBER:bytes:int}|-) "%{DATA:referrer}" "%{DATA:agent}"'
        )
        parser = GrokParser(
            patterns=[pattern],
            field_map={
                "client_ip": "source.ip",
                "auth": "user.name",
                "response": "http.response.status_code",
                "bytes": "http.response.body.bytes",
                "verb": "http.request.method",
            },
            type_coercions={"http.response.status_code": "int", "http.response.body.bytes": "int"},
        )

        success_count = 0
        error_count = 0

        with open(file_path, encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    event = parser.parse(line)
                    success_count += 1
                    assert "source.ip" in event
                    assert isinstance(event["http.response.status_code"], int)
                except ParseError:
                    error_count += 1

        assert success_count == 96
        assert error_count == 6

    def test_sample_sshd_log_regex(self) -> None:
        file_path = SAMPLE_DIR / "sshd.log"
        assert file_path.exists(), f"Missing sample file: {file_path}"

        patterns = [
            (
                r"^Failed (?P<auth_method>\S+) for invalid user (?P<user>\S+) "
                r"from (?P<src_ip>\S+) port (?P<src_port>\d+) ssh2$"
            ),
            (
                r"^Failed (?P<auth_method>\S+) for (?P<user>\S+) "
                r"from (?P<src_ip>\S+) port (?P<src_port>\d+) ssh2$"
            ),
            (
                r"^Accepted (?P<auth_method>\S+) for (?P<user>\S+) "
                r"from (?P<src_ip>\S+) port (?P<src_port>\d+) ssh2"
                r"(?:: (?P<key_type>\S+) (?P<key_fingerprint>\S+))?"
            ),
            r"^Invalid user (?P<user>\S+) from (?P<src_ip>\S+) port (?P<src_port>\d+)$",
            (
                r"^Received disconnect from (?P<src_ip>\S+) port (?P<src_port>\d+):"
                r"(?P<disconnect_code>\d+): (?P<disconnect_msg>.*)$"
            ),
            (
                r"^Connection closed by (?:authenticating user (?P<user>\S+) )?"
                r"(?P<src_ip>\S+) port (?P<src_port>\d+).*$"
            ),
            (
                r"^pam_unix\(sshd:session\): session (?P<session_action>opened|closed) "
                r"for user (?P<user>\S+)(?: by \(uid=(?P<uid>\d+)\))?$"
            ),
        ]
        parser = RegexParser(
            patterns=patterns,
            field_map={
                "src_ip": "source.ip",
                "src_port": "source.port",
                "user": "user.name",
            },
            type_coercions={"source.port": "int"},
        )

        success_count = 0
        error_count = 0

        with open(file_path, encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    event = parser.parse(line)
                    success_count += 1
                    if "source.port" in event:
                        assert isinstance(event["source.port"], int)
                except ParseError:
                    error_count += 1

        assert success_count == 51
        assert error_count == 3  # exactly 3 malformed lines at end

    def test_sample_syslog_regex(self) -> None:
        file_path = SAMPLE_DIR / "syslog.log"
        assert file_path.exists(), f"Missing sample file: {file_path}"

        patterns = [
            (
                r"^<(?P<priority>\d{1,3})>1 (?P<timestamp>\S+) (?P<hostname>\S+) "
                r"(?P<app_name>\S+) (?P<proc_id>\S+) (?P<msg_id>\S+) "
                r"(?:-|\[(?P<structured_data>[^\]]+)\]) (?P<message>.*)$"
            ),
            (
                r"^<(?P<priority>\d{1,3})>(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) "
                r"(?P<hostname>\S+) (?P<app_name>[^:\[\s]+)"
                r"(?:\[(?P<proc_id>\d+)\])?: (?P<message>.*)$"
            ),
        ]
        parser = RegexParser(
            patterns=patterns,
            field_map={
                "hostname": "host.hostname",
                "app_name": "process.name",
                "proc_id": "process.pid",
            },
            type_coercions={"priority": "int", "process.pid": "int"},
        )

        success_count = 0
        error_count = 0

        with open(file_path, encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    event = parser.parse(line)
                    success_count += 1
                    assert isinstance(event["priority"], int)
                    assert "host.hostname" in event
                    assert "process.name" in event
                    assert "message" in event
                except ParseError:
                    error_count += 1

        assert success_count == 69
        assert error_count == 6  # 6 malformed lines
