#!/usr/bin/env python3
"""WeShieldSIEM - Sample Data Verification Script.

Tests all parser implementations (JsonParser, RegexParser, GrokParser) against
the realistic log datasets in `sample-data/`.

Usage:
    uv run python scripts/test_sample_data.py
    uv run python scripts/test_sample_data.py --verbose
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from siem.parsers.base import ParseError, Parser
from siem.parsers.grok_parser import GrokParser
from siem.parsers.json_parser import JsonParser
from siem.parsers.regex_parser import RegexParser


def get_firewall_json_parser() -> JsonParser:
    return JsonParser(
        field_map={
            "src_ip": "source.ip",
            "dst_ip": "destination.ip",
            "src_port": "source.port",
            "dst_port": "destination.port",
            "proto": "network.transport",
            "action": "event.action",
        },
        static_fields={"event.category": ["network"], "observer.type": "firewall"},
    )


def get_nginx_regex_parser() -> RegexParser:
    pattern = (
        r'^(?P<client_ip>\S+) \S+ (?P<remote_user>\S+) \[(?P<timestamp>[^\]]+)\] '
        r'"(?P<http_method>[A-Z]+) (?P<url_path>\S+) [^"]*" '
        r'(?P<status_code>\d{3}) (?P<body_bytes>\d+) '
        r'"(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"'
    )
    return RegexParser(
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
        static_fields={"event.category": ["web"], "observer.product": "nginx"},
        type_coercions={
            "http.response.status_code": "int",
            "http.response.body.bytes": "int",
        },
    )


def get_sshd_regex_parser() -> RegexParser:
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
    return RegexParser(
        patterns=patterns,
        field_map={
            "src_ip": "source.ip",
            "src_port": "source.port",
            "user": "user.name",
        },
        static_fields={"event.category": ["authentication"], "observer.product": "OpenSSH"},
        type_coercions={"source.port": "int"},
    )


def get_syslog_regex_parser() -> RegexParser:
    # RFC 5424 or RFC 3164
    patterns = [
        # RFC 5424: <PRI>VERSION TIMESTAMP HOST APP PROCID MSGID [SD] MSG
        (
            r"^<(?P<priority>\d{1,3})>1 (?P<timestamp>\S+) (?P<hostname>\S+) "
            r"(?P<app_name>\S+) (?P<proc_id>\S+) (?P<msg_id>\S+) "
            r"(?:-|\[(?P<structured_data>[^\]]+)\]) (?P<message>.*)$"
        ),
        # RFC 3164: <PRI>Mmm dd hh:mm:ss HOST APP[PID]: MSG or APP: MSG
        (
            r"^<(?P<priority>\d{1,3})>(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) "
            r"(?P<hostname>\S+) (?P<app_name>[^:\[\s]+)(?:\[(?P<proc_id>\d+)\])?: (?P<message>.*)$"
        ),
    ]
    return RegexParser(
        patterns=patterns,
        field_map={
            "hostname": "host.hostname",
            "app_name": "process.name",
            "proc_id": "process.pid",
        },
        static_fields={"event.category": ["system"]},
        type_coercions={"priority": "int", "process.pid": "int"},
    )


def get_nginx_grok_parser() -> GrokParser:
    pattern = (
        "%{IPORHOST:client_ip} %{USER:ident} %{USER:auth} \\[%{HTTPDATE:timestamp}\\] "
        '"%{WORD:verb} %{DATA:request} HTTP/%{NUMBER:httpversion}" '
        '%{NUMBER:response:int} (?:%{NUMBER:bytes:int}|-) "%{DATA:referrer}" "%{DATA:agent}"'
    )
    return GrokParser(
        patterns=[pattern],
        field_map={
            "client_ip": "source.ip",
            "auth": "user.name",
            "response": "http.response.status_code",
            "bytes": "http.response.body.bytes",
            "verb": "http.request.method",
            "request": "url.original",
        },
        static_fields={"event.category": ["web"], "observer.product": "nginx"},
        type_coercions={"http.response.status_code": "int", "http.response.body.bytes": "int"},
    )


def parse_sample_file(
    path: Path,
    parser: Parser,
    expected_failures: int = 0,
    verbose: bool = False,
) -> tuple[int, int, list[dict[str, Any]], list[tuple[int, str, str]]]:
    """Parse a file line by line and collect stats."""
    total = 0
    success = 0
    parsed_samples: list[dict[str, Any]] = []
    errors: list[tuple[int, str, str]] = []

    with open(path, encoding="utf-8") as f:
        for idx, raw_line in enumerate(f, start=1):
            line = raw_line.strip()
            if not line:
                continue
            total += 1
            try:
                result = parser.parse(line)
                success += 1
                if len(parsed_samples) < 2:
                    parsed_samples.append(result)
                if verbose:
                    print(f"  [OK Line {idx:03d}] -> {json.dumps(result, default=str)[:120]}...")
            except ParseError as exc:
                errors.append((idx, line, str(exc)))
                if verbose:
                    print(f"  [ERROR Line {idx:03d}] -> {exc}")

    return total, success, parsed_samples, errors


def main() -> int:
    parser_args = argparse.ArgumentParser(description="Test WeShieldSIEM parsers on sample logs")
    parser_args.add_argument(
        "--verbose", "-v", action="store_true", help="Print every line parsed"
    )
    args = parser_args.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    sample_dir = repo_root / "sample-data"

    if not sample_dir.exists():
        print(f"Error: Sample directory not found at {sample_dir}", file=sys.stderr)
        return 1

    test_configs: list[dict[str, Any]] = [
        {
            "name": "Firewall Logs (NDJSON)",
            "file": sample_dir / "firewall.json",
            "parser": get_firewall_json_parser(),
            "expected_errors": 3,
        },
        {
            "name": "Nginx Access Logs (Regex)",
            "file": sample_dir / "nginx-access.log",
            "parser": get_nginx_regex_parser(),
            "expected_errors": 6,
        },
        {
            "name": "Nginx Access Logs (Grok)",
            "file": sample_dir / "nginx-access.log",
            "parser": get_nginx_grok_parser(),
            "expected_errors": 6,
        },
        {
            "name": "OpenSSH Auth Logs (Regex)",
            "file": sample_dir / "sshd.log",
            "parser": get_sshd_regex_parser(),
            "expected_errors": 3,
        },
        {
            "name": "Syslog RFC 3164 & 5424 (Regex)",
            "file": sample_dir / "syslog.log",
            "parser": get_syslog_regex_parser(),
            "expected_errors": 6,
        },
    ]

    print("=" * 80)
    print(" WeShieldSIEM Parser Sample Data Verification")
    print("=" * 80)

    overall_passed = True

    for item in test_configs:
        file_path = item["file"]
        name = item["name"]
        parser_inst = item["parser"]
        expected_errs = item["expected_errors"]

        print(f"\n📂 Testing Dataset: {name}")
        print(f"   File:   {file_path.relative_to(repo_root)}")
        print(f"   Parser: {parser_inst.__class__.__name__} ({parser_inst.name})")

        total, success, samples, errors = parse_sample_file(
            file_path, parser_inst, expected_errs, verbose=args.verbose
        )

        status_flag = "PASS" if len(errors) == expected_errs else "FAIL"
        if status_flag == "FAIL":
            overall_passed = False

        print(f"   Lines:  {total} total | {success} parsed successfully | {len(errors)} errors")
        print(
            f"   Status: [{status_flag}] "
            f"(Expected {expected_errs} malformed/error test lines, got {len(errors)})"
        )

        if samples:
            print("   Sample Parsed Event:")
            print(f"   {json.dumps(samples[0], indent=6)[:400]}...")

        if errors and not args.verbose:
            print("   Caught Expected ParseErrors:")
            for idx, raw, err in errors[:3]:
                snippet = raw if len(raw) <= 50 else f"{raw[:47]}..."
                print(f"     • Line {idx:02d}: '{snippet}' -> {err}")

    print("\n" + "=" * 80)
    if overall_passed:
        print("✅ ALL SAMPLE DATA TESTS PASSED PERFECTLY!")
        print("=" * 80)
        return 0
    else:
        print("❌ SOME DATASET TESTS FAILED UNEXPECTEDLY!")
        print("=" * 80)
        return 1


if __name__ == "__main__":
    sys.exit(main())
