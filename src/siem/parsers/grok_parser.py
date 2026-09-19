"""Grok log parser for WeShieldSIEM."""

from __future__ import annotations

import contextlib
from typing import Any

import pygrok  # type: ignore[import-untyped]

from siem.parsers.base import ParseError, Parser
from siem.parsers.regex_parser import COERCION_REGISTRY


class GrokParser(Parser):
    """Parses log lines using pygrok patterns with multi-pattern fallback."""

    name: str = "grok"

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
        """Parse raw string against configured Grok patterns in order.

        Raises:
            ParseError: If no pattern matches.
        """
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
                with contextlib.suppress(ValueError, TypeError):
                    v = coercer(v)
            result[target_key] = v

        if self.static_fields:
            for sk, sv in self.static_fields.items():
                result[sk] = sv

        return result
