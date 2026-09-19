"""Regex log parser for WeShieldSIEM."""

from __future__ import annotations

import contextlib
import re
from collections.abc import Callable
from typing import Any

from siem.parsers.base import ParseError, Parser

COERCION_REGISTRY: dict[str, Callable[[Any], Any]] = {
    "int": int,
    "float": float,
    "str": str,
    "bool": lambda v: str(v).lower() in ("true", "1", "yes"),
}


class RegexParser(Parser):
    """Parses log lines using compiled regular expressions with named groups."""

    name: str = "regex"

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
        """Parse raw string against configured regex patterns in order.

        Raises:
            ParseError: If no pattern matches.
        """
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
                with contextlib.suppress(ValueError, TypeError):
                    v = coercer(v)
            result[target_key] = v

        if self.static_fields:
            for sk, sv in self.static_fields.items():
                result[sk] = sv

        return result
