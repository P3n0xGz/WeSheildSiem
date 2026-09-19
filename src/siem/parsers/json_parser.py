"""JSON log parser for WeShieldSIEM."""

from __future__ import annotations

import json
from typing import Any

from siem.parsers.base import ParseError, Parser


class JsonParser(Parser):
    """Parses JSON-formatted log lines into flat or structured dictionaries."""

    name: str = "json"

    def __init__(
        self,
        field_map: dict[str, str] | None = None,
        static_fields: dict[str, Any] | None = None,
    ) -> None:
        self.field_map = field_map or {}
        self.static_fields = static_fields or {}

    def parse(self, raw: str) -> dict[str, Any]:
        """Parse raw JSON string into a dictionary.

        Raises:
            ParseError: If raw is not valid JSON or root is not an object/dict.
        """
        try:
            data = json.loads(raw)
        except Exception as exc:
            raise ParseError(f"Malformed JSON: {exc}", raw=raw, parser_name=self.name) from exc

        if not isinstance(data, dict):
            raise ParseError("JSON root must be an object/dict", raw=raw, parser_name=self.name)

        result: dict[str, Any] = {}
        for k, v in data.items():
            key_str = str(k)
            target_key = self.field_map.get(key_str, key_str)
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
