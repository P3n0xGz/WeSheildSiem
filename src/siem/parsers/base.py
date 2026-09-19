"""Base interfaces and exceptions for WeShieldSIEM log parsers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class ParseError(Exception):
    """Raised when a parser fails to match or parse a raw log line."""

    def __init__(self, message: str, raw: str = "", parser_name: str = "") -> None:
        super().__init__(message)
        self.message = message
        self.raw = raw
        self.parser_name = parser_name

    def __str__(self) -> str:
        prefix = f"[{self.parser_name}] " if self.parser_name else ""
        raw_repr = f": {self.raw[:100]!r}" if self.raw else ""
        return f"{prefix}{self.message}{raw_repr}"


class Parser(ABC):
    """Abstract interface for all log parsers."""

    name: str = "base"

    @abstractmethod
    def parse(self, raw: str) -> dict[str, Any]:
        """Parse raw log text into a dictionary of fields.

        Parameters:
            raw: Unparsed log line string.

        Returns:
            Dictionary containing parsed fields (typically flat or dotted-key ECS fields).

        Raises:
            ParseError: If the raw payload cannot be parsed or matched.
        """
        ...
