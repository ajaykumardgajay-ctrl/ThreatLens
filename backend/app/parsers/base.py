"""Shared result container for log parsers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from app.schemas.models import CanonicalEvent, ParseErrorItem


@dataclass
class ParseResult:
    format_detected: str
    total_lines: int
    events: List[CanonicalEvent] = field(default_factory=list)
    errors: List[ParseErrorItem] = field(default_factory=list)

    @property
    def parsed_count(self) -> int:
        return len(self.events)

    @property
    def skipped_count(self) -> int:
        return len(self.errors)
