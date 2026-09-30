from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable


VALID_TYPES = {"ip", "domain", "url", "hash"}
VALID_SEVERITIES = {"low", "medium", "high", "critical"}


@dataclass(frozen=True)
class Indicator:
    """Normalized cyber threat intelligence indicator."""

    value: str
    indicator_type: str
    severity: str
    confidence: int
    first_seen: datetime
    source: str
    tags: tuple[str, ...] = field(default_factory=tuple)
    mitre_techniques: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        indicator_type = self.indicator_type.lower().strip()
        severity = self.severity.lower().strip()

        if indicator_type not in VALID_TYPES:
            raise ValueError(f"Unsupported indicator type: {self.indicator_type}")
        if severity not in VALID_SEVERITIES:
            raise ValueError(f"Unsupported severity: {self.severity}")
        if not 0 <= self.confidence <= 100:
            raise ValueError("confidence must be between 0 and 100")
        if self.first_seen.tzinfo is None:
            object.__setattr__(self, "first_seen", self.first_seen.replace(tzinfo=timezone.utc))

        object.__setattr__(self, "indicator_type", indicator_type)
        object.__setattr__(self, "severity", severity)
        object.__setattr__(self, "value", self.value.strip())
        object.__setattr__(self, "source", self.source.strip())

    @staticmethod
    def tuple_from_csv(value: str | Iterable[str]) -> tuple[str, ...]:
        if isinstance(value, str):
            return tuple(item.strip() for item in value.split("|") if item.strip())
        return tuple(str(item).strip() for item in value if str(item).strip())
