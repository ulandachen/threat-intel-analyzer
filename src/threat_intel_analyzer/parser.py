from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path

from .models import Indicator


def parse_datetime(value: str) -> datetime:
    normalized = value.strip().replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def indicator_from_mapping(row: dict) -> Indicator:
    return Indicator(
        value=str(row["value"]),
        indicator_type=str(row["indicator_type"]),
        severity=str(row["severity"]),
        confidence=int(row["confidence"]),
        first_seen=parse_datetime(str(row["first_seen"])),
        source=str(row.get("source", "unknown")),
        tags=Indicator.tuple_from_csv(row.get("tags", "")),
        mitre_techniques=Indicator.tuple_from_csv(row.get("mitre_techniques", "")),
    )


def load_csv(path: Path) -> list[Indicator]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return [indicator_from_mapping(row) for row in csv.DictReader(handle)]


def load_json(path: Path) -> list[Indicator]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    if isinstance(payload, dict):
        payload = payload.get("indicators", [])
    if not isinstance(payload, list):
        raise ValueError("JSON input must be a list or contain an 'indicators' list")
    return [indicator_from_mapping(row) for row in payload]


def load_indicators(path: str | Path) -> list[Indicator]:
    input_path = Path(path)
    suffix = input_path.suffix.lower()
    if suffix == ".csv":
        return load_csv(input_path)
    if suffix == ".json":
        return load_json(input_path)
    raise ValueError("Supported input formats are .csv and .json")
