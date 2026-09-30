from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone

from .models import Indicator


SEVERITY_POINTS = {
    "low": 15,
    "medium": 35,
    "high": 55,
    "critical": 75,
}


@dataclass(frozen=True)
class AnalyzedIndicator:
    indicator: Indicator
    risk_score: int
    risk_level: str
    age_days: int


def normalize_value(indicator: Indicator) -> str:
    value = indicator.value.strip()
    if indicator.indicator_type in {"domain", "url"}:
        return value.lower()
    return value


def risk_score(indicator: Indicator, now: datetime | None = None) -> int:
    now = now or datetime.now(timezone.utc)
    age_days = max((now - indicator.first_seen.astimezone(timezone.utc)).days, 0)

    if age_days <= 7:
        recency_points = 5
    elif age_days <= 30:
        recency_points = 3
    elif age_days <= 90:
        recency_points = 1
    else:
        recency_points = 0

    score = SEVERITY_POINTS[indicator.severity]
    score += round(indicator.confidence * 0.20)
    score += recency_points
    return min(score, 100)


def risk_level(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def deduplicate(indicators: list[Indicator]) -> list[Indicator]:
    """Keep the highest-confidence version of each type/value pair."""
    selected: dict[tuple[str, str], Indicator] = {}
    for indicator in indicators:
        key = (indicator.indicator_type, normalize_value(indicator))
        existing = selected.get(key)
        if existing is None or indicator.confidence > existing.confidence:
            selected[key] = indicator
    return list(selected.values())


def analyze_indicators(
    indicators: list[Indicator], now: datetime | None = None
) -> list[AnalyzedIndicator]:
    now = now or datetime.now(timezone.utc)
    results = []
    for indicator in deduplicate(indicators):
        score = risk_score(indicator, now=now)
        age_days = max((now - indicator.first_seen.astimezone(timezone.utc)).days, 0)
        results.append(
            AnalyzedIndicator(
                indicator=indicator,
                risk_score=score,
                risk_level=risk_level(score),
                age_days=age_days,
            )
        )
    return sorted(results, key=lambda item: item.risk_score, reverse=True)


def summarize(results: list[AnalyzedIndicator]) -> dict[str, object]:
    return {
        "total_indicators": len(results),
        "by_risk_level": dict(Counter(item.risk_level for item in results)),
        "by_type": dict(Counter(item.indicator.indicator_type for item in results)),
        "mitre_techniques": dict(
            Counter(
                technique
                for item in results
                for technique in item.indicator.mitre_techniques
            )
        ),
    }
