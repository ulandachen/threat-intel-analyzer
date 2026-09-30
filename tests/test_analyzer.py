from datetime import datetime, timezone

from threat_intel_analyzer.analyzer import analyze_indicators, deduplicate, risk_score
from threat_intel_analyzer.models import Indicator


NOW = datetime(2026, 9, 29, tzinfo=timezone.utc)


def make_indicator(**overrides):
    values = {
        "value": "evil.example",
        "indicator_type": "domain",
        "severity": "high",
        "confidence": 80,
        "first_seen": datetime(2026, 9, 27, tzinfo=timezone.utc),
        "source": "sample-feed",
        "tags": ("phishing",),
        "mitre_techniques": ("T1566",),
    }
    values.update(overrides)
    return Indicator(**values)


def test_recent_high_confidence_indicator_scores_high():
    indicator = make_indicator()
    assert risk_score(indicator, now=NOW) == 76


def test_deduplicate_keeps_highest_confidence():
    low = make_indicator(confidence=40)
    high = make_indicator(confidence=90, source="better-source")
    result = deduplicate([low, high])
    assert len(result) == 1
    assert result[0].confidence == 90
    assert result[0].source == "better-source"


def test_results_are_sorted_by_score():
    medium = make_indicator(value="a.example", severity="medium", confidence=60)
    critical = make_indicator(value="b.example", severity="critical", confidence=95)
    results = analyze_indicators([medium, critical], now=NOW)
    assert results[0].indicator.value == "b.example"
    assert results[0].risk_score > results[1].risk_score
