from __future__ import annotations

from .analyzer import AnalyzedIndicator, summarize


def markdown_report(results: list[AnalyzedIndicator]) -> str:
    summary = summarize(results)
    lines = [
        "# Threat Intelligence Analysis Report",
        "",
        f"**Unique indicators analyzed:** {summary['total_indicators']}",
        "",
        "## Risk Summary",
        "",
    ]

    risk_counts = summary["by_risk_level"]
    for level in ("critical", "high", "medium", "low"):
        lines.append(f"- **{level.title()}**: {risk_counts.get(level, 0)}")

    lines.extend(
        [
            "",
            "## Prioritized Indicators",
            "",
            "| Score | Risk | Type | Indicator | Confidence | Source | Age | MITRE ATT&CK |",
            "|---:|---|---|---|---:|---|---:|---|",
        ]
    )

    for item in results:
        indicator = item.indicator
        techniques = ", ".join(indicator.mitre_techniques) or "-"
        safe_value = indicator.value.replace("|", "\\|")
        lines.append(
            f"| {item.risk_score} | {item.risk_level.title()} | "
            f"{indicator.indicator_type} | `{safe_value}` | {indicator.confidence}% | "
            f"{indicator.source} | {item.age_days}d | {techniques} |"
        )

    lines.extend(["", "## MITRE ATT&CK Coverage", ""])
    techniques = summary["mitre_techniques"]
    if techniques:
        for technique, count in sorted(techniques.items(), key=lambda x: (-x[1], x[0])):
            lines.append(f"- **{technique}**: {count} indicator(s)")
    else:
        lines.append("No ATT&CK techniques were included in the input data.")

    lines.extend(
        [
            "",
            "> Risk scores are a prioritization aid for this demo project and should not be treated as a replacement for analyst validation.",
            "",
        ]
    )
    return "\n".join(lines)
