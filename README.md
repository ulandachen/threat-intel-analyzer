# Threat Intel Analyzer

A small Python cybersecurity project that turns raw threat intelligence indicators into a prioritized analyst report. It is designed as a portfolio project around practical CTI workflows: normalization, deduplication, risk scoring, and MITRE ATT&CK context.

## Why I built it

Threat intelligence feeds can contain repeated indicators from different sources, inconsistent formatting, and different confidence levels. Analysts still need a quick way to decide what deserves attention first. This project creates a simple pipeline that cleans those indicators and produces a readable report for triage.

## Features

- Reads indicators from CSV or JSON
- Supports IP addresses, domains, URLs, and hashes
- Normalizes and deduplicates repeated indicators
- Keeps the higher-confidence record when duplicates appear
- Calculates a 0-100 prioritization score using severity, confidence, and recency
- Includes MITRE ATT&CK technique context when it is available in the source data
- Generates a Markdown report sorted by risk
- Includes automated tests and a GitHub Actions CI workflow

## Project structure

```text
threat-intel-analyzer/
├── .github/workflows/ci.yml
├── data/sample_indicators.csv
├── examples/sample_report.md
├── src/threat_intel_analyzer/
│   ├── analyzer.py
│   ├── cli.py
│   ├── models.py
│   ├── parser.py
│   └── report.py
├── tests/
├── pyproject.toml
└── README.md
```

## Quick start

Requires Python 3.10+.

```bash
git clone https://github.com/ulandachen/threat-intel-analyzer.git
cd threat-intel-analyzer
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Run the analyzer against the included demo data:

```bash
threat-intel data/sample_indicators.csv -o threat_report.md
```

Run tests:

```bash
pytest -q
```

## Input format

CSV files should contain these fields:

```text
value,indicator_type,severity,confidence,first_seen,source,tags,mitre_techniques
```

`tags` and `mitre_techniques` may contain multiple values separated with `|`.

Example:

```text
198.51.100.24,ip,critical,96,2026-09-27T14:30:00Z,demo-feed,c2|malware,T1071|T1105
```

The sample indicators use documentation-only IP ranges and `.example` domains. They are intentionally non-operational.

## Risk scoring

The demo scoring model combines three signals:

1. **Severity** supplies the largest portion of the score.
2. **Confidence** contributes up to 20 points.
3. **Recency** contributes up to 5 points.

The result is capped at 100 and grouped into low, medium, high, or critical priority. This is meant to demonstrate analyst prioritization logic. A production system would need organization-specific weighting, source reliability, historical context, asset relevance, false-positive handling, and analyst validation.

## Example output

The generated Markdown report contains a risk summary, a table of prioritized indicators, and a count of included MITRE ATT&CK techniques. See [`examples/sample_report.md`](examples/sample_report.md).

## Ideas for the next version

- Add live enrichment through a public threat intelligence API
- Export STIX 2.1 objects
- Track source reliability separately from indicator confidence
- Add a small dashboard for filtering by indicator type and risk level
- Correlate indicators across multiple feeds
- Add persistence with SQLite or PostgreSQL

## What this project demonstrates

This project demonstrates Python development, CTI data modeling, threat prioritization, MITRE ATT&CK mapping, defensive security thinking, automated testing, and CI/CD basics.

## Disclaimer

This project is for defensive cybersecurity learning and portfolio use. The included sample data is synthetic and non-operational.
