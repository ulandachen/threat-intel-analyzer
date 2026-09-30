from __future__ import annotations

import argparse
from pathlib import Path

from .analyzer import analyze_indicators
from .parser import load_indicators
from .report import markdown_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="threat-intel",
        description="Normalize and prioritize cyber threat intelligence indicators.",
    )
    parser.add_argument("input", help="Path to a CSV or JSON indicator file")
    parser.add_argument(
        "-o",
        "--output",
        default="threat_report.md",
        help="Markdown report output path (default: threat_report.md)",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    indicators = load_indicators(args.input)
    results = analyze_indicators(indicators)
    report = markdown_report(results)

    output_path = Path(args.output)
    output_path.write_text(report, encoding="utf-8")
    print(f"Analyzed {len(results)} unique indicators")
    print(f"Report written to {output_path}")


if __name__ == "__main__":
    main()
