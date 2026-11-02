"""
Offline CSV export in PlexTrac's "Report Findings CSV Template" format.

Upload in a report: Findings tab -> Add Findings -> "CSV" -> choose file -> Continue -> Upload.

Column order is fixed by the template schema (PlexTrac docs, "Using Report Findings CSV
Template"): title, severity, status, description, recommendations, references,
affected_assets, tags, cvss_temporal, cwe, cve, category. In references, affected_assets and
tags, a comma separates values, so commas inside a single value are replaced.

Findings are grouped per Prowler check: one row per check, with every failing resource
listed in affected_assets.

Output mirrors "PlexTrac Finding CSV Template v3.2.csv": exact header, CRLF line endings,
minimal quoting, multi-value cells joined with a bare ",", and every cell on a single line.
"""

import csv
import re
from pathlib import Path
from typing import Iterable, List

from .converter import MANUAL_TAG, GroupedFinding, group_findings
from .ocsf_parser import OCSFFinding

CSV_COLUMNS = [
    "title",
    "severity",
    "status",
    "description",
    "recommendations",
    "references",
    "affected_assets",
    "tags",
    "cvss_temporal",
    "cwe",
    "cve",
    "category",
]
SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"]
TAGS = ["prowler"]

_BOLD_RE = re.compile(r"\*\*(.+?)\*\*")
_WS_RE = re.compile(r"\s+")
DESCRIPTION_SEPARATOR = " | "
# Cap on per-resource result lines in a description cell
MAX_RESOURCE_DETAILS = 200


def _cell(value) -> str:
    """Single-line cell text: line breaks and runs of whitespace collapse to one space."""
    return _WS_RE.sub(" ", str(value or "")).strip()


def _multi_value(values: Iterable[str]) -> str:
    """Join values with ',' for a multi-value column; commas inside a value would split it."""
    cleaned = []
    for value in values:
        value = _cell(str(value).replace(",", " "))
        if value and value not in cleaned:
            cleaned.append(value)
    return ",".join(cleaned)


def _plain_text(parts: List[str]) -> str:
    """Description parts on one line (markdown bold markers removed)."""
    return DESCRIPTION_SEPARATOR.join(_cell(_BOLD_RE.sub(r"\1", p)) for p in parts if p)


def _resource_details(group: GroupedFinding) -> str:
    """Per-resource Prowler results, since CSV affected assets carry names only."""
    lines = [f"{r.name}: {r.detail}" if r.detail else r.name for r in group.resources]
    if len(lines) > MAX_RESOURCE_DETAILS:
        extra = len(lines) - MAX_RESOURCE_DETAILS
        lines = lines[:MAX_RESOURCE_DETAILS] + [f"... and {extra} more"]
    return "Details: " + "; ".join(_cell(line) for line in lines)


def build_csv_rows(findings: List[OCSFFinding]) -> List[List[str]]:
    """Build template-ordered rows (without header): one row per Prowler check."""
    rows = []
    for group in group_findings(findings):
        severity = group.severity if group.severity in SEVERITIES else "Informational"
        tags = list(TAGS) + [p.lower() for p in group.cloud_providers]
        if group.manual:
            tags.append(MANUAL_TAG)
        description = _plain_text(group.description_parts + [_resource_details(group)])

        rows.append(
            [
                _cell(group.title),
                severity,
                "Open",
                description or "No description",
                _cell(group.recommendation),
                _multi_value(group.references),
                _multi_value(r.name for r in group.resources),
                _multi_value(tags),
                "",
                "",
                "",
                _cell(group.category_name),
            ]
        )
    return rows


def write_csv(findings: List[OCSFFinding], path) -> Path:
    """Write findings as a PlexTrac findings CSV (UTF-8) and return the path."""
    path = Path(path)
    with open(path, "w", encoding="utf-8", newline="") as f:
        # csv's default "excel" dialect matches the template: CRLF rows, minimal quoting,
        # embedded quotes doubled.
        writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL, lineterminator="\r\n")
        writer.writerow(CSV_COLUMNS)
        writer.writerows(build_csv_rows(findings))
    return path
