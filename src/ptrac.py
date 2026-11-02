"""
Offline .ptrac export.

Builds a PlexTrac report export (.ptrac) from OCSF findings so it can be uploaded manually:
- into an existing report: Findings tab -> Add findings -> File Imports -> source "PlexTrac"
- as a new report: Reports -> Import Report -> choose client -> drop the file

Schema follows PlexTrac-Labs' own JSON -> .ptrac converter
(https://github.com/PlexTrac-Labs/checkmarx-sca-json-to-ptrac-parser, save_data_as_ptrac).
Findings imported from a .ptrac skip PlexTrac's normal finding validation, so the metadata
PlexTrac would normally generate (flaw_id, sev, timestamps, data array, doc_version) is
filled in here.
"""

import html
import json
import re
import time
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from typing import Any, Dict, List, Optional

from .converter import MANUAL_TAG, AffectedResource, GroupedFinding, group_findings
from .ocsf_parser import OCSFFinding

SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"]
TAGS = ["prowler"]

_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
_BOLD_RE = re.compile(r"\*\*(.+?)\*\*")


def validate_doc_version(version: Optional[str]) -> bool:
    """A PlexTrac app version looks like '2.10.1'."""
    return bool(version) and bool(_VERSION_RE.match(version.strip()))


def generate_flaw_id(title: str) -> int:
    """Same title hash PlexTrac uses for flaw_id (and title-based de-duplication)."""
    return int(sha256(title.encode("utf-8")).hexdigest(), 16) % 10**8


def _markdownish_to_html(text: str) -> str:
    """Escape text and convert **bold** to <strong>; newlines become <br/>."""
    escaped = html.escape(text, quote=False)
    escaped = _BOLD_RE.sub(r"<strong>\1</strong>", escaped)
    return escaped.replace("\n", "<br/>")


def _paragraphs(parts: List[str]) -> str:
    return "".join(f"<p>{_markdownish_to_html(p)}</p>" for p in parts if p)


def _references_html(refs: List[str]) -> str:
    return "".join(f"<p>{html.escape(r, quote=False)}</p>" for r in refs)


def _empty_scores() -> Dict[str, Any]:
    return {
        "scores": {
            name: {"type": name, "calculation": "", "value": "", "label": ""}
            for name in ("cvss3", "cvss", "general")
        }
    }


def _asset_notes(resource: AffectedResource) -> str:
    """Per-resource detail kept on the affected-asset instance."""
    parts = []
    if resource.detail:
        parts.append(resource.detail)
    if resource.resource_type:
        parts.append(f"Type: {resource.resource_type}")
    if resource.region:
        parts.append(f"Region: {resource.region}")
    if resource.account:
        parts.append(resource.account)
    return html.escape("; ".join(parts), quote=False)


def _build_flaw(converted: GroupedFinding, doc_version: str, now_ms: int) -> Dict[str, Any]:
    severity = converted.severity
    if severity not in SEVERITIES:
        severity = "Informational"

    flaw: Dict[str, Any] = {
        "title": converted.title,
        "severity": severity,
        "status": "Open",
        "description": _paragraphs(converted.description_parts) or "<p>No description</p>",
        "recommendations": _paragraphs([converted.recommendation]),
        "references": _references_html(converted.references),
        "fields": _empty_scores(),
        "risk_score": {"CVSS3_1": {"overall": 0, "vector": ""}},
        "common_identifiers": {"CVE": [], "CWE": []},
        "tags": list(TAGS) + ([MANUAL_TAG] if converted.manual else []),
        "affected_assets": {},
        # Metadata PlexTrac normally generates on finding creation
        "flaw_id": generate_flaw_id(converted.title),
        "doc_type": "flaw",
        "source": "plextrac",
        "visibility": "published",
        "doc_version": doc_version,
        "createdAt": now_ms,
        "closedAt": None,
        "last_update": now_ms,
        "sev": SEVERITIES.index(severity),
        "assignedTo": None,
    }
    flaw["data"] = [
        flaw["flaw_id"],
        flaw["severity"],
        flaw["title"],
        flaw["status"],
        flaw["last_update"],
        flaw["assignedTo"],
        flaw["createdAt"],
        flaw["closedAt"],
        None,
        None,
        flaw["visibility"],
    ]
    return flaw


def build_ptrac(
    findings: List[OCSFFinding],
    *,
    report_name: str,
    client_name: str,
    doc_version: str,
    now: Optional[float] = None,
) -> Dict[str, Any]:
    """Build a .ptrac document (as a dict) from OCSF findings."""
    if not validate_doc_version(doc_version):
        raise ValueError(
            f"Invalid PlexTrac version {doc_version!r}: expected X.Y.Z "
            "(shown at the bottom right of the Account Admin page)"
        )
    doc_version = doc_version.strip()
    now_ms = int((time.time() if now is None else now) * 1000)

    report_assets: Dict[str, Dict[str, Any]] = {}
    asset_ids: Dict[str, str] = {}  # asset name -> synthetic id
    flaws = []

    for group in group_findings(findings):
        flaw = _build_flaw(group, doc_version, now_ms)

        for resource in group.resources:
            asset_name = resource.name
            if asset_name not in asset_ids:
                asset_id = str(len(asset_ids) + 1)
                asset_ids[asset_name] = asset_id
                report_assets[asset_id] = {
                    "id": asset_id,
                    "asset": asset_name,
                    "description": html.escape(
                        " ".join(filter(None, [resource.resource_type, resource.account])),
                        quote=False,
                    ),
                    "assetCriticality": None,
                    "hostname": "",
                    "knownIps": [],
                    "operating_system": [],
                    "tags": list(TAGS),
                    "ports": {},
                    "parent_asset": None,
                }
            asset_id = asset_ids[asset_name]
            affected = deepcopy(report_assets[asset_id])
            affected.update(
                {
                    "status": "Open",
                    "ports": {},
                    "locationUrl": "",
                    "vulnerableParameters": [],
                    "evidence": [],
                    "notes": _asset_notes(resource),
                }
            )
            flaw["affected_assets"][asset_id] = affected

        flaws.append(flaw)

    return {
        "report_info": {
            "doc_type": "report",
            "name": report_name,
            "status": "Draft",
            "tags": list(TAGS),
            "custom_field": [],
            "start_date": None,
            "end_date": None,
            "exec_summary": {"custom_fields": []},
            "includeEvidence": False,
            "reportType": "default",
        },
        "flaws_array": flaws,
        "summary": {"ReportAssets": report_assets},
        "evidence": [],
        "client_info": {
            "doc_type": "client",
            "name": client_name,
            "tags": list(TAGS),
            "custom_field": [],
            "description": "Client for Prowler findings imported from a .ptrac export.",
            "poc": "",
            "poc_email": "",
            "tenant_id": 0,
        },
    }


def write_ptrac(ptrac: Dict[str, Any], path) -> Path:
    """Write a .ptrac document as UTF-8 JSON and return the path written."""
    path = Path(path)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(ptrac, f, ensure_ascii=False)
    return path
