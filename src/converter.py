"""
Shared OCSF -> PlexTrac content conversion.

Used by both the online importer (API upload) and the offline .ptrac exporter so the two
modes produce identical titles, descriptions, recommendations and references.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .ocsf_parser import OCSFFinding
from .utils.cloud import asset_label_for_provider


@dataclass
class ConvertedFinding:
    """Source-agnostic PlexTrac finding content derived from one OCSF finding."""

    source: OCSFFinding
    title: str
    description_parts: List[str] = field(default_factory=list)
    recommendation: str = ""
    references: List[str] = field(default_factory=list)

    @property
    def asset_name(self) -> Optional[str]:
        """PlexTrac asset name for the finding's cloud account, if any."""
        return asset_name_for(self.source)


def asset_name_for(ocsf_finding: OCSFFinding) -> Optional[str]:
    """Asset name used for a finding's cloud account, e.g. 'AWS Account 123456789012'."""
    if not ocsf_finding.cloud_account_uid:
        return None
    label = asset_label_for_provider(ocsf_finding.cloud_provider)
    return f"{label} {ocsf_finding.cloud_account_uid}"


def convert_findings(ocsf_findings: List[OCSFFinding]) -> List[ConvertedFinding]:
    """Convert OCSF findings to PlexTrac content, making titles unique."""
    converted = []
    title_counts: Dict[str, int] = {}

    for ocsf_finding in ocsf_findings:
        # Use message as title, ensure uniqueness
        base_title = ocsf_finding.message or "Security Finding"
        title = base_title
        if title in title_counts:
            title_counts[title] += 1
            suffix = ocsf_finding.resource_name or ocsf_finding.class_name or title_counts[title]
            title = f"{base_title} ({suffix})"
        else:
            title_counts[title] = 1

        description_parts = []
        if ocsf_finding.message:
            description_parts.append(f"**Finding**: {ocsf_finding.message}")
        if ocsf_finding.resource_name:
            description_parts.append(f"**Resource**: {ocsf_finding.resource_name}")
        if ocsf_finding.resource_type:
            description_parts.append(f"**Resource Type**: {ocsf_finding.resource_type}")
        if ocsf_finding.cloud_provider:
            description_parts.append(f"**Cloud Provider**: {ocsf_finding.cloud_provider}")
        if ocsf_finding.cloud_region:
            description_parts.append(f"**Region**: {ocsf_finding.cloud_region}")
        if ocsf_finding.class_name:
            description_parts.append(f"**Class**: {ocsf_finding.class_name}")
        if ocsf_finding.category_name:
            description_parts.append(f"**Category**: {ocsf_finding.category_name}")
        if ocsf_finding.compliance_frameworks:
            description_parts.append(
                f"**Compliance**: {', '.join(ocsf_finding.compliance_frameworks)}"
            )

        raw_data = ocsf_finding.raw_data or {}
        converted.append(
            ConvertedFinding(
                source=ocsf_finding,
                title=title,
                description_parts=description_parts,
                recommendation=extract_remediation(raw_data) or "",
                references=extract_references(raw_data),
            )
        )

    return converted


def extract_remediation(raw_data: Dict[str, Any]) -> str:
    """Extract clean remediation text from raw data."""
    remediation_fields = ["remediation", "recommendation", "fix", "solution", "mitigation"]

    for field_name in remediation_fields:
        if field_name in raw_data and raw_data[field_name]:
            raw_rec = raw_data[field_name]
            if isinstance(raw_rec, dict):
                return (
                    raw_rec.get("desc")
                    or raw_rec.get("text")
                    or raw_rec.get("description")
                    or raw_rec.get("details")
                )
            elif isinstance(raw_rec, list):
                return ". ".join(str(item) for item in raw_rec if item)
            else:
                return str(raw_rec)

    # Check unmapped section
    unmapped = raw_data.get("unmapped", {})
    for field_name in ["Remediation", "Recommendation", "Fix", "Solution"]:
        if field_name in unmapped and unmapped[field_name]:
            raw_rec = unmapped[field_name]
            if isinstance(raw_rec, dict):
                # Prowler: {"Recommendation": {"Text": ..., "Url": ...}, "Code": {...}}
                nested = raw_rec.get("Recommendation")
                text = (
                    raw_rec.get("desc")
                    or raw_rec.get("text")
                    or raw_rec.get("Text")
                    or raw_rec.get("description")
                    or (nested.get("Text") if isinstance(nested, dict) else None)
                )
                if text:
                    return text
            else:
                return str(raw_rec)

    return ""


def _collect_refs(refs: Any, out: List[str]) -> None:
    if isinstance(refs, list):
        for ref in refs:
            if isinstance(ref, dict):
                url = ref.get("url") or ref.get("link") or ref.get("href")
                if url:
                    out.append(str(url))
            elif isinstance(ref, str) and ("http" in ref or "www." in ref):
                out.append(ref)
    elif isinstance(refs, str) and ("http" in refs or "www." in refs):
        out.append(refs)


def extract_references(raw_data: Dict[str, Any]) -> List[str]:
    """Extract clean reference URLs from raw data."""
    references: List[str] = []

    for field_name in ["references", "links", "urls", "external_links"]:
        if field_name in raw_data:
            _collect_refs(raw_data[field_name], references)

    unmapped = raw_data.get("unmapped", {})
    for field_name in ["References", "Links", "URLs", "External_Links", "RelatedUrl"]:
        if field_name in unmapped:
            _collect_refs(unmapped[field_name], references)

    # Prowler remediation links: OCSF remediation.references (v4+) and
    # unmapped.Remediation.Recommendation.Url (older output)
    remediation = raw_data.get("remediation")
    if isinstance(remediation, dict):
        _collect_refs(remediation.get("references"), references)
    unmapped_rem = unmapped.get("Remediation")
    if isinstance(unmapped_rem, dict) and isinstance(unmapped_rem.get("Recommendation"), dict):
        _collect_refs(unmapped_rem["Recommendation"].get("Url"), references)

    # De-duplicate, keeping first-seen order so output is deterministic
    return list(dict.fromkeys(ref for ref in references if ref and ref.strip()))


# ---------------------------------------------------------------------------
# Grouping: one PlexTrac finding per Prowler check, with every affected resource
# ---------------------------------------------------------------------------


@dataclass
class AffectedResource:
    """One resource a grouped finding applies to."""

    name: str  # PlexTrac asset name
    detail: str = ""  # Prowler's per-resource result (status_extended / message)
    resource_type: Optional[str] = None
    region: Optional[str] = None
    account: Optional[str] = None  # e.g. "AWS Account 123456789012"


@dataclass
class GroupedFinding:
    """A Prowler check that failed on one or more resources."""

    key: str
    title: str
    severity: str
    description_parts: List[str] = field(default_factory=list)
    recommendation: str = ""
    references: List[str] = field(default_factory=list)
    resources: List[AffectedResource] = field(default_factory=list)
    sources: List[OCSFFinding] = field(default_factory=list)
    manual: bool = False  # Prowler MANUAL result: needs human verification

    @property
    def category_name(self) -> Optional[str]:
        return self.sources[0].category_name if self.sources else None

    @property
    def cloud_providers(self) -> List[str]:
        return _unique(f.cloud_provider for f in self.sources)


def _dig(data: Dict[str, Any], *path: str) -> Any:
    for key in path:
        if not isinstance(data, dict):
            return None
        data = data.get(key)
    return data


def _unique(values) -> List[Any]:
    return list(dict.fromkeys(v for v in values if v))


_SEVERITY_RANK = {
    name: rank for rank, name in enumerate(["Critical", "High", "Medium", "Low", "Informational"])
}

MANUAL_TAG = "manual-check"
MANUAL_PREFIX = "MANUAL: "
MANUAL_NOTICE = (
    "**Manual check**: Prowler cannot evaluate this control automatically. Verify each "
    "affected resource by hand and update this finding's status in PlexTrac."
)


_OCSF_STATUS_TO_PROWLER = {"failed": "FAIL", "failure": "FAIL", "success": "PASS"}


def prowler_status(finding: OCSFFinding) -> str:
    """Prowler result: FAIL, PASS or MANUAL (upper-case), or "" if unknown.

    Newer output has status_code; older output keeps it in unmapped.Status, or only
    has the OCSF status ("Failed"/"Success").
    """
    code = finding.status_code or _dig(finding.raw_data or {}, "unmapped", "Status")
    if code:
        return str(code).strip().upper()
    return _OCSF_STATUS_TO_PROWLER.get((finding.status or "").strip().lower(), "")


def is_manual(finding: OCSFFinding) -> bool:
    """Prowler marks controls it can't evaluate automatically as MANUAL."""
    return prowler_status(finding) == "MANUAL"


def check_key(finding: OCSFFinding) -> str:
    """Identity of the Prowler check that produced a finding."""
    raw = finding.raw_data or {}
    return str(
        _dig(raw, "metadata", "event_code")
        or _dig(raw, "unmapped", "CheckId")
        or check_title(finding)
    )


def check_title(finding: OCSFFinding) -> str:
    """Generic (resource-independent) title of the check."""
    raw = finding.raw_data or {}
    return str(
        _dig(raw, "finding_info", "title")
        or _dig(raw, "unmapped", "CheckTitle")
        or _dig(raw, "finding", "title")
        or finding.message
        or "Security Finding"
    ).strip()


def _check_description(finding: OCSFFinding) -> Optional[str]:
    raw = finding.raw_data or {}
    return (
        _dig(raw, "finding_info", "desc")
        or _dig(raw, "unmapped", "Description")
        or _dig(raw, "finding", "desc")
    )


def _check_risk(finding: OCSFFinding) -> Optional[str]:
    raw = finding.raw_data or {}
    return raw.get("risk_details") or _dig(raw, "unmapped", "Risk")


def evidence_text(finding: OCSFFinding) -> str:
    """Prowler's verbatim per-resource result (STATUSEXTENDED), never rewritten."""
    raw = finding.raw_data or {}
    return str(
        finding.message or _dig(raw, "unmapped", "StatusExtended") or raw.get("status_detail") or ""
    ).strip()


def _resource_for(finding: OCSFFinding) -> AffectedResource:
    name = finding.resource_uid or finding.resource_name or asset_name_for(finding)
    return AffectedResource(
        name=str(name or "Unknown resource"),
        detail=evidence_text(finding),
        resource_type=finding.resource_type,
        region=finding.cloud_region,
        account=asset_name_for(finding),
    )


# ---------------------------------------------------------------------------
# Failure-state titles
#
# A Prowler check title states the EXPECTED/secure condition ("... is enabled"), so it
# must never be used as the title of a FAIL finding. The title is derived instead from
# Prowler's own FAIL evidence (STATUSEXTENDED): resource-specific identifiers are removed
# so the failing resources' messages collapse to one statement of what was observed.
# Nothing is negated or inferred from the check title's wording.
# ---------------------------------------------------------------------------

FAILED_CONTROL_PREFIX = "Failed Control: "
_MAX_TITLE_LEN = 150
_MIN_TITLE_WORDS = 3
_SCOPE_WORDS = (
    r"subscription|account|project|tenant|region|location|resource group|organization"
    r"|management group|folder|workspace|vault|server|namespace|cluster"
)
_CONNECTORS = r"from|in|for|of|on|within|at|under|belonging to"
_SMALL_WORDS = {
    "a",
    "an",
    "the",
    "and",
    "or",
    "nor",
    "but",
    "of",
    "for",
    "to",
    "in",
    "on",
    "at",
    "by",
    "with",
    "from",
    "as",
    "is",
    "are",
    "be",
    "via",
    "per",
    "than",
    "into",
}


def _identifiers(finding: OCSFFinding) -> List[str]:
    """Resource-specific strings that vary between affected resources."""
    raw = finding.raw_data or {}
    values = [
        finding.resource_uid,
        finding.resource_name,
        finding.cloud_account_uid,
        _dig(raw, "cloud", "account", "name"),
        _dig(raw, "cloud", "org", "name"),
        _dig(raw, "unmapped", "AccountName"),
        _dig(raw, "unmapped", "ResourceId"),
    ]
    for res in raw.get("resources") or []:
        if isinstance(res, dict):
            values += [res.get("uid"), res.get("name")]
    region = finding.cloud_region
    # Bare region names are only removed when they look like identifiers (eu-west-2),
    # so words such as "global" in the evidence are left alone.
    if region and re.search(r"[-\d]", region):
        values.append(region)
    cleaned = {str(v).strip() for v in values if v and len(str(v).strip()) >= 3}
    # Longest first so an ARN is removed before the name it contains
    return sorted(cleaned, key=len, reverse=True)


def failure_statement(finding: OCSFFinding) -> str:
    """The FAIL evidence with resource-specific identifiers removed (may be '')."""
    text = evidence_text(finding)
    if not text:
        return ""
    for ident in _identifiers(finding):
        quoted = rf"[\'\"`]?{re.escape(ident)}[\'\"`]?"
        # "... from subscription <id>" / "in region <id>" -> drop the whole phrase
        text = re.sub(
            rf"\s*\b(?:{_CONNECTORS})\s+(?:the\s+)?(?:{_SCOPE_WORDS})\s+{quoted}",
            "",
            text,
            flags=re.IGNORECASE,
        )
        text = re.sub(rf"(?<![\w-]){quoted}(?![\w-])", "", text)
    text = re.sub(r"\(\s*\)", "", text)
    text = re.sub(r"\s+([.,;:])", r"\1", text)
    text = re.sub(r"\s+", " ", text).strip(" .;:,-")
    return text


def _title_word(word: str) -> str:
    """Capitalise a plain lower-case word; leave acronyms/identifiers (DB, TDE, OFF) as is."""
    core = word.strip("()[]\"'.,;:")
    if core[:1].islower() and not any(c.isupper() or c.isdigit() for c in core[1:]):
        return word.replace(core, core[:1].upper() + core[1:], 1)
    return word


def _title_case(text: str) -> str:
    out = []
    for i, word in enumerate(text.split()):
        core = word.strip("()[]\"'.,;:")
        if i and core.lower() in _SMALL_WORDS:
            out.append(word.lower())
        else:
            # customer-managed -> Customer-Managed
            out.append("-".join(_title_word(part) for part in word.split("-")))
    return " ".join(out)


def failure_title(members: List[OCSFFinding]) -> str:
    """Title stating the failed condition, from the FAIL evidence of the group."""
    statements = [failure_statement(m) for m in members]
    counts: Dict[str, int] = {}
    for st in statements:
        if st:
            counts[st] = counts.get(st, 0) + 1
    if counts:
        best = max(counts, key=lambda st: (counts[st], -len(st)))
        if len(best.split()) >= _MIN_TITLE_WORDS and len(best) <= _MAX_TITLE_LEN:
            return _title_case(best)
    # No usable evidence: say plainly that the control failed rather than presenting the
    # expected state as if it were the finding.
    return f"{FAILED_CONTROL_PREFIX}{check_title(members[0])}"


def group_findings(ocsf_findings: List[OCSFFinding]) -> List[GroupedFinding]:
    """Group Prowler FAIL (and MANUAL) results by check: one finding, many resources.

    - Only FAIL and MANUAL results are used; anything else (e.g. PASS) is ignored here
      too, so passed resources can never end up as affected assets.
    - FAIL titles describe the observed failure (see failure_title); MANUAL titles are
      "MANUAL: <control to verify>".
    - Each resource keeps its verbatim Prowler evidence.
    - Groups keep first-seen order; severity is the most severe in the group.
    """
    groups: Dict[tuple, List[OCSFFinding]] = {}
    for finding in ocsf_findings:
        status = prowler_status(finding)
        if status not in ("FAIL", "MANUAL"):
            continue
        groups.setdefault((check_key(finding), status == "MANUAL"), []).append(finding)

    result: List[GroupedFinding] = []
    title_owner: Dict[str, tuple] = {}
    for group_id, members in groups.items():
        key, manual = group_id
        first = members[0]
        # Rank by severity name, not severity_id, so this holds whatever ID mapping is used
        worst = min(members, key=lambda f: _SEVERITY_RANK.get(f.severity, len(_SEVERITY_RANK)))

        expected = check_title(first)
        title = f"{MANUAL_PREFIX}{expected}" if manual else failure_title(members)
        # Different checks can produce the same title; keep PlexTrac titles unique
        if title_owner.setdefault(title, group_id) != group_id:
            title = f"{title} ({key})"

        resources: Dict[str, AffectedResource] = {}
        for member in members:
            res = _resource_for(member)
            if res.name in resources:
                existing = resources[res.name]
                if res.detail and res.detail not in existing.detail:
                    existing.detail = "; ".join(filter(None, [existing.detail, res.detail]))
            else:
                resources[res.name] = res

        description = _check_description(first)
        expectation = expected if not description else f"{expected}. {description}"
        parts = []
        if manual:
            parts.append(MANUAL_NOTICE)
            parts.append(f"**Control to Verify**: {expectation}")
        else:
            parts.append(f"**Security Control Expects**: {expectation}")
            observed = _unique(failure_statement(m) for m in members)
            if observed:
                parts.append(
                    "**Prowler Observed (FAIL)**: "
                    + "; ".join(observed)
                    + " (per-resource evidence below)"
                )
        risk = _check_risk(first)
        if risk:
            parts.append(f"**Why It Matters**: {risk}")
        providers = _unique(m.cloud_provider for m in members)
        if providers:
            parts.append(f"**Cloud Provider**: {', '.join(providers)}")
        accounts = _unique(m.cloud_account_uid for m in members)
        if accounts:
            parts.append(f"**Accounts**: {', '.join(accounts)}")
        regions = _unique(m.cloud_region for m in members)
        if regions:
            parts.append(f"**Regions**: {', '.join(regions)}")
        types = _unique(m.resource_type for m in members)
        if types:
            parts.append(f"**Resource Type**: {', '.join(types)}")
        compliance = _unique(c for m in members for c in m.compliance_frameworks)
        if compliance:
            parts.append(f"**Compliance**: {', '.join(compliance)}")
        parts.append(f"**Prowler Check**: {key}")
        label = "Resources to Review" if manual else "Failed Resources"
        parts.append(f"**{label}**: {len(resources)}")

        recommendation = ""
        for member in members:
            recommendation = extract_remediation(member.raw_data or {}) or ""
            if recommendation:
                break

        result.append(
            GroupedFinding(
                key=key,
                title=title,
                severity=worst.severity,
                description_parts=parts,
                recommendation=recommendation,
                references=_unique(
                    ref for m in members for ref in extract_references(m.raw_data or {})
                ),
                resources=list(resources.values()),
                sources=members,
                manual=manual,
            )
        )
    return result
