"""
FAIL findings must describe the observed failure, never the expected/secure state.

Prowler check titles state the expected condition ("... is enabled"). STATUS and
STATUSEXTENDED (OCSF status_code / message) state what was observed. These tests pin:
- titles come from the FAIL evidence, not the check title
- the evidence itself is carried through verbatim
- descriptions separate expectation / observation / impact / failed resources
- PASS resources can never appear as affected assets
"""

import csv

import pytest

from src.converter import FAILED_CONTROL_PREFIX, failure_title, group_findings
from src.csv_export import CSV_COLUMNS, build_csv_rows, write_csv
from src.ocsf_parser import OCSFParser
from src.ptrac import build_ptrac

SUB_ID = "8f6e2d10-1111-2222-3333-444455556666"
SUB_NAME = "Prod-Subscription"


def azure(check, check_title, status, name, evidence, severity="High", risk="Risk text."):
    """A Prowler v5 OCSF result for Azure, shaped like real output."""
    sev_ids = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Informational": 1}
    uid = f"/subscriptions/{SUB_ID}/resourceGroups/rg-prod/providers/x/{name}"
    return {
        "message": evidence,
        "status_code": status,
        "status": "New",
        "status_id": 1,
        "severity": severity,
        "severity_id": sev_ids[severity],
        "category_name": "Findings",
        "class_name": "Detection Finding",
        "finding_info": {
            "title": check_title,
            "desc": f"Description of {check}.",
            "uid": f"prowler-azure-{check}-{name}",
        },
        "risk_details": risk,
        "metadata": {"event_code": check, "product": {"name": "Prowler", "version": "5.4.0"}},
        "remediation": {"desc": "Fix it.", "references": ["https://learn.microsoft.com/x"]},
        "cloud": {
            "provider": "azure",
            "region": "uksouth",
            "account": {"uid": SUB_ID, "name": SUB_NAME},
        },
        "resources": [{"uid": uid, "name": name, "type": "AzureResource", "region": "uksouth"}],
    }


def parse(*raw):
    parser = OCSFParser()
    return [parser._parse_finding(r) for r in raw]


ACR = "containerregistry_not_publicly_accessible"
ACR_TITLE = "Container Registry public network access is disabled"
COSMOS = "defender_ensure_defender_for_cosmosdb_is_on"
COSMOS_TITLE = "Defender for Cosmos DB is set to On (Standard pricing tier)"
APPAUTH = "app_function_access_keys_configured"
APPAUTH_TITLE = "App Service app has App Service Authentication enabled"
SQLCMK = "sqlserver_tde_encrypted_with_cmk"
SQLCMK_TITLE = "SQL Server uses CMK for TDE"


@pytest.fixture
def mixed():
    return parse(
        azure(
            ACR,
            ACR_TITLE,
            "FAIL",
            "acrprod1",
            f"Container Registry acrprod1 from subscription {SUB_NAME} allows unrestricted "
            "network access.",
        ),
        azure(
            ACR,
            ACR_TITLE,
            "FAIL",
            "acrprod2",
            f"Container Registry acrprod2 from subscription {SUB_NAME} allows unrestricted "
            "network access.",
        ),
        azure(
            ACR,
            ACR_TITLE,
            "PASS",
            "acrlocked",
            f"Container Registry acrlocked from subscription {SUB_NAME} does not allow "
            "unrestricted network access.",
        ),
        azure(
            COSMOS,
            COSMOS_TITLE,
            "FAIL",
            "CosmosDbs",
            f"Defender plan Defender for Cosmos DB from subscription {SUB_NAME} is set to "
            "OFF (pricing tier not standard).",
        ),
        azure(
            APPAUTH,
            APPAUTH_TITLE,
            "FAIL",
            "webapp-orders",
            f"Authentication is not configured for app 'webapp-orders' in subscription "
            f"'{SUB_NAME}'.",
        ),
        azure(
            SQLCMK,
            SQLCMK_TITLE,
            "FAIL",
            "sql-prod-01",
            f"SQL Server sql-prod-01 from subscription {SUB_NAME} does not use a "
            "customer-managed key for TDE.",
        ),
    )


def by_key(findings):
    return {g.key: g for g in group_findings(findings)}


class TestTitlesDescribeTheFailure:
    @pytest.mark.parametrize(
        "check, expected_title, check_title",
        [
            (ACR, "Container Registry Allows Unrestricted Network Access", ACR_TITLE),
            (
                COSMOS,
                "Defender Plan Defender for Cosmos DB is Set to OFF (Pricing Tier Not Standard)",
                COSMOS_TITLE,
            ),
            (APPAUTH, "Authentication is Not Configured for App", APPAUTH_TITLE),
            (
                SQLCMK,
                "SQL Server Does Not Use a Customer-Managed Key for TDE",
                SQLCMK_TITLE,
            ),
        ],
    )
    def test_title_comes_from_fail_evidence(self, mixed, check, expected_title, check_title):
        group = by_key(mixed)[check]
        assert group.title == expected_title
        assert group.title != check_title

    def test_no_fail_title_repeats_the_expected_state(self, mixed):
        for group in group_findings(mixed):
            expected_state = group.sources[0].raw_data["finding_info"]["title"]
            assert expected_state.lower() not in group.title.lower()

    def test_titles_contain_no_resource_or_subscription_identifiers(self, mixed):
        for group in group_findings(mixed):
            for ident in (SUB_ID, SUB_NAME, "acrprod1", "sql-prod-01", "webapp-orders", "uksouth"):
                assert ident not in group.title

    def test_fallback_when_there_is_no_evidence(self):
        (finding,) = parse(azure(ACR, ACR_TITLE, "FAIL", "acr9", ""))
        title = failure_title([finding])
        assert title == f"{FAILED_CONTROL_PREFIX}{ACR_TITLE}"

    def test_fallback_when_evidence_is_only_an_identifier(self):
        (finding,) = parse(azure(ACR, ACR_TITLE, "FAIL", "acr9", "acr9"))
        assert failure_title([finding]).startswith(FAILED_CONTROL_PREFIX)

    def test_most_common_statement_wins_when_evidence_varies(self):
        findings = parse(
            azure(ACR, ACR_TITLE, "FAIL", "acr-a1", "Registry acr-a1 allows unrestricted access."),
            azure(ACR, ACR_TITLE, "FAIL", "acr-a2", "Registry acr-a2 allows unrestricted access."),
            azure(ACR, ACR_TITLE, "FAIL", "acr-a3", "Registry acr-a3 has public endpoint enabled."),
        )
        assert failure_title(findings) == "Registry Allows Unrestricted Access"


class TestEvidenceIntegrity:
    def test_pass_resource_never_an_affected_asset(self, mixed):
        group = by_key(mixed)[ACR]
        names = [r.name for r in group.resources]
        assert len(names) == 2
        assert not any("acrlocked" in n for n in names)

    def test_group_findings_ignores_pass_even_if_given_it(self):
        only_pass = parse(azure(ACR, ACR_TITLE, "PASS", "acrlocked", "does not allow ..."))
        assert group_findings(only_pass) == []

    def test_evidence_kept_verbatim_per_resource(self, mixed):
        group = by_key(mixed)[SQLCMK]
        (res,) = group.resources
        assert res.detail == (
            f"SQL Server sql-prod-01 from subscription {SUB_NAME} does not use a "
            "customer-managed key for TDE."
        )

    def test_ptrac_asset_notes_carry_verbatim_evidence(self, mixed):
        ptrac = build_ptrac(mixed, report_name="r", client_name="c", doc_version="2.10.1")
        flaw = next(f for f in ptrac["flaws_array"] if "Container Registry" in f["title"])
        notes = [a["notes"] for a in flaw["affected_assets"].values()]
        assert len(notes) == 2
        assert all("allows unrestricted network access." in n for n in notes)
        assert not any("does not allow" in n for n in notes)

    def test_description_sections(self, mixed):
        parts = by_key(mixed)[COSMOS].description_parts
        text = " | ".join(parts)
        assert f"**Security Control Expects**: {COSMOS_TITLE}." in text
        assert (
            "**Prowler Observed (FAIL)**: Defender plan Defender for Cosmos DB is set to OFF"
            in text
        )
        assert "**Why It Matters**: Risk text." in text
        assert "**Failed Resources**: 1" in text
        # Order: expectation, observation, impact
        idx = [text.index(k) for k in ("Expects", "Observed", "Why It Matters", "Failed Resources")]
        assert idx == sorted(idx)


class TestCsvOutput:
    def test_csv_rows(self, mixed, tmp_path):
        path = write_csv(mixed, tmp_path / "findings.csv")
        with open(path, encoding="utf-8", newline="") as f:
            rows = {r["title"]: r for r in csv.DictReader(f)}

        acr = rows["Container Registry Allows Unrestricted Network Access"]
        assert acr["affected_assets"].count(",") == 1  # two FAIL resources, no PASS
        assert "acrlocked" not in acr["affected_assets"]
        assert "acrlocked" not in acr["description"]
        assert "Failed resources and Prowler evidence:" in acr["description"]
        assert (
            f"Container Registry acrprod1 from subscription {SUB_NAME} allows unrestricted "
            "network access." in acr["description"]
        )
        assert len(rows) == 4  # 4 checks with FAIL results

    def test_manual_rows_keep_control_title(self):
        (manual,) = parse(
            azure(
                "iam_review", "Ensure custom roles are reviewed", "MANUAL", "sub", "Review roles."
            )
        )
        row = dict(zip(CSV_COLUMNS, build_csv_rows([manual])[0]))
        assert row["title"] == "MANUAL: Ensure custom roles are reviewed"
        assert "Control to Verify: " in row["description"]
        assert "Resources to review:" in row["description"]
