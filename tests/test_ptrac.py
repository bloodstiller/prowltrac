"""
Tests for offline .ptrac export.
"""

import json
from copy import deepcopy
import sys
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch

import pytest

from src.converter import check_key, check_title, prowler_status
from src.ocsf_parser import OCSFParser
from src.ptrac import build_ptrac, generate_flaw_id, validate_doc_version, write_ptrac

FIXTURE = Path(__file__).parent / "fixtures" / "sample_ocsf.json"
VERSION = "2.10.1"
NOW = 1_700_000_000.0


def variant(
    finding,
    *,
    uid,
    message=None,
    check_id=None,
    title=None,
    description=None,
    refs=None,
    **fields,
):
    """Copy of a parsed finding pointed at another resource / check."""
    raw = deepcopy(finding.raw_data or {})
    unmapped = raw.setdefault("unmapped", {})
    if check_id:
        raw.setdefault("metadata", {})["event_code"] = check_id
        unmapped["CheckId"] = check_id
    if title:
        unmapped["CheckTitle"] = title
        raw.pop("finding", None)
    if description:
        unmapped["Description"] = description
    if refs:
        raw["references"] = refs
    return replace(
        finding,
        resource_uid=uid,
        resource_name=uid,
        message=message if message is not None else finding.message,
        raw_data=raw,
        **fields,
    )


def reportable_checks(findings):
    """Checks that become PlexTrac findings: FAIL or MANUAL only, never PASS."""
    return {check_key(f) for f in findings if prowler_status(f) in ("FAIL", "MANUAL")}


@pytest.fixture
def findings():
    return OCSFParser().parse_file(str(FIXTURE))


def build(findings, **kwargs):
    defaults = dict(report_name="Report", client_name="Client", doc_version=VERSION, now=NOW)
    defaults.update(kwargs)
    return build_ptrac(findings, **defaults)


class TestBuildPtrac:
    def test_top_level_structure(self, findings):
        ptrac = build(findings)

        assert set(ptrac) == {"report_info", "flaws_array", "summary", "evidence", "client_info"}
        assert ptrac["report_info"]["doc_type"] == "report"
        assert ptrac["report_info"]["name"] == "Report"
        assert ptrac["client_info"]["doc_type"] == "client"
        assert ptrac["client_info"]["name"] == "Client"
        assert ptrac["client_info"]["tenant_id"] == 0
        assert ptrac["evidence"] == []
        assert len(ptrac["flaws_array"]) == len(reportable_checks(findings))
        # Must be plain JSON
        assert json.loads(json.dumps(ptrac)) == ptrac

    def test_flaw_metadata(self, findings):
        ptrac = build(findings)
        severities = ["Critical", "High", "Medium", "Low", "Informational"]

        for flaw in ptrac["flaws_array"]:
            expected_id = int(sha256(flaw["title"].encode()).hexdigest(), 16) % 10**8
            assert flaw["flaw_id"] == expected_id
            assert flaw["doc_type"] == "flaw"
            assert flaw["source"] == "plextrac"
            assert flaw["visibility"] == "published"
            assert flaw["doc_version"] == VERSION
            assert flaw["severity"] in severities
            assert flaw["sev"] == severities.index(flaw["severity"])
            assert flaw["createdAt"] == flaw["last_update"] == int(NOW * 1000)
            assert flaw["status"] == "Open"
            assert flaw["closedAt"] is None
            assert flaw["data"] == [
                flaw["flaw_id"],
                flaw["severity"],
                flaw["title"],
                "Open",
                flaw["last_update"],
                None,
                flaw["createdAt"],
                None,
                None,
                None,
                "published",
            ]

    def test_same_check_on_many_resources_is_one_flaw(self, findings):
        base = findings[0]
        group = [
            variant(
                base,
                uid="arn:aws:s3:::bucket-a",
                message="S3 Bucket arn:aws:s3:::bucket-a is public.",
            ),
            variant(
                base,
                uid="arn:aws:s3:::bucket-b",
                message="S3 Bucket arn:aws:s3:::bucket-b is public.",
            ),
            variant(
                base,
                uid="arn:aws:s3:::bucket-c",
                message="S3 Bucket arn:aws:s3:::bucket-c is public.",
            ),
        ]
        ptrac = build(group)

        assert len(ptrac["flaws_array"]) == 1
        flaw = ptrac["flaws_array"][0]
        # Title states the observed failure from the FAIL evidence (resource
        # identifiers removed), never the expected-state check title
        assert flaw["title"] == "S3 Bucket is Public"
        assert flaw["title"] != check_title(base)
        assets = {a["asset"]: a for a in flaw["affected_assets"].values()}
        assert sorted(assets) == [
            "arn:aws:s3:::bucket-a",
            "arn:aws:s3:::bucket-b",
            "arn:aws:s3:::bucket-c",
        ]
        assert (
            "S3 Bucket arn:aws:s3:::bucket-b is public." in assets["arn:aws:s3:::bucket-b"]["notes"]
        )
        assert "<strong>Failed Resources</strong>: 3" in flaw["description"]

    def test_different_checks_stay_separate(self, findings):
        ptrac = build(findings)
        assert len(ptrac["flaws_array"]) == len(reportable_checks(findings))

    def test_group_takes_worst_severity_and_merges_references(self, findings):
        base = findings[0]
        low = variant(base, uid="r1", severity="Low", severity_id=2, refs=["https://one.example"])
        crit = variant(
            base, uid="r2", severity="Critical", severity_id=5, refs=["https://two.example"]
        )
        flaw = build([low, crit])["flaws_array"][0]

        assert flaw["severity"] == "Critical"
        assert "https://one.example" in flaw["references"]
        assert "https://two.example" in flaw["references"]

    def test_same_resource_twice_is_one_asset(self, findings):
        base = findings[0]
        dupes = [
            variant(base, uid="r1", message="first"),
            variant(base, uid="r1", message="second"),
        ]
        flaw = build(dupes)["flaws_array"][0]
        (asset,) = flaw["affected_assets"].values()
        assert "first" in asset["notes"] and "second" in asset["notes"]

    def test_distinct_checks_sharing_a_title_get_unique_titles(self, findings):
        a = variant(findings[0], uid="r1", check_id="check_a", title="Same title")
        b = variant(findings[0], uid="r2", check_id="check_b", title="Same title")
        flaws = build([a, b])["flaws_array"]

        assert len({f["title"] for f in flaws}) == 2
        assert len({f["flaw_id"] for f in flaws}) == 2

    def test_assets_consistent_between_summary_and_flaws(self, findings):
        ptrac = build(findings)
        report_assets = ptrac["summary"]["ReportAssets"]

        resources = {f.resource_uid for f in findings if prowler_status(f) in ("FAIL", "MANUAL")}
        assert len(report_assets) == len(resources)

        for flaw in ptrac["flaws_array"]:
            for asset_id, affected in flaw["affected_assets"].items():
                assert asset_id in report_assets
                assert affected["id"] == asset_id
                assert affected["asset"] == report_assets[asset_id]["asset"]
                assert affected["status"] == "Open"
                assert affected["vulnerableParameters"] == []

    def test_asset_shared_across_checks_listed_once(self, findings):
        a = variant(findings[0], uid="shared", check_id="check_a", title="A")
        b = variant(findings[0], uid="shared", check_id="check_b", title="B")
        ptrac = build([a, b])
        assert len(ptrac["summary"]["ReportAssets"]) == 1
        assert [list(f["affected_assets"]) for f in ptrac["flaws_array"]] == [["1"], ["1"]]

    def test_falls_back_to_account_asset_without_resource(self, findings):
        bare = replace(
            findings[0],
            resource_uid=None,
            resource_name=None,
            cloud_provider="gcp",
            cloud_account_uid="proj-1",
        )
        flaw = build([bare])["flaws_array"][0]
        assert [a["asset"] for a in flaw["affected_assets"].values()] == ["GCP Project proj-1"]

    def test_recommendation_from_prowler_remediation(self, findings):
        flaw = build(findings[:1])["flaws_array"][0]
        assert "Remove public read access" in flaw["recommendations"]
        assert "docs.aws.amazon.com" in flaw["references"]

    def test_description_is_escaped_html(self, findings):
        evil = variant(findings[0], uid="r1", description="<script>alert(1)</script> & co")
        flaw = build([evil])["flaws_array"][0]

        assert "<script>" not in flaw["description"]
        assert "&lt;script&gt;" in flaw["description"]
        assert "<strong>Prowler Check</strong>" in flaw["description"]
        assert "\\n" not in flaw["description"]
        assert flaw["description"].startswith("<p>")

    def test_unknown_severity_falls_back(self, findings):
        flaw = build([replace(findings[0], severity="Weird")])["flaws_array"][0]
        assert flaw["severity"] == "Informational"
        assert flaw["sev"] == 4

    def test_invalid_version_rejected(self, findings):
        with pytest.raises(ValueError, match="X.Y.Z"):
            build(findings, doc_version="latest")

    def test_write_ptrac_roundtrip(self, findings, tmp_path):
        ptrac = build(findings)
        path = write_ptrac(ptrac, tmp_path / "out.ptrac")
        assert json.loads(path.read_text(encoding="utf-8")) == ptrac


def test_validate_doc_version():
    assert validate_doc_version("2.10.1")
    assert not validate_doc_version("2.10")
    assert not validate_doc_version("")
    assert not validate_doc_version(None)


def test_generate_flaw_id_is_stable():
    assert generate_flaw_id("abc") == generate_flaw_id("abc")
    assert 0 <= generate_flaw_id("abc") < 10**8


class TestCli:
    """End-to-end CLI: --ptrac must never authenticate or prompt."""

    def run_main(self, argv):
        import simple_import

        def no_network(*args, **kwargs):
            raise AssertionError("offline mode must not authenticate")

        with patch.object(sys, "argv", ["simple_import.py", *argv]), patch(
            "src.auth.auth_handler.AuthHandler.authenticate", side_effect=no_network
        ), patch("builtins.input", side_effect=AssertionError("offline mode must not prompt")):
            simple_import.main()

    def test_writes_ptrac_offline(self, tmp_path):
        out = tmp_path / "out"  # extension appended automatically
        self.run_main(
            [str(FIXTURE), "--filter", "all", "--ptrac", str(out), "--plextrac-version", VERSION]
        )

        written = tmp_path / "out.ptrac"
        ptrac = json.loads(written.read_text())
        assert len(ptrac["flaws_array"]) > 0
        assert ptrac["flaws_array"][0]["doc_version"] == VERSION

    def test_version_from_env(self, tmp_path, monkeypatch):
        monkeypatch.setenv("PLEXTRAC_APP_VERSION", VERSION)
        out = tmp_path / "env.ptrac"
        self.run_main([str(FIXTURE), "--filter", "all", "--ptrac", str(out)])
        assert out.exists()

    def test_missing_version_exits(self, tmp_path, monkeypatch):
        monkeypatch.delenv("PLEXTRAC_APP_VERSION", raising=False)
        with pytest.raises(SystemExit) as exc:
            self.run_main([str(FIXTURE), "--ptrac", str(tmp_path / "x.ptrac")])
        assert exc.value.code == 1

    def test_refuses_overwrite_without_force(self, tmp_path):
        out = tmp_path / "exists.ptrac"
        out.write_text("keep me")
        args = [str(FIXTURE), "--filter", "all", "--ptrac", str(out), "--plextrac-version", VERSION]

        with pytest.raises(SystemExit):
            self.run_main(args)
        assert out.read_text() == "keep me"

        self.run_main(args + ["--force"])
        assert json.loads(out.read_text())["flaws_array"]


class TestManualChecks:
    """Prowler MANUAL results are imported, tagged, and never merged with automated ones."""

    def test_manual_check_tagged_and_flagged(self, findings):
        manual = variant(findings[0], uid="acct", status_code="MANUAL", check_id="manual_ctl")
        flaw = build([manual])["flaws_array"][0]

        assert "manual-check" in flaw["tags"]
        assert flaw["title"].startswith("MANUAL: ")
        assert flaw["description"].startswith("<p><strong>Manual check</strong>")
        assert flaw["status"] == "Open"

    def test_automated_finding_not_tagged_manual(self, findings):
        flaw = build(findings[:1])["flaws_array"][0]
        assert "manual-check" not in flaw["tags"]
        assert not flaw["title"].startswith("MANUAL")
        assert "Manual check" not in flaw["description"]

    def test_manual_and_fail_of_same_check_kept_apart(self, findings):
        fail = variant(findings[0], uid="r1", status_code="FAIL")
        manual = variant(findings[0], uid="r2", status_code="MANUAL")
        flaws = build([fail, manual])["flaws_array"]

        assert len(flaws) == 2
        assert len({f["title"] for f in flaws}) == 2
        assert [("manual-check" in f["tags"]) for f in flaws] == [False, True]


class TestImportRules:
    """Only FAIL and MANUAL are imported; MANUAL always, PASS never."""

    def write_mixed(self, tmp_path, rows):
        """rows: list of (status_code, severity_name, severity_id, check_id)."""
        template = json.loads(FIXTURE.read_text())[0]
        raw = []
        for i, (status, sev, sev_id, check) in enumerate(rows):
            item = deepcopy(template)
            item["status_code"] = status
            item["unmapped"]["Status"] = status
            item["severity"], item["severity_id"] = sev, sev_id
            item["metadata"]["event_code"] = check
            item["unmapped"]["CheckId"] = check
            item["unmapped"]["CheckTitle"] = f"Check {check}"
            item.pop("finding", None)
            item["resources"][0]["uid"] = f"arn:res:{i}"
            item["resources"][0]["name"] = f"res{i}"
            # Prowler evidence (STATUSEXTENDED): FAIL titles are derived from this
            item["message"] = f"Resource res{i} fails check {check}."
            raw.append(item)
        path = tmp_path / "mixed.ocsf.json"
        path.write_text(json.dumps(raw))
        return path

    def export(self, tmp_path, rows, *extra):
        src = self.write_mixed(tmp_path, rows)
        out = tmp_path / "out.ptrac"
        TestCli().run_main(
            [str(src), "--ptrac", str(out), "--plextrac-version", VERSION, "--force", *extra]
        )
        return json.loads(out.read_text())["flaws_array"]

    def test_pass_never_imported_even_with_all(self, tmp_path):
        rows = [("FAIL", "High", 4, "a"), ("PASS", "High", 4, "b"), ("MANUAL", "Low", 2, "c")]
        for filt in ["all", "fail", "critical-high-medium", "fail-critical-high"]:
            titles = {f["title"] for f in self.export(tmp_path, rows, "--filter", filt)}
            assert "Resource Fails Check B" not in titles, filt

    def test_manual_always_imported_whatever_the_filter(self, tmp_path):
        rows = [
            ("FAIL", "Critical", 5, "crit"),
            ("FAIL", "Low", 2, "low"),
            ("MANUAL", "Low", 2, "man"),
        ]
        titles = {f["title"] for f in self.export(tmp_path, rows, "--filter", "critical")}
        assert titles == {"Resource Fails Check Crit", "MANUAL: Check man"}

    def test_manual_title_prefix_and_tag(self, tmp_path):
        flaws = self.export(tmp_path, [("MANUAL", "Medium", 3, "m")])
        assert flaws[0]["title"] == "MANUAL: Check m"
        assert "manual-check" in flaws[0]["tags"]

    def test_same_check_many_resources_single_entry(self, tmp_path):
        rows = [("FAIL", "High", 4, "same")] * 4 + [("MANUAL", "Low", 2, "man")] * 3
        flaws = self.export(tmp_path, rows)
        assert sorted(f["title"] for f in flaws) == [
            "MANUAL: Check man",
            "Resource Fails Check Same",
        ]
        counts = {f["title"]: len(f["affected_assets"]) for f in flaws}
        assert counts == {"Resource Fails Check Same": 4, "MANUAL: Check man": 3}

    def test_old_format_without_status_code(self, tmp_path):
        """Older Prowler output: no status_code, result only in unmapped.Status / status."""
        out = tmp_path / "old.ptrac"
        TestCli().run_main(
            [str(FIXTURE), "--filter", "all", "--ptrac", str(out), "--plextrac-version", VERSION]
        )
        flaws = json.loads(out.read_text())["flaws_array"]
        assert len(flaws) == 2  # fixture: 2 FAIL + 1 PASS

    def test_default_exports_every_fail_severity(self, tmp_path):
        """No --filter flag: FAIL results of every severity, plus MANUAL, no PASS."""
        rows = [
            ("FAIL", "Critical", 5, "c"),
            ("FAIL", "High", 4, "h"),
            ("FAIL", "Medium", 3, "m"),
            ("FAIL", "Low", 2, "l"),
            ("FAIL", "Informational", 1, "i"),
            ("PASS", "Critical", 5, "p"),
            ("MANUAL", "Medium", 3, "man"),
        ]
        src = self.write_mixed(tmp_path, rows)
        out = tmp_path / "default.ptrac"
        TestCli().run_main([str(src), "--ptrac", str(out), "--plextrac-version", VERSION])

        flaws = {f["title"]: f["severity"] for f in json.loads(out.read_text())["flaws_array"]}
        assert flaws == {
            "Resource Fails Check C": "Critical",
            "Resource Fails Check H": "High",
            "Resource Fails Check M": "Medium",
            "Resource Fails Check L": "Low",
            "Resource Fails Check I": "Informational",
            "MANUAL: Check man": "Medium",
        }

    def test_critical_filter_selects_real_prowler_criticals(self, tmp_path):
        rows = [("FAIL", "Critical", 5, "c"), ("FAIL", "Informational", 1, "i")]
        flaws = self.export(tmp_path, rows, "--filter", "critical")
        assert [(f["title"], f["severity"]) for f in flaws] == [
            ("Resource Fails Check C", "Critical")
        ]
