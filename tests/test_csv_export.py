"""
Tests for the offline PlexTrac findings CSV export.
"""

import csv
import json
import sys
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest

from src.converter import check_key
from src.csv_export import CSV_COLUMNS, build_csv_rows, write_csv
from src.ocsf_parser import OCSFParser
from tests.test_ptrac import reportable_checks, variant

FIXTURE = Path(__file__).parent / "fixtures" / "sample_ocsf.json"
# Copy of "PlexTrac Finding CSV Template v3.2.csv" as supplied by PlexTrac
TEMPLATE = Path(__file__).parent / "fixtures" / "plextrac_finding_csv_template_v3.2.csv"


@pytest.fixture
def findings():
    return OCSFParser().parse_file(str(FIXTURE))


def read_rows(path):
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def test_header_matches_plextrac_template_file(findings, tmp_path):
    with open(TEMPLATE, encoding="utf-8", newline="") as f:
        template_header = next(csv.reader(f))
    path = write_csv(findings, tmp_path / "out.csv")
    with open(path, encoding="utf-8", newline="") as f:
        header = next(csv.reader(f))

    assert header == template_header == CSV_COLUMNS


def test_file_layout_matches_template(findings, tmp_path):
    """Same physical layout as the template: CRLF rows, one line per record, no BOM."""
    template_raw = TEMPLATE.read_bytes()
    raw = write_csv(findings, tmp_path / "out.csv").read_bytes()

    assert not raw.startswith(b"\xef\xbb\xbf")
    assert template_raw.split(b"\r\n", 1)[0] == raw.split(b"\r\n", 1)[0]
    lines = raw.split(b"\r\n")
    assert lines[-1] == b""  # trailing CRLF, like the template
    assert b"\n" not in b"".join(lines)  # no bare LF / embedded newlines
    assert len(lines) - 2 == len(build_csv_rows(findings))  # header + one line per row

    width = len(CSV_COLUMNS)
    with open(tmp_path / "out.csv", encoding="utf-8", newline="") as f:
        assert all(len(r) == width for r in csv.reader(f))


def test_template_example_row_shape_is_reproducible():
    """Writing the template's own example row back out yields the template bytes."""
    import io

    with open(TEMPLATE, encoding="utf-8", newline="") as f:
        template_rows = list(csv.reader(f))
    buf = io.StringIO(newline="")
    csv.writer(buf, quoting=csv.QUOTE_MINIMAL, lineterminator="\r\n").writerows(template_rows)
    assert buf.getvalue().encode("utf-8") == TEMPLATE.read_bytes()


def test_rows_have_required_fields(findings, tmp_path):
    rows = read_rows(write_csv(findings, tmp_path / "out.csv"))

    assert len(rows) == len(reportable_checks(findings))
    for row in rows:
        assert row["title"]
        assert row["description"]
        assert row["severity"] in {"Critical", "High", "Medium", "Low", "Informational"}
        assert row["status"] == "Open"
        assert "**" not in row["description"]
        assert "\n" not in row["description"]
        assert "prowler" in row["tags"].split(",")


def test_one_row_per_check_with_all_resources(findings):
    base = findings[0]
    group = [
        variant(base, uid="arn:aws:s3:::bucket-a", message="bucket-a is public"),
        variant(base, uid="arn:aws:s3:::bucket-b", message="bucket-b is public"),
    ]
    rows = build_csv_rows(group)

    assert len(rows) == 1
    row = dict(zip(CSV_COLUMNS, rows[0]))
    assert row["affected_assets"] == "arn:aws:s3:::bucket-a,arn:aws:s3:::bucket-b"
    assert "arn:aws:s3:::bucket-b: bucket-b is public" in row["description"]
    assert "Failed Resources: 2" in row["description"]


def test_resource_details_are_capped(findings):
    many = [variant(findings[0], uid=f"r{i}", message=f"m{i}") for i in range(250)]
    row = dict(zip(CSV_COLUMNS, build_csv_rows(many)[0]))
    assert len(row["affected_assets"].split(",")) == 250
    assert "... and 50 more" in row["description"]


def test_multi_value_columns_strip_inner_commas(findings):
    finding = variant(findings[0], uid="r1", refs=["https://a.example/x,y", "https://b.example"])
    row = dict(zip(CSV_COLUMNS, build_csv_rows([finding])[0]))
    refs = row["references"].split(",")
    assert "https://a.example/x y" in refs
    assert "https://b.example" in refs


def test_asset_names_with_commas_do_not_split(findings):
    finding = variant(findings[0], uid="weird,name")
    row = dict(zip(CSV_COLUMNS, build_csv_rows([finding])[0]))
    assert row["affected_assets"] == "weird name"


def test_quotes_kept_and_newlines_flattened(findings, tmp_path):
    tricky = variant(findings[0], uid="res-1", message='Bucket res-1 "x", public\nread')
    rows = read_rows(write_csv([tricky], tmp_path / "t.csv"))
    assert rows[0]["title"] == 'Bucket "X", Public Read'
    # Evidence itself is kept verbatim (only whitespace flattened for the single-line CSV)
    assert 'res-1: Bucket res-1 "x", public read' in rows[0]["description"]


class TestCli:
    def run_main(self, argv):
        import simple_import

        with patch.object(sys, "argv", ["simple_import.py", *argv]), patch(
            "src.auth.auth_handler.AuthHandler.authenticate",
            side_effect=AssertionError("offline mode must not authenticate"),
        ), patch("builtins.input", side_effect=AssertionError("offline mode must not prompt")):
            simple_import.main()

    def test_csv_offline(self, tmp_path):
        self.run_main([str(FIXTURE), "--filter", "all", "--csv", str(tmp_path / "out")])
        rows = read_rows(tmp_path / "out.csv")
        assert len(rows) > 0

    def test_csv_and_ptrac_together(self, tmp_path):
        self.run_main(
            [
                str(FIXTURE),
                "--filter",
                "all",
                "--csv",
                str(tmp_path / "a.csv"),
                "--ptrac",
                str(tmp_path / "a.ptrac"),
                "--plextrac-version",
                "2.10.1",
            ]
        )
        assert read_rows(tmp_path / "a.csv")
        assert json.loads((tmp_path / "a.ptrac").read_text())["flaws_array"]

    def test_csv_refuses_overwrite(self, tmp_path):
        out = tmp_path / "x.csv"
        out.write_text("keep")
        with pytest.raises(SystemExit):
            self.run_main([str(FIXTURE), "--csv", str(out)])
        assert out.read_text() == "keep"


def test_manual_check_row_tagged(findings):
    manual = variant(findings[0], uid="acct", status_code="MANUAL")
    row = dict(zip(CSV_COLUMNS, build_csv_rows([manual])[0]))
    assert "manual-check" in row["tags"].split(",")
    assert row["title"].startswith("MANUAL: ")
    assert row["description"].startswith("Manual check: ")
