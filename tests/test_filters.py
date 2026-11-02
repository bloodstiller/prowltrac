"""Tests for the filtering system."""

import pytest

from src.filters import FilterEngine, SeverityFilter, StatusFilter
from src.ocsf_parser import OCSFParser
from tests.fixtures.sample_ocsf import get_sample_findings_list


class TestStatusFilter:
    """Test status-based filtering."""

    def test_fail_filter(self):
        """Test filtering for FAIL status."""
        # Create sample findings
        parser = OCSFParser()
        sample_data = get_sample_findings_list()

        # Parse findings
        findings = []
        for data in sample_data:
            finding = parser._parse_finding(data)
            if finding:
                findings.append(finding)

        # Apply FAIL filter
        status_filter = StatusFilter(["FAIL"])
        filtered = status_filter.apply(findings)

        # Should have 3 FAIL findings (Critical, High, Low)
        assert len(filtered) == 3

        # All should have status_code FAIL
        for finding in filtered:
            assert finding.status_code == "FAIL"

    def test_pass_filter(self):
        """Test filtering for PASS status."""
        parser = OCSFParser()
        sample_data = get_sample_findings_list()

        findings = []
        for data in sample_data:
            finding = parser._parse_finding(data)
            if finding:
                findings.append(finding)

        status_filter = StatusFilter(["PASS"])
        filtered = status_filter.apply(findings)

        # Should have 1 PASS finding (Medium)
        assert len(filtered) == 1
        assert filtered[0].status_code == "PASS"


class TestSeverityFilter:
    """Test severity-based filtering."""

    def test_critical_filter(self):
        """Test filtering for Critical severity."""
        parser = OCSFParser()
        sample_data = get_sample_findings_list()

        findings = []
        for data in sample_data:
            finding = parser._parse_finding(data)
            if finding:
                findings.append(finding)

        severity_filter = SeverityFilter(["Critical"])
        filtered = severity_filter.apply(findings)

        # Should have 1 Critical finding
        assert len(filtered) == 1
        assert filtered[0].severity_id == 5  # OCSF: 5 = Critical
        assert filtered[0].severity == "Critical"

    def test_critical_high_filter(self):
        """Test filtering for Critical and High severity."""
        parser = OCSFParser()
        sample_data = get_sample_findings_list()

        findings = []
        for data in sample_data:
            finding = parser._parse_finding(data)
            if finding:
                findings.append(finding)

        severity_filter = SeverityFilter(["Critical", "High"])
        filtered = severity_filter.apply(findings)

        # Should have 2 findings (Critical + High)
        assert len(filtered) == 2

        severities = [f.severity for f in filtered]
        assert "Critical" in severities
        assert "High" in severities


class TestFilterEngine:
    """Test the filter engine with combined filters."""

    def test_fail_and_critical_high(self):
        """Test FAIL status AND Critical/High severity."""
        parser = OCSFParser()
        sample_data = get_sample_findings_list()

        findings = []
        for data in sample_data:
            finding = parser._parse_finding(data)
            if finding:
                findings.append(finding)

        # Create filter engine with AND logic
        engine = FilterEngine()
        engine.create_from_preset(
            {"filters": {"status": ["FAIL"], "severity": ["Critical", "High"]}}
        )

        result = engine.apply_filters(findings)

        # Should have 2 findings (Critical FAIL + High FAIL)
        assert len(result.filtered_findings) == 2

        # All should be FAIL status and Critical/High severity
        for finding in result.filtered_findings:
            assert finding.status_code == "FAIL"
            assert finding.severity in ["Critical", "High"]

    def test_fail_or_critical_high(self):
        """Test FAIL status OR Critical/High severity."""
        from src.filters import FilterOperator

        parser = OCSFParser()
        sample_data = get_sample_findings_list()

        findings = []
        for data in sample_data:
            finding = parser._parse_finding(data)
            if finding:
                findings.append(finding)

        # Create filter engine with OR logic
        engine = FilterEngine()
        engine.create_from_preset(
            {"filters": {"status": ["FAIL"], "severity": ["Critical", "High"]}}
        )
        engine.set_operator(FilterOperator.OR)

        result = engine.apply_filters(findings)

        # Should have 3 findings (all FAIL findings: Critical, High, Low)
        # The Medium PASS finding doesn't match either condition
        assert len(result.filtered_findings) == 3

    def test_filter_stats(self):
        """Test that filter statistics are generated correctly."""
        parser = OCSFParser()
        sample_data = get_sample_findings_list()

        findings = []
        for data in sample_data:
            finding = parser._parse_finding(data)
            if finding:
                findings.append(finding)

        engine = FilterEngine()
        engine.create_from_preset({"filters": {"status": ["FAIL"]}})

        result = engine.apply_filters(findings)

        # Check basic stats
        assert result.original_count == 4
        assert result.filtered_count == 3
        assert "total_removed" in result.filter_stats
        assert "percent_retained" in result.filter_stats
        assert result.filter_stats["total_removed"] == 1
        assert result.filter_stats["percent_retained"] == 75.0
