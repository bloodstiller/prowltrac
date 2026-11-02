"""
Tests for OCSF parser module.
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.ocsf_parser import OCSFFinding, OCSFParser


class TestOCSFParser:
    """Test cases for OCSFParser."""

    def setup_method(self):
        """Set up test fixtures."""
        self.parser = OCSFParser()

        # Sample OCSF finding data
        self.sample_finding = {
            "message": "S3 bucket is publicly readable",
            "severity_id": 4,
            "severity": "High",
            "status": "Failed",
            "status_id": 1,
            "class_name": "Security Finding",
            "category_name": "Findings",
            "cloud": {
                "account": {"uid": "123456789012"},
                "region": "us-east-1",
                "provider": "AWS",
                "resource": {
                    "name": "my-test-bucket",
                    "type": "S3",
                    "uid": "arn:aws:s3:::my-test-bucket",
                },
            },
            "unmapped": {
                "Compliance": "CIS 2.1.1",
                "References": "https://docs.aws.amazon.com/s3/latest/userguide/access-control-block-public-access.html",
            },
        }

    def test_parse_single_finding(self):
        """Test parsing a single OCSF finding."""
        # Create temporary file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(self.sample_finding, f)
            temp_path = Path(f.name)

        try:
            findings = self.parser.parse_file(temp_path)

            assert len(findings) == 1
            finding = findings[0]

            assert isinstance(finding, OCSFFinding)
            assert finding.message == "S3 bucket is publicly readable"
            assert finding.severity_id == 4
            assert finding.severity == "High"
            assert finding.status == "Failed"
            assert finding.cloud_account_uid == "123456789012"
            assert finding.cloud_region == "us-east-1"
            assert finding.cloud_provider == "AWS"
            assert finding.resource_name == "my-test-bucket"
            assert finding.resource_type == "S3"
            assert "CIS 2.1.1" in finding.compliance_frameworks

        finally:
            temp_path.unlink()

    def test_parse_multiple_findings(self):
        """Test parsing multiple OCSF findings."""
        findings_data = [self.sample_finding, self.sample_finding.copy()]
        findings_data[1]["message"] = "Different finding"
        findings_data[1]["severity_id"] = 5

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(findings_data, f)
            temp_path = Path(f.name)

        try:
            findings = self.parser.parse_file(temp_path)

            assert len(findings) == 2
            assert findings[0].message == "S3 bucket is publicly readable"
            assert findings[1].message == "Different finding"
            assert findings[1].severity_id == 5
            assert findings[1].severity == "Critical"

        finally:
            temp_path.unlink()

    def test_parse_invalid_json(self):
        """Test parsing invalid JSON file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("invalid json {")
            temp_path = Path(f.name)

        try:
            with pytest.raises(ValueError, match="Invalid JSON format"):
                self.parser.parse_file(temp_path)

        finally:
            temp_path.unlink()

    def test_parse_missing_required_fields(self):
        """Test parsing finding with missing required fields."""
        invalid_finding = {"description": "Missing required fields"}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(invalid_finding, f)
            temp_path = Path(f.name)

        try:
            # Should raise ValueError due to validation failure
            with pytest.raises(ValueError, match="Invalid OCSF file"):
                self.parser.parse_file(temp_path)

        finally:
            temp_path.unlink()

    def test_finding_properties(self):
        """Test OCSFFinding property methods."""
        finding = OCSFFinding(
            message="Test finding",
            severity_id=5,
            severity="Critical",
            status="Failed",
            status_id=1,
            compliance_frameworks=["CIS 1.1", "NIST AC-1"],
            resource_name="test-resource",
        )

        assert finding.is_failed is True
        assert finding.is_critical is True
        assert finding.is_high_severity is True
        assert finding.has_compliance_framework("CIS") is True
        assert finding.has_compliance_framework("PCI") is False
        assert finding.matches_resource_pattern("test-*") is True
        assert finding.matches_resource_pattern("prod-*") is False

    def test_get_file_summary(self):
        """Test file summary generation."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump([self.sample_finding], f)
            temp_path = Path(f.name)

        try:
            summary = self.parser.get_file_summary(temp_path)

            assert "file_path" in summary
            assert "total_findings" in summary
            assert "by_status" in summary
            assert "by_severity" in summary
            assert summary["total_findings"] == 1
            assert summary["by_status"]["Failed"] == 1
            assert summary["by_severity"]["High"] == 1

        finally:
            temp_path.unlink()

    @patch("src.ocsf_parser.validate_ocsf_file")
    def test_validation_error_handling(self, mock_validate):
        """Test handling of validation errors."""
        mock_validate.return_value = {"valid": False, "error": "Test error"}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(self.sample_finding, f)
            temp_path = Path(f.name)

        try:
            with pytest.raises(ValueError, match="Invalid OCSF file: Test error"):
                self.parser.parse_file(temp_path)

        finally:
            temp_path.unlink()


class TestOCSFFinding:
    """Test cases for OCSFFinding dataclass."""

    def test_finding_initialization(self):
        """Test OCSFFinding initialization."""
        finding = OCSFFinding(
            message="Test message", severity_id=2, severity="High", status="Failed", status_id=1
        )

        assert finding.message == "Test message"
        assert finding.severity_id == 2
        assert finding.compliance_frameworks == []
        assert finding.raw_data == {}

    def test_finding_with_optional_fields(self):
        """Test OCSFFinding with optional fields."""
        finding = OCSFFinding(
            message="Test message",
            severity_id=5,
            severity="Critical",
            status="Failed",
            status_id=1,
            class_name="Security Finding",
            cloud_account_uid="123456789012",
            resource_name="test-resource",
            compliance_frameworks=["CIS 1.1"],
        )

        assert finding.class_name == "Security Finding"
        assert finding.cloud_account_uid == "123456789012"
        assert finding.resource_name == "test-resource"
        assert "CIS 1.1" in finding.compliance_frameworks
