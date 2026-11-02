"""
OCSF (Open Cybersecurity Schema Framework) parser for Prowler findings.
"""

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .utils.logger import get_logger
from .utils.validators import validate_finding_data, validate_ocsf_file

# Try to import py-ocsf-models if available, but don't require it
try:
    import py_ocsf_models

    HAS_OCSF_MODELS = True
except ImportError:
    HAS_OCSF_MODELS = False


# OCSF / Prowler severity names -> PlexTrac severities (used when severity_id is unmapped)
_SEVERITY_TEXT = {
    "critical": "Critical",
    "fatal": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Informational",
    "info": "Informational",
}


@dataclass
class OCSFFinding:
    """Represents a parsed OCSF finding."""

    # Core OCSF fields
    message: str
    severity_id: int
    severity: str
    status: str
    status_id: int
    status_code: Optional[str] = None

    # Metadata
    class_name: Optional[str] = None
    category_name: Optional[str] = None
    activity_name: Optional[str] = None
    type_name: Optional[str] = None

    # Cloud information
    cloud_account_uid: Optional[str] = None
    cloud_region: Optional[str] = None
    cloud_provider: Optional[str] = None

    # Resource information
    resource_name: Optional[str] = None
    resource_type: Optional[str] = None
    resource_uid: Optional[str] = None

    # Compliance information
    compliance_frameworks: List[str] = None

    # Raw data for advanced processing
    raw_data: Dict[str, Any] = None

    def __post_init__(self):
        if self.compliance_frameworks is None:
            self.compliance_frameworks = []
        if self.raw_data is None:
            self.raw_data = {}

    @property
    def is_failed(self) -> bool:
        """Check if this is a failed finding."""
        return self.status == "Failed"

    @property
    def is_critical(self) -> bool:
        """Check if this is a critical finding."""
        return self.severity == "Critical"

    @property
    def is_high_severity(self) -> bool:
        """Check if this is high severity or above."""
        return self.severity in ("Critical", "High")

    def has_compliance_framework(self, framework: str) -> bool:
        """Check if finding relates to a specific compliance framework."""
        return any(framework.lower() in cf.lower() for cf in self.compliance_frameworks)

    def matches_resource_pattern(self, pattern: str) -> bool:
        """Check if resource name matches a pattern (supports wildcards)."""
        if not self.resource_name:
            return False

        import re

        # Convert glob pattern to regex
        regex_pattern = pattern.replace("*", ".*").replace("?", ".")
        return bool(re.match(regex_pattern, self.resource_name, re.IGNORECASE))


class OCSFParser:
    """Parser for OCSF format files from Prowler."""

    def __init__(self):
        self.logger = get_logger(__name__)
        # Use severity mapping from config
        from .utils.config import get_config

        config = get_config()
        self._severity_map = config.mapping.severity

        if HAS_OCSF_MODELS:
            self.logger.debug("Using py-ocsf-models for enhanced OCSF validation")
        else:
            self.logger.debug("py-ocsf-models not available, using basic JSON parsing")

    def parse_file(self, file_path: Union[str, Path]) -> List[OCSFFinding]:
        """Parse an OCSF file and return findings."""
        path = Path(file_path)

        self.logger.info(f"Parsing OCSF file: {path}")

        # Validate file first
        validation = validate_ocsf_file(path)
        if not validation["valid"]:
            raise ValueError(f"Invalid OCSF file: {validation['error']}")

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Handle both single finding and array of findings
            if isinstance(data, dict):
                findings_data = [data]
            elif isinstance(data, list):
                findings_data = data
            else:
                raise ValueError("Invalid OCSF format: expected object or array")

            findings = []
            for i, finding_data in enumerate(findings_data):
                try:
                    finding = self._parse_finding(finding_data)
                    if finding:
                        findings.append(finding)
                except Exception as e:
                    self.logger.warning(f"Failed to parse finding {i}: {str(e)}")
                    continue

            self.logger.info(f"Successfully parsed {len(findings)} findings from {path.name}")
            return findings

        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON format: {str(e)}")
        except Exception as e:
            raise ValueError(f"Error parsing OCSF file: {str(e)}")

    def _resolve_severity(self, severity_id: Any, severity_text: Any) -> str:
        """PlexTrac severity for an OCSF finding.

        severity_id is mapped with config.mapping.severity (OCSF scale: 5 = Critical ...
        1 = Informational). IDs outside the mapping (0 Unknown, 99 Other) fall back to the
        severity text, and finally to Informational.
        """
        mapped = self._severity_map.get(severity_id)
        if mapped:
            return mapped
        text = str(severity_text or "").strip().lower()
        return _SEVERITY_TEXT.get(text, "Informational")

    def _parse_finding(self, data: Dict[str, Any]) -> Optional[OCSFFinding]:
        """Parse a single OCSF finding."""
        # Validate finding structure
        validation = validate_finding_data(data)
        if not validation["valid"]:
            self.logger.warning(f"Invalid finding data: {validation['errors']}")
            return None

        # Extract core fields
        message = data.get("message", "")
        severity_id = data.get("severity_id", 0)
        severity = self._resolve_severity(severity_id, data.get("severity"))
        status = data.get("status", "Unknown")
        status_id = data.get("status_id", 0)
        status_code = data.get("status_code")

        # Extract metadata
        class_name = data.get("class_name")
        category_name = data.get("category_name")
        activity_name = data.get("activity_name")
        type_name = data.get("type_name")

        # Extract cloud information
        cloud_info = data.get("cloud", {})
        cloud_account_uid = cloud_info.get("account", {}).get("uid")
        cloud_region = cloud_info.get("region")
        cloud_provider = cloud_info.get("provider")

        # Extract resource information from various possible locations
        resource_name = None
        resource_type = None
        resource_uid = None

        # Check for resources in cloud section
        if "cloud" in data and "resource" in data["cloud"]:
            resource_info = data["cloud"]["resource"]
            resource_name = resource_info.get("name")
            resource_type = resource_info.get("type")
            resource_uid = resource_info.get("uid")

        # Check for resources in other locations
        if not resource_name:
            resources = data.get("resources", [])
            if resources and isinstance(resources, list) and len(resources) > 0:
                first_resource = resources[0]
                resource_name = first_resource.get("name")
                resource_type = first_resource.get("type")
                resource_uid = first_resource.get("uid")

        # Extract compliance information
        compliance_frameworks = []

        # Check unmapped section for compliance info
        unmapped = data.get("unmapped", {})
        if unmapped:
            # Common compliance fields
            for field in ["Compliance", "References", "CIS", "NIST", "PCI", "SOC2", "ISO27001"]:
                if field in unmapped:
                    value = unmapped[field]
                    if isinstance(value, str):
                        compliance_frameworks.append(value)
                    elif isinstance(value, list):
                        compliance_frameworks.extend([str(v) for v in value])

        # Check for compliance in other sections
        if "compliance" in data:
            comp_data = data["compliance"]
            if isinstance(comp_data, dict):
                for key, value in comp_data.items():
                    if isinstance(value, str):
                        compliance_frameworks.append(f"{key}: {value}")
                    elif isinstance(value, list):
                        compliance_frameworks.extend([f"{key}: {v}" for v in value])

        return OCSFFinding(
            message=message,
            severity_id=severity_id,
            severity=severity,
            status=status,
            status_id=status_id,
            status_code=status_code,
            class_name=class_name,
            category_name=category_name,
            activity_name=activity_name,
            type_name=type_name,
            cloud_account_uid=cloud_account_uid,
            cloud_region=cloud_region,
            cloud_provider=cloud_provider,
            resource_name=resource_name,
            resource_type=resource_type,
            resource_uid=resource_uid,
            compliance_frameworks=compliance_frameworks,
            raw_data=data,
        )

    def get_file_summary(self, file_path: Union[str, Path]) -> Dict[str, Any]:
        """Get summary information about an OCSF file."""
        path = Path(file_path)

        # Basic file info
        summary = {
            "file_path": str(path),
            "file_name": path.name,
            "file_size": 0,
            "total_findings": 0,
            "by_status": {},
            "by_severity": {},
            "by_compliance": {},
            "by_service": {},
            "by_provider": {},
            "date_parsed": datetime.now().isoformat(),
        }

        try:
            summary["file_size"] = path.stat().st_size
            findings = self.parse_file(path)
            summary["total_findings"] = len(findings)

            # Analyze findings
            for finding in findings:
                # Count by status
                status = finding.status
                summary["by_status"][status] = summary["by_status"].get(status, 0) + 1

                # Count by severity
                severity = finding.severity
                summary["by_severity"][severity] = summary["by_severity"].get(severity, 0) + 1

                # Count by compliance frameworks
                for framework in finding.compliance_frameworks:
                    # Extract framework name (before colon if present)
                    fw_name = framework.split(":")[0].strip()
                    summary["by_compliance"][fw_name] = summary["by_compliance"].get(fw_name, 0) + 1

                # Count by service/resource type
                if finding.resource_type:
                    summary["by_service"][finding.resource_type] = (
                        summary["by_service"].get(finding.resource_type, 0) + 1
                    )

                # Count by cloud provider
                if finding.cloud_provider:
                    summary["by_provider"][finding.cloud_provider] = (
                        summary["by_provider"].get(finding.cloud_provider, 0) + 1
                    )

        except Exception as e:
            summary["error"] = str(e)
            self.logger.error(f"Error generating summary for {path}: {str(e)}")

        return summary

    def batch_parse_files(self, file_paths: List[Union[str, Path]]) -> Dict[str, List[OCSFFinding]]:
        """Parse multiple OCSF files."""
        results = {}

        for file_path in file_paths:
            try:
                findings = self.parse_file(file_path)
                results[str(file_path)] = findings
            except Exception as e:
                self.logger.error(f"Failed to parse {file_path}: {str(e)}")
                results[str(file_path)] = []

        return results
