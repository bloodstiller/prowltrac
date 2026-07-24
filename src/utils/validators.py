"""
Validation utilities for Prowler OCSF to PlexTrac tool.
"""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator


class FilterCriteria(BaseModel):
    """Validation model for filter criteria."""

    status: Optional[List[str]] = Field(default=None, description="Status filters")
    severity: Optional[List[str]] = Field(default=None, description="Severity filters")
    compliance: Optional[List[str]] = Field(default=None, description="Compliance filters")
    services: Optional[List[str]] = Field(default=None, description="Service filters")
    resource_patterns: Optional[List[str]] = Field(
        default=None, description="Resource pattern filters"
    )
    account_ids: Optional[List[str]] = Field(default=None, description="Account ID filters")
    regions: Optional[List[str]] = Field(default=None, description="Region filters")

    @field_validator("status")
    @classmethod
    def validate_status(cls, v):
        if v is None:
            return v
        valid_statuses = ["Failed", "Success", "New", "Suppressed", "Unknown"]
        for status in v:
            if status not in valid_statuses:
                raise ValueError(f"Invalid status: {status}. Must be one of {valid_statuses}")
        return v

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v):
        if v is None:
            return v
        valid_severities = ["Critical", "High", "Medium", "Low"]
        for severity in v:
            if severity not in valid_severities:
                raise ValueError(f"Invalid severity: {severity}. Must be one of {valid_severities}")
        return v

    @field_validator("resource_patterns")
    @classmethod
    def validate_patterns(cls, v):
        if v is None:
            return v
        # Validate that patterns are valid regex or glob patterns
        for pattern in v:
            try:
                # Test if it's a valid regex (basic validation)
                re.compile(pattern.replace("*", ".*"))
            except re.error:
                raise ValueError(f"Invalid pattern: {pattern}")
        return v

    @field_validator("account_ids")
    @classmethod
    def validate_account_ids(cls, v):
        if v is None:
            return v
        # Validate AWS account ID format (12 digits)
        for account_id in v:
            if not re.match(r"^\d{12}$", account_id):
                raise ValueError(f"Invalid AWS account ID format: {account_id}")
        return v


def validate_url(url: str) -> bool:
    """Validate URL format."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def validate_file_path(file_path: Union[str, Path]) -> bool:
    """Validate file path exists and is readable."""
    try:
        path = Path(file_path)
        return path.exists() and path.is_file() and path.stat().st_size > 0
    except Exception:
        return False


def validate_ocsf_file(file_path: Union[str, Path]) -> Dict[str, Any]:
    """Validate OCSF file format and return basic info."""
    import json

    result = {
        "valid": False,
        "error": None,
        "finding_count": 0,
        "file_size": 0,
        "has_ocsf_structure": False,
    }

    try:
        path = Path(file_path)
        if not path.exists():
            result["error"] = "File does not exist"
            return result

        result["file_size"] = path.stat().st_size

        with open(path, "r") as f:
            data = json.load(f)

        # Check if it's a list of findings or a single finding
        if isinstance(data, list):
            findings = data
        elif isinstance(data, dict):
            findings = [data]
        else:
            result["error"] = "Invalid JSON structure"
            return result

        result["finding_count"] = len(findings)

        # Basic OCSF structure validation
        if findings:
            first_finding = findings[0]
            required_fields = ["message", "severity_id", "status"]
            has_required = all(field in first_finding for field in required_fields)

            # Check for OCSF-specific fields
            ocsf_fields = ["class_name", "category_name", "metadata", "cloud"]
            has_ocsf = any(field in first_finding for field in ocsf_fields)

            result["has_ocsf_structure"] = has_ocsf
            result["valid"] = has_required

            if not has_required:
                result["error"] = f"Missing required OCSF fields: {required_fields}"
        else:
            result["error"] = "No findings found in file"

    except json.JSONDecodeError as e:
        result["error"] = f"Invalid JSON format: {str(e)}"
    except Exception as e:
        result["error"] = f"Error reading file: {str(e)}"

    return result


def validate_credentials(username: str, password: str, url: str) -> Dict[str, Any]:
    """Validate credential format."""
    result = {"valid": True, "errors": []}

    if not username or len(username.strip()) == 0:
        result["errors"].append("Username is required")

    if not password or len(password.strip()) == 0:
        result["errors"].append("Password is required")

    if not validate_url(url):
        result["errors"].append("Invalid URL format")

    result["valid"] = len(result["errors"]) == 0
    return result


def validate_token(token: str, url: str) -> Dict[str, Any]:
    """Validate bearer token format."""
    result = {"valid": True, "errors": []}

    if not token or len(token.strip()) == 0:
        result["errors"].append("Token is required")

    if not validate_url(url):
        result["errors"].append("Invalid URL format")

    result["valid"] = len(result["errors"]) == 0
    return result


def validate_finding_data(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Validate individual finding data structure."""
    result = {"valid": True, "errors": [], "warnings": []}

    # Required fields
    required_fields = ["message", "severity_id", "status"]
    for field in required_fields:
        if field not in finding:
            result["errors"].append(f"Missing required field: {field}")

    # Validate severity_id
    if "severity_id" in finding:
        severity_id = finding["severity_id"]
        if not isinstance(severity_id, int) or severity_id not in [1, 2, 3, 4, 5]:
            result["errors"].append(f"Invalid severity_id: {severity_id}. Must be 1-5")
        elif severity_id == 5:
            # severity_id 5 is often "Informational" - treat as Low (4)
            result["warnings"].append(f"Severity ID 5 found, treating as Low severity")

    # Validate status
    if "status" in finding:
        status = finding["status"]
        valid_statuses = ["Success", "Failed", "New", "Suppressed", "Unknown"]
        if status not in valid_statuses:
            result["warnings"].append(f"Unexpected status value: {status}")

    # Check for message length
    if "message" in finding:
        message = finding["message"]
        if len(message) > 1000:
            result["warnings"].append("Message is very long and may be truncated")

    result["valid"] = len(result["errors"]) == 0
    return result


def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe file operations."""
    # Remove or replace invalid characters
    sanitized = re.sub(r'[<>:"/\\|?*]', "_", filename)

    # Remove leading/trailing spaces and dots
    sanitized = sanitized.strip(" .")

    # Limit length
    if len(sanitized) > 200:
        sanitized = sanitized[:200]

    return sanitized or "unnamed_file"


def validate_batch_size(batch_size: int) -> bool:
    """Validate batch size for API requests."""
    return 1 <= batch_size <= 100


def validate_filter_preset(preset: Dict[str, Any]) -> Dict[str, Any]:
    """Validate filter preset structure."""
    result = {"valid": True, "errors": []}

    required_fields = ["name", "description", "filters"]
    for field in required_fields:
        if field not in preset:
            result["errors"].append(f"Missing required field: {field}")

    if "filters" in preset:
        try:
            FilterCriteria(**preset["filters"])
        except ValueError as e:
            result["errors"].append(f"Invalid filter criteria: {str(e)}")

    result["valid"] = len(result["errors"]) == 0
    return result
