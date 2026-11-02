"""
Comprehensive filtering system for OCSF findings.
"""

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set

from .ocsf_parser import OCSFFinding
from .utils.logger import get_logger
from .utils.validators import FilterCriteria


class FilterOperator(Enum):
    """Filter operators for combining conditions."""

    AND = "and"
    OR = "or"
    NOT = "not"


@dataclass
class FilterResult:
    """Result of applying filters to findings."""

    original_count: int
    filtered_count: int
    filtered_findings: List[OCSFFinding]
    filters_applied: Dict[str, Any]
    filter_stats: Dict[str, int]


class FindingFilter:
    """Base class for finding filters."""

    def __init__(self, name: str):
        self.name = name
        self.logger = get_logger(__name__)

    def apply(self, findings: List[OCSFFinding]) -> List[OCSFFinding]:
        """Apply filter to list of findings."""
        raise NotImplementedError

    def describe(self) -> str:
        """Return human-readable description of filter."""
        raise NotImplementedError


class StatusFilter(FindingFilter):
    """Filter findings by status_code (FAIL/PASS/etc)."""

    def __init__(self, statuses: List[str]):
        super().__init__("status")
        self.statuses = [s.lower() for s in statuses]
        self.logger.debug(f"StatusFilter: looking for status_codes={self.statuses}")

    def apply(self, findings: List[OCSFFinding]) -> List[OCSFFinding]:
        # Debug: Show what status_codes we're actually finding
        actual_status_codes = set(
            (f.status_code or "").lower() for f in findings[:10] if f.status_code
        )
        actual_statuses = set(f.status.lower() for f in findings[:10])
        self.logger.debug(f"StatusFilter: sample actual status_codes={actual_status_codes}")
        self.logger.debug(f"StatusFilter: sample actual statuses={actual_statuses}")

        # Filter by status_code (FAIL/PASS) instead of status (New/Unknown)
        filtered = [f for f in findings if f.status_code and f.status_code.lower() in self.statuses]
        self.logger.debug(f"StatusFilter: {len(findings)} -> {len(filtered)} findings")
        return filtered

    def describe(self) -> str:
        return f"Status in: {', '.join(self.statuses)}"


class SeverityFilter(FindingFilter):
    """Filter findings by severity."""

    def __init__(self, severities: List[str]):
        super().__init__("severity")
        self.severities = [s.lower() for s in severities]
        self.logger.debug(f"SeverityFilter: severities={self.severities}")

    def apply(self, findings: List[OCSFFinding]) -> List[OCSFFinding]:
        # Match on the resolved PlexTrac severity name (the parser has already mapped
        # OCSF severity_id), so this can't drift from the configured mapping.
        filtered = [f for f in findings if (f.severity or "").lower() in self.severities]
        self.logger.debug(f"SeverityFilter: {len(findings)} -> {len(filtered)} findings")
        return filtered

    def describe(self) -> str:
        return f"Severity in: {', '.join(self.severities)}"


class ComplianceFilter(FindingFilter):
    """Filter findings by compliance frameworks."""

    def __init__(self, frameworks: List[str]):
        super().__init__("compliance")
        self.frameworks = [f.lower() for f in frameworks]

    def apply(self, findings: List[OCSFFinding]) -> List[OCSFFinding]:
        return [f for f in findings if self._matches_compliance(f)]

    def _matches_compliance(self, finding: OCSFFinding) -> bool:
        """Check if finding matches any compliance framework."""
        for framework in self.frameworks:
            if finding.has_compliance_framework(framework):
                return True
        return False

    def describe(self) -> str:
        return f"Compliance frameworks: {', '.join(self.frameworks)}"


class ServiceFilter(FindingFilter):
    """Filter findings by cloud service/resource type."""

    def __init__(self, services: List[str]):
        super().__init__("service")
        self.services = [s.lower() for s in services]

    def apply(self, findings: List[OCSFFinding]) -> List[OCSFFinding]:
        return [f for f in findings if self._matches_service(f)]

    def _matches_service(self, finding: OCSFFinding) -> bool:
        """Check if finding matches any service."""
        if not finding.resource_type:
            return False

        resource_type = finding.resource_type.lower()
        return any(service in resource_type for service in self.services)

    def describe(self) -> str:
        return f"Services: {', '.join(self.services)}"


class ResourcePatternFilter(FindingFilter):
    """Filter findings by resource name patterns."""

    def __init__(self, patterns: List[str]):
        super().__init__("resource_pattern")
        self.patterns = patterns

    def apply(self, findings: List[OCSFFinding]) -> List[OCSFFinding]:
        return [f for f in findings if self._matches_pattern(f)]

    def _matches_pattern(self, finding: OCSFFinding) -> bool:
        """Check if finding resource matches any pattern."""
        if not finding.resource_name:
            return False

        for pattern in self.patterns:
            if finding.matches_resource_pattern(pattern):
                return True
        return False

    def describe(self) -> str:
        return f"Resource patterns: {', '.join(self.patterns)}"


class AccountFilter(FindingFilter):
    """Filter findings by cloud account IDs."""

    def __init__(self, account_ids: List[str]):
        super().__init__("account")
        self.account_ids = account_ids

    def apply(self, findings: List[OCSFFinding]) -> List[OCSFFinding]:
        return [f for f in findings if f.cloud_account_uid in self.account_ids]

    def describe(self) -> str:
        return f"Account IDs: {', '.join(self.account_ids)}"


class RegionFilter(FindingFilter):
    """Filter findings by cloud regions."""

    def __init__(self, regions: List[str]):
        super().__init__("region")
        self.regions = [r.lower() for r in regions]

    def apply(self, findings: List[OCSFFinding]) -> List[OCSFFinding]:
        return [f for f in findings if self._matches_region(f)]

    def _matches_region(self, finding: OCSFFinding) -> bool:
        """Check if finding matches any region."""
        if not finding.cloud_region:
            return False
        return finding.cloud_region.lower() in self.regions

    def describe(self) -> str:
        return f"Regions: {', '.join(self.regions)}"


class ProviderFilter(FindingFilter):
    """Filter findings by cloud provider."""

    def __init__(self, providers: List[str]):
        super().__init__("provider")
        self.providers = [p.lower() for p in providers]

    def apply(self, findings: List[OCSFFinding]) -> List[OCSFFinding]:
        return [f for f in findings if self._matches_provider(f)]

    def _matches_provider(self, finding: OCSFFinding) -> bool:
        """Check if finding matches any provider."""
        if not finding.cloud_provider:
            return False
        return finding.cloud_provider.lower() in self.providers

    def describe(self) -> str:
        return f"Providers: {', '.join(self.providers)}"


class CustomFilter(FindingFilter):
    """Custom filter with user-defined function."""

    def __init__(self, name: str, filter_func: Callable[[OCSFFinding], bool], description: str):
        super().__init__(name)
        self.filter_func = filter_func
        self.description = description

    def apply(self, findings: List[OCSFFinding]) -> List[OCSFFinding]:
        return [f for f in findings if self.filter_func(f)]

    def describe(self) -> str:
        return self.description


class FilterEngine:
    """Main filtering engine that combines multiple filters."""

    def __init__(self):
        self.logger = get_logger(__name__)
        self.filters: List[FindingFilter] = []
        self.operator = FilterOperator.AND

    def add_filter(self, filter_obj: FindingFilter) -> None:
        """Add a filter to the engine."""
        self.filters.append(filter_obj)
        self.logger.debug(f"Added filter: {filter_obj.describe()}")

    def set_operator(self, operator: FilterOperator) -> None:
        """Set the operator for combining filters."""
        self.operator = operator

    def apply_filters(self, findings: List[OCSFFinding]) -> FilterResult:
        """Apply all filters to findings list."""
        original_count = len(findings)
        self.logger.info(f"Applying {len(self.filters)} filters to {original_count} findings")

        if not self.filters:
            return FilterResult(
                original_count=original_count,
                filtered_count=original_count,
                filtered_findings=findings,
                filters_applied={},
                filter_stats={},
            )

        # Apply filters based on operator
        if self.operator == FilterOperator.AND:
            filtered_findings = self._apply_and_filters(findings)
        elif self.operator == FilterOperator.OR:
            filtered_findings = self._apply_or_filters(findings)
        else:  # NOT operator
            filtered_findings = self._apply_not_filters(findings)

        # Generate filter statistics
        filter_stats = self._generate_filter_stats(findings, filtered_findings)

        filters_applied = {f.name: f.describe() for f in self.filters}

        result = FilterResult(
            original_count=original_count,
            filtered_count=len(filtered_findings),
            filtered_findings=filtered_findings,
            filters_applied=filters_applied,
            filter_stats=filter_stats,
        )

        self.logger.info(f"Filtered {original_count} findings to {len(filtered_findings)}")
        return result

    def _apply_and_filters(self, findings: List[OCSFFinding]) -> List[OCSFFinding]:
        """Apply filters with AND logic."""
        result = findings
        for filter_obj in self.filters:
            result = filter_obj.apply(result)
            self.logger.debug(f"After {filter_obj.name}: {len(result)} findings remain")
        return result

    def _apply_or_filters(self, findings: List[OCSFFinding]) -> List[OCSFFinding]:
        """Apply filters with OR logic."""
        all_results = set()
        for filter_obj in self.filters:
            filtered = filter_obj.apply(findings)
            all_results.update(id(f) for f in filtered)
            self.logger.debug(f"After {filter_obj.name}: {len(filtered)} additional findings")

        return [f for f in findings if id(f) in all_results]

    def _apply_not_filters(self, findings: List[OCSFFinding]) -> List[OCSFFinding]:
        """Apply filters with NOT logic (exclude matching findings)."""
        excluded = set()
        for filter_obj in self.filters:
            filtered = filter_obj.apply(findings)
            excluded.update(id(f) for f in filtered)

        return [f for f in findings if id(f) not in excluded]

    def _generate_filter_stats(
        self, original: List[OCSFFinding], filtered: List[OCSFFinding]
    ) -> Dict[str, int]:
        """Generate statistics about filtering results."""
        return {
            "total_removed": len(original) - len(filtered),
            "percent_retained": round((len(filtered) / len(original)) * 100, 1) if original else 0,
            "critical_retained": sum(1 for f in filtered if f.severity == "Critical"),
            "high_retained": sum(1 for f in filtered if f.severity == "High"),
            "failed_retained": sum(1 for f in filtered if f.status == "Failed"),
        }

    def clear_filters(self) -> None:
        """Clear all filters."""
        self.filters.clear()
        self.logger.debug("Cleared all filters")

    def create_from_criteria(self, criteria: FilterCriteria) -> None:
        """Create filters from FilterCriteria object."""
        self.clear_filters()

        if criteria.status:
            self.add_filter(StatusFilter(criteria.status))

        if criteria.severity:
            self.add_filter(SeverityFilter(criteria.severity))

        if criteria.compliance:
            self.add_filter(ComplianceFilter(criteria.compliance))

        if criteria.services:
            self.add_filter(ServiceFilter(criteria.services))

        if criteria.resource_patterns:
            self.add_filter(ResourcePatternFilter(criteria.resource_patterns))

        if criteria.account_ids:
            self.add_filter(AccountFilter(criteria.account_ids))

        if criteria.regions:
            self.add_filter(RegionFilter(criteria.regions))

    def create_from_preset(self, preset_config: Dict[str, Any]) -> None:
        """Create filters from preset configuration."""
        self.clear_filters()

        filters = preset_config.get("filters", {})

        if "status" in filters:
            self.add_filter(StatusFilter(filters["status"]))

        if "severity" in filters:
            self.add_filter(SeverityFilter(filters["severity"]))

        if "compliance" in filters:
            self.add_filter(ComplianceFilter(filters["compliance"]))

        if "services" in filters:
            self.add_filter(ServiceFilter(filters["services"]))

        if "resource_patterns" in filters:
            self.add_filter(ResourcePatternFilter(filters["resource_patterns"]))

        if "account_ids" in filters:
            self.add_filter(AccountFilter(filters["account_ids"]))

        if "regions" in filters:
            self.add_filter(RegionFilter(filters["regions"]))

        if "providers" in filters:
            self.add_filter(ProviderFilter(filters["providers"]))


def create_quick_filters() -> Dict[str, FilterEngine]:
    """Create commonly used filter combinations."""
    filters = {}

    # Failed findings only
    failed_filter = FilterEngine()
    failed_filter.add_filter(StatusFilter(["Failed"]))
    filters["failed_only"] = failed_filter

    # Critical and high severity
    critical_high = FilterEngine()
    critical_high.add_filter(SeverityFilter(["Critical", "High"]))
    filters["critical_high"] = critical_high

    # Critical failed findings
    critical_failed = FilterEngine()
    critical_failed.add_filter(StatusFilter(["Failed"]))
    critical_failed.add_filter(SeverityFilter(["Critical"]))
    filters["critical_failed"] = critical_failed

    # Production resources (example pattern)
    production = FilterEngine()
    production.add_filter(ResourcePatternFilter(["prod-*", "*-production", "*-prod"]))
    filters["production"] = production

    return filters
