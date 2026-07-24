"""
PlexTrac API endpoint wrappers.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Union

import requests

from ..auth.auth_handler import AuthenticationError, AuthHandler
from ..utils.logger import get_logger


@dataclass
class Client:
    """Represents a PlexTrac client."""

    id: str
    name: str
    description: Optional[str] = None
    created_date: Optional[str] = None

    def __str__(self):
        return f"{self.name} ({self.id})"


@dataclass
class Report:
    """Represents a PlexTrac report."""

    id: str
    name: str
    client_id: str
    template_id: Optional[str] = None
    created_date: Optional[str] = None
    status: Optional[str] = None

    def __str__(self):
        return f"{self.name} ({self.id})"


@dataclass
class Asset:
    """Represents a PlexTrac asset."""

    id: Optional[str] = None
    name: str = ""
    description: Optional[str] = None
    asset_type: str = "Other"
    ip_addresses: List[str] = None
    hostnames: List[str] = None

    def __post_init__(self):
        if self.ip_addresses is None:
            self.ip_addresses = []
        if self.hostnames is None:
            self.hostnames = []


@dataclass
class Finding:
    """Represents a PlexTrac finding."""

    id: Optional[str] = None
    title: str = ""
    description: str = ""
    severity: str = "Low"
    status: str = "Open"
    references: List[str] = None
    affected_assets: Dict[str, Any] = None
    recommendation: str = ""

    def __post_init__(self):
        if self.references is None:
            self.references = []
        if self.affected_assets is None:
            self.affected_assets = {}


class PlexTracAPIError(Exception):
    """Custom exception for PlexTrac API errors."""

    def __init__(
        self, message: str, status_code: Optional[int] = None, response_data: Optional[Dict] = None
    ):
        super().__init__(message)
        self.status_code = status_code
        self.response_data = response_data


class PlexTracAPI:
    """PlexTrac API client with endpoint wrappers."""

    def __init__(self, auth_handler: Optional[AuthHandler] = None):
        self.auth = auth_handler or AuthHandler()
        self.logger = get_logger(__name__)

    def _handle_response(self, response: requests.Response) -> Dict[str, Any]:
        """Handle API response and extract data."""
        try:
            if response.status_code >= 400:
                error_data = {}
                try:
                    error_data = response.json()
                except:  # nosec B110 - Intentionally ignoring JSON decode errors
                    pass

                error_msg = error_data.get("message", f"HTTP {response.status_code}")
                raise PlexTracAPIError(
                    message=error_msg, status_code=response.status_code, response_data=error_data
                )

            # Handle different response formats
            if response.status_code == 204:  # No content
                return {}

            return response.json()

        except requests.exceptions.JSONDecodeError:
            raise PlexTracAPIError(f"Invalid JSON response from API")

    # Client Management
    def get_clients(self) -> List[Client]:
        """Get all clients."""
        try:
            # Use the correct PlexTrac API endpoint structure
            if hasattr(self.auth, "tenant_id") and self.auth.tenant_id is not None:
                endpoint = f"/api/v1/tenant/{self.auth.tenant_id}/client/list"
            else:
                # Fallback if no tenant_id available
                endpoint = "/api/v1/client/list"

            response = self.auth.make_authenticated_request("GET", endpoint)
            data = self._handle_response(response)

            clients = []
            # PlexTrac API returns list with 'data' field containing actual client info
            client_list = data if isinstance(data, list) else data.get("clients", [])

            for client_item in client_list:
                # Extract client data from 'data' field
                client_data = (
                    client_item.get("data", client_item)
                    if isinstance(client_item, dict)
                    else client_item
                )
                clients.append(
                    Client(
                        id=str(client_data.get("client_id", client_data.get("id", ""))),
                        name=client_data.get("name", ""),
                        description=client_data.get("description"),
                        created_date=client_data.get("created_date"),
                    )
                )

            self.logger.info(f"Retrieved {len(clients)} clients")
            return clients

        except Exception as e:
            self.logger.error(f"Error getting clients: {str(e)}")
            raise PlexTracAPIError(f"Failed to get clients: {str(e)}")

    def get_client(self, client_id: str) -> Optional[Client]:
        """Get a specific client by ID."""
        try:
            response = self.auth.make_authenticated_request("GET", f"/clients/{client_id}")
            data = self._handle_response(response)

            return Client(
                id=str(data.get("id", "")),
                name=data.get("name", ""),
                description=data.get("description"),
                created_date=data.get("created_date"),
            )

        except PlexTracAPIError as e:
            if e.status_code == 404:
                return None
            raise
        except Exception as e:
            self.logger.error(f"Error getting client {client_id}: {str(e)}")
            raise PlexTracAPIError(f"Failed to get client: {str(e)}")

    # Report Management
    def get_reports(self, client_id: str) -> List[Report]:
        """Get all reports for a client."""
        try:
            # Use the correct PlexTrac API endpoint from docs
            endpoint = f"/api/v1/client/{client_id}/reports"
            response = self.auth.make_authenticated_request("GET", endpoint)
            data = self._handle_response(response)

            self.logger.debug(f"Reports response data: {data}")

            reports = []
            report_list = data.get("reports", data) if isinstance(data, dict) else data
            self.logger.debug(f"Report list type: {type(report_list)}, content: {report_list}")

            for report_data in report_list:
                self.logger.debug(f"Processing report: {report_data}")

                # PlexTrac returns objects with 'id' field and 'data' array
                # data[0] = id, data[1] = name, data[3] = status, etc.
                if isinstance(report_data, dict) and "data" in report_data:
                    data_array = report_data["data"]
                    report_id = str(report_data.get("id", ""))
                    report_name = str(data_array[1]) if len(data_array) > 1 else ""
                    report_status = str(data_array[3]) if len(data_array) > 3 else ""

                    report = Report(
                        id=report_id, name=report_name, client_id=client_id, status=report_status
                    )
                elif isinstance(report_data, list):
                    # Pure array format: [id, title, ...]
                    report_id = str(report_data[0]) if len(report_data) > 0 else ""
                    report_name = str(report_data[1]) if len(report_data) > 1 else ""
                    report = Report(id=report_id, name=report_name, client_id=client_id)
                else:
                    # Standard object format
                    report = Report(
                        id=str(report_data.get("id", "")),
                        name=report_data.get("name", ""),
                        client_id=client_id,
                        template_id=report_data.get("template_id"),
                        created_date=report_data.get("created_date"),
                        status=report_data.get("status"),
                    )

                self.logger.debug(f"Created report object: name='{report.name}', id='{report.id}'")
                reports.append(report)

            self.logger.info(f"Retrieved {len(reports)} reports for client {client_id}")
            return reports

        except Exception as e:
            self.logger.error(f"Error getting reports for client {client_id}: {str(e)}")
            raise PlexTracAPIError(f"Failed to get reports: {str(e)}")

    def get_report(self, client_id: str, report_id: str) -> Optional[Report]:
        """Get a specific report by ID."""
        try:
            response = self.auth.make_authenticated_request(
                "GET", f"/clients/{client_id}/reports/{report_id}"
            )
            data = self._handle_response(response)

            return Report(
                id=str(data.get("id", "")),
                name=data.get("name", ""),
                client_id=client_id,
                template_id=data.get("template_id"),
                created_date=data.get("created_date"),
                status=data.get("status"),
            )

        except PlexTracAPIError as e:
            if e.status_code == 404:
                return None
            raise
        except Exception as e:
            self.logger.error(f"Error getting report {report_id}: {str(e)}")
            raise PlexTracAPIError(f"Failed to get report: {str(e)}")

    def create_report(self, client_id: str, name: str, template_id: Optional[str] = None) -> Report:
        """Create a new report."""
        try:
            payload = {"name": name}

            if template_id:
                payload["template_id"] = template_id

            # Use the correct PlexTrac API endpoint from docs
            # Add client_id to payload as required by the API
            payload["client_id"] = client_id

            response = self.auth.make_authenticated_request(
                "POST", "/api/v1/report/create", json=payload
            )
            data = self._handle_response(response)

            report = Report(
                id=str(data.get("id", "")),
                name=data.get("name", ""),
                client_id=client_id,
                template_id=data.get("template_id"),
                created_date=data.get("created_date"),
                status=data.get("status"),
            )

            self.logger.info(f"Created report '{name}' with ID {report.id}")
            return report

        except Exception as e:
            self.logger.error(f"Error creating report '{name}': {str(e)}")
            raise PlexTracAPIError(f"Failed to create report: {str(e)}")

    # Finding Management
    def get_findings(self, client_id: str, report_id: str) -> List[Finding]:
        """Get all findings for a report."""
        try:
            # Use the correct PlexTrac API endpoint pattern (flaws, not findings)
            endpoint = f"/api/v1/client/{client_id}/report/{report_id}/flaws"
            response = self.auth.make_authenticated_request("GET", endpoint)
            data = self._handle_response(response)

            findings = []
            finding_list = data.get("findings", data) if isinstance(data, dict) else data

            for finding_data in finding_list:
                findings.append(
                    Finding(
                        id=str(finding_data.get("id", "")),
                        title=finding_data.get("title", ""),
                        description=finding_data.get("description", ""),
                        severity=finding_data.get("severity", "Low"),
                        status=finding_data.get("status", "Open"),
                        references=finding_data.get("references", []),
                        affected_assets=finding_data.get("affected_assets", {}),
                        recommendation=finding_data.get("recommendation", ""),
                    )
                )

            self.logger.info(f"Retrieved {len(findings)} findings for report {report_id}")
            return findings

        except Exception as e:
            self.logger.error(f"Error getting findings for report {report_id}: {str(e)}")
            raise PlexTracAPIError(f"Failed to get findings: {str(e)}")

    def create_finding(self, client_id: str, report_id: str, finding: Finding) -> Finding:
        """Create a new finding."""
        try:
            payload = {
                "title": finding.title,
                "description": finding.description,
                "severity": finding.severity,
                "status": finding.status,
                "affected_assets": finding.affected_assets,
                "recommendations": finding.recommendation,
                "references": finding.references,
                "source": "custom",
            }

            self.logger.debug(
                f"Creating finding '{finding.title}' with severity: {finding.severity}"
            )
            self.logger.debug(f"Affected assets for finding: {finding.affected_assets}")
            self.logger.debug(f"Full payload: {payload}")

            # Use the correct PlexTrac API endpoint from docs
            response = self.auth.make_authenticated_request(
                "POST", f"/api/v1/client/{client_id}/report/{report_id}/flaw/create", json=payload
            )
            data = self._handle_response(response)

            created_finding = Finding(
                id=str(data.get("id", "")),
                title=data.get("title", finding.title),
                description=data.get("description", finding.description),
                severity=data.get("severity", finding.severity),
                status=data.get("status", finding.status),
                references=data.get("references", finding.references),
                affected_assets=data.get("affected_assets", finding.affected_assets),
                recommendation=data.get("recommendation", finding.recommendation),
            )

            self.logger.debug(f"Created finding '{finding.title}'")
            return created_finding

        except Exception as e:
            self.logger.error(f"Error creating finding '{finding.title}': {str(e)}")
            raise PlexTracAPIError(f"Failed to create finding: {str(e)}")

    def create_findings_batch(
        self, client_id: str, report_id: str, findings: List[Finding]
    ) -> List[Finding]:
        """Create multiple findings in batches."""
        created_findings = []
        batch_size = 10  # Reasonable batch size to avoid timeouts

        self.logger.info(f"Creating {len(findings)} findings in batches of {batch_size}")

        for i in range(0, len(findings), batch_size):
            batch = findings[i : i + batch_size]
            self.logger.info(f"Processing batch {i//batch_size + 1}: {len(batch)} findings")

            for finding in batch:
                try:
                    created_finding = self.create_finding(client_id, report_id, finding)
                    created_findings.append(created_finding)
                except Exception as e:
                    self.logger.error(f"Failed to create finding '{finding.title}': {str(e)}")
                    # Continue with other findings
                    continue

        self.logger.info(
            f"Successfully created {len(created_findings)} out of {len(findings)} findings"
        )
        return created_findings

    # Asset Management
    def get_assets(self, client_id: str) -> List[Asset]:
        """Get all assets for a client."""
        try:
            endpoint = f"/api/v1/client/{client_id}/assets"
            response = self.auth.make_authenticated_request("GET", endpoint)
            data = self._handle_response(response)

            assets = []
            asset_list = data.get("assets", data) if isinstance(data, dict) else data

            for asset_data in asset_list:
                assets.append(
                    Asset(
                        id=str(asset_data.get("id", "")),
                        name=asset_data.get("name", ""),
                        description=asset_data.get("description"),
                        asset_type=asset_data.get("asset_type", "Other"),
                        ip_addresses=asset_data.get("ip_addresses", []),
                        hostnames=asset_data.get("hostnames", []),
                    )
                )

            self.logger.info(f"Retrieved {len(assets)} assets for client {client_id}")
            return assets

        except Exception as e:
            self.logger.error(f"Error getting assets for client {client_id}: {str(e)}")
            raise PlexTracAPIError(f"Failed to get assets: {str(e)}")

    def create_asset(self, client_id: str, asset: Asset) -> Asset:
        """Create a new asset."""
        try:
            # Use the exact PlexTrac API structure from docs
            payload = {
                "asset": asset.name,
                "description": asset.description or f"{asset.asset_type}: {asset.name}",
                "doc_type": "client_asset",
                "type": asset.asset_type,
                "knownIps": asset.ip_addresses,
                "hostname": asset.hostnames[0] if asset.hostnames else "",
                "findings": {},
                "ports": {},
                "data_owner": "",
                "dns_name": "",
                "host_fqdn": "",
                "host_rdns": "",
                "mac_address": "",
                "netbios_name": "",
                "parent_asset": None,
                "physical_location": "",
                "system_owner": "",
                "total_cves": "0",
            }

            self.logger.debug(f"Creating asset with PlexTrac format: {payload}")
            endpoint = f"/api/v1/client/{client_id}/asset/0"

            response = self.auth.make_authenticated_request("PUT", endpoint, json=payload)

            self.logger.debug(f"Asset creation response status: {response.status_code}")
            self.logger.debug(f"Asset creation response headers: {dict(response.headers)}")
            self.logger.debug(f"Asset creation response body: {response.text}")

            data = self._handle_response(response)

            created_asset = Asset(
                id=str(data.get("id", "")),
                name=data.get("name", asset.name),
                description=data.get("description", asset.description),
                asset_type=data.get("asset_type", asset.asset_type),
                ip_addresses=data.get("ip_addresses", asset.ip_addresses),
                hostnames=data.get("hostnames", asset.hostnames),
            )

            self.logger.info(f"Created asset '{asset.name}' with ID {created_asset.id}")
            return created_asset

        except Exception as e:
            self.logger.error(f"Error creating asset '{asset.name}': {str(e)}")
            self.logger.error(f"Asset creation failed for client {client_id}, asset: {asset}")
            raise PlexTracAPIError(f"Failed to create asset: {str(e)}")

    def get_or_create_asset(
        self,
        client_id: str,
        asset_name: str,
        asset_type: str = "Cloud Account",
        description: str = None,
    ) -> Asset:
        """Get existing asset or create new one."""
        try:
            # Get existing assets
            assets = self.get_assets(client_id)

            # Look for existing asset by name
            existing_asset = next((a for a in assets if a.name == asset_name), None)
            if existing_asset:
                self.logger.debug(f"Found existing asset: {asset_name}")
                return existing_asset

            # Create new asset
            new_asset = Asset(
                name=asset_name,
                description=description or f"{asset_type}: {asset_name}",
                asset_type=asset_type,
            )

            return self.create_asset(client_id, new_asset)

        except Exception as e:
            self.logger.error(f"Error getting/creating asset '{asset_name}': {str(e)}")
            raise PlexTracAPIError(f"Failed to get/create asset: {str(e)}")

    # Utility Methods
    def test_connection(self) -> bool:
        """Test the API connection and authentication."""
        try:
            # First check if auth handler thinks we're authenticated
            if not self.auth.is_authenticated():
                self.logger.error("API connection test failed - not authenticated")
                return False

            self.logger.debug("Starting API connection test...")

            # Try to get user info first
            self.logger.debug("Testing /whoami endpoint...")
            user_info = self.auth.get_current_user()
            if user_info:
                self.logger.info("API connection test successful using /whoami endpoint")
                self.logger.debug(f"User info retrieved: {user_info}")
                return True

            self.logger.debug("/whoami endpoint failed, trying alternative endpoints...")

            # If user info fails, try alternative PlexTrac endpoints
            test_endpoints = []
            if hasattr(self.auth, "tenant_id") and self.auth.tenant_id:
                tenant_endpoints = [
                    f"/api/v1/tenant/{self.auth.tenant_id}/client/list",
                    f"/api/v1/tenant/{self.auth.tenant_id}/clients",
                    f"/api/v2/tenant/{self.auth.tenant_id}/clients",
                    f"/api/v1/tenant/{self.auth.tenant_id}",
                    f"/api/v2/tenant/{self.auth.tenant_id}",
                ]
                test_endpoints.extend(tenant_endpoints)
                self.logger.debug(
                    f"Testing tenant-based endpoints with tenant_id: {self.auth.tenant_id}"
                )
            else:
                self.logger.debug("No tenant_id available, skipping tenant-based endpoints")

            # Fallback endpoints
            fallback_endpoints = [
                "/api/v1/clients",
                "/api/v2/clients",
                "/api/v1/user",
                "/api/v2/user",
            ]
            test_endpoints.extend(fallback_endpoints)

            self.logger.debug(f"Testing {len(test_endpoints)} connection test endpoints...")

            for i, endpoint in enumerate(test_endpoints, 1):
                try:
                    self.logger.debug(f"Testing endpoint {i}/{len(test_endpoints)}: {endpoint}")
                    response = self.auth.make_authenticated_request("GET", endpoint, timeout=5)
                    self.logger.debug(f"Response from {endpoint}: {response.status_code}")

                    if response.status_code in [
                        200,
                        403,
                    ]:  # 403 means authenticated but no permission
                        self.logger.info(f"API connection test successful (tested with {endpoint})")
                        if response.status_code == 200:
                            self.logger.debug(
                                f"Response data preview: {str(response.text)[:200]}..."
                            )
                        return True
                    elif response.status_code == 404:
                        self.logger.debug(f"Endpoint {endpoint} not found (404) - trying next")
                        continue
                    else:
                        self.logger.debug(
                            f"Endpoint {endpoint} returned {response.status_code} - trying next"
                        )
                        continue

                except Exception as e:
                    self.logger.debug(f"Exception testing endpoint {endpoint}: {str(e)}")
                    continue

            self.logger.warning(
                "API connection test - no accessible endpoints found but authentication succeeded"
            )
            self.logger.debug(
                "This may indicate API endpoint structure differences - proceeding with authenticated status"
            )

            # Since authentication succeeded, don't fail the connection test
            # The actual API calls will reveal if there are real connectivity issues
            return True

        except Exception as e:
            self.logger.error(f"API connection test failed: {str(e)}")
            return False

    def get_api_info(self) -> Dict[str, Any]:
        """Get API version and server information."""
        try:
            response = self.auth.make_authenticated_request("GET", "/info")
            return self._handle_response(response)
        except Exception as e:
            self.logger.error(f"Error getting API info: {str(e)}")
            return {}

    def search_clients(self, query: str) -> List[Client]:
        """Search clients by name."""
        clients = self.get_clients()
        query_lower = query.lower()

        return [
            client
            for client in clients
            if query_lower in client.name.lower()
            or (client.description and query_lower in client.description.lower())
        ]

    def search_reports(self, client_id: str, query: str) -> List[Report]:
        """Search reports by name."""
        reports = self.get_reports(client_id)
        query_lower = query.lower()

        return [report for report in reports if query_lower in report.name.lower()]
