#!/usr/bin/env python3
"""
Simple Prowler OCSF to PlexTrac importer.
No complex TUI - just a straightforward CLI tool.

Copyright 2025 Prowltrac Contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import json
import sys
import os
import requests
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import getpass
from datetime import datetime
import argparse

# Add current directory to path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import our existing modules
from src.utils.config import get_config, get_credentials
from src.utils.logger import get_logger
from src.ocsf_parser import OCSFParser
from src.auth.auth_handler import AuthHandler
from src.plextrac_client import PlexTracClient
from src.filters import FilterEngine
from src.utils.cloud import asset_label_for_provider


class ProwlerCLIImporter:
    """Enhanced CLI importer using the full infrastructure."""
    
    def __init__(self, debug_requests=False):
        self.logger = get_logger(__name__)
        self.config = get_config()
        self.parser = OCSFParser()
        self.filter_engine = FilterEngine()
        
        # Initialize auth and client 
        self.auth_handler = AuthHandler(use_cache=True, interactive=False, debug_requests=debug_requests)
        self.plextrac_client = None
        
        # State
        self.findings = []
        self.filtered_findings = []
    
    def parse_file(self, file_path: str) -> bool:
        """Parse OCSF file and return success status."""
        try:
            self.findings = self.parser.parse_file(file_path)
            self.filtered_findings = self.findings.copy()
            print(f"✅ Parsed {len(self.findings)} findings from {file_path}")
            return len(self.findings) > 0
        except Exception as e:
            print(f"❌ Error parsing file {file_path}: {e}")
            return False
    
    def apply_filter(self, filter_type: str) -> None:
        """Apply filtering based on type."""
        original_count = len(self.filtered_findings)
        
        self.filter_engine.clear_filters()
        
        if filter_type == "fail":
            self.filter_engine.create_from_preset({'filters': {'status': ['FAIL']}})
        elif filter_type == "critical":
            self.filter_engine.create_from_preset({'filters': {'severity': ['Critical']}})
        elif filter_type == "critical-high":
            self.filter_engine.create_from_preset({'filters': {'severity': ['Critical', 'High']}})
        elif filter_type == "critical-high-medium":
            self.filter_engine.create_from_preset({'filters': {'severity': ['Critical', 'High', 'Medium']}})
        elif filter_type == "fail-critical-high":
            self.filter_engine.create_from_preset({'filters': {'status': ['FAIL'], 'severity': ['Critical', 'High']}})
            from src.filters import FilterOperator
            self.filter_engine.set_operator(FilterOperator.OR)
        elif filter_type == "all":
            # No filtering
            return
        
        if filter_type != "all":
            filter_result = self.filter_engine.apply_filters(self.findings)
            self.filtered_findings = filter_result.filtered_findings
        
        print(f"🔍 Filter '{filter_type}': {len(self.filtered_findings)} findings (was {original_count})")
    
    def connect(self, url: str = None, username: str = None, password: str = None, mfa_token: str = None, token: str = None) -> bool:
        """Connect to PlexTrac."""
        try:
            # Get credentials from environment/config or parameters
            creds = get_credentials()

            # A directly-supplied bearer token takes precedence over username/password
            auth_token = token or creds.get('token')

            auth_url = url or self.config.plextrac.url
            if auth_token:
                if not auth_url:
                    auth_url = input("PlexTrac URL: ").strip()

                print("🔄 Authenticating with bearer token...")
                success = self.auth_handler.authenticate(token=auth_token, url=auth_url)
            else:
                # Override with provided parameters
                auth_username = username or creds.get('username')
                auth_password = password or creds.get('password')
                auth_mfa = mfa_token or creds.get('mfa_token')

                # Prompt for missing credentials
                if not auth_url:
                    auth_url = input("PlexTrac URL: ").strip()
                if not auth_username:
                    auth_username = input("Username: ").strip()
                if not auth_password:
                    auth_password = getpass.getpass("Password: ")
                if not auth_mfa:
                    mfa_input = input("MFA Token (optional): ").strip()
                    auth_mfa = mfa_input if mfa_input else None

                print("🔄 Authenticating...")
                success = self.auth_handler.authenticate(
                    username=auth_username,
                    password=auth_password,
                    mfa_token=auth_mfa,
                    url=auth_url
                )
            
            if success:
                print("🔄 Loading client list...")
                self.plextrac_client = PlexTracClient(self.auth_handler)
                
                if self.plextrac_client.is_authenticated():
                    clients = self.plextrac_client.get_clients()
                    print(f"✅ Connected to PlexTrac with {len(clients)} clients")
                    return True
                else:
                    print("❌ Authentication succeeded but client creation failed")
                    return False
            else:
                print("❌ Authentication failed")
                return False
                
        except Exception as e:
            print(f"❌ Connection failed: {e}")
            return False
    
    def get_clients(self) -> List:
        """Get available clients."""
        if not self.plextrac_client:
            return []
        return self.plextrac_client.get_clients(use_cache=True)
    
    def get_reports(self, client_id: str) -> List:
        """Get reports for a client."""
        if not self.plextrac_client:
            return []
        return self.plextrac_client.get_reports(client_id)
    
    def create_report(self, client_id: str, report_name: str) -> Optional:
        """Create or get a report."""
        if not self.plextrac_client:
            return None
        return self.plextrac_client.create_report_if_needed(client_id, report_name)
    
    def import_findings(self, client_id: str, report_id: str) -> bool:
        """Import filtered findings to PlexTrac."""
        if not self.plextrac_client or not self.filtered_findings:
            return False
        
        # Pre-create assets
        print("🔄 Analyzing and creating assets...")
        unique_assets = {}  # account_uid -> cloud_provider

        for ocsf_finding in self.filtered_findings:
            if ocsf_finding.cloud_account_uid:
                unique_assets[ocsf_finding.cloud_account_uid] = ocsf_finding.cloud_provider

        asset_mapping = {}
        if unique_assets:
            for i, (account_uid, cloud_provider) in enumerate(unique_assets.items(), 1):
                try:
                    asset_label = asset_label_for_provider(cloud_provider)
                    asset_name = f"{asset_label} {account_uid}"
                    asset = self.plextrac_client.api.get_or_create_asset(
                        client_id, asset_name, asset_label, f"{asset_label} ID: {account_uid}"
                    )
                    asset_mapping[account_uid] = asset.id
                    print(f"  [{i}/{len(unique_assets)}] {asset_name} -> {asset.id}")
                except Exception as e:
                    print(f"  ⚠️  Failed to create asset {account_uid}: {e}")
        
        # Convert and import findings (reuse logic from menu_import.py)
        print("🔄 Converting findings...")
        plextrac_findings = self._convert_findings_to_plextrac(self.filtered_findings, asset_mapping)
        
        print(f"📤 Importing {len(plextrac_findings)} findings...")
        
        def progress_callback(current, total, message):
            if current % 10 == 0 or current == total:
                print(f"  [{current:3d}/{total}] {message}")
        
        try:
            result = self.plextrac_client.import_findings(
                client_id, report_id, plextrac_findings, progress_callback
            )
            
            print(f"\n🎉 Import complete!")
            print(f"   ✅ Imported: {result.imported_findings}")
            print(f"   🔄 Duplicates: {result.duplicate_findings}")
            print(f"   ❌ Failed: {result.failed_findings}")
            print(f"   📊 Total: {result.total_findings}")
            
            return result.success
            
        except Exception as e:
            print(f"❌ Import failed: {e}")
            return False
    
    def _convert_findings_to_plextrac(self, ocsf_findings, asset_mapping):
        """Convert OCSF findings to PlexTrac format (same as menu_import.py)."""
        from src.api.endpoints import Finding
        
        plextrac_findings = []
        title_counts = {}
        
        for ocsf_finding in ocsf_findings:
            # Use message as title, ensure uniqueness
            base_title = ocsf_finding.message or "Security Finding"
            title = base_title
            if title in title_counts:
                title_counts[title] += 1
                title = f"{base_title} ({ocsf_finding.resource_name or ocsf_finding.class_name or title_counts[title]})"
            else:
                title_counts[title] = 1
            
            # Build description (same logic as menu)
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
                description_parts.append(f"**Compliance**: {', '.join(ocsf_finding.compliance_frameworks)}")
            
            description = "\\n\\n".join(description_parts)
            
            # Extract remediation and references (same logic as menu)
            raw_data = ocsf_finding.raw_data or {}
            remediation_text = self._extract_remediation(raw_data)
            references = self._extract_references(raw_data)
            
            # Set affected assets
            affected_assets = {}
            if ocsf_finding.cloud_account_uid and ocsf_finding.cloud_account_uid in asset_mapping:
                asset_id = asset_mapping[ocsf_finding.cloud_account_uid]
                asset_label = asset_label_for_provider(ocsf_finding.cloud_provider)
                asset_name = f"{asset_label} {ocsf_finding.cloud_account_uid}"

                affected_assets[asset_id] = {
                    "id": asset_id,
                    "asset": asset_name,
                    "ports": None,
                    "status": None,
                    "locationUrl": None,
                    "vulnerableParameters": None,
                    "evidence": None,
                    "notes": None
                }
            
            plextrac_finding = Finding(
                title=title,
                description=description,
                severity=ocsf_finding.severity,
                status="Open",
                references=references,
                affected_assets=affected_assets,
                recommendation=remediation_text or ""
            )
            plextrac_findings.append(plextrac_finding)
        
        return plextrac_findings
    
    def _extract_remediation(self, raw_data):
        """Extract clean remediation text from raw data."""
        remediation_fields = ['remediation', 'recommendation', 'fix', 'solution', 'mitigation']
        
        for field in remediation_fields:
            if field in raw_data and raw_data[field]:
                raw_rec = raw_data[field]
                if isinstance(raw_rec, dict):
                    return (raw_rec.get('desc') or 
                           raw_rec.get('text') or 
                           raw_rec.get('description') or 
                           raw_rec.get('details'))
                elif isinstance(raw_rec, list):
                    return '. '.join(str(item) for item in raw_rec if item)
                else:
                    return str(raw_rec)
        
        # Check unmapped section
        unmapped = raw_data.get('unmapped', {})
        for field in ['Remediation', 'Recommendation', 'Fix', 'Solution']:
            if field in unmapped and unmapped[field]:
                raw_rec = unmapped[field]
                if isinstance(raw_rec, dict):
                    return (raw_rec.get('desc') or
                           raw_rec.get('text') or 
                           raw_rec.get('description'))
                else:
                    return str(raw_rec)
        
        return ""
    
    def _extract_references(self, raw_data):
        """Extract clean reference URLs from raw data."""
        references = []
        ref_fields = ['references', 'links', 'urls', 'external_links']
        
        for field in ref_fields:
            if field in raw_data:
                refs = raw_data[field]
                if isinstance(refs, list):
                    for ref in refs:
                        if isinstance(ref, dict):
                            url = ref.get('url') or ref.get('link') or ref.get('href')
                            if url:
                                references.append(str(url))
                        elif isinstance(ref, str) and ('http' in ref or 'www.' in ref):
                            references.append(ref)
                elif isinstance(refs, str) and ('http' in refs or 'www.' in refs):
                    references.append(refs)
        
        # Check unmapped for references
        unmapped = raw_data.get('unmapped', {})
        for field in ['References', 'Links', 'URLs', 'External_Links']:
            if field in unmapped:
                refs = unmapped[field]
                if isinstance(refs, list):
                    for ref in refs:
                        if isinstance(ref, dict):
                            url = ref.get('url') or ref.get('link') or ref.get('href')
                            if url:
                                references.append(str(url))
                        elif isinstance(ref, str) and ('http' in ref or 'www.' in ref):
                            references.append(ref)
                elif isinstance(refs, str) and ('http' in refs or 'www.' in refs):
                    references.append(refs)
        
        return list(set(ref for ref in references if ref and ref.strip()))


def select_client(clients: List) -> Optional[str]:
    """Let user select a client."""
    if not clients:
        print("❌ No clients found")
        return None
    
    print("\nAvailable clients:")
    for i, client in enumerate(clients):
        if hasattr(client, 'name') and hasattr(client, 'id'):
            desc = f" - {client.description}" if client.description else ""
            print(f"{i+1}. {client.name} (ID: {client.id}){desc}")
        else:
            print(f"{i+1}. Unknown client: {client}")
    
    while True:
        try:
            choice = input(f"\nSelect client (1-{len(clients)}): ").strip()
            idx = int(choice) - 1
            if 0 <= idx < len(clients):
                return getattr(clients[idx], 'id', clients[idx].get('id') if hasattr(clients[idx], 'get') else str(clients[idx]))
            else:
                print("Invalid selection")
        except (ValueError, KeyboardInterrupt):
            return None


def select_report(importer, client_id: str, client_name: str, report_name: str = None) -> Optional[str]:
    """Let user select or create a report."""
    try:
        reports = importer.get_reports(client_id)
    except Exception as e:
        print(f"⚠️  Could not load reports: {e}")
        reports = []
    
    if reports:
        print(f"\nAvailable reports for {client_name}:")
        for i, report in enumerate(reports):
            if hasattr(report, 'name') and hasattr(report, 'id'):
                name = report.name if report.name else f"Report {report.id}"
                print(f"{i+1}. {name} (ID: {report.id})")
        
        print(f"{len(reports)+1}. Create new report")
        
        while True:
            try:
                choice = input(f"\nSelect report (1-{len(reports)+1}): ").strip()
                idx = int(choice) - 1
                if 0 <= idx < len(reports):
                    return getattr(reports[idx], 'id', reports[idx].get('id'))
                elif idx == len(reports):
                    break  # Create new report
                else:
                    print("Invalid selection")
            except (ValueError, KeyboardInterrupt):
                return None
    
    # Create new report
    default_name = report_name or f"Prowler Import {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    final_name = input(f"Report name [{default_name}]: ").strip() or default_name
    
    try:
        report = importer.create_report(client_id, final_name)
        if report:
            return getattr(report, 'id', report.get('id') if hasattr(report, 'get') else None)
        else:
            print("❌ Failed to create report")
            return None
    except Exception as e:
        print(f"❌ Failed to create report: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(
        description='Import Prowler OCSF findings to PlexTrac',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Filter Options:
  all                   Import all findings
  fail                  Import only FAIL findings 
  critical              Import only Critical severity
  critical-high         Import Critical and High severity
  critical-high-medium  Import Critical, High, and Medium severity
  fail-critical-high    Import FAIL findings OR Critical/High severity

Examples:
  %(prog)s prowler-findings.ocsf.json
  %(prog)s prowler-findings.ocsf.json --filter fail --client-id 123
  %(prog)s prowler-findings.ocsf.json --filter critical-high --report-name "Security Review"
  %(prog)s prowler-findings.ocsf.json --debug --url https://myapp.plextrac.com
        """
    )
    
    # Required arguments
    parser.add_argument('ocsf_file', help='Path to OCSF JSON file')
    
    # Connection options
    parser.add_argument('--url', help='PlexTrac instance URL')
    parser.add_argument('--username', help='PlexTrac username')
    parser.add_argument('--password', help='PlexTrac password')
    parser.add_argument('--mfa-token', help='MFA token')
    parser.add_argument('--token', help='PlexTrac API bearer token (takes precedence over --username/--password)')
    
    # Import options
    parser.add_argument('--client-id', help='PlexTrac client ID (skip selection)')
    parser.add_argument('--report-id', help='PlexTrac report ID (skip selection/creation)')
    parser.add_argument('--report-name', help='Custom report name for new reports')
    
    # Filtering options
    parser.add_argument('--filter', 
                       choices=['all', 'fail', 'critical', 'critical-high', 'critical-high-medium', 'fail-critical-high'],
                       default='fail',
                       help='Filter findings to import (default: fail)')
    
    # Debug options
    parser.add_argument('--debug', action='store_true', help='Enable enhanced debug logging for API requests')
    parser.add_argument('--show-stats', action='store_true', help='Show finding statistics before filtering')
    
    args = parser.parse_args()
    
    # Check if file exists
    if not Path(args.ocsf_file).exists():
        print(f"❌ File not found: {args.ocsf_file}")
        sys.exit(1)
    
    print("🚀 Prowler OCSF to PlexTrac Importer (Enhanced CLI)")
    print("=" * 50)
    
    if args.debug:
        print("🔍 Debug mode enabled - enhanced request logging active")
    
    # Initialize importer
    importer = ProwlerCLIImporter(debug_requests=args.debug)
    
    # Parse OCSF file
    print(f"📄 Parsing OCSF file: {args.ocsf_file}...")
    if not importer.parse_file(args.ocsf_file):
        print("❌ No findings found in file")
        sys.exit(1)
    
    # Show stats if requested
    if args.show_stats:
        print(f"\n📊 File Statistics:")
        print(f"   Total findings: {len(importer.findings)}")
        
        # Quick stats
        severity_counts = {}
        status_counts = {}
        for f in importer.findings:
            sev = f.severity
            status = f.status_code or 'UNKNOWN'
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            status_counts[status] = status_counts.get(status, 0) + 1
        
        print(f"   By severity: {dict(sorted(severity_counts.items()))}")
        print(f"   By status: {dict(sorted(status_counts.items()))}")
    
    # Apply filtering
    print(f"🔍 Applying filter: {args.filter}")
    importer.apply_filter(args.filter)
    
    if not importer.filtered_findings:
        print("❌ No findings to import after filtering")
        sys.exit(1)
    
    # Connect to PlexTrac
    print("\n🔐 Connecting to PlexTrac...")
    if not importer.connect(args.url, args.username, args.password, args.mfa_token, args.token):
        print("❌ Failed to connect to PlexTrac")
        sys.exit(1)
    
    # Select client
    if args.client_id:
        client_id = args.client_id
        client_name = f"Client {client_id}"
    else:
        clients = importer.get_clients()
        if not clients:
            print("❌ No clients found")
            sys.exit(1)
        
        client_id = select_client(clients)
        if not client_id:
            print("❌ No client selected")
            sys.exit(1)
        
        # Find client name
        client_name = "Unknown"
        for client in clients:
            if getattr(client, 'id', None) == client_id:
                client_name = getattr(client, 'name', f"Client {client_id}")
                break
    
    # Select or create report
    if args.report_id:
        report_id = args.report_id
        print(f"📄 Using existing report ID: {report_id}")
    else:
        report_id = select_report(importer, client_id, client_name, args.report_name)
        if not report_id:
            print("❌ No report selected/created")
            sys.exit(1)
    
    # Import findings
    print(f"\n📋 Import Summary:")
    print(f"   Client: {client_name} ({client_id})")
    print(f"   Report ID: {report_id}")
    print(f"   Findings: {len(importer.filtered_findings)}")
    print(f"   Filter: {args.filter}")
    
    confirm = input("\nProceed with import? (y/N): ").strip().lower()
    if confirm != 'y':
        print("❌ Import cancelled")
        sys.exit(0)
    
    # Perform import
    if importer.import_findings(client_id, report_id):
        print(f"\n🎉 Import completed successfully!")
    else:
        print(f"\n❌ Import failed")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n❌ Import cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)