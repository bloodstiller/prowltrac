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
from src.converter import convert_findings, group_findings, is_manual, prowler_status
from src.ptrac import build_ptrac, write_ptrac, validate_doc_version
from src.csv_export import write_csv


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
    
    # Severity narrowing per --filter choice (None = every severity)
    _FILTER_SEVERITIES = {
        "all": None,
        "fail": None,
        "fail-critical-high": None,  # FAIL is always required now, so same as "fail"
        "critical": {"Critical"},
        "critical-high": {"Critical", "High"},
        "critical-high-medium": {"Critical", "High", "Medium"},
    }

    def apply_filter(self, filter_type: str) -> None:
        """Select what gets imported.

        - Only FAIL and MANUAL results are ever imported; PASS (and anything else) never is.
        - Every MANUAL result is imported regardless of the filter, so controls needing
          human verification always reach PlexTrac.
        - The filter only narrows FAIL results by severity.
        """
        original_count = len(self.filtered_findings)
        severities = self._FILTER_SEVERITIES.get(filter_type)

        def keep(finding) -> bool:
            if is_manual(finding):
                return True
            if prowler_status(finding) != "FAIL":
                return False
            return severities is None or finding.severity in severities

        self.filtered_findings = [f for f in self.findings if keep(f)]
        manual = sum(1 for f in self.filtered_findings if is_manual(f))
        print(f"🔍 Filter '{filter_type}': {len(self.filtered_findings)} results "
              f"({len(self.filtered_findings) - manual} FAIL + {manual} MANUAL; "
              f"was {original_count}, PASS excluded)")
    
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
        """Convert OCSF findings to PlexTrac API Finding objects."""
        from src.api.endpoints import Finding

        plextrac_findings = []
        for converted in convert_findings(ocsf_findings):
            ocsf_finding = converted.source

            affected_assets = {}
            if ocsf_finding.cloud_account_uid and ocsf_finding.cloud_account_uid in asset_mapping:
                asset_id = asset_mapping[ocsf_finding.cloud_account_uid]
                affected_assets[asset_id] = {
                    "id": asset_id,
                    "asset": converted.asset_name,
                    "ports": None,
                    "status": None,
                    "locationUrl": None,
                    "vulnerableParameters": None,
                    "evidence": None,
                    "notes": None
                }

            plextrac_findings.append(Finding(
                title=converted.title,
                description="\\n\\n".join(converted.description_parts),
                severity=ocsf_finding.severity,
                status="Open",
                references=converted.references,
                affected_assets=affected_assets,
                recommendation=converted.recommendation
            ))

        return plextrac_findings


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


def _output_path(raw: str, suffix: str, force: bool) -> Path:
    """Resolve an offline output path, appending the suffix and refusing to overwrite."""
    path = Path(raw)
    if path.suffix.lower() != suffix:
        path = path.with_name(path.name + suffix)
    if path.exists() and not force:
        print(f"❌ Output file already exists: {path} (use --force to overwrite)")
        sys.exit(1)
    return path


def main():
    parser = argparse.ArgumentParser(
        description='Import Prowler OCSF findings to PlexTrac',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Filter Options (PASS results are never imported; every MANUAL check always is):
  fail / all            Import all FAIL findings
  critical              Import Critical FAIL findings
  critical-high         Import Critical and High FAIL findings
  critical-high-medium  Import Critical, High and Medium FAIL findings
  fail-critical-high    Same as fail (kept for compatibility)

Examples:
  %(prog)s prowler-findings.ocsf.json
  %(prog)s prowler-findings.ocsf.json --filter fail --client-id 123
  %(prog)s prowler-findings.ocsf.json --filter critical-high --report-name "Security Review"
  %(prog)s prowler-findings.ocsf.json --debug --url https://myapp.plextrac.com
  %(prog)s prowler-findings.ocsf.json --url https://plextrac.internal --ca-bundle internal-ca.pem
  %(prog)s prowler-findings.ocsf.json --ptrac findings.ptrac --plextrac-version 2.10.1   (offline)
  %(prog)s prowler-findings.ocsf.json --csv findings.csv   (offline)
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
    parser.add_argument('--ca-bundle', help='CA bundle (PEM) used to verify the PlexTrac TLS certificate (self-hosted/internal CA)')
    parser.add_argument('--insecure', action='store_true', help='Disable TLS certificate verification (self-signed certificates; use with care)')
    
    # Offline export options
    parser.add_argument('--ptrac', metavar='FILE', help='Offline mode: write findings to a .ptrac file for manual upload instead of connecting to PlexTrac')
    parser.add_argument('--plextrac-version', metavar='X.Y.Z', help='Version of the PlexTrac instance the .ptrac will be uploaded to (Account Admin page, bottom right). Required with --ptrac; or set PLEXTRAC_APP_VERSION')
    parser.add_argument('--client-name', help='Client name stored in the .ptrac (used by Reports > Import Report)')
    parser.add_argument('--csv', metavar='FILE', help='Offline mode: write findings to a PlexTrac findings CSV (Add Findings > CSV) instead of connecting to PlexTrac')
    parser.add_argument('--force', action='store_true', help='Overwrite existing --ptrac/--csv output files')
    
    # Import options
    parser.add_argument('--client-id', help='PlexTrac client ID (skip selection)')
    parser.add_argument('--report-id', help='PlexTrac report ID (skip selection/creation)')
    parser.add_argument('--report-name', help='Custom report name for new reports')
    
    # Filtering options
    parser.add_argument('--filter', 
                       choices=['all', 'fail', 'critical', 'critical-high', 'critical-high-medium', 'fail-critical-high'],
                       default='fail',
                       help='Narrow FAIL results by severity (default: fail). PASS results are never imported; MANUAL checks always are')
    
    # Debug options
    parser.add_argument('--debug', action='store_true', help='Enable enhanced debug logging for API requests')
    parser.add_argument('--show-stats', action='store_true', help='Show finding statistics before filtering')
    
    args = parser.parse_args()
    
    # Check if file exists
    if not Path(args.ocsf_file).exists():
        print(f"❌ File not found: {args.ocsf_file}")
        sys.exit(1)
    
    # Validate offline export options up front, before any parsing work
    ptrac_path = None
    ptrac_version = None
    if args.ptrac:
        ptrac_version = args.plextrac_version or os.getenv("PLEXTRAC_APP_VERSION")
        if not validate_doc_version(ptrac_version):
            print("❌ --ptrac needs the target PlexTrac version as X.Y.Z via --plextrac-version "
                  "or PLEXTRAC_APP_VERSION.")
            print("   Find it at the bottom right of the Account Admin page in PlexTrac.")
            sys.exit(1)
        ptrac_path = _output_path(args.ptrac, ".ptrac", args.force)
    csv_path = _output_path(args.csv, ".csv", args.force) if args.csv else None
    
    print("🚀 Prowler OCSF to PlexTrac Importer (Enhanced CLI)")
    print("=" * 50)
    
    if args.debug:
        print("🔍 Debug mode enabled - enhanced request logging active")
    
    # TLS options must be applied before the AuthHandler builds its session
    config = get_config()
    if args.ca_bundle:
        if not Path(args.ca_bundle).is_file():
            print(f"❌ CA bundle not found: {args.ca_bundle}")
            sys.exit(1)
        config.plextrac.ca_bundle = args.ca_bundle
    if args.insecure:
        config.plextrac.verify_ssl = False
        print("⚠️  TLS certificate verification disabled (--insecure)")
    
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
    
    # Offline mode: write file(s) and stop - no auth, no network
    if ptrac_path or csv_path:
        if ptrac_path:
            report_name = args.report_name or f"Prowler Import {datetime.now():%Y-%m-%d}"
            client_name = args.client_name or "Prowler Import"
            ptrac = build_ptrac(
                importer.filtered_findings,
                report_name=report_name,
                client_name=client_name,
                doc_version=ptrac_version,
            )
            write_ptrac(ptrac, ptrac_path)
            print(f"\n💾 Wrote {ptrac_path}")
            print(f"   Report: {report_name}")
            print(f"   Findings: {len(ptrac['flaws_array'])} "
                  f"(from {len(importer.filtered_findings)} Prowler results, grouped by check)")
            print(f"   Assets: {len(ptrac['summary']['ReportAssets'])}")
            print(f"   PlexTrac version: {ptrac_version}")
            print("   📤 Upload, either:")
            print("   • Existing report: Findings tab → Add findings → File Imports → "
                  "Import source 'PlexTrac' → select the file")
            print("   • New report: Reports → Import Report → choose client → drop the file")
        if csv_path:
            write_csv(importer.filtered_findings, csv_path)
            groups = group_findings(importer.filtered_findings)
            print(f"\n💾 Wrote {csv_path}")
            print(f"   Findings: {len(groups)} "
                  f"(from {len(importer.filtered_findings)} Prowler results, grouped by check)")
            print("   📤 Upload: report Findings tab → Add Findings → 'CSV' → choose file → "
                  "Continue → Upload")
        return
    
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