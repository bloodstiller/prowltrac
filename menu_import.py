#!/usr/bin/env python3
"""
Menu-based Prowler OCSF to PlexTrac importer.
Simple text menus with scrolling - no complex TUI.
Uses existing config system and authentication.

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
from simple_term_menu import TerminalMenu

# Add current directory to path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import our existing modules
from src.utils.config import get_config, get_credentials
from src.utils.logger import get_logger
from src.ocsf_parser import OCSFParser
from src.auth.auth_handler import AuthHandler
from src.plextrac_client import PlexTracClient
from src.filters import FilterEngine


class MenuOCSFParser:
    """Menu wrapper for our existing OCSF parser."""
    
    def __init__(self):
        self.parser = OCSFParser()
        self.logger = get_logger(__name__)
    
    def parse_file(self, file_path: str) -> Tuple[List[Any], Dict]:
        """Parse OCSF JSON file and return findings + stats."""
        try:
            findings = self.parser.parse_file(file_path)
            stats = self._generate_stats(findings)
            self.logger.info(f"Parsed {len(findings)} findings from {file_path}")
            return findings, stats
            
        except Exception as e:
            self.logger.error(f"Error parsing file {file_path}: {e}")
            print(f"❌ Error parsing file {file_path}: {e}")
            return [], {}
    
    def _generate_stats(self, findings: List[Any]) -> Dict:
        """Generate statistics about findings."""
        stats = {
            'total': len(findings),
            'by_severity': {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0},
            'by_status': {'PASS': 0, 'FAIL': 0, 'UNKNOWN': 0, 'Other': 0}
        }
        
        for finding in findings:
            # Use the severity and status from our OCSFFinding objects
            severity_id = getattr(finding, 'severity_id', 3)
            status_code = getattr(finding, 'status_code', 'UNKNOWN')
            
            # Map severity using the same mapping as config
            severity_map = {1: "Critical", 2: "High", 3: "Medium", 4: "Low", 5: "Informational"}
            severity = severity_map.get(severity_id, "Medium")
            
            if severity in stats['by_severity']:
                stats['by_severity'][severity] += 1
            
            # Map status_code (FAIL/PASS/UNKNOWN)
            if status_code in ['FAIL', 'PASS', 'UNKNOWN']:
                stats['by_status'][status_code] += 1
            else:
                stats['by_status']['Other'] += 1
        
        return stats


class ProwlerImportMenu:
    """Main menu-driven importer."""
    
    def __init__(self, debug_requests=False):
        self.logger = get_logger(__name__)
        self.config = get_config()
        self.parser = MenuOCSFParser()
        self.filter_engine = FilterEngine()
        
        # Initialize auth and client 
        self.auth_handler = AuthHandler(use_cache=True, interactive=False, debug_requests=debug_requests)
        self.plextrac_client = None
        
        # State
        self.current_file = None
        self.findings = []
        self.stats = {}
        self.filtered_findings = []
    
    def run(self):
        """Main menu loop."""
        while True:
            choice = self._main_menu()
            
            if choice == "Select OCSF File":
                self._select_file_menu()
            elif choice == "View File Stats":
                self._view_stats()
            elif choice == "Configure Filters":
                self._filter_menu()
            elif choice == "Connect to PlexTrac":
                self._connect_menu()
            elif choice == "Import Findings":
                self._import_menu()
            elif choice == "Exit":
                print("👋 Goodbye!")
                break
    
    def _main_menu(self) -> str:
        """Display main menu."""
        status_lines = [
            "🚀 Prowler OCSF to PlexTrac Importer",
            "=" * 40,
            ""
        ]
        
        # Show current status
        if self.current_file:
            status_lines.append(f"📄 File: {self.current_file.name}")
            status_lines.append(f"   Findings: {len(self.findings)} total, {len(self.filtered_findings)} filtered")
        else:
            status_lines.append("📄 No file selected")
        
        if self.plextrac_client and self.plextrac_client.is_authenticated():
            status_lines.append(f"🔐 Connected to {self.config.plextrac.url}")
        else:
            status_lines.append(f"🔐 Not connected (URL: {self.config.plextrac.url})")
        
        status_lines.extend(["", "Choose an option:"])
        
        options = [
            "Select OCSF File",
            "View File Stats" if self.current_file else "[View File Stats]",
            "Configure Filters" if self.current_file else "[Configure Filters]", 
            "Connect to PlexTrac",
            "Import Findings" if (self.plextrac_client and self.plextrac_client.is_authenticated() and self.filtered_findings) else "[Import Findings]",
            "Exit"
        ]
        
        menu = TerminalMenu(
            options,
            title="\n".join(status_lines),
            show_search_hint=True
        )
        
        choice_index = menu.show()
        return options[choice_index] if choice_index is not None else "Exit"
    
    def _select_file_menu(self):
        """File selection menu."""
        current_dir = Path(".")
        
        # Find OCSF files (avoid duplicates by using a set)
        ocsf_files = []
        
        # First add .ocsf.json files (most specific)
        ocsf_files.extend(current_dir.glob("*.ocsf.json"))
        
        # Then add other .json files that aren't already .ocsf.json
        for json_file in current_dir.glob("*.json"):
            if not json_file.name.endswith(".ocsf.json"):
                ocsf_files.append(json_file)
        
        # Sort by modification time (newest first)
        ocsf_files.sort(key=lambda f: f.stat().st_mtime, reverse=True)
        
        if not ocsf_files:
            print("❌ No OCSF files found in current directory")
            input("Press Enter to continue...")
            return
        
        # Prepare menu options
        file_options = []
        for file_path in ocsf_files:
            size = file_path.stat().st_size / 1024
            modified = datetime.fromtimestamp(file_path.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
            file_options.append(f"{file_path.name} ({size:.1f}KB, {modified})")
        
        file_options.append("🔙 Back to main menu")
        
        menu = TerminalMenu(
            file_options,
            title="📄 Select OCSF File:",
            show_search_hint=True
        )
        
        choice_index = menu.show()
        if choice_index is not None and choice_index < len(ocsf_files):
            selected_file = ocsf_files[choice_index]
            print(f"📊 Parsing {selected_file.name}...")
            
            self.findings, self.stats = self.parser.parse_file(str(selected_file))
            if self.findings:
                self.current_file = selected_file
                self.filtered_findings = self.findings.copy()  # Start with all findings
                print(f"✅ Loaded {len(self.findings)} findings")
            else:
                print("❌ No findings found in file")
            
            input("Press Enter to continue...")
    
    def _view_stats(self):
        """Display file statistics."""
        if not self.stats:
            return
        
        print("\n📊 File Statistics:")
        print("=" * 40)
        print(f"Total findings: {self.stats['total']}")
        
        print("\nBy Severity:")
        for severity, count in self.stats['by_severity'].items():
            if count > 0:
                print(f"  {severity}: {count}")
        
        print("\nBy Status:")
        for status, count in self.stats['by_status'].items():
            if count > 0:
                print(f"  {status}: {count}")
        
        input("\nPress Enter to continue...")
    
    def _filter_menu(self):
        """Filter configuration menu."""
        if not self.findings:
            return
        
        # Debug: Show actual values in the data
        print("\n🔍 Debug - Sample data values:")
        sample_findings = self.findings[:5]
        unique_statuses = set()
        unique_status_codes = set()
        unique_severities = set()
        severity_ids = set()
        
        for f in sample_findings:
            unique_statuses.add(f.status)
            if f.status_code:
                unique_status_codes.add(f.status_code)
            unique_severities.add(f.severity)
            severity_ids.add(f.severity_id)
            print(f"  Finding: status='{f.status}', status_code='{f.status_code}', severity='{f.severity}', severity_id={f.severity_id}")
        
        print(f"All unique statuses found: {sorted(unique_statuses)}")
        print(f"All unique status_codes found: {sorted(unique_status_codes)}")
        print(f"All unique severities found: {sorted(unique_severities)}")
        print(f"All severity IDs found: {sorted(severity_ids)}")
        
        filter_options = [
            "All findings",
            "FAIL findings only", 
            "Critical & High severity only",
            "Critical, High & Medium severity",
            "FAIL + Critical/High severity",
            "🔙 Back to main menu"
        ]
        
        menu = TerminalMenu(
            filter_options,
            title="🔍 Choose Filter:",
            show_search_hint=True
        )
        
        choice_index = menu.show()
        if choice_index is None or choice_index == len(filter_options) - 1:
            return
        
        original_count = len(self.filtered_findings)
        
        # Clear and configure filter engine
        self.filter_engine.clear_filters()
        
        if choice_index == 0:  # All findings
            self.filtered_findings = self.findings.copy()
        elif choice_index == 1:  # FAIL only
            self.filter_engine.create_from_preset({'filters': {'status': ['FAIL']}})
        elif choice_index == 2:  # Critical & High
            self.filter_engine.create_from_preset({'filters': {'severity': ['Critical', 'High']}})
        elif choice_index == 3:  # Critical, High & Medium
            self.filter_engine.create_from_preset({'filters': {'severity': ['Critical', 'High', 'Medium']}})
        elif choice_index == 4:  # FAIL + Critical/High
            self.filter_engine.create_from_preset({'filters': {'status': ['FAIL'], 'severity': ['Critical', 'High']}})
            from src.filters import FilterOperator
            self.filter_engine.set_operator(FilterOperator.OR)
        
        # Apply filters if any were set
        if choice_index > 0:
            # Debug: show sample statuses and severities before filtering
            sample_statuses = list(set(f.status for f in self.findings[:20]))
            sample_severities = list(set((f.severity_id, f.severity) for f in self.findings[:20]))
            print(f"🔍 Sample statuses before filtering: {sample_statuses}")
            print(f"🔍 Sample severities before filtering: {sample_severities}")
            
            filter_result = self.filter_engine.apply_filters(self.findings)
            self.filtered_findings = filter_result.filtered_findings
            
            # Debug: show what was filtered
            if self.filtered_findings:
                filtered_statuses = list(set(f.status for f in self.filtered_findings[:10]))
                filtered_severities = list(set((f.severity_id, f.severity) for f in self.filtered_findings[:10]))
                print(f"🔍 Filtered result statuses: {filtered_statuses}")
                print(f"🔍 Filtered result severities: {filtered_severities}")
            
            self.logger.debug(f"Filter applied: {original_count} -> {len(self.filtered_findings)} findings")
        
        print(f"✅ Filter applied: {len(self.filtered_findings)} findings (was {original_count})")
        input("Press Enter to continue...")
    
    def _connect_menu(self):
        """PlexTrac connection menu."""
        print("\n🔐 Connect to PlexTrac")
        print("=" * 30)
        print(f"URL: {self.config.plextrac.url}")
        
        # Get credentials from environment/config or prompt
        creds = get_credentials()
        token = creds.get('token')

        try:
            if token:
                print("Bearer token: [from environment]")
                print("🔄 Authenticating with bearer token...")
                success = self.auth_handler.authenticate(
                    token=token,
                    url=self.config.plextrac.url
                )
            else:
                username = creds.get('username')
                password = creds.get('password')
                mfa_token = creds.get('mfa_token')

                # Prompt for missing credentials
                if not username:
                    username = input("Username: ").strip()
                else:
                    print(f"Username: {username}")

                if not password:
                    password = getpass.getpass("Password: ")
                else:
                    print("Password: [from environment]")

                if not mfa_token:
                    mfa_input = input("MFA Token (optional): ").strip()
                    mfa_token = mfa_input if mfa_input else None

                print("🔄 Authenticating...")

                # Use our existing auth system
                success = self.auth_handler.authenticate(
                    username=username,
                    password=password,
                    mfa_token=mfa_token,
                    url=self.config.plextrac.url
                )
            
            if success:
                # Create PlexTrac client with authenticated handler
                print("🔄 Loading client list...")
                self.plextrac_client = PlexTracClient(self.auth_handler)
                
                if self.plextrac_client.is_authenticated():
                    clients = self.plextrac_client.get_clients()
                    print(f"✅ Successfully connected to PlexTrac with {len(clients)} clients")
                else:
                    print("⚠️  Authentication succeeded but client creation failed")
                    self.plextrac_client = None
            else:
                print("❌ Authentication failed")
                self.plextrac_client = None
                
        except Exception as e:
            print(f"❌ Connection failed: {e}")
            self.logger.error(f"Connection error: {e}")
            self.plextrac_client = None
        
        input("Press Enter to continue...")
    
    def _import_menu(self):
        """Import findings menu."""
        if not self.plextrac_client or not self.plextrac_client.is_authenticated() or not self.filtered_findings:
            return
        
        # Get clients from cache (faster since they were pre-loaded)
        clients = self.plextrac_client.get_clients(use_cache=True)
        
        if not clients:
            print("❌ No clients found")
            input("Press Enter to continue...")
            return
        
        # Select client
        selected_client = self._select_client(clients)
        if not selected_client:
            return
            
        # Select or create report
        selected_report = self._select_report(selected_client)
        if not selected_report:
            return
            
        # Import findings
        self._perform_import(selected_client, selected_report)
    
    def _select_client(self, clients):
        """Client selection menu with search."""
        # Client selection
        client_options = []
        for c in clients:
            if hasattr(c, 'name') and hasattr(c, 'id'):
                # Client object
                desc = f" - {c.description}" if c.description else ""
                client_options.append(f"{c.name} (ID: {c.id}){desc}")
            elif isinstance(c, dict):
                # Dict format  
                desc = f" - {c.get('description', '')}" if c.get('description') else ""
                client_options.append(f"{c.get('name', 'Unknown')} (ID: {c.get('id')}){desc}")
            else:
                client_options.append(f"Unknown client: {c}")
        client_options.append("🔙 Back to main menu")
        
        menu = TerminalMenu(
            client_options,
            title=f"👥 Select Client ({len(clients)} available):",
            show_search_hint=True
        )
        
        choice_index = menu.show()
        if choice_index is None or choice_index == len(clients):
            return None
        
        return clients[choice_index]
    
    def _select_report(self, client):
        """Select or create a report for the client."""
        client_id = getattr(client, 'id', client.get('id') if isinstance(client, dict) else None)
        client_name = getattr(client, 'name', client.get('name', 'Unknown') if isinstance(client, dict) else 'Unknown')
        
        print(f"\n👥 Selected Client: {client_name}")
        print("🔄 Loading reports...")
        
        try:
            reports = self.plextrac_client.get_reports(client_id)
        except Exception as e:
            print(f"⚠️  Could not load reports: {e}")
            reports = []
        
        # Report options
        report_options = []
        if reports:
            for r in reports:
                if hasattr(r, 'name') and hasattr(r, 'id'):
                    name = r.name if r.name else f"Report {r.id}"
                    report_options.append(f"{name} (ID: {r.id})")
                elif isinstance(r, dict):
                    name = r.get('name') or f"Report {r.get('id', 'Unknown')}"
                    report_options.append(f"{name} (ID: {r.get('id')})")
        
        report_options.extend([
            "📝 Create new report",
            "🔙 Back to client selection"
        ])
        
        menu = TerminalMenu(
            report_options,
            title=f"📄 Select Report for {client_name}:",
            show_search_hint=True
        )
        
        choice_index = menu.show()
        if choice_index is None or choice_index == len(report_options) - 1:
            return None  # Back to client selection
        
        if choice_index == len(report_options) - 2:
            # Create new report
            default_name = f"Prowler Import {datetime.now().strftime('%Y-%m-%d %H:%M')}"
            report_name = input(f"Report name [{default_name}]: ").strip() or default_name
            
            try:
                report = self.plextrac_client.create_report_if_needed(client_id, report_name)
                return report
            except Exception as e:
                print(f"❌ Failed to create report: {e}")
                input("Press Enter to continue...")
                return None
        else:
            # Use existing report
            return reports[choice_index]
    
    def _perform_import(self, client, report):
        """Perform the actual import of findings."""
        client_id = getattr(client, 'id', client.get('id') if isinstance(client, dict) else None)
        client_name = getattr(client, 'name', client.get('name', 'Unknown') if isinstance(client, dict) else 'Unknown')
        report_id = getattr(report, 'id', report.get('id') if isinstance(report, dict) else None)
        report_name = getattr(report, 'name', report.get('name', 'Unknown') if isinstance(report, dict) else 'Unknown')
        
        # Confirm import
        print(f"\n📋 Import Summary:")
        print(f"   Client: {client_name}")
        print(f"   Report: {report_name}")
        print(f"   Findings: {len(self.filtered_findings)}")
        
        confirm = input("\nProceed with import? (y/N): ").strip().lower()
        if confirm != 'y':
            return
        
        # Pre-parse and create assets
        print("🔄 Analyzing assets...")
        unique_assets = set()
        
        for ocsf_finding in self.filtered_findings:
            if ocsf_finding.cloud_account_uid:
                unique_assets.add(ocsf_finding.cloud_account_uid)
        
        print(f"📋 Found {len(unique_assets)} unique AWS accounts")
        
        # Create assets if any exist
        asset_mapping = {}  # asset_name -> asset_id
        if unique_assets:
            print("🔄 Creating/verifying assets...")
            for i, account_uid in enumerate(unique_assets, 1):
                try:
                    asset_name = f"AWS Account {account_uid}"
                    asset = self.plextrac_client.api.get_or_create_asset(
                        client_id, 
                        asset_name, 
                        "AWS Account",
                        f"AWS Account ID: {account_uid}"
                    )
                    asset_mapping[account_uid] = asset.id
                    print(f"  [{i}/{len(unique_assets)}] {asset_name} -> {asset.id}")
                except Exception as e:
                    print(f"  ⚠️  Failed to create asset {account_uid}: {e}")
                    self.logger.error(f"Asset creation failed for {account_uid}: {e}")
                    # Continue without this asset - findings will just not have affected_assets
        
        # Convert OCSF findings to PlexTrac format
        print("🔄 Converting findings...")
        plextrac_findings = []
        title_counts = {}  # Track titles for uniqueness
        
        for ocsf_finding in self.filtered_findings:
            # Convert OCSF finding to PlexTrac Finding
            from src.api.endpoints import Finding
            
            # Use message as title, ensure uniqueness
            base_title = ocsf_finding.message or "Security Finding"
            title = base_title
            if title in title_counts:
                title_counts[title] += 1
                title = f"{base_title} ({ocsf_finding.resource_name or ocsf_finding.class_name or title_counts[title]})"
            else:
                title_counts[title] = 1
            
            # Build comprehensive description
            description_parts = []
            
            # Core message/description
            if ocsf_finding.message:
                description_parts.append(f"**Finding**: {ocsf_finding.message}")
            
            # Resource information
            if ocsf_finding.resource_name:
                description_parts.append(f"**Resource**: {ocsf_finding.resource_name}")
            if ocsf_finding.resource_type:
                description_parts.append(f"**Resource Type**: {ocsf_finding.resource_type}")
            
            # Cloud context
            if ocsf_finding.cloud_provider:
                description_parts.append(f"**Cloud Provider**: {ocsf_finding.cloud_provider}")
            if ocsf_finding.cloud_region:
                description_parts.append(f"**Region**: {ocsf_finding.cloud_region}")
            
            # Classification
            if ocsf_finding.class_name:
                description_parts.append(f"**Class**: {ocsf_finding.class_name}")
            if ocsf_finding.category_name:
                description_parts.append(f"**Category**: {ocsf_finding.category_name}")
            
            # Compliance frameworks
            if ocsf_finding.compliance_frameworks:
                description_parts.append(f"**Compliance**: {', '.join(ocsf_finding.compliance_frameworks)}")
            
            # Extract additional data from raw_data
            raw_data = ocsf_finding.raw_data or {}
            
            # Risk details - properly format instead of dumping JSON
            if 'risk' in raw_data:
                risk_data = raw_data['risk']
                if isinstance(risk_data, dict):
                    risk_parts = []
                    for key, value in risk_data.items():
                        if value:
                            risk_parts.append(f"{key.replace('_', ' ').title()}: {value}")
                    if risk_parts:
                        description_parts.append(f"**Risk Details**: {', '.join(risk_parts)}")
                else:
                    description_parts.append(f"**Risk**: {risk_data}")
            
            # Remediation from raw data (common fields) - extract clean text
            remediation_fields = ['remediation', 'recommendation', 'fix', 'solution', 'mitigation']
            remediation_text = None
            remediation_refs = []
            
            for field in remediation_fields:
                if field in raw_data and raw_data[field]:
                    raw_rec = raw_data[field]
                    if isinstance(raw_rec, dict):
                        # Extract clean description text
                        remediation_text = (raw_rec.get('desc') or 
                                          raw_rec.get('text') or 
                                          raw_rec.get('description') or 
                                          raw_rec.get('details'))
                        
                        # Extract references from remediation
                        if 'references' in raw_rec:
                            rec_refs = raw_rec['references']
                            if isinstance(rec_refs, list):
                                remediation_refs.extend([str(ref) for ref in rec_refs if ref])
                            elif isinstance(rec_refs, str):
                                remediation_refs.append(rec_refs)
                                
                        if not remediation_text:
                            # Fallback to string representation without references
                            remediation_text = str(raw_rec)
                    elif isinstance(raw_rec, list):
                        # Join list items
                        remediation_text = '. '.join(str(item) for item in raw_rec if item)
                    else:
                        remediation_text = str(raw_rec)
                    break
            
            # Check unmapped section for remediation
            unmapped = raw_data.get('unmapped', {})
            if not remediation_text:
                for field in ['Remediation', 'Recommendation', 'Fix', 'Solution']:
                    if field in unmapped and unmapped[field]:
                        raw_rec = unmapped[field]
                        if isinstance(raw_rec, dict):
                            remediation_text = (raw_rec.get('desc') or
                                              raw_rec.get('text') or 
                                              raw_rec.get('description'))
                            # Extract references from unmapped remediation too
                            if 'references' in raw_rec:
                                rec_refs = raw_rec['references']
                                if isinstance(rec_refs, list):
                                    remediation_refs.extend([str(ref) for ref in rec_refs])
                                elif isinstance(rec_refs, str):
                                    remediation_refs.append(rec_refs)
                        else:
                            remediation_text = str(raw_rec)
                        break
            
            # Don't add remediation to description since it has its own field
            description = "\n\n".join(description_parts)
            
            # Extract references for dedicated field - clean URLs only
            references = []
            ref_fields = ['references', 'links', 'urls', 'external_links']
            
            for field in ref_fields:
                if field in raw_data:
                    refs = raw_data[field]
                    if isinstance(refs, list):
                        for ref in refs:
                            if isinstance(ref, dict):
                                # Extract URL from dict
                                url = ref.get('url') or ref.get('link') or ref.get('href')
                                if url:
                                    references.append(str(url))
                            elif isinstance(ref, str) and ('http' in ref or 'www.' in ref):
                                references.append(ref)
                    elif isinstance(refs, str) and ('http' in refs or 'www.' in refs):
                        references.append(refs)
            
            # Check unmapped for references
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
            
            # Add remediation references to main references
            references.extend(remediation_refs)
            
            # Remove duplicates and empty references
            references = list(set(ref for ref in references if ref and ref.strip()))
            
            # Set affected assets (use PlexTrac format: {asset_id: asset_object})
            affected_assets = {}
            if ocsf_finding.cloud_account_uid and ocsf_finding.cloud_account_uid in asset_mapping:
                asset_id = asset_mapping[ocsf_finding.cloud_account_uid]
                asset_name = f"AWS Account {ocsf_finding.cloud_account_uid}"
                
                # Create affected asset object per PlexTrac docs
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
            
            # Debug severity and status mapping
            self.logger.debug(f"OCSF finding severity_id: {ocsf_finding.severity_id}, severity: '{ocsf_finding.severity}'")
            self.logger.debug(f"OCSF finding status: '{ocsf_finding.status}', status_id: {ocsf_finding.status_id}")
            
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
        
        # Import findings using the client's batch import
        print(f"📤 Importing {len(plextrac_findings)} findings...")
        
        def progress_callback(current, total, message):
            if current % 5 == 0 or current == total:  # Update every 5 findings
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
            
            if result.errors and len(result.errors) <= 5:
                print("\n❌ Error details:")
                for error in result.errors[:5]:
                    print(f"   {error}")
            elif result.errors:
                print(f"\n❌ {len(result.errors)} errors occurred (check log for details)")
                    
        except Exception as e:
            print(f"❌ Import failed: {e}")
            self.logger.error(f"Import error: {e}")
        
        input("Press Enter to continue...")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Menu-based Prowler OCSF to PlexTrac importer')
    parser.add_argument('--file', help='Start with specific OCSF file')
    parser.add_argument('--debug', action='store_true', help='Enable enhanced debug logging for API requests')
    args = parser.parse_args()
    
    try:
        importer = ProwlerImportMenu(debug_requests=args.debug)
        
        if args.debug:
            print("🔍 Debug mode enabled - enhanced request logging active")
        
        # If file specified, load it first
        if args.file and Path(args.file).exists():
            print(f"📊 Loading {args.file}...")
            importer.findings, importer.stats = importer.parser.parse_file(args.file)
            if importer.findings:
                importer.current_file = Path(args.file)
                importer.filtered_findings = importer.findings.copy()
                print(f"✅ Loaded {len(importer.findings)} findings")
        
        importer.run()
        
    except KeyboardInterrupt:
        print("\n❌ Cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()