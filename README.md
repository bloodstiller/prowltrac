# Prowltrac

**Prowler OCSF to PlexTrac Import Tool**

A comprehensive tool for importing [Prowler](https://prowler.com/) security findings in OCSF format into [PlexTrac](https://plextrac.com/) for vulnerability management and reporting.

## Features

- **Full OCSF Support**: Parses Prowler OCSF JSON files with proper field mapping
- **Advanced Filtering**: Filter by severity (Critical/High/Medium/Low), status (FAIL/PASS), and combinations
- **Smart Asset Management**: Automatically creates and maps cloud account assets (AWS, Azure, GCP)
- **Duplicate Handling**: Detects and gracefully handles duplicate findings
- **Clean Data Extraction**: Properly extracts recommendations and references from OCSF data
- **Two Interfaces**: Menu-driven interactive mode and CLI mode for automation
- **Enhanced Authentication**: Token caching, MFA support, debug logging

## Quick Start

### Menu Interface (Interactive)

```bash
python menu_import.py [--debug]
```

Features a user-friendly menu system for:
- File selection with metadata
- Visual filtering options  
- Client/report selection with search
- Real-time import progress

### CLI Interface (Automation)

```bash
# Import FAIL findings (default)
python simple_import.py prowler-findings.ocsf.json

# Import with specific filters
python simple_import.py prowler-findings.ocsf.json --filter critical-high

# Fully automated import
python simple_import.py prowler-findings.ocsf.json \
  --client-id 123 \
  --report-name "Security Review" \
  --filter fail-critical-high
```

## Installation

### Requirements

- Python 3.8+
- PlexTrac instance with API access

### Setup

```bash
# Clone the repository
git clone <repository-url>
cd prowltrac

# Install dependencies
pip install -r requirements.txt

# Set up environment variables (optional)
export PLEXTRAC_URL="https://yourapp.plextrac.com"
export PLEXTRAC_USERNAME="your-username"
export PLEXTRAC_PASSWORD="your-password"
```

## CLI Usage

### Basic Usage

```bash
python simple_import.py <ocsf-file> [options]
```

### Connection Options

```bash
--url URL                PlexTrac instance URL
--username USERNAME      PlexTrac username  
--password PASSWORD      PlexTrac password
--mfa-token TOKEN        MFA token
--token TOKEN            PlexTrac API bearer token (takes precedence over --username/--password)
```

### Import Options

```bash
--client-id ID           PlexTrac client ID (skip selection)
--report-id ID           PlexTrac report ID (skip selection/creation) 
--report-name NAME       Custom report name for new reports
```

### Filtering Options

```bash
--filter FILTER          Filter findings to import (default: fail)
```

Available filters:
- `all` - Import all findings
- `fail` - Import only FAIL findings (default)
- `critical` - Import only Critical severity
- `critical-high` - Import Critical and High severity  
- `critical-high-medium` - Import Critical, High, and Medium severity
- `fail-critical-high` - Import FAIL findings OR Critical/High severity

### Debug Options

```bash
--debug                  Enable enhanced debug logging for API requests
--show-stats             Show finding statistics before filtering
```

### Examples

```bash
# Interactive selection with failed findings only
python simple_import.py prowler-findings.ocsf.json

# Import critical findings with debug logging
python simple_import.py prowler-findings.ocsf.json --filter critical --debug

# Fully automated import to specific client and report
python simple_import.py prowler-findings.ocsf.json \
  --client-id 456 \
  --report-name "Prowler Security Scan $(date +%Y-%m-%d)" \
  --filter critical-high-medium

# Show stats before importing
python simple_import.py prowler-findings.ocsf.json --show-stats --filter all
```

## Configuration

The tool supports configuration via:

1. **Environment Variables** (highest priority)
2. **Config file** (`config.yaml`)
3. **Interactive prompts** (fallback)

### Environment Variables

```bash
export PLEXTRAC_URL="https://yourapp.plextrac.com"
export PLEXTRAC_USERNAME="your-username" 
export PLEXTRAC_PASSWORD="your-password"
export PLEXTRAC_MFA_TOKEN="123456"          # Optional
export PLEXTRAC_API_TOKEN="your-bearer-token" # Optional - takes precedence over username/password
export LOG_LEVEL="INFO"                      # DEBUG, INFO, WARNING, ERROR
export LOG_FILE="prowltrac.log"             # Log file path
```

> **Bearer token authentication**: if `PLEXTRAC_API_TOKEN` (or `--token`) is set, it is
> used directly and the username/password login step is skipped entirely. PlexTrac
> bearer tokens expire after 15 minutes and, since there are no credentials to silently
> re-authenticate with, an expired token will cause a clear authentication error rather
> than an automatic retry — supply a fresh token if that happens.

### Config File

Create `config.yaml`:

```yaml
plextrac:
  url: "https://yourapp.plextrac.com"
  
logging:
  level: "INFO"
  file: "prowltrac.log"
  
import:
  batch_size: 25
  auto_create_reports: false
```

## Data Mapping

### OCSF to PlexTrac Field Mapping

| OCSF Field | PlexTrac Field | Notes |
|------------|----------------|--------|
| `message` | `title` | Primary finding title |
| `severity_id` | `severity` | 1=Critical, 2=High, 3=Medium, 4=Low, 5=Informational |
| `status_code` | Used for filtering | FAIL/PASS/UNKNOWN |
| `cloud.account.uid` | `affected_assets` | Auto-creates cloud account assets (labeled by `cloud.provider`) |
| `remediation.desc` | `recommendation` | Clean text extraction |
| `references` | `references` | URL extraction and deduplication |

### Asset Management

The tool automatically:
- Identifies unique cloud account UIDs from findings (AWS, Azure, GCP)
- Creates PlexTrac assets for each account, labeled by cloud provider (e.g. "AWS Account", "Azure Subscription", "GCP Project")
- Maps findings to their respective assets
- Handles asset creation failures gracefully

## Offline Export (.ptrac)

If the PlexTrac instance isn't reachable from where you process Prowler output, write a
`.ptrac` file and upload it yourself. No credentials or network access are needed:

```bash
python simple_import.py prowler-output.ocsf.json --filter fail \
  --ptrac findings.ptrac --plextrac-version 2.10.1 \
  --report-name "AWS Review Nov 2026"
```

- `--plextrac-version` (or `PLEXTRAC_APP_VERSION`) is **required**: use the version of the
  instance you'll upload to, shown at the bottom right of the Account Admin page. It's written
  into every finding, and PlexTrac needs it to accept the import.
- `--client-name` sets the client stored in the file (default `Prowler Import`).
- An existing output file is not overwritten unless you pass `--force`.

Upload the file in PlexTrac, either:
- **into an existing report**: Findings tab → Add findings → File Imports → Import source
  "PlexTrac" → select the file, or
- **as a new report**: Reports → Import Report → choose the client → drop the file.

**What gets imported:** only `FAIL` and `MANUAL` results. `PASS` results are never imported,
not even with `--filter all`. `--filter` only narrows `FAIL` results by severity.

**Manual checks:** Prowler reports controls it can't evaluate automatically with status
`MANUAL`. Every one is always imported, whatever the filter. Their titles get the prefix
`MANUAL: ` (e.g. "MANUAL: Ensure security contact details are registered"), and they're
tagged `manual-check`, with a "Manual check" note at the top of the description. Sort or
filter by title or tag in PlexTrac to work through them, updating each status as you verify it.

**Grouping:** offline exports (`.ptrac` and CSV) produce one finding per Prowler check, not one
per resource. A check that fails on 40 buckets becomes a single finding with all 40 FAIL
resources as affected assets; resources that passed are never included. Assets are named by
resource ID (ARN / resource UID), or by cloud account when a result has no resource. The group
takes the most severe severity, and references are merged.

**Titles state the failure, not the control.** A Prowler check title describes the *expected*
state ("Container Registry public network access is disabled"), so it's never used as a FAIL
finding's title. The title comes from Prowler's own FAIL evidence (`STATUSEXTENDED` / OCSF
`message`). Resource, subscription, account and region identifiers are removed, so the failing
resources collapse to one statement of what was observed:

| Prowler check title (expected state) | FAIL evidence | Finding title |
|---|---|---|
| Container Registry public network access is disabled | Container Registry acr1 from subscription Prod allows unrestricted network access. | Container Registry Allows Unrestricted Network Access |
| SQL Server uses CMK for TDE | SQL Server sql-01 from subscription Prod does not use a customer-managed key for TDE. | SQL Server Does Not Use a Customer-Managed Key for TDE |

Nothing is negated or inferred from the check title's wording. If no usable statement can be
derived (for example, empty evidence), the title is `Failed Control: <check title>`, so it
still can't read as if the secure state were met. Manual checks keep `MANUAL: <control to
verify>`.

Each description is laid out as: **Security Control Expects** (check title and description),
**Prowler Observed (FAIL)**, **Why It Matters** (Prowler's risk text), context (provider,
accounts, regions, compliance, check ID) and **Failed Resources**. Each resource's Prowler
evidence is kept verbatim: in its affected-asset notes in `.ptrac`, and in the CSV description
under "Failed resources and Prowler evidence" (capped at 200 entries). The converter doesn't
judge whether a FAIL is a true positive. Each finding is a candidate for manual validation in
PlexTrac.

The file format follows PlexTrac-Labs' own
[JSON → .ptrac converter](https://github.com/PlexTrac-Labs/checkmarx-sca-json-to-ptrac-parser).

### CSV export

You can also write a CSV in PlexTrac's
[Report Findings CSV Template](https://docs.plextrac.com/plextrac-documentation/product-documentation/reports/findings/csv-findings-templates/using-report-findings-csv-template)
format. No version flag is needed:

```bash
python simple_import.py prowler-output.ocsf.json --filter fail --csv findings.csv
```

Upload it in a report: Findings tab → Add Findings → "CSV" → choose the file → Continue →
Upload. `--csv` and `--ptrac` can be combined in a single run.

Columns follow the template order (`title, severity, status, description, recommendations,
references, affected_assets, tags, cvss_temporal, cwe, cve, category`). PlexTrac splits
`references`, `affected_assets` and `tags` on commas, so commas inside a single value are
replaced with spaces. The layout matches PlexTrac's `Finding CSV Template v3.2`: same
header, CRLF line endings, one line per finding (description parts are joined with ` | `). Compared with `.ptrac`, CSV is simpler and doesn't depend on the
instance version. It carries less per-asset detail, though: affected assets are names only,
without the per-resource notes.

## Troubleshooting

### Authentication Issues

```bash
# Enable debug logging to see API calls
python simple_import.py file.json --debug

# Check your credentials
echo $PLEXTRAC_URL
echo $PLEXTRAC_USERNAME
```

### TLS / Connection Errors (self-hosted instances)

Connection and TLS failures are reported separately from token errors. If you get
"TLS handshake ... failed: the server closed the connection":

- Check the URL and port point at the PlexTrac HTTPS listener, and that this machine can reach it
  (`curl -vk https://<host>/api/v2/whoami` should get an HTTP response, even a 401).
- Use the instance's DNS hostname rather than its IP: reverse proxies often drop TLS connections
  that carry no SNI hostname, which is what clients send for raw IPs.

If the certificate is self-signed or issued by an internal CA:

```bash
python simple_import.py file.json --url https://plextrac.internal --ca-bundle internal-ca.pem
python simple_import.py file.json --url https://plextrac.internal --insecure   # skip verification
```

The same settings are available as `PLEXTRAC_CA_BUNDLE` / `PLEXTRAC_VERIFY_SSL=false` or
`plextrac.ca_bundle` / `plextrac.verify_ssl` in `config.yaml`.

### No Findings After Filtering

```bash
# Check what's in your file
python simple_import.py file.json --show-stats --filter all

# Use the menu interface for detailed debugging
python menu_import.py --debug
```

### Import Failures

- Check PlexTrac permissions for your user
- Verify client/report IDs exist
- Review debug logs for API errors
- Ensure findings don't have duplicate titles

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable  
5. Submit a pull request

## Development Notes

⚡ **Rapid Development**: This tool was built in just a few hours with the assistance of [Claude Code](https://claude.ai/code), Anthropic's AI coding assistant. While functional and tested, it may have rough edges or edge cases that need refinement.

🐛 **Found an Issue?** Please file issues on the repository! Given the rapid development timeline, your feedback helps improve the tool for everyone.

## Support

For issues and questions:
- **File issues**: Open an issue on the repository for bugs, feature requests, or improvements
- **Troubleshooting**: Check the troubleshooting section above
- **Debug logging**: Use the `--debug` flag to get detailed API request/response logs
- **Menu debugging**: Use `menu_import.py --debug` for interactive troubleshooting