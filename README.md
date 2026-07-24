# Prowltrac

**Prowler OCSF to PlexTrac Import Tool**

A comprehensive tool for importing [Prowler](https://prowler.com/) security findings in OCSF format into [PlexTrac](https://plextrac.com/) for vulnerability management and reporting.

## Features

- **Full OCSF Support**: Parses Prowler OCSF JSON files with proper field mapping
- **Advanced Filtering**: Filter by severity (Critical/High/Medium/Low), status (FAIL/PASS), and combinations
- **Smart Asset Management**: Automatically creates and maps AWS account assets
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
| `cloud.account.uid` | `affected_assets` | Auto-creates AWS account assets |
| `remediation.desc` | `recommendation` | Clean text extraction |
| `references` | `references` | URL extraction and deduplication |

### Asset Management

The tool automatically:
- Identifies unique AWS account UIDs from findings
- Creates PlexTrac assets for each account
- Maps findings to their respective assets
- Handles asset creation failures gracefully

## Troubleshooting

### Authentication Issues

```bash
# Enable debug logging to see API calls
python simple_import.py file.json --debug

# Check your credentials
echo $PLEXTRAC_URL
echo $PLEXTRAC_USERNAME
```

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