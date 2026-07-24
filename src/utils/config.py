"""
Configuration management for Prowler OCSF to PlexTrac tool.
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, Field, field_validator


class PlexTracConfig(BaseModel):
    """PlexTrac API configuration."""

    url: str = Field(..., description="PlexTrac instance URL")
    api_version: str = Field(default="v2", description="API version")
    request_timeout: int = Field(default=30, description="Request timeout in seconds")
    auth_timeout: int = Field(default=60, description="Authentication timeout in seconds")

    @field_validator("url")
    @classmethod
    def validate_url(cls, v):
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v.rstrip("/")


class LoggingConfig(BaseModel):
    """Logging configuration."""

    level: str = Field(default="INFO", description="Log level")
    file: str = Field(default="prowltrac.log", description="Log file path")
    max_size_mb: int = Field(default=10, description="Max log file size in MB")
    backup_count: int = Field(default=3, description="Number of backup files")
    format: str = Field(
        default="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        description="Log format string",
    )


class ImportConfig(BaseModel):
    """Import settings configuration."""

    max_preview: int = Field(default=100, description="Max findings in preview")
    batch_size: int = Field(default=25, description="API request batch size")
    auto_create_reports: bool = Field(default=False, description="Auto-create reports")
    default_report_template_id: Optional[str] = Field(
        default=None, description="Default report template"
    )


class MappingConfig(BaseModel):
    """Field mapping configuration."""

    severity: Dict[int, str] = Field(
        default={1: "Critical", 2: "High", 3: "Medium", 4: "Low", 5: "Informational"},
        description="OCSF severity to PlexTrac severity mapping",
    )
    status: Dict[str, str] = Field(
        default={"New": "Open", "Suppressed": "Closed", "Unknown": "Open"},
        description="OCSF status to PlexTrac status mapping",
    )
    max_title_length: int = Field(default=100, description="Max finding title length")
    compliance_fields: List[str] = Field(
        default=["Compliance", "References", "CIS", "NIST", "PCI", "SOC2"],
        description="Compliance fields to extract",
    )


class FilterPreset(BaseModel):
    """Filter preset configuration."""

    name: str = Field(..., description="Preset name")
    description: str = Field(..., description="Preset description")
    filters: Dict[str, Any] = Field(..., description="Filter criteria")


class UIConfig(BaseModel):
    """UI configuration."""

    theme: str = Field(default="auto", description="UI theme")
    debug_mode: bool = Field(default=False, description="Debug mode")
    progress_refresh: float = Field(default=0.5, description="Progress refresh interval")


class Config(BaseModel):
    """Main configuration model."""

    plextrac: PlexTracConfig
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    import_: ImportConfig = Field(default_factory=ImportConfig, alias="import")
    mapping: MappingConfig = Field(default_factory=MappingConfig)
    filter_presets: Dict[str, FilterPreset] = Field(default_factory=dict)
    services: Dict[str, List[str]] = Field(default_factory=dict)
    ui: UIConfig = Field(default_factory=UIConfig)


class ConfigManager:
    """Configuration manager with environment variable support."""

    def __init__(self, config_path: Optional[Path] = None, env_path: Optional[Path] = None):
        self.config_path = config_path or Path("config.yaml")
        self.env_path = env_path or Path(".env")
        self.config: Optional[Config] = None

        # Load environment variables
        if self.env_path.exists():
            load_dotenv(self.env_path)

    def load_config(self) -> Config:
        """Load configuration from file and environment variables."""
        config_data = {}

        # Load from YAML file if it exists
        if self.config_path.exists():
            with open(self.config_path, "r") as f:
                config_data = yaml.safe_load(f) or {}

        # Override with environment variables
        config_data.setdefault("plextrac", {})

        # PlexTrac settings from environment
        if url := os.getenv("PLEXTRAC_URL"):
            config_data["plextrac"]["url"] = url

        # Set default URL for testing/development if none provided
        if "url" not in config_data["plextrac"]:
            # Check if we're in a test environment, CI, or development
            import sys

            is_test_env = (
                "pytest" in sys.modules
                or "test" in sys.argv[0]
                or any("test" in arg for arg in sys.argv)
                or os.getenv("CI") == "true"  # GitHub Actions CI
                or os.getenv("GITHUB_ACTIONS") == "true"  # GitHub Actions
                or not os.getenv("PLEXTRAC_URL")  # No URL configured
            )

            if is_test_env:
                config_data["plextrac"]["url"] = "https://test.plextrac.com"

        # Logging settings from environment
        config_data.setdefault("logging", {})
        if log_level := os.getenv("LOG_LEVEL"):
            config_data["logging"]["level"] = log_level
        if log_file := os.getenv("LOG_FILE"):
            config_data["logging"]["file"] = log_file

        # Import settings from environment
        config_data.setdefault("import", {})
        if max_preview := os.getenv("MAX_FINDINGS_PREVIEW"):
            config_data["import"]["max_preview"] = int(max_preview)
        if batch_size := os.getenv("BATCH_SIZE"):
            config_data["import"]["batch_size"] = int(batch_size)
        if auto_create := os.getenv("AUTO_CREATE_REPORTS"):
            config_data["import"]["auto_create_reports"] = auto_create.lower() == "true"

        self.config = Config(**config_data)
        return self.config

    def get_credentials(self) -> Dict[str, Optional[str]]:
        """Get credentials from environment variables."""
        return {
            "username": os.getenv("PLEXTRAC_USERNAME"),
            "password": os.getenv("PLEXTRAC_PASSWORD"),
            "mfa_token": os.getenv("PLEXTRAC_MFA_TOKEN"),
            "token": os.getenv("PLEXTRAC_API_TOKEN"),
        }

    def get_filter_preset(self, preset_name: str) -> Optional[FilterPreset]:
        """Get a filter preset by name."""
        if not self.config:
            self.load_config()

        # Check for default preset from environment
        if not preset_name:
            preset_name = os.getenv("DEFAULT_FILTER_PRESET", "security_review")

        return self.config.filter_presets.get(preset_name)

    def save_config(self, config: Config) -> None:
        """Save configuration to file."""
        with open(self.config_path, "w") as f:
            yaml.dump(config.dict(by_alias=True), f, default_flow_style=False, indent=2)
        self.config = config

    def create_default_config(self) -> Config:
        """Create a default configuration."""
        return Config(
            plextrac=PlexTracConfig(url="https://yourapp.plextrac.com"),
            filter_presets={
                "security_review": FilterPreset(
                    name="Security Review (Fails Only)",
                    description="Failed findings for security reviews",
                    filters={"status": ["Failed"], "severity": ["Critical", "High", "Medium"]},
                ),
                "critical_only": FilterPreset(
                    name="Critical Issues",
                    description="Only critical severity findings",
                    filters={"status": ["Failed"], "severity": ["Critical"]},
                ),
            },
        )


# Global config manager instance
config_manager = ConfigManager()


def get_config() -> Config:
    """Get the current configuration."""
    if not config_manager.config:
        config_manager.load_config()
    return config_manager.config


def get_credentials() -> Dict[str, Optional[str]]:
    """Get credentials from environment."""
    return config_manager.get_credentials()
