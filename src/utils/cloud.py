"""Helpers for mapping OCSF cloud provider values to PlexTrac asset labels."""

from typing import Optional

_PROVIDER_ASSET_LABELS = {
    "aws": "AWS Account",
    "azure": "Azure Subscription",
    "gcp": "GCP Project",
}


def asset_label_for_provider(cloud_provider: Optional[str]) -> str:
    """Map an OCSF cloud.provider value to a PlexTrac asset-type label."""
    if cloud_provider:
        return _PROVIDER_ASSET_LABELS.get(cloud_provider.strip().lower(), f"{cloud_provider} Account")
    return "Cloud Account"
