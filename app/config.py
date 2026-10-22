"""Configuration and default official Microsoft telemetry sources for PATCH ALERT."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = Path(os.environ.get("PATCH_ALERT_DB_PATH", str(BASE_DIR / "patch_alert.db")))

# HTTP Collection settings
HTTP_TIMEOUT_SECONDS: float = float(os.environ.get("PATCH_ALERT_HTTP_TIMEOUT", "15.0"))
HTTP_MAX_RETRIES: int = int(os.environ.get("PATCH_ALERT_HTTP_RETRIES", "3"))
HTTP_BACKOFF_BASE_SECONDS: float = float(os.environ.get("PATCH_ALERT_HTTP_BACKOFF", "1.0"))
DEFAULT_SYNC_INTERVAL_MINUTES: int = int(os.environ.get("PATCH_ALERT_SYNC_INTERVAL_MINUTES", "240"))  # 4 hours
ENABLE_BACKGROUND_SCHEDULER: bool = os.environ.get("PATCH_ALERT_ENABLE_SCHEDULER", "true").lower() in ("1", "true", "yes")

USER_AGENT = (
    "PatchAlert-OperationalMonitor/1.0 "
    "(+https://learn.microsoft.com/en-us/windows/release-health/; Windows Desktop Update Intelligence)"
)

# Default configurable Official Microsoft Sources
DEFAULT_MICROSOFT_SOURCES: list[dict[str, Any]] = [
    {
        "source_key": "win11_24h2_release_health",
        "name": "Windows 11, version 24H2 Release Health",
        "source_type": "release_health",
        "windows_version": "Windows 11 24H2",
        "url": "https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-24h2",
        "enabled": True,
        "check_interval_minutes": 240,
    },
    {
        "source_key": "win11_23h2_release_health",
        "name": "Windows 11, version 23H2 Release Health",
        "source_type": "release_health",
        "windows_version": "Windows 11 23H2",
        "url": "https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-23h2",
        "enabled": True,
        "check_interval_minutes": 240,
    },
    {
        "source_key": "win11_22h2_release_health",
        "name": "Windows 11, version 22H2 Release Health",
        "source_type": "release_health",
        "windows_version": "Windows 11 22H2",
        "url": "https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-22h2",
        "enabled": True,
        "check_interval_minutes": 240,
    },
    {
        "source_key": "win10_22h2_release_health",
        "name": "Windows 10, version 22H2 Release Health",
        "source_type": "release_health",
        "windows_version": "Windows 10 22H2",
        "url": "https://learn.microsoft.com/en-us/windows/release-health/status-windows-10-22h2",
        "enabled": True,
        "check_interval_minutes": 240,
    },
    {
        "source_key": "windows_message_center",
        "name": "Microsoft Windows Message Center Announcements",
        "source_type": "message_center",
        "windows_version": "All Supported Desktop Releases",
        "url": "https://learn.microsoft.com/en-us/windows/release-health/windows-message-center",
        "enabled": True,
        "check_interval_minutes": 240,
    },
    {
        "source_key": "msrc_cvrf_api",
        "name": "Microsoft Security Response Center (MSRC) CVRF v3.0 API",
        "source_type": "msrc_cvrf",
        "windows_version": "All Supported Desktop Releases",
        "url": "https://api.msrc.microsoft.com/cvrf/v3.0/updates",
        "enabled": True,
        "check_interval_minutes": 240,
    },
]

