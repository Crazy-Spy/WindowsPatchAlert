"""RSS 2.0 feed generator for PATCH ALERT operational advisories and Microsoft update alerts."""

from __future__ import annotations

from datetime import datetime, timezone
from email.utils import format_datetime
from typing import Any, Sequence
import xml.etree.ElementTree as ET


def _iso_to_rfc2822(iso_str: str | None) -> str:
    """Convert an ISO-8601 UTC string into an RFC 2822 date string required by RSS 2.0."""
    if not iso_str:
        return format_datetime(datetime.now(timezone.utc))
    cleaned = iso_str.strip()
    try:
        if cleaned.endswith("Z"):
            cleaned = cleaned[:-1] + "+00:00"
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return format_datetime(dt)
    except ValueError:
        return format_datetime(datetime.now(timezone.utc))


def generate_rss_xml(
    alerts: Sequence[dict[str, Any]],
    base_url: str = "http://127.0.0.1:8000",
) -> str:
    """Generate a valid RSS 2.0 XML document from stored operational alerts."""
    rss = ET.Element("rss", attrib={"version": "2.0", "xmlns:atom": "http://www.w3.org/2005/Atom"})
    channel = ET.SubElement(rss, "channel")

    ET.SubElement(channel, "title").text = "PATCH ALERT — Windows Desktop Update Intelligence & Operational Health"
    ET.SubElement(channel, "link").text = base_url
    ET.SubElement(channel, "description").text = (
        "Operational Patch Health alerts, Known Issue Rollbacks (KIR), Out-of-Band (OOB) updates, "
        "and MSRC security advisories for Microsoft Windows 11 and Windows 10 Desktop releases."
    )
    ET.SubElement(channel, "language").text = "en-us"
    ET.SubElement(channel, "ttl").text = "240"
    ET.SubElement(channel, "lastBuildDate").text = format_datetime(datetime.now(timezone.utc))

    atom_link = ET.SubElement(
        channel,
        "{http://www.w3.org/2005/Atom}link",
        attrib={
            "href": f"{base_url.rstrip('/')}/rss.xml",
            "rel": "self",
            "type": "application/rss+xml",
        },
    )
    _ = atom_link

    for alert in alerts:
        item = ET.SubElement(channel, "item")
        severity = alert.get("severity", "INFO")
        kb_num = alert.get("kb_number") or "Windows"
        title_str = f"[{severity}] {alert.get('title', 'Windows Update Alert')}"
        ET.SubElement(item, "title").text = title_str

        link_url = alert.get("source_url") or f"{base_url.rstrip('/')}/?kb={kb_num}"
        ET.SubElement(item, "link").text = link_url

        origin_note = " (Local Reference Seed)" if alert.get("is_demo") else " (Microsoft Official Telemetry)"
        desc_text = (
            f"KB: {kb_num} | Windows Version: {alert.get('windows_version') or 'All Supported'} | "
            f"Severity: {severity} | Type: {alert.get('alert_type', 'ADVISORY')}{origin_note}\n\n"
            f"{alert.get('summary', '')}"
        )
        ET.SubElement(item, "description").text = desc_text

        guid = ET.SubElement(item, "guid", attrib={"isPermaLink": "false"})
        guid.text = f"patch-alert-{alert.get('id', 0)}-{kb_num}-{alert.get('created_at', '')}"

        ET.SubElement(item, "category").text = alert.get("alert_type", "ADVISORY")
        ET.SubElement(item, "pubDate").text = _iso_to_rfc2822(alert.get("created_at"))

    xml_bytes = ET.tostring(rss, encoding="utf-8", xml_declaration=True)
    return xml_bytes.decode("utf-8")

