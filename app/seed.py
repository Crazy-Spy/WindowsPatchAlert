"""Local reference seed dataset for PATCH ALERT (clearly labeled as pre-sync reference data)."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from app.database import (
    add_kb_relationship,
    add_lifecycle_event,
    create_alert_if_not_exists,
    get_connection,
    init_db,
    recalculate_kb_status,
    upsert_cve,
    upsert_kb,
    upsert_known_issue,
)

DEMO_ORIGIN = "Local Reference Dataset (Pre-Sync Seed)"


def seed_demo_data_if_empty(db_path: Optional[Path | str] = None, force: bool = False) -> bool:
    """
    Populate the SQLite database with a clearly labeled local reference dataset if no KBs exist yet.
    Returns True if seed data was inserted, False if data was already present.
    """
    init_db(db_path)
    with get_connection(db_path) as conn:
        existing_count = int(conn.execute("SELECT COUNT(*) FROM kbs").fetchone()[0])
        if existing_count > 0 and not force:
            return False
        if force:
            conn.execute("DELETE FROM change_log WHERE is_demo = 1")
            conn.execute("DELETE FROM alerts WHERE is_demo = 1")
            conn.execute("DELETE FROM kbs WHERE is_demo = 1")

        seed_time_initial = "2026-10-13T18:00:00Z"
        seed_time_update = "2026-10-16T14:30:00Z"

        # 1. KB5044284 - Windows 11 24H2 Cumulative Update (AFFECTED: critical regression + OOB replacement KB5045934)
        upsert_kb(
            conn,
            {
                "kb_number": "KB5044284",
                "title": "October 2026 Cumulative Security Update for Windows 11, version 24H2 (OS Build 26100.2033)",
                "windows_version": "Windows 11 24H2",
                "os_build": "26100.2033",
                "release_date": "2026-10-13",
                "patch_tuesday_cycle": "2026-10",
                "update_type": "Cumulative",
                "is_security_update": True,
                "is_oob": False,
                "has_kir": True,
                "health_status": "SAFE",
                "health_rationale": "Initial release prior to regression report.",
                "summary": "Monthly Patch Tuesday security and quality cumulative update for Windows 11 version 24H2.",
                "highlights": "Addresses security vulnerabilities in Windows Kernel, Kerberos, OpenSSH, and Remote Desktop.",
                "source_url": "https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-24h2",
                "telemetry_verified": True,
                "data_origin": DEMO_ORIGIN,
                "is_demo": True,
            },
            detected_at=seed_time_initial,
        )

        # 2. KB5045934 - Windows 11 24H2 Out-of-Band (OOB) Update replacing KB5044284 (CAUTION: OOB emergency release)
        upsert_kb(
            conn,
            {
                "kb_number": "KB5045934",
                "title": "Out-of-Band (OOB) Update for Windows 11, version 24H2 (OS Build 26100.2036)",
                "windows_version": "Windows 11 24H2",
                "os_build": "26100.2036",
                "release_date": "2026-10-16",
                "patch_tuesday_cycle": "2026-10",
                "update_type": "Out-of-Band (OOB)",
                "is_security_update": True,
                "is_oob": True,
                "has_kir": False,
                "summary": "Emergency Out-of-Band cumulative update resolving OpenSSH service startup failure and Kerberos authentication stop error introduced in KB5044284.",
                "highlights": "Supersedes KB5044284. Deploy to endpoints and servers experiencing OpenSSH or Kerberos authentication failures.",
                "source_url": "https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-24h2",
                "telemetry_verified": True,
                "data_origin": DEMO_ORIGIN,
                "is_demo": True,
            },
            detected_at=seed_time_update,
        )

        # 3. KB5044285 - Windows 11 23H2 Cumulative Update (CAUTION: Confirmed issue + Enterprise Group Policy KIR)
        upsert_kb(
            conn,
            {
                "kb_number": "KB5044285",
                "title": "October 2026 Cumulative Security Update for Windows 11, version 23H2 (OS Build 22631.4317)",
                "windows_version": "Windows 11 23H2",
                "os_build": "22631.4317",
                "release_date": "2026-10-13",
                "patch_tuesday_cycle": "2026-10",
                "update_type": "Cumulative",
                "is_security_update": True,
                "is_oob": False,
                "has_kir": True,
                "summary": "Monthly cumulative security update for Windows 11 version 23H2.",
                "highlights": "Includes servicing stack improvements and security fixes for Windows Management Instrumentation and USB print drivers.",
                "source_url": "https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-23h2",
                "telemetry_verified": True,
                "data_origin": DEMO_ORIGIN,
                "is_demo": True,
            },
            detected_at=seed_time_initial,
        )

        # 4. KB5044273 - Windows 10 22H2 Cumulative Update (MONITOR: Mitigated issue via automatic KIR + exploited CVE)
        upsert_kb(
            conn,
            {
                "kb_number": "KB5044273",
                "title": "October 2026 Cumulative Security Update for Windows 10, version 22H2 (OS Build 19045.5011)",
                "windows_version": "Windows 10 22H2",
                "os_build": "19045.5011",
                "release_date": "2026-10-13",
                "patch_tuesday_cycle": "2026-10",
                "update_type": "Cumulative",
                "is_security_update": True,
                "is_oob": False,
                "has_kir": True,
                "summary": "Monthly security update for Windows 10 version 22H2 Desktop editions.",
                "highlights": "Addresses actively exploited MSHTML platform spoofing vulnerability and Win32k elevation of privilege.",
                "source_url": "https://learn.microsoft.com/en-us/windows/release-health/status-windows-10-22H2",
                "telemetry_verified": True,
                "data_origin": DEMO_ORIGIN,
                "is_demo": True,
            },
            detected_at=seed_time_initial,
        )

        # 5. KB5043076 - Windows 11 23H2 Prior Month Cumulative Update (SAFE: Verified telemetry, zero active issues)
        upsert_kb(
            conn,
            {
                "kb_number": "KB5043076",
                "title": "September 2026 Cumulative Security Update for Windows 11, version 23H2 (OS Build 22631.4169)",
                "windows_version": "Windows 11 23H2",
                "os_build": "22631.4169",
                "release_date": "2026-09-08",
                "patch_tuesday_cycle": "2026-09",
                "update_type": "Cumulative",
                "is_security_update": True,
                "is_oob": False,
                "has_kir": False,
                "summary": "September Patch Tuesday cumulative security update for Windows 11 version 23H2.",
                "highlights": "Validated across production rings with zero active Microsoft known issues.",
                "source_url": "https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-23h2",
                "telemetry_verified": True,
                "data_origin": DEMO_ORIGIN,
                "is_demo": True,
            },
            detected_at="2026-09-08T18:00:00Z",
        )

        # 6. KB5043064 - Windows 10 22H2 Prior Month Security Update (SAFE: Verified telemetry, zero active issues)
        upsert_kb(
            conn,
            {
                "kb_number": "KB5043064",
                "title": "September 2026 Security Update for Windows 10, version 22H2 (OS Build 19045.4894)",
                "windows_version": "Windows 10 22H2",
                "os_build": "19045.4894",
                "release_date": "2026-09-08",
                "patch_tuesday_cycle": "2026-09",
                "update_type": "Security Only",
                "is_security_update": True,
                "is_oob": False,
                "has_kir": False,
                "summary": "September security update for Windows 10 22H2 with verified clean release health.",
                "highlights": "Addresses Windows TCP/IP and Windows Installer security vulnerabilities.",
                "source_url": "https://learn.microsoft.com/en-us/windows/release-health/status-windows-10-22h2",
                "telemetry_verified": True,
                "data_origin": DEMO_ORIGIN,
                "is_demo": True,
            },
            detected_at="2026-09-08T18:00:00Z",
        )

        # 7. KB5044281 - Windows 11 22H2 October Cumulative Security Update (SAFE: Verified telemetry, zero active issues)
        upsert_kb(
            conn,
            {
                "kb_number": "KB5044281",
                "title": "October 2026 Cumulative Security Update for Windows 11, version 22H2 (OS Build 22621.4317)",
                "windows_version": "Windows 11 22H2",
                "os_build": "22621.4317",
                "release_date": "2026-10-13",
                "patch_tuesday_cycle": "2026-10",
                "update_type": "Cumulative",
                "is_security_update": True,
                "is_oob": False,
                "has_kir": False,
                "summary": "October Patch Tuesday cumulative security update for Windows 11 version 22H2 Enterprise and Education.",
                "highlights": "Verified clean release health with zero active Microsoft known issues.",
                "source_url": "https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-22h2",
                "telemetry_verified": True,
                "data_origin": DEMO_ORIGIN,
                "is_demo": True,
            },
            detected_at=seed_time_initial,
        )

        # 8. KB5046109 - Windows 11 22H2 Preview Update (UNKNOWN: Telemetry unverified)
        upsert_kb(
            conn,
            {
                "kb_number": "KB5046109",
                "title": "Non-Security Preview Update for Windows 11, version 22H2 (OS Build 22621.4391)",
                "windows_version": "Windows 11 22H2",
                "os_build": "22621.4391",
                "release_date": "2026-10-20",
                "patch_tuesday_cycle": "2026-10",
                "update_type": "Preview",
                "is_security_update": False,
                "is_oob": False,
                "has_kir": False,
                "summary": "Optional C-release preview update for Windows 11 version 22H2 Enterprise and Education editions.",
                "highlights": "Official Release Health telemetry verification pending live synchronization.",
                "source_url": "https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-22h2",
                "telemetry_verified": False,
                "data_origin": DEMO_ORIGIN,
                "is_demo": True,
            },
            detected_at="2026-10-20T19:00:00Z",
        )

        # Relationships (Supersession and OOB replacement chains)
        add_kb_relationship(
            conn,
            kb_number="KB5044284",
            related_kb="KB5045934",
            relationship_type="oob_replaced_by",
            issue_key="ISSUE-KB5044284-SSH-KERBEROS",
            description="Superseded by Out-of-Band update KB5045934 which resolves OpenSSH and Kerberos service failures.",
            source_url="https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-24h2",
        )
        add_kb_relationship(
            conn,
            kb_number="KB5045934",
            related_kb="KB5044284",
            relationship_type="oob_replaces",
            issue_key="ISSUE-KB5044284-SSH-KERBEROS",
            description="Out-of-Band update KB5045934 replaces and supersedes KB5044284.",
            source_url="https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-24h2",
        )
        add_kb_relationship(
            conn,
            kb_number="KB5044285",
            related_kb="KB5043076",
            relationship_type="supersedes",
            description="October 2026 cumulative update KB5044285 supersedes September 2026 update KB5043076.",
            source_url="https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-23h2",
        )
        add_kb_relationship(
            conn,
            kb_number="KB5043076",
            related_kb="KB5044285",
            relationship_type="superseded_by",
            description="Superseded by October 2026 cumulative update KB5044285.",
            source_url="https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-23h2",
        )
        add_kb_relationship(
            conn,
            kb_number="KB5044273",
            related_kb="KB5043064",
            relationship_type="supersedes",
            description="October 2026 cumulative update KB5044273 supersedes September 2026 update KB5043064.",
            source_url="https://learn.microsoft.com/en-us/windows/release-health/status-windows-10-22h2",
        )
        add_kb_relationship(
            conn,
            kb_number="KB5043064",
            related_kb="KB5044273",
            relationship_type="superseded_by",
            description="Superseded by October 2026 cumulative update KB5044273.",
            source_url="https://learn.microsoft.com/en-us/windows/release-health/status-windows-10-22h2",
        )

        # Known Issues
        # Issue 1: Critical failure on KB5044284 (triggers AFFECTED + OOB KB5045934)
        upsert_known_issue(
            conn,
            {
                "issue_key": "ISSUE-KB5044284-SSH-KERBEROS",
                "kb_number": "KB5044284",
                "windows_version": "Windows 11 24H2",
                "os_build": "26100.2033",
                "title": "OpenSSH (sshd) service fails to start and Kerberos authentication failure after installing KB5044284",
                "symptoms": "After installing KB5044284 on Windows 11 version 24H2, the OpenSSH (sshd) service might fail to start without logging detailed errors, and enterprise endpoints with Credential Guard enabled might experience Kerberos authentication failure or LSASS stop error.",
                "status": "Confirmed",
                "severity": "Critical",
                "is_severe_failure": True,
                "workaround": "Remove ACL restrictions on C:\\ProgramData\\ssh\\logs or deploy Out-of-Band update KB5045934.",
                "resolution": "Resolved in Out-of-Band (OOB) update KB5045934 (OS Build 26100.2036).",
                "has_kir": True,
                "kir_restart_required": True,
                "kir_deployment_method": "Automatic via Windows Update (Consumer) & Group Policy MSI (Enterprise Managed)",
                "kir_guidance_url": "https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-24h2#4990msgdesc",
                "kir_gpo_name": "KB5044284 241015_03301 Known Issue Rollback",
                "oob_fix_kb": "KB5045934",
                "opened_date": "2026-10-14",
                "last_updated_date": "2026-10-16",
                "source_url": "https://support.microsoft.com/help/5044284#known-issues-in-this-update",
                "is_demo": True,
            },
            detected_at=seed_time_update,
        )

        # Issue 2: Confirmed issue on KB5044285 with Enterprise Group Policy KIR (triggers CAUTION)
        upsert_known_issue(
            conn,
            {
                "issue_key": "ISSUE-KB5044285-USB-PRINT-KIR",
                "kb_number": "KB5044285",
                "windows_version": "Windows 11 23H2",
                "os_build": "22631.4317",
                "title": "Dual-mode USB printers might print unexpected text or fail to initialize over IPP-over-USB",
                "symptoms": "After installing KB5044285, USB printers supporting both USB Print and IPP Over USB might unexpectedly output random protocol headers when the Print Spooler reinitializes after sleep.",
                "status": "Confirmed",
                "severity": "High",
                "is_severe_failure": False,
                "workaround": "Deploy the Microsoft Known Issue Rollback (KIR) Group Policy MSI package to affected managed organizational units and restart devices.",
                "resolution": "Mitigated via Known Issue Rollback (KIR). Permanent fix scheduled for next monthly cumulative update.",
                "has_kir": True,
                "kir_restart_required": True,
                "kir_deployment_method": "Automatic via Windows Update (Consumer) & Group Policy MSI (Enterprise Managed)",
                "kir_guidance_url": "https://support.microsoft.com/help/5044285#known-issues-in-this-update",
                "kir_gpo_name": "KB5044285 241014_21401 Known Issue Rollback",
                "opened_date": "2026-10-14",
                "last_updated_date": "2026-10-15",
                "source_url": "https://support.microsoft.com/help/5044285#known-issues-in-this-update",
                "is_demo": True,
            },
            detected_at="2026-10-15T11:20:00Z",
        )

        # Issue 3: Mitigated issue on KB5044273 (triggers MONITOR)
        upsert_known_issue(
            conn,
            {
                "issue_key": "ISSUE-KB5044273-TASKBAR-KIR",
                "kb_number": "KB5044273",
                "windows_version": "Windows 10 22H2",
                "os_build": "19045.5011",
                "title": "Intermittent delay launching Win32 applications from custom taskbar jump lists",
                "symptoms": "Devices with redirected roaming AppData folders might observe a 2-3 second delay when opening pinned jump list items.",
                "status": "Mitigated",
                "severity": "Low",
                "is_severe_failure": False,
                "workaround": "Automatically mitigated by Windows Update Known Issue Rollback (KIR) within 24 hours.",
                "resolution": "Mitigated automatically via Windows Update KIR.",
                "has_kir": True,
                "kir_restart_required": True,
                "kir_deployment_method": "Automatic via Windows Update",
                "kir_guidance_url": "https://support.microsoft.com/help/5044273#known-issues-in-this-update",
                "opened_date": "2026-10-14",
                "last_updated_date": "2026-10-15",
                "source_url": "https://support.microsoft.com/help/5044273#known-issues-in-this-update",
                "is_demo": True,
            },
            detected_at="2026-10-15T09:00:00Z",
        )

        # CVEs mapped from MSRC data
        cves_to_seed = [
            {
                "cve_id": "CVE-2024-43573",
                "kb_number": "KB5044284",
                "title": "Windows MSHTML Platform Spoofing Vulnerability",
                "severity": "Important",
                "cvss_score": 6.5,
                "affected_component": "Windows MSHTML Platform",
                "exploitability_status": "Exploited:Yes; Publicly Disclosed:Yes",
                "is_exploited": True,
                "publicly_disclosed": True,
                "published_date": "2026-10-13",
                "source_url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43573",
                "is_demo": True,
            },
            {
                "cve_id": "CVE-2024-43573",
                "kb_number": "KB5045934",
                "title": "Windows MSHTML Platform Spoofing Vulnerability",
                "severity": "Important",
                "cvss_score": 6.5,
                "affected_component": "Windows MSHTML Platform",
                "exploitability_status": "Exploited:Yes; Publicly Disclosed:Yes",
                "is_exploited": True,
                "publicly_disclosed": True,
                "published_date": "2026-10-13",
                "source_url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43573",
                "is_demo": True,
            },
            {
                "cve_id": "CVE-2024-43573",
                "kb_number": "KB5044285",
                "title": "Windows MSHTML Platform Spoofing Vulnerability",
                "severity": "Important",
                "cvss_score": 6.5,
                "affected_component": "Windows MSHTML Platform",
                "exploitability_status": "Exploited:Yes; Publicly Disclosed:Yes",
                "is_exploited": True,
                "publicly_disclosed": True,
                "published_date": "2026-10-13",
                "source_url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43573",
                "is_demo": True,
            },
            {
                "cve_id": "CVE-2024-43573",
                "kb_number": "KB5044273",
                "title": "Windows MSHTML Platform Spoofing Vulnerability",
                "severity": "Important",
                "cvss_score": 6.5,
                "affected_component": "Windows MSHTML Platform",
                "exploitability_status": "Exploited:Yes; Publicly Disclosed:Yes",
                "is_exploited": True,
                "publicly_disclosed": True,
                "published_date": "2026-10-13",
                "source_url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43573",
                "is_demo": True,
            },
            {
                "cve_id": "CVE-2024-43572",
                "kb_number": "KB5044284",
                "title": "Microsoft Management Console Remote Code Execution Vulnerability",
                "severity": "Important",
                "cvss_score": 7.8,
                "affected_component": "Microsoft Management Console (MMC)",
                "exploitability_status": "Exploited:Yes; Publicly Disclosed:No",
                "is_exploited": True,
                "publicly_disclosed": False,
                "published_date": "2026-10-13",
                "source_url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43572",
                "is_demo": True,
            },
            {
                "cve_id": "CVE-2024-43572",
                "kb_number": "KB5044273",
                "title": "Microsoft Management Console Remote Code Execution Vulnerability",
                "severity": "Important",
                "cvss_score": 7.8,
                "affected_component": "Microsoft Management Console (MMC)",
                "exploitability_status": "Exploited:Yes; Publicly Disclosed:No",
                "is_exploited": True,
                "publicly_disclosed": False,
                "published_date": "2026-10-13",
                "source_url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43572",
                "is_demo": True,
            },
            {
                "cve_id": "CVE-2024-43582",
                "kb_number": "KB5044285",
                "title": "Remote Desktop Protocol Server Remote Code Execution Vulnerability",
                "severity": "Critical",
                "cvss_score": 8.1,
                "affected_component": "Windows Remote Desktop Services",
                "exploitability_status": "Exploitation More Likely",
                "is_exploited": False,
                "publicly_disclosed": False,
                "published_date": "2026-10-13",
                "source_url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43582",
                "is_demo": True,
            },
            {
                "cve_id": "CVE-2024-38217",
                "kb_number": "KB5043076",
                "title": "Windows Mark of the Web (MotW) Security Feature Bypass Vulnerability",
                "severity": "Important",
                "cvss_score": 5.4,
                "affected_component": "Windows Shell / SmartScreen",
                "exploitability_status": "Exploitation Less Likely",
                "is_exploited": False,
                "publicly_disclosed": True,
                "published_date": "2026-09-08",
                "source_url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38217",
                "is_demo": True,
            },
            {
                "cve_id": "CVE-2024-38018",
                "kb_number": "KB5043064",
                "title": "Windows TCP/IP Remote Code Execution Vulnerability",
                "severity": "Critical",
                "cvss_score": 8.8,
                "affected_component": "Windows TCP/IP Stack",
                "exploitability_status": "Exploitation More Likely",
                "is_exploited": False,
                "publicly_disclosed": False,
                "published_date": "2026-09-08",
                "source_url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38018",
                "is_demo": True,
            },
        ]

        for c in cves_to_seed:
            upsert_cve(conn, c, detected_at=seed_time_initial)

        # Lifecycle Events
        lifecycle_entries = [
            (
                "KB5044284",
                "2026-10-13",
                "Released",
                "Patch Tuesday General Availability",
                "Released to Windows Update, WSUS, and Microsoft Update Catalog as build 26100.2033.",
                "https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-24h2",
            ),
            (
                "KB5044284",
                "2026-10-14",
                "Known Issue Reported",
                "Microsoft Confirms OpenSSH & Kerberos Failure",
                "Microsoft Release Health opened a critical known issue regarding OpenSSH (sshd) startup failure and Kerberos authentication errors.",
                "https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-24h2",
            ),
            (
                "KB5044284",
                "2026-10-15",
                "KIR Issued",
                "Known Issue Rollback (KIR) Published",
                "Microsoft released Group Policy MSI 'KB5044284 241015_03301 Known Issue Rollback' requiring endpoint restart.",
                "https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-24h2",
            ),
            (
                "KB5044284",
                "2026-10-16",
                "OOB Issued",
                "Superseded by Out-of-Band Update KB5045934",
                "Microsoft published Out-of-Band update KB5045934 (Build 26100.2036) replacing KB5044284.",
                "https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-24h2",
            ),
            (
                "KB5045934",
                "2026-10-16",
                "Released",
                "Out-of-Band (OOB) Emergency Release",
                "Published out-of-band to Microsoft Update Catalog and WSUS to remediate KB5044284 OpenSSH and Kerberos regressions.",
                "https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-24h2",
            ),
            (
                "KB5044285",
                "2026-10-13",
                "Released",
                "Patch Tuesday General Availability",
                "Released for Windows 11 23H2 (Build 22631.4317), superseding KB5043076.",
                "https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-23h2",
            ),
            (
                "KB5044285",
                "2026-10-14",
                "KIR Issued",
                "Known Issue Rollback Issued for USB Print Regression",
                "Microsoft published KIR Group Policy MSI for enterprise-managed devices experiencing USB IPP print issues.",
                "https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-23h2",
            ),
            (
                "KB5044273",
                "2026-10-13",
                "Released",
                "Patch Tuesday General Availability",
                "Released for Windows 10 22H2 (Build 19045.5011), superseding KB5043064.",
                "https://learn.microsoft.com/en-us/windows/release-health/status-windows-10-22h2",
            ),
            (
                "KB5044273",
                "2026-10-15",
                "KIR Issued",
                "Automatic Windows Update KIR Mitigation Active",
                "Taskbar jump list delay automatically mitigated via Windows Update KIR.",
                "https://learn.microsoft.com/en-us/windows/release-health/status-windows-10-22h2",
            ),
            (
                "KB5043076",
                "2026-09-08",
                "Released",
                "Patch Tuesday General Availability",
                "Released for Windows 11 23H2 (Build 22631.4169) with zero active regressions.",
                "https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-23h2",
            ),
            (
                "KB5043076",
                "2026-10-13",
                "Superseded",
                "Superseded by KB5044285",
                "Superseded by October 2026 cumulative security update KB5044285.",
                "https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-23h2",
            ),
        ]
        for kb_num, ev_date, ev_type, title, details, url in lifecycle_entries:
            add_lifecycle_event(conn, kb_num, ev_date, ev_type, title, details, url)

        # Recalculate all KB health states deterministically
        for kb_num in ("KB5044284", "KB5045934", "KB5044285", "KB5044273", "KB5044281", "KB5043076", "KB5043064", "KB5046109"):
            recalculate_kb_status(conn, kb_num, detected_at=seed_time_update)

        # Create explicit Operational Alerts
        create_alert_if_not_exists(
            conn,
            kb_number="KB5045934",
            windows_version="Windows 11 24H2",
            severity="AFFECTED",
            alert_type="OOB_RELEASE",
            title="[Reference Seed] Out-of-Band Update KB5045934 Issued for Windows 11 24H2 (Replaces KB5044284)",
            summary="Microsoft released emergency Out-of-Band update KB5045934 (OS Build 26100.2036) to resolve OpenSSH service startup failure and Kerberos authentication errors in KB5044284.",
            source_url="https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-24h2",
            is_demo=True,
            created_at="2026-10-16T15:00:00Z",
        )
        create_alert_if_not_exists(
            conn,
            kb_number="KB5044285",
            windows_version="Windows 11 23H2",
            severity="CAUTION",
            alert_type="KIR_ISSUED",
            title="[Reference Seed] Known Issue Rollback (KIR) Group Policy Issued for KB5044285 (Windows 11 23H2)",
            summary="Enterprise-managed endpoints require Group Policy MSI 'KB5044285 241014_21401 Known Issue Rollback' and a system restart to mitigate USB IPP printer protocol issues.",
            source_url="https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-23h2",
            is_demo=True,
            created_at="2026-10-15T12:00:00Z",
        )
        create_alert_if_not_exists(
            conn,
            kb_number="KB5044273",
            windows_version="Windows 10 22H2",
            severity="MONITOR",
            alert_type="EXPLOITED_CVE",
            title="[Reference Seed] Active Zero-Day Exploitation Reported in MSRC: CVE-2024-43573 & CVE-2024-43572",
            summary="MSRC confirms active exploitation of CVE-2024-43573 (MSHTML Spoofing) and CVE-2024-43572 (MMC RCE). Addressed in October cumulative updates KB5044273, KB5044285, and OOB KB5045934.",
            source_url="https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43573",
            is_demo=True,
            created_at="2026-10-13T20:00:00Z",
        )

    return True

