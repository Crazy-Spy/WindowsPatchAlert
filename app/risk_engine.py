"""Deterministic Operational Health State engine, Patch Tuesday calculator, and KIR/OOB detectors."""

from __future__ import annotations

import calendar
import re
from datetime import date, datetime
from typing import Any, Optional, Sequence
from urllib.parse import unquote

from app.models import HealthState, RiskEvaluationResult

KB_REGEX = re.compile(r"\bKB\d{6,8}\b", re.IGNORECASE)

SEVERE_FAILURE_KEYWORDS = (
    "bsod",
    "stop error",
    "blue screen",
    "boot failure",
    "might fail to start",
    "unable to boot",
    "bitlocker recovery",
    "data corruption",
    "data loss",
    "domain controller",
    "authentication failure",
    "lsass",
    "kerberos",
    "remote desktop connection failure",
    "network adapter failure",
    "dhcp failure",
    "black screen",
    "boot loop",
)


def get_patch_tuesday_date(year: int, month: int) -> date:
    """Return the exact date of Microsoft Patch Tuesday (second Tuesday of the given month)."""
    cal = calendar.monthcalendar(year, month)
    tuesdays = [week[calendar.TUESDAY] for week in cal if week[calendar.TUESDAY] != 0]
    return date(year, month, tuesdays[1])


def derive_patch_tuesday_cycle(release_date_str: str) -> str:
    """
    Determine the Patch Tuesday cycle identifier (YYYY-MM) for a given release date string (YYYY-MM-DD).
    If a valid YYYY-MM-DD date is provided, returns YYYY-MM of its cycle.
    """
    if not release_date_str:
        return "Unknown"
    cleaned = release_date_str.strip()[:10]
    try:
        dt = datetime.strptime(cleaned, "%Y-%m-%d").date()
        return f"{dt.year:04d}-{dt.month:02d}"
    except ValueError:
        match = re.search(r"(\d{4}-\d{2})", release_date_str)
        if match:
            return match.group(1)
        return "Unknown"


def is_patch_tuesday_release(release_date_str: str) -> bool:
    """Return True if the date falls exactly on the second Tuesday of that month."""
    cleaned = (release_date_str or "").strip()[:10]
    try:
        dt = datetime.strptime(cleaned, "%Y-%m-%d").date()
        return dt == get_patch_tuesday_date(dt.year, dt.month)
    except ValueError:
        return False


def detect_kir_metadata(
    text: str,
    links: Optional[Sequence[tuple[str, str]]] = None,
    default_source_url: str = "https://learn.microsoft.com/en-us/windows/release-health/",
) -> dict[str, Any]:
    """
    Detect Known Issue Rollback (KIR) indicators from official Microsoft issue text.
    Extracts whether a restart is required, deployment method (Windows Update automatic vs Group Policy),
    GPO name if present, and official guidance URL.
    """
    raw = text or ""
    lower = raw.lower()
    has_kir = "known issue rollback" in lower or bool(re.search(r"\bkir\b", lower))
    if not has_kir:
        return {
            "has_kir": False,
            "kir_restart_required": None,
            "kir_deployment_method": None,
            "kir_guidance_url": None,
            "kir_gpo_name": None,
        }

    # Determine restart requirement
    if "no restart" in lower or "without a restart" in lower or "does not require a restart" in lower:
        restart_required = False
    elif "restart" in lower or "reboot" in lower:
        restart_required = True
    else:
        # Microsoft standard KIR architecture requires a device restart after policy/rollback delivery
        restart_required = True

    # Determine deployment method
    has_gpo = "group policy" in lower or "special group policy" in lower or "enterprise-managed" in lower
    has_auto = "windows update" in lower or "automatically" in lower or "consumer" in lower or "non-managed" in lower

    if has_gpo and has_auto:
        deployment_method = "Automatic via Windows Update (Consumer) & Group Policy MSI (Enterprise Managed)"
    elif has_gpo:
        deployment_method = "Group Policy MSI (Enterprise Managed Devices)"
    else:
        deployment_method = "Automatic via Windows Update"

    # Extract Group Policy name if mentioned in text or in unquoted link URLs/labels
    gpo_match = re.search(r"(KB\d{6,8}\s*[^\n.;\"'()]*Rollback)", raw, re.IGNORECASE)
    gpo_name = gpo_match.group(1).strip() if gpo_match else None
    if not gpo_name and links:
        for label, href in links:
            unquoted = f"{label} {unquote(href or '')}"
            m_link = re.search(r"(KB\d{6,8}\s+[\d_]+\s+Known Issue Rollback)", unquoted, re.IGNORECASE)
            if not m_link:
                m_link = re.search(r"(KB\d{6,8}\s*[^\n.;\"'()/]*Rollback)", unquoted, re.IGNORECASE)
            if m_link:
                gpo_name = m_link.group(1).strip()
                break

    # Find best specific guidance URL (prefer direct .msi, #msgdesc anchor, or specific KIR article over generic page)
    guidance_url = default_source_url
    if links:
        msi_or_anchor_url = None
        kir_specific_url = None
        fallback_match_url = None

        for label, href in links:
            if not href:
                continue
            combined = f"{label} {unquote(href)}".lower()
            href_low = href.lower()
            if (".msi" in href_low and ("rollback" in combined or "kir" in combined)) or "msgdesc" in href_low:
                msi_or_anchor_url = href
                break
            if ("use-group-policy-to-deploy-known-issue-rollback" in href_low or "known-issues-in-this-update" in href_low) and not kir_specific_url:
                kir_specific_url = href
            elif ("rollback" in combined or "kir" in combined or "kb" in combined or "release-health" in combined) and not fallback_match_url:
                fallback_match_url = href

        if msi_or_anchor_url:
            guidance_url = msi_or_anchor_url
        elif "#" in (default_source_url or ""):
            guidance_url = default_source_url
        elif kir_specific_url:
            guidance_url = kir_specific_url
        elif fallback_match_url:
            guidance_url = fallback_match_url

    return {
        "has_kir": True,
        "kir_restart_required": restart_required,
        "kir_deployment_method": deployment_method,
        "kir_guidance_url": guidance_url,
        "kir_gpo_name": gpo_name,
    }


def detect_oob_metadata(title: str, description: str = "", kb_number: str = "") -> dict[str, Any]:
    """
    Detect Out-of-Band (OOB) update indicators and referenced KB numbers.
    """
    combined = f"{title or ''} {description or ''}"
    lower = combined.lower()
    is_oob = "out-of-band" in lower or "out of band" in lower or bool(re.search(r"\boob\b", lower))

    all_kbs = []
    for match in KB_REGEX.findall(combined):
        norm = match.upper()
        if norm != (kb_number or "").upper() and norm not in all_kbs:
            all_kbs.append(norm)

    return {
        "is_oob": is_oob,
        "referenced_kbs": all_kbs,
    }


def evaluate_kb_health(
    kb_number: str,
    telemetry_verified: bool,
    source_failed: bool = False,
    is_oob: bool = False,
    known_issues: Optional[Sequence[dict[str, Any]]] = None,
    relationships: Optional[Sequence[dict[str, Any]]] = None,
    cves: Optional[Sequence[dict[str, Any]]] = None,
    source_error_reason: Optional[str] = None,
) -> RiskEvaluationResult:
    """
    Calculate deterministic Operational Health State and human-readable rationale from Microsoft facts.

    Priority Order (strictly deterministic):
    1. UNKNOWN: Telemetry is not verified OR source collection failed with no verified telemetry.
       NEVER infer SAFE from a failed collection or missing source verification.
    2. AFFECTED (red):
       - The KB has been superseded/replaced by an Out-of-Band (OOB) update due to a regression (`oob_replaced_by`), OR
       - One or more active (Confirmed / Investigating) known issues have Critical severity, severe component failure
         (boot, BSOD, authentication, networking, data loss), or triggered an OOB fix KB.
    3. CAUTION (orange):
       - One or more active known issues with status 'Confirmed' (moderate/high impact) or requiring manual intervention, OR
       - Known Issue Rollback (KIR) active requiring Enterprise Group Policy deployment, OR
       - The KB itself is an Out-of-Band (OOB) emergency release requiring targeted applicability evaluation.
    4. MONITOR (yellow):
       - Known issues exist that are 'Mitigated' (e.g., automatic KIR or workaround), 'Investigating' (limited scope),
         or 'Resolved' on this update branch, OR
       - Contains actively exploited CVEs ('is_exploited' = True) with no active known regressions (advising prompt deployment & monitoring).
    5. SAFE (green):
       - Telemetry is verified from official Microsoft source AND zero active/mitigated/investigating known issues
         AND not replaced by an OOB update.
    """
    issues = list(known_issues or [])
    rels = list(relationships or [])
    cve_list = list(cves or [])

    factors: list[str] = []

    # Rule 1: UNKNOWN check (never infer SAFE from failed collection or unverified telemetry)
    if not telemetry_verified or (source_failed and len(issues) == 0):
        reason_detail = (
            f" ({source_error_reason})"
            if source_error_reason
            else " because official Microsoft Release Health telemetry could not be verified"
        )
        rationale = (
            f"Operational status is UNKNOWN{reason_detail}. "
            "PATCH ALERT never infers a SAFE state from unverified or failed source collections."
        )
        factors.append("Insufficient or unavailable Microsoft source telemetry.")
        if source_error_reason:
            factors.append(f"Source status detail: {source_error_reason}")
        return RiskEvaluationResult(
            status=HealthState.UNKNOWN,
            rationale=rationale,
            factors=factors,
            active_issues_count=0,
            mitigated_issues_count=0,
            resolved_issues_count=0,
            has_kir=False,
            has_oob_supersession=False,
            exploited_cve_count=sum(1 for c in cve_list if c.get("is_exploited")),
        )

    # Categorize relationships
    oob_replaced_by: list[str] = []
    oob_replaces: list[str] = []
    superseded_by: list[str] = []

    for r in rels:
        rtype = (r.get("relationship_type") or "").lower()
        rel_kb = r.get("related_kb") or ""
        if rtype == "oob_replaced_by" and rel_kb:
            oob_replaced_by.append(rel_kb)
        elif rtype == "oob_replaces" and rel_kb:
            oob_replaces.append(rel_kb)
        elif rtype == "superseded_by" and rel_kb:
            superseded_by.append(rel_kb)

    # Categorize known issues
    active_severe_issues: list[dict[str, Any]] = []
    active_confirmed_issues: list[dict[str, Any]] = []
    investigating_issues: list[dict[str, Any]] = []
    mitigated_issues: list[dict[str, Any]] = []
    resolved_issues: list[dict[str, Any]] = []
    kir_issues: list[dict[str, Any]] = []

    for issue in issues:
        st = (issue.get("status") or "Confirmed").strip().lower()
        sev = (issue.get("severity") or "Moderate").strip().lower()
        text_blob = f"{issue.get('title', '')} {issue.get('symptoms', '')}".lower()
        is_severe = bool(issue.get("is_severe_failure")) or sev == "critical" or any(
            kw in text_blob for kw in SEVERE_FAILURE_KEYWORDS
        )
        oob_fix = issue.get("oob_fix_kb")
        if oob_fix and oob_fix not in oob_replaced_by and oob_fix.upper() != kb_number.upper():
            oob_replaced_by.append(oob_fix)

        if issue.get("has_kir"):
            kir_issues.append(issue)

        if st == "resolved":
            resolved_issues.append(issue)
        elif st == "mitigated":
            mitigated_issues.append(issue)
        elif st == "investigating":
            if is_severe:
                active_severe_issues.append(issue)
            else:
                investigating_issues.append(issue)
        else:  # Confirmed / Active
            if is_severe or bool(oob_fix):
                active_severe_issues.append(issue)
            else:
                active_confirmed_issues.append(issue)

    exploited_cves = [c for c in cve_list if c.get("is_exploited")]
    has_kir = len(kir_issues) > 0
    has_oob_supersession = len(oob_replaced_by) > 0
    active_count = len(active_severe_issues) + len(active_confirmed_issues) + len(investigating_issues)

    # Rule 2: AFFECTED (red)
    if has_oob_supersession or len(active_severe_issues) > 0:
        reasons: list[str] = []
        if has_oob_supersession:
            oob_str = ", ".join(sorted(set(oob_replaced_by)))
            msg = f"Microsoft issued Out-of-Band (OOB) emergency replacement update(s) {oob_str} to resolve critical regressions in {kb_number}"
            reasons.append(msg)
            factors.append(f"Superseded by OOB update: {oob_str}")

        for iss in active_severe_issues:
            title = iss.get("title", "Severe component issue")
            reasons.append(f"Confirmed critical component failure: \"{title}\" ({iss.get('status', 'Confirmed')})")
            factors.append(f"Severe issue [{iss.get('status', 'Confirmed')}]: {title}")

        if has_kir:
            factors.append(f"Known Issue Rollback (KIR) available for {len(kir_issues)} issue(s).")

        rationale = (
            f"AFFECTED: Do not deploy {kb_number} without remediation. "
            + "; ".join(reasons)
            + "."
        )
        return RiskEvaluationResult(
            status=HealthState.AFFECTED,
            rationale=rationale,
            factors=factors,
            active_issues_count=active_count,
            mitigated_issues_count=len(mitigated_issues),
            resolved_issues_count=len(resolved_issues),
            has_kir=has_kir,
            has_oob_supersession=has_oob_supersession,
            exploited_cve_count=len(exploited_cves),
        )

    # Rule 3: CAUTION (orange)
    enterprise_kir_issues = [
        i for i in kir_issues
        if (i.get("status") or "").lower() != "resolved"
        and "group policy" in (i.get("kir_deployment_method") or "").lower()
    ]

    if len(active_confirmed_issues) > 0 or len(enterprise_kir_issues) > 0 or is_oob:
        reasons = []
        for iss in active_confirmed_issues:
            title = iss.get("title", "Confirmed known issue")
            reasons.append(f"Microsoft confirmed active known issue: \"{title}\"")
            factors.append(f"Confirmed issue: {title}")

        for kir_iss in enterprise_kir_issues:
            title = kir_iss.get("title", "KIR issue")
            method = kir_iss.get("kir_deployment_method", "Group Policy MSI")
            restart_note = "requires restart" if kir_iss.get("kir_restart_required") else "no restart required"
            msg = f"Known Issue Rollback (KIR) active for \"{title}\" ({method}; {restart_note})"
            if msg not in reasons:
                reasons.append(msg)
            factors.append(msg)

        if is_oob:
            replaces_note = (
                f" replacing {', '.join(oob_replaces)}" if oob_replaces else ""
            )
            oob_msg = (
                f"{kb_number} is an Out-of-Band (OOB) update{replaces_note}; Microsoft recommends deploying only to environments impacted by the targeted regression"
            )
            reasons.append(oob_msg)
            factors.append(oob_msg)

        rationale = f"CAUTION: Requires administrator evaluation before broad deployment. " + "; ".join(reasons) + "."
        return RiskEvaluationResult(
            status=HealthState.CAUTION,
            rationale=rationale,
            factors=factors,
            active_issues_count=active_count,
            mitigated_issues_count=len(mitigated_issues),
            resolved_issues_count=len(resolved_issues),
            has_kir=has_kir,
            has_oob_supersession=False,
            exploited_cve_count=len(exploited_cves),
        )

    # Rule 4: MONITOR (yellow)
    if len(mitigated_issues) > 0 or len(investigating_issues) > 0 or len(resolved_issues) > 0 or len(exploited_cves) > 0:
        reasons = []
        for iss in investigating_issues:
            title = iss.get("title", "Issue under investigation")
            reasons.append(f"Issue under Microsoft investigation (limited scope): \"{title}\"")
            factors.append(f"Investigating: {title}")

        for iss in mitigated_issues:
            title = iss.get("title", "Mitigated issue")
            kir_tag = " via automatic Known Issue Rollback (KIR)" if iss.get("has_kir") else " with documented workaround"
            reasons.append(f"Known issue mitigated{kir_tag}: \"{title}\"")
            factors.append(f"Mitigated{kir_tag}: {title}")

        for iss in resolved_issues:
            title = iss.get("title", "Resolved issue")
            reasons.append(f"Previously tracked known issue resolved: \"{title}\"")
            factors.append(f"Recently resolved: {title}")

        if len(exploited_cves) > 0:
            cve_ids = ", ".join(c.get("cve_id", "") for c in exploited_cves[:3])
            reasons.append(
                f"Addresses {len(exploited_cves)} zero-day / actively exploited vulnerability(ies) ({cve_ids}) with no active deployment blockers"
            )
            factors.append(f"Contains {len(exploited_cves)} actively exploited CVE(s): {cve_ids}")

        rationale = f"MONITOR: Safe for phased rings with routine telemetry monitoring. " + "; ".join(reasons) + "."
        return RiskEvaluationResult(
            status=HealthState.MONITOR,
            rationale=rationale,
            factors=factors,
            active_issues_count=active_count,
            mitigated_issues_count=len(mitigated_issues),
            resolved_issues_count=len(resolved_issues),
            has_kir=has_kir,
            has_oob_supersession=False,
            exploited_cve_count=len(exploited_cves),
        )

    # Rule 5: SAFE (green)
    factors.append("Official Microsoft Release Health telemetry verified.")
    factors.append("Zero active, mitigated, or investigating known issues reported by Microsoft.")
    if len(cve_list) > 0:
        factors.append(f"Addresses {len(cve_list)} documented security vulnerability(ies) with no reported regressions.")

    rationale = (
        f"SAFE: Official Microsoft Release Health telemetry verified for {kb_number}. "
        "No active known issues, Known Issue Rollbacks (KIR), or Out-of-Band (OOB) replacements are reported by Microsoft."
    )
    return RiskEvaluationResult(
        status=HealthState.SAFE,
        rationale=rationale,
        factors=factors,
        active_issues_count=0,
        mitigated_issues_count=0,
        resolved_issues_count=0,
        has_kir=False,
        has_oob_supersession=False,
        exploited_cve_count=0,
    )

