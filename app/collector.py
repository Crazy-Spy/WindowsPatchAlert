"""Live Microsoft telemetry collector using httpx and BeautifulSoup with bounded retries and audit diffing."""

from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urljoin

import httpx
from bs4 import BeautifulSoup

from app.audit import calculate_content_hash, normalize_text, record_entity_changes, utc_now_iso
from app.config import (
    DEFAULT_SYNC_INTERVAL_MINUTES,
    HTTP_BACKOFF_BASE_SECONDS,
    HTTP_MAX_RETRIES,
    HTTP_TIMEOUT_SECONDS,
    USER_AGENT,
)
from app.database import (
    add_kb_relationship,
    add_lifecycle_event,
    create_alert_if_not_exists,
    get_connection,
    recalculate_kb_status,
    upsert_cve,
    upsert_kb,
    upsert_known_issue,
)
from app.risk_engine import (
    KB_REGEX,
    SEVERE_FAILURE_KEYWORDS,
    derive_patch_tuesday_cycle,
    detect_kir_metadata,
    detect_oob_metadata,
)

BUILD_REGEX = re.compile(r"\b(\d{5}\.\d{1,5})\b")
DATE_ISO_REGEX = re.compile(r"\b(20\d{2}-\d{2}-\d{2})\b")
CVE_REGEX = re.compile(r"\b(CVE-20\d{2}-\d{4,7})\b", re.IGNORECASE)


class CollectorState:
    """In-memory runtime status tracker for active and completed synchronization jobs."""

    def __init__(self) -> None:
        self.is_running: bool = False
        self.current_source: Optional[str] = None
        self.started_at: Optional[str] = None
        self.finished_at: Optional[str] = None
        self.last_trigger: str = "none"
        self.last_status: str = "IDLE"
        self.sources_total: int = 0
        self.sources_completed: int = 0
        self.sources_succeeded: int = 0
        self.sources_failed: int = 0
        self.changes_detected: int = 0
        self.last_summary: str = "No synchronization run executed in this session yet."
        self.errors: list[dict[str, str]] = []
        self._lock = asyncio.Lock()

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_running": self.is_running,
            "current_source": self.current_source,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "last_trigger": self.last_trigger,
            "last_status": self.last_status,
            "sources_total": self.sources_total,
            "sources_completed": self.sources_completed,
            "sources_succeeded": self.sources_succeeded,
            "sources_failed": self.sources_failed,
            "changes_detected": self.changes_detected,
            "last_summary": self.last_summary,
            "errors": list(self.errors),
            "schedule_interval_minutes": DEFAULT_SYNC_INTERVAL_MINUTES,
        }


collector_state = CollectorState()


async def fetch_with_retries(
    client: httpx.AsyncClient,
    url: str,
    accept: str = "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
    max_retries: int = HTTP_MAX_RETRIES,
    backoff_base: float = HTTP_BACKOFF_BASE_SECONDS,
) -> tuple[int, str, dict[str, str]]:
    """
    Fetch a URL using bounded retries and exponential backoff.
    Raises RuntimeError with explicit diagnostic details if all attempts fail.
    """
    last_exc: Optional[Exception] = None
    last_status: Optional[int] = None

    for attempt in range(1, max_retries + 1):
        try:
            resp = await client.get(
                url,
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept": accept,
                    "Accept-Language": "en-US,en;q=0.9",
                },
                follow_redirects=True,
            )
            last_status = resp.status_code
            if 200 <= resp.status_code < 300:
                return resp.status_code, resp.text, dict(resp.headers)
            if resp.status_code in (429, 500, 502, 503, 504) and attempt < max_retries:
                await asyncio.sleep(backoff_base * (2 ** (attempt - 1)))
                continue
            raise RuntimeError(f"HTTP {resp.status_code} returned from {url}")
        except (httpx.TimeoutException, httpx.TransportError, RuntimeError) as exc:
            last_exc = exc
            if attempt < max_retries:
                await asyncio.sleep(backoff_base * (2 ** (attempt - 1)))
            else:
                break

    code_note = f" (HTTP {last_status})" if last_status else ""
    raise RuntimeError(f"Failed to collect {url} after {max_retries} attempts{code_note}: {last_exc}")


def _normalize_date_string(raw: str) -> str:
    """Parse common Microsoft Learn date formats into YYYY-MM-DD."""
    if not raw:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")
    cleaned = normalize_text(raw)
    iso_match = DATE_ISO_REGEX.search(cleaned)
    if iso_match:
        return iso_match.group(1)

    for fmt in ("%B %d, %Y", "%b %d, %Y", "%m/%d/%Y", "%Y/%m/%d"):
        try:
            return datetime.strptime(cleaned, fmt).strftime("%Y-%m-%d")
        except ValueError:
            continue
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def parse_release_health_html(
    html_text: str,
    windows_version: str,
    source_url: str,
) -> dict[str, Any]:
    """
    Parse a Microsoft Windows Release Health HTML document into structured KBs and Known Issues.
    Extracts Known Issues tables, Resolved Issues tables, KB identifiers, build numbers, KIR, and OOB metadata.
    """
    soup = BeautifulSoup(html_text, "html.parser")
    extracted_kbs: dict[str, dict[str, Any]] = {}
    extracted_issues: list[dict[str, Any]] = []

    default_build_map = {
        "Windows 11 24H2": "26100",
        "Windows 11 23H2": "22631",
        "Windows 11 22H2": "22621",
        "Windows 10 22H2": "19045",
    }
    base_build = default_build_map.get(windows_version, "26100")

    # Index detailed issue sections (<div id="XXXXmsgdesc">...</div>) on the Release Health page
    # so summary table rows linking to #XXXXmsgdesc inherit the full KIR/MSI links and exact #anchor URL.
    detail_blocks_by_anchor: dict[str, dict[str, Any]] = {}
    for anchor_div in soup.find_all(["div", "section", "a"], id=True):
        anchor_id = str(anchor_div.get("id", "")).strip()
        if not anchor_id.endswith("msgdesc"):
            continue
        sec_texts: list[str] = []
        sec_links: list[tuple[str, str]] = []
        cur = anchor_div.next_sibling
        while cur:
            if getattr(cur, "attrs", None) and str(cur.attrs.get("id", "")).endswith("msgdesc"):
                break
            if getattr(cur, "name", None) == "h2":
                break
            if getattr(cur, "name", None):
                txt_piece = normalize_text(cur.get_text(" ", strip=True))
                if txt_piece:
                    sec_texts.append(txt_piece)
                for a_el in cur.find_all("a", href=True):
                    raw_href = a_el.get("href", "").strip()
                    if raw_href and not raw_href.startswith("feedback-hub:"):
                        sec_links.append(
                            (normalize_text(a_el.get_text(" ", strip=True)), urljoin(source_url, raw_href))
                        )
            cur = cur.next_sibling
        detail_blocks_by_anchor[anchor_id] = {
            "text": " ".join(sec_texts),
            "links": sec_links,
        }

    tables = soup.find_all("table")
    for table in tables:
        headers = [normalize_text(th.get_text(" ", strip=True)).lower() for th in table.find_all("th")]
        if not headers:
            continue

        # Identify whether this table lists known/resolved issues or update history
        is_issue_table = any(
            h in " ".join(headers) for h in ("summary", "issue", "originating", "status", "symptom")
        )
        # Skip small inner metadata tables inside #msgdesc blocks ("Status | Originating update | History")
        if not is_issue_table or (len(headers) == 3 and "history" in " ".join(headers)):
            continue

        tbody = table.find("tbody") or table
        for tr in tbody.find_all("tr"):
            cells = tr.find_all(["td", "th"])
            if len(cells) < 2 or all(c.name == "th" for c in cells):
                continue

            row_texts = [normalize_text(c.get_text(" ", strip=True)) for c in cells]
            full_row_text = " | ".join(row_texts)

            anchor_id_found: Optional[str] = None
            links: list[tuple[str, str]] = []
            for a in tr.find_all("a", href=True):
                raw_href = a.get("href", "").strip()
                if raw_href.startswith("#") and raw_href[1:].endswith("msgdesc"):
                    anchor_id_found = raw_href[1:]
                links.append((normalize_text(a.get_text(" ", strip=True)), urljoin(source_url, raw_href)))

            detail_text = ""
            if anchor_id_found and anchor_id_found in detail_blocks_by_anchor:
                detail_text = detail_blocks_by_anchor[anchor_id_found]["text"]
                links.extend(detail_blocks_by_anchor[anchor_id_found]["links"])

            combined_issue_text = f"{full_row_text} {detail_text}".strip()

            kbs_in_row = []
            for kb_m in KB_REGEX.findall(combined_issue_text):
                norm_kb = kb_m.upper()
                if norm_kb not in kbs_in_row:
                    kbs_in_row.append(norm_kb)

            if not kbs_in_row:
                continue

            primary_kb = kbs_in_row[0]
            build_match = BUILD_REGEX.search(combined_issue_text)
            os_build = build_match.group(1) if build_match else f"{base_build}.1"

            # Determine status from row cells
            status_val = "Confirmed"
            for cell_txt in row_texts:
                low_c = cell_txt.lower()
                if low_c in ("resolved", "mitigated", "confirmed", "investigating"):
                    status_val = cell_txt.capitalize()
                    break
                if "resolved" in low_c:
                    status_val = "Resolved"
                elif "mitigated" in low_c:
                    status_val = "Mitigated"
                elif "investigating" in low_c:
                    status_val = "Investigating"

            title = row_texts[0] if len(row_texts[0]) > 8 else (row_texts[1] if len(row_texts) > 1 else full_row_text[:120])
            date_str = _normalize_date_string(row_texts[-1] if len(row_texts) >= 3 else "")

            issue_source_url = (
                f"{source_url}#{anchor_id_found}"
                if anchor_id_found
                else f"https://support.microsoft.com/help/{primary_kb[2:]}#known-issues-in-this-update"
            )

            kir_meta = detect_kir_metadata(combined_issue_text, links=links, default_source_url=issue_source_url)
            oob_meta = detect_oob_metadata(title, combined_issue_text, kb_number=primary_kb)

            is_severe = any(kw in combined_issue_text.lower() for kw in SEVERE_FAILURE_KEYWORDS)
            severity = "Critical" if is_severe else ("High" if status_val == "Confirmed" else "Moderate")

            oob_fix_kb = None
            if oob_meta["is_oob"] and len(kbs_in_row) > 1:
                oob_fix_kb = kbs_in_row[-1]

            issue_hash_seed = f"{windows_version}:{primary_kb}:{title[:80]}"
            issue_key = f"LIVE-{calculate_content_hash(issue_hash_seed)[:12].upper()}"

            extracted_issues.append(
                {
                    "issue_key": issue_key,
                    "kb_number": primary_kb,
                    "windows_version": windows_version,
                    "os_build": os_build,
                    "title": title[:300],
                    "symptoms": combined_issue_text[:1200],
                    "status": status_val,
                    "severity": severity,
                    "is_severe_failure": is_severe,
                    "has_kir": kir_meta["has_kir"],
                    "kir_restart_required": kir_meta["kir_restart_required"],
                    "kir_deployment_method": kir_meta["kir_deployment_method"],
                    "kir_guidance_url": kir_meta["kir_guidance_url"],
                    "kir_gpo_name": kir_meta["kir_gpo_name"],
                    "oob_fix_kb": oob_fix_kb,
                    "opened_date": date_str,
                    "last_updated_date": date_str,
                    "resolved_date": date_str if status_val == "Resolved" else None,
                    "source_url": issue_source_url,
                    "is_demo": False,
                }
            )

            for kb_code in kbs_in_row:
                is_this_oob = bool(oob_fix_kb and kb_code == oob_fix_kb)
                if kb_code not in extracted_kbs:
                    extracted_kbs[kb_code] = {
                        "kb_number": kb_code,
                        "title": (
                            f"Out-of-Band (OOB) Update {kb_code} for {windows_version} (OS Build {os_build})"
                            if is_this_oob
                            else f"Cumulative Update {kb_code} for {windows_version} (OS Build {os_build})"
                        ),
                        "windows_version": windows_version,
                        "os_build": os_build,
                        "release_date": date_str,
                        "patch_tuesday_cycle": derive_patch_tuesday_cycle(date_str),
                        "update_type": "Out-of-Band (OOB)" if is_this_oob else "Cumulative",
                        "is_security_update": True,
                        "is_oob": is_this_oob,
                        "has_kir": kir_meta["has_kir"],
                        "source_url": source_url,
                        "telemetry_verified": True,
                        "data_origin": "Microsoft Release Health (Live Sync)",
                        "is_demo": False,
                    }

    # Also scan headings/paragraphs for KB mentions if page uses non-table blocks
    if not extracted_kbs:
        text_body = soup.get_text(" ", strip=True)
        found_kbs = list(dict.fromkeys(m.upper() for m in KB_REGEX.findall(text_body)))[:10]
        build_m = BUILD_REGEX.search(text_body)
        os_build = build_m.group(1) if build_m else f"{base_build}.1"
        today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        for kb_code in found_kbs:
            extracted_kbs[kb_code] = {
                "kb_number": kb_code,
                "title": f"Cumulative Update {kb_code} for {windows_version} (OS Build {os_build})",
                "windows_version": windows_version,
                "os_build": os_build,
                "release_date": today_str,
                "patch_tuesday_cycle": derive_patch_tuesday_cycle(today_str),
                "update_type": "Cumulative",
                "is_security_update": True,
                "is_oob": False,
                "has_kir": False,
                "source_url": source_url,
                "telemetry_verified": True,
                "data_origin": "Microsoft Release Health (Live Sync)",
                "is_demo": False,
            }

    return {
        "kbs": list(extracted_kbs.values()),
        "known_issues": extracted_issues,
    }


def parse_msrc_cvrf_payload(raw_text: str, source_url: str) -> dict[str, Any]:
    """
    Parse MSRC CVRF API JSON response (`https://api.msrc.microsoft.com/cvrf/v3.0/updates` or CVRF document).
    Extracts security update cycles and any embedded CVE-to-KB mappings.
    """
    data = json.loads(raw_text)
    updates_list: list[dict[str, Any]] = []
    cves_list: list[dict[str, Any]] = []

    if isinstance(data, dict) and "value" in data and isinstance(data["value"], list):
        # Standard /cvrf/v3.0/updates list response
        for item in data["value"][:12]:
            updates_list.append(
                {
                    "id": item.get("ID"),
                    "title": item.get("DocumentTitle"),
                    "release_date": (item.get("CurrentReleaseDate") or item.get("InitialReleaseDate") or "")[:10],
                    "cvrf_url": item.get("CvrfUrl"),
                }
            )
    elif isinstance(data, dict) and "Vulnerability" in data:
        # Full CVRF document with Vulnerability entries
        for vuln in data.get("Vulnerability", []):
            cve_id = vuln.get("CVE")
            if not cve_id:
                continue
            title_obj = vuln.get("Title", {})
            title = title_obj.get("Value", f"{cve_id} Windows Security Vulnerability") if isinstance(title_obj, dict) else str(title_obj)

            threats = vuln.get("Threats", [])
            exploit_status = "Exploitation Less Likely"
            is_exploited = False
            pub_disclosed = False
            for t in threats:
                desc = t.get("Description", {})
                val = desc.get("Value", "") if isinstance(desc, dict) else str(desc)
                if "exploited:yes" in val.lower():
                    is_exploited = True
                    exploit_status = val
                if "publicly disclosed:yes" in val.lower():
                    pub_disclosed = True

            remediations = vuln.get("Remediations", [])
            for rem in remediations:
                desc = rem.get("Description", {})
                kb_val = desc.get("Value", "") if isinstance(desc, dict) else str(desc)
                kb_match = KB_REGEX.search(kb_val) or (KB_REGEX.search(f"KB{kb_val}") if kb_val.isdigit() else None)
                if kb_match:
                    kb_num = kb_match.group(0).upper()
                    cves_list.append(
                        {
                            "cve_id": cve_id.upper(),
                            "kb_number": kb_num,
                            "title": title,
                            "severity": "Important",
                            "cvss_score": 7.5,
                            "affected_component": "Microsoft Windows",
                            "exploitability_status": exploit_status,
                            "is_exploited": is_exploited,
                            "publicly_disclosed": pub_disclosed,
                            "published_date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                            "source_url": f"https://msrc.microsoft.com/update-guide/vulnerability/{cve_id.upper()}",
                            "is_demo": False,
                        }
                    )

    return {
        "updates": updates_list,
        "cves": cves_list,
    }


async def sync_single_source(
    client: httpx.AsyncClient,
    source_row: dict[str, Any],
    db_path: Optional[str] = None,
) -> dict[str, Any]:
    """
    Collect, normalize, hash, and persist telemetry for a single configured Microsoft source.
    Explicitly records any HTTP or parsing failures and never fabricates telemetry on error.
    """
    source_id = source_row["id"]
    source_key = source_row["source_key"]
    source_type = source_row["source_type"]
    windows_version = source_row["windows_version"]
    url = source_row["url"]
    now = utc_now_iso()

    try:
        accept_hdr = "application/json" if source_type == "msrc_cvrf" else "text/html,application/xhtml+xml,*/*;q=0.8"
        http_code, raw_body, _ = await fetch_with_retries(client, url, accept=accept_hdr)
        normalized_hash = calculate_content_hash(raw_body)

        changes_count = 0
        items_collected = 0

        with get_connection(db_path) as conn:
            old_source_hash = source_row.get("content_hash")
            if old_source_hash and old_source_hash != normalized_hash:
                record_entity_changes(
                    conn=conn,
                    entity_type="SOURCE",
                    entity_id=source_key,
                    kb_number=None,
                    old_record={"content_hash": old_source_hash, "last_status": source_row.get("last_status")},
                    new_record={"content_hash": normalized_hash, "last_status": "OK"},
                    tracked_fields=("last_status",),
                    source_url=url,
                    is_demo=False,
                    detected_at=now,
                )

            if source_type in ("release_health", "message_center"):
                parsed = parse_release_health_html(raw_body, windows_version, url)
                for kb_item in parsed["kbs"]:
                    _, ch = upsert_kb(conn, kb_item, detected_at=now)
                    changes_count += len(ch)
                    items_collected += 1

                for issue_item in parsed["known_issues"]:
                    # Ensure parent KB exists before inserting foreign key issue
                    kb_num = issue_item["kb_number"]
                    exists = conn.execute("SELECT 1 FROM kbs WHERE kb_number = ?", (kb_num,)).fetchone()
                    if not exists:
                        upsert_kb(
                            conn,
                            {
                                "kb_number": kb_num,
                                "title": f"Cumulative Update {kb_num} for {windows_version}",
                                "windows_version": windows_version,
                                "os_build": issue_item.get("os_build") or "Unknown",
                                "release_date": issue_item.get("opened_date") or now[:10],
                                "patch_tuesday_cycle": derive_patch_tuesday_cycle(issue_item.get("opened_date") or now[:10]),
                                "update_type": "Cumulative",
                                "is_security_update": True,
                                "is_oob": False,
                                "has_kir": issue_item.get("has_kir", False),
                                "source_url": url,
                                "telemetry_verified": True,
                                "data_origin": "Microsoft Release Health (Live Sync)",
                                "is_demo": False,
                            },
                            detected_at=now,
                        )
                    _, ich = upsert_known_issue(conn, issue_item, detected_at=now)
                    changes_count += len(ich)
                    items_collected += 1

                for kb_item in parsed["kbs"]:
                    recalculate_kb_status(conn, kb_item["kb_number"], source_failed=False, detected_at=now)

            elif source_type == "msrc_cvrf":
                parsed_msrc = parse_msrc_cvrf_payload(raw_body, url)
                items_collected += len(parsed_msrc["updates"]) + len(parsed_msrc["cves"])
                for cve_item in parsed_msrc["cves"]:
                    kb_num = cve_item["kb_number"]
                    exists = conn.execute("SELECT 1 FROM kbs WHERE kb_number = ?", (kb_num,)).fetchone()
                    if exists:
                        _, cch = upsert_cve(conn, cve_item, detected_at=now)
                        changes_count += len(cch)
                        recalculate_kb_status(conn, kb_num, source_failed=False, detected_at=now)

            conn.execute(
                """
                UPDATE sources SET
                    last_checked_at = ?,
                    last_success_at = ?,
                    last_status = 'OK',
                    last_http_code = ?,
                    last_error = NULL,
                    content_hash = ?,
                    items_collected = ?
                WHERE id = ?
                """,
                (now, now, http_code, normalized_hash, items_collected, source_id),
            )

        return {
            "source_key": source_key,
            "status": "OK",
            "http_code": http_code,
            "items_collected": items_collected,
            "changes_detected": changes_count,
            "content_hash": normalized_hash,
            "error": None,
        }

    except Exception as exc:
        err_msg = str(exc)
        with get_connection(db_path) as conn:
            conn.execute(
                """
                UPDATE sources SET
                    last_checked_at = ?,
                    last_status = 'ERROR',
                    last_error = ?
                WHERE id = ?
                """,
                (now, err_msg[:500], source_id),
            )
            # Mark any unverified KBs for this Windows version as UNKNOWN if they have no verified data
            unverified_kbs = conn.execute(
                "SELECT kb_number FROM kbs WHERE windows_version = ? AND telemetry_verified = 0",
                (windows_version,),
            ).fetchall()
            for r in unverified_kbs:
                recalculate_kb_status(
                    conn,
                    r["kb_number"],
                    source_failed=True,
                    source_error_reason=f"Source '{source_row['name']}' sync failed: {err_msg[:140]}",
                    detected_at=now,
                )

        return {
            "source_key": source_key,
            "status": "ERROR",
            "http_code": None,
            "items_collected": 0,
            "changes_detected": 0,
            "content_hash": None,
            "error": err_msg,
        }


async def run_synchronization(
    trigger_type: str = "manual",
    db_path: Optional[str] = None,
    client: Optional[httpx.AsyncClient] = None,
) -> dict[str, Any]:
    """
    Execute a full synchronization pass across all enabled Microsoft sources.
    Safe against concurrent overlapping invocations.
    """
    if collector_state.is_running:
        return {
            "started": False,
            "message": "Synchronization is already in progress.",
            "status": collector_state.to_dict(),
        }

    async with collector_state._lock:
        collector_state.is_running = True
        collector_state.started_at = utc_now_iso()
        collector_state.finished_at = None
        collector_state.last_trigger = trigger_type
        collector_state.last_status = "RUNNING"
        collector_state.sources_completed = 0
        collector_state.sources_succeeded = 0
        collector_state.sources_failed = 0
        collector_state.changes_detected = 0
        collector_state.errors = []

        with get_connection(db_path) as conn:
            sources = [
                dict(r)
                for r in conn.execute("SELECT * FROM sources WHERE enabled = 1 ORDER BY id ASC").fetchall()
            ]
            cur = conn.execute(
                "INSERT INTO sync_runs (started_at, trigger_type, status) VALUES (?, ?, 'RUNNING')",
                (collector_state.started_at, trigger_type),
            )
            run_id = cur.lastrowid

        collector_state.sources_total = len(sources)
        owns_client = client is None
        active_client = client or httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS)

        try:
            for src in sources:
                collector_state.current_source = src["name"]
                res = await sync_single_source(active_client, src, db_path=db_path)
                collector_state.sources_completed += 1
                collector_state.changes_detected += int(res.get("changes_detected", 0))
                if res["status"] == "OK":
                    collector_state.sources_succeeded += 1
                else:
                    collector_state.sources_failed += 1
                    collector_state.errors.append(
                        {"source": src["name"], "error": res.get("error") or "Unknown collection error"}
                    )
        finally:
            if owns_client:
                await active_client.aclose()

        collector_state.current_source = None
        collector_state.finished_at = utc_now_iso()
        collector_state.is_running = False

        if collector_state.sources_failed == 0 and collector_state.sources_succeeded > 0:
            collector_state.last_status = "COMPLETED"
        elif collector_state.sources_succeeded > 0 and collector_state.sources_failed > 0:
            collector_state.last_status = "PARTIAL_FAILURE"
        elif collector_state.sources_total == 0:
            collector_state.last_status = "NO_ENABLED_SOURCES"
        else:
            collector_state.last_status = "FAILED"

        summary_msg = (
            f"Checked {collector_state.sources_completed}/{collector_state.sources_total} Microsoft sources: "
            f"{collector_state.sources_succeeded} succeeded, {collector_state.sources_failed} failed, "
            f"{collector_state.changes_detected} field-level change(s) recorded."
        )
        collector_state.last_summary = summary_msg

        with get_connection(db_path) as conn:
            conn.execute(
                """
                UPDATE sync_runs SET
                    finished_at = ?,
                    status = ?,
                    sources_checked = ?,
                    sources_succeeded = ?,
                    sources_failed = ?,
                    changes_detected = ?,
                    summary = ?
                WHERE id = ?
                """,
                (
                    collector_state.finished_at,
                    collector_state.last_status,
                    collector_state.sources_completed,
                    collector_state.sources_succeeded,
                    collector_state.sources_failed,
                    collector_state.changes_detected,
                    summary_msg,
                    run_id,
                ),
            )

        return collector_state.to_dict()

