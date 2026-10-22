"""SQLite persistent storage, schema initialization, and query/upsert operations for PATCH ALERT."""

from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Optional, Sequence

from app.audit import calculate_content_hash, record_entity_changes, utc_now_iso
from app.config import DEFAULT_DB_PATH, DEFAULT_MICROSOFT_SOURCES
from app.models import HealthState
from app.risk_engine import derive_patch_tuesday_cycle, evaluate_kb_health

_CURRENT_DB_PATH: Path = DEFAULT_DB_PATH


def set_db_path(path: Path | str) -> None:
    """Configure the active SQLite database file path (useful for tests and custom launchers)."""
    global _CURRENT_DB_PATH
    _CURRENT_DB_PATH = Path(path)


def get_db_path() -> Path:
    """Return the active SQLite database file path."""
    env_override = os.environ.get("PATCH_ALERT_DB_PATH")
    if env_override:
        return Path(env_override)
    return _CURRENT_DB_PATH


@contextmanager
def get_connection(db_path: Optional[Path | str] = None) -> Iterator[sqlite3.Connection]:
    """Open a SQLite connection with row factory, WAL mode, and foreign keys enabled."""
    target = Path(db_path) if db_path else get_db_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(target), timeout=30.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_key TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    source_type TEXT NOT NULL,
    windows_version TEXT NOT NULL,
    url TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    check_interval_minutes INTEGER NOT NULL DEFAULT 240,
    last_checked_at TEXT,
    last_success_at TEXT,
    last_status TEXT NOT NULL DEFAULT 'NEVER_CHECKED',
    last_http_code INTEGER,
    last_error TEXT,
    content_hash TEXT,
    items_collected INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS kbs (
    kb_number TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    windows_version TEXT NOT NULL,
    os_build TEXT NOT NULL,
    release_date TEXT NOT NULL,
    patch_tuesday_cycle TEXT NOT NULL,
    update_type TEXT NOT NULL DEFAULT 'Cumulative',
    is_security_update INTEGER NOT NULL DEFAULT 1,
    is_oob INTEGER NOT NULL DEFAULT 0,
    has_kir INTEGER NOT NULL DEFAULT 0,
    health_status TEXT NOT NULL DEFAULT 'UNKNOWN',
    health_rationale TEXT NOT NULL DEFAULT '',
    summary TEXT,
    highlights TEXT,
    source_url TEXT NOT NULL,
    telemetry_verified INTEGER NOT NULL DEFAULT 1,
    data_origin TEXT NOT NULL DEFAULT 'Microsoft Official',
    is_demo INTEGER NOT NULL DEFAULT 0,
    last_checked_at TEXT,
    content_hash TEXT
);

CREATE TABLE IF NOT EXISTS known_issues (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    issue_key TEXT NOT NULL UNIQUE,
    kb_number TEXT NOT NULL,
    windows_version TEXT NOT NULL,
    os_build TEXT,
    title TEXT NOT NULL,
    symptoms TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Confirmed',
    severity TEXT NOT NULL DEFAULT 'Moderate',
    is_severe_failure INTEGER NOT NULL DEFAULT 0,
    workaround TEXT,
    resolution TEXT,
    has_kir INTEGER NOT NULL DEFAULT 0,
    kir_restart_required INTEGER,
    kir_deployment_method TEXT,
    kir_guidance_url TEXT,
    kir_gpo_name TEXT,
    oob_fix_kb TEXT,
    opened_date TEXT,
    last_updated_date TEXT,
    resolved_date TEXT,
    source_url TEXT NOT NULL,
    is_demo INTEGER NOT NULL DEFAULT 0,
    content_hash TEXT,
    FOREIGN KEY (kb_number) REFERENCES kbs(kb_number) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cves (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    kb_number TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'Important',
    cvss_score REAL,
    affected_component TEXT NOT NULL,
    exploitability_status TEXT NOT NULL,
    is_exploited INTEGER NOT NULL DEFAULT 0,
    publicly_disclosed INTEGER NOT NULL DEFAULT 0,
    published_date TEXT,
    source_url TEXT NOT NULL,
    is_demo INTEGER NOT NULL DEFAULT 0,
    content_hash TEXT,
    UNIQUE(cve_id, kb_number),
    FOREIGN KEY (kb_number) REFERENCES kbs(kb_number) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS kb_relationships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kb_number TEXT NOT NULL,
    related_kb TEXT NOT NULL,
    relationship_type TEXT NOT NULL,
    issue_key TEXT,
    description TEXT,
    source_url TEXT,
    UNIQUE(kb_number, related_kb, relationship_type),
    FOREIGN KEY (kb_number) REFERENCES kbs(kb_number) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS lifecycle_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kb_number TEXT NOT NULL,
    event_date TEXT NOT NULL,
    event_type TEXT NOT NULL,
    title TEXT NOT NULL,
    details TEXT NOT NULL,
    source_url TEXT,
    UNIQUE(kb_number, event_date, event_type, title),
    FOREIGN KEY (kb_number) REFERENCES kbs(kb_number) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kb_number TEXT,
    windows_version TEXT,
    severity TEXT NOT NULL,
    alert_type TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    source_url TEXT,
    acknowledged INTEGER NOT NULL DEFAULT 0,
    acknowledged_at TEXT,
    is_demo INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS change_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    kb_number TEXT,
    field_name TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT,
    change_type TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    source_url TEXT,
    is_demo INTEGER NOT NULL DEFAULT 0,
    detected_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sync_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    trigger_type TEXT NOT NULL DEFAULT 'manual',
    status TEXT NOT NULL DEFAULT 'RUNNING',
    sources_checked INTEGER NOT NULL DEFAULT 0,
    sources_succeeded INTEGER NOT NULL DEFAULT 0,
    sources_failed INTEGER NOT NULL DEFAULT 0,
    changes_detected INTEGER NOT NULL DEFAULT 0,
    summary TEXT
);

CREATE INDEX IF NOT EXISTS idx_kbs_version ON kbs(windows_version);
CREATE INDEX IF NOT EXISTS idx_kbs_status ON kbs(health_status);
CREATE INDEX IF NOT EXISTS idx_kbs_cycle ON kbs(patch_tuesday_cycle);
CREATE INDEX IF NOT EXISTS idx_issues_kb ON known_issues(kb_number);
CREATE INDEX IF NOT EXISTS idx_cves_kb ON cves(kb_number);
CREATE INDEX IF NOT EXISTS idx_changes_kb ON change_log(kb_number);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at DESC);
"""


def init_db(db_path: Optional[Path | str] = None) -> None:
    """Create database tables and ensure default official Microsoft sources are configured."""
    with get_connection(db_path) as conn:
        conn.executescript(SCHEMA_SQL)
        for src in DEFAULT_MICROSOFT_SOURCES:
            conn.execute(
                """
                INSERT INTO sources (
                    source_key, name, source_type, windows_version, url, enabled, check_interval_minutes
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(source_key) DO NOTHING
                """,
                (
                    src["source_key"],
                    src["name"],
                    src["source_type"],
                    src["windows_version"],
                    src["url"],
                    1 if src.get("enabled", True) else 0,
                    src.get("check_interval_minutes", 240),
                ),
            )


KB_TRACKED_FIELDS = (
    "title",
    "windows_version",
    "os_build",
    "release_date",
    "update_type",
    "is_security_update",
    "is_oob",
    "has_kir",
    "health_status",
    "health_rationale",
    "telemetry_verified",
)

ISSUE_TRACKED_FIELDS = (
    "title",
    "symptoms",
    "status",
    "severity",
    "is_severe_failure",
    "workaround",
    "resolution",
    "has_kir",
    "kir_restart_required",
    "kir_deployment_method",
    "oob_fix_kb",
)

CVE_TRACKED_FIELDS = (
    "title",
    "severity",
    "cvss_score",
    "affected_component",
    "exploitability_status",
    "is_exploited",
    "publicly_disclosed",
)


def recalculate_kb_status(
    conn: sqlite3.Connection,
    kb_number: str,
    source_failed: bool = False,
    source_error_reason: Optional[str] = None,
    detected_at: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    """
    Re-evaluate a KB's operational health state based on its stored issues, relationships, CVEs, and verification state.
    Records field-level audit logs and creates alerts if the health status changes.
    """
    kb_row = conn.execute("SELECT * FROM kbs WHERE kb_number = ?", (kb_number,)).fetchone()
    if not kb_row:
        return None
    kb_dict = dict(kb_row)

    issues = [
        dict(r)
        for r in conn.execute("SELECT * FROM known_issues WHERE kb_number = ? ORDER BY id ASC", (kb_number,)).fetchall()
    ]
    rels = [
        dict(r)
        for r in conn.execute("SELECT * FROM kb_relationships WHERE kb_number = ? ORDER BY id ASC", (kb_number,)).fetchall()
    ]
    cves = [
        dict(r)
        for r in conn.execute("SELECT * FROM cves WHERE kb_number = ? ORDER BY id ASC", (kb_number,)).fetchall()
    ]

    telemetry_verified = bool(kb_dict.get("telemetry_verified", 1))
    if source_failed and not issues:
        telemetry_verified = False

    eval_res = evaluate_kb_health(
        kb_number=kb_number,
        telemetry_verified=telemetry_verified,
        source_failed=source_failed,
        is_oob=bool(kb_dict.get("is_oob")),
        known_issues=issues,
        relationships=rels,
        cves=cves,
        source_error_reason=source_error_reason,
    )

    has_kir = 1 if (eval_res.has_kir or bool(kb_dict.get("has_kir"))) else 0
    new_kb_state = dict(kb_dict)
    new_kb_state["health_status"] = eval_res.status.value
    new_kb_state["health_rationale"] = eval_res.rationale
    new_kb_state["has_kir"] = has_kir
    new_kb_state["telemetry_verified"] = 1 if telemetry_verified else 0

    now = detected_at or utc_now_iso()
    content_hash, changes = record_entity_changes(
        conn=conn,
        entity_type="KB",
        entity_id=kb_number,
        kb_number=kb_number,
        old_record=kb_dict,
        new_record=new_kb_state,
        tracked_fields=KB_TRACKED_FIELDS,
        source_url=kb_dict.get("source_url"),
        is_demo=bool(kb_dict.get("is_demo")),
        detected_at=now,
    )

    conn.execute(
        """
        UPDATE kbs
        SET health_status = ?,
            health_rationale = ?,
            has_kir = ?,
            telemetry_verified = ?,
            last_checked_at = ?,
            content_hash = ?
        WHERE kb_number = ?
        """,
        (
            eval_res.status.value,
            eval_res.rationale,
            has_kir,
            1 if telemetry_verified else 0,
            now,
            content_hash,
            kb_number,
        ),
    )

    old_status = kb_dict.get("health_status")
    if old_status and old_status != eval_res.status.value and old_status != "UNKNOWN":
        create_alert_if_not_exists(
            conn=conn,
            kb_number=kb_number,
            windows_version=kb_dict.get("windows_version"),
            severity=eval_res.status.value,
            alert_type="STATUS_CHANGE",
            title=f"{kb_number} Operational Health Changed: {old_status} -> {eval_res.status.value}",
            summary=eval_res.rationale,
            source_url=kb_dict.get("source_url"),
            is_demo=bool(kb_dict.get("is_demo")),
            created_at=now,
        )

    return {
        "kb_number": kb_number,
        "status": eval_res.status.value,
        "rationale": eval_res.rationale,
        "changes": changes,
    }


def upsert_kb(
    conn: sqlite3.Connection,
    kb_data: dict[str, Any],
    detected_at: Optional[str] = None,
) -> tuple[str, list[dict[str, Any]]]:
    """Insert or update a KB record and record field-level audit trail."""
    kb_number = kb_data["kb_number"].strip().upper()
    existing_row = conn.execute("SELECT * FROM kbs WHERE kb_number = ?", (kb_number,)).fetchone()
    existing = dict(existing_row) if existing_row else None

    release_date = kb_data.get("release_date") or (existing.get("release_date") if existing else "2026-10-13")
    cycle = kb_data.get("patch_tuesday_cycle") or derive_patch_tuesday_cycle(release_date)
    now = detected_at or kb_data.get("last_checked_at") or utc_now_iso()

    merged = {
        "kb_number": kb_number,
        "title": kb_data.get("title") or (existing.get("title") if existing else f"{kb_number} Windows Update"),
        "windows_version": kb_data.get("windows_version") or (existing.get("windows_version") if existing else "Windows 11 24H2"),
        "os_build": kb_data.get("os_build") or (existing.get("os_build") if existing else "Unknown"),
        "release_date": release_date,
        "patch_tuesday_cycle": cycle,
        "update_type": kb_data.get("update_type") or (existing.get("update_type") if existing else "Cumulative"),
        "is_security_update": 1 if kb_data.get("is_security_update", True) else 0,
        "is_oob": 1 if kb_data.get("is_oob", False) else 0,
        "has_kir": 1 if kb_data.get("has_kir", existing.get("has_kir", 0) if existing else 0) else 0,
        "health_status": kb_data.get("health_status") or (existing.get("health_status") if existing else "UNKNOWN"),
        "health_rationale": kb_data.get("health_rationale") or (existing.get("health_rationale") if existing else ""),
        "summary": kb_data.get("summary") or (existing.get("summary") if existing else None),
        "highlights": kb_data.get("highlights") or (existing.get("highlights") if existing else None),
        "source_url": kb_data.get("source_url") or (existing.get("source_url") if existing else "https://learn.microsoft.com/en-us/windows/release-health/"),
        "telemetry_verified": 1 if kb_data.get("telemetry_verified", True) else 0,
        "data_origin": kb_data.get("data_origin") or (existing.get("data_origin") if existing else "Microsoft Official"),
        "is_demo": 1 if kb_data.get("is_demo", False) else 0,
        "last_checked_at": now,
    }

    content_hash, changes = record_entity_changes(
        conn=conn,
        entity_type="KB",
        entity_id=kb_number,
        kb_number=kb_number,
        old_record=existing,
        new_record=merged,
        tracked_fields=KB_TRACKED_FIELDS,
        source_url=merged["source_url"],
        is_demo=bool(merged["is_demo"]),
        detected_at=now,
    )

    if existing is None:
        conn.execute(
            """
            INSERT INTO kbs (
                kb_number, title, windows_version, os_build, release_date,
                patch_tuesday_cycle, update_type, is_security_update, is_oob, has_kir,
                health_status, health_rationale, summary, highlights, source_url,
                telemetry_verified, data_origin, is_demo, last_checked_at, content_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                merged["kb_number"],
                merged["title"],
                merged["windows_version"],
                merged["os_build"],
                merged["release_date"],
                merged["patch_tuesday_cycle"],
                merged["update_type"],
                merged["is_security_update"],
                merged["is_oob"],
                merged["has_kir"],
                merged["health_status"],
                merged["health_rationale"],
                merged["summary"],
                merged["highlights"],
                merged["source_url"],
                merged["telemetry_verified"],
                merged["data_origin"],
                merged["is_demo"],
                merged["last_checked_at"],
                content_hash,
            ),
        )
    else:
        conn.execute(
            """
            UPDATE kbs SET
                title = ?, windows_version = ?, os_build = ?, release_date = ?,
                patch_tuesday_cycle = ?, update_type = ?, is_security_update = ?,
                is_oob = ?, has_kir = ?, health_status = ?, health_rationale = ?,
                summary = ?, highlights = ?, source_url = ?, telemetry_verified = ?,
                data_origin = ?, is_demo = ?, last_checked_at = ?, content_hash = ?
            WHERE kb_number = ?
            """,
            (
                merged["title"],
                merged["windows_version"],
                merged["os_build"],
                merged["release_date"],
                merged["patch_tuesday_cycle"],
                merged["update_type"],
                merged["is_security_update"],
                merged["is_oob"],
                merged["has_kir"],
                merged["health_status"],
                merged["health_rationale"],
                merged["summary"],
                merged["highlights"],
                merged["source_url"],
                merged["telemetry_verified"],
                merged["data_origin"],
                merged["is_demo"],
                merged["last_checked_at"],
                content_hash,
                merged["kb_number"],
            ),
        )

    return content_hash, changes


def upsert_known_issue(
    conn: sqlite3.Connection,
    issue_data: dict[str, Any],
    detected_at: Optional[str] = None,
) -> tuple[str, list[dict[str, Any]]]:
    """Insert or update a Known Issue record and record field-level audit trail."""
    issue_key = issue_data["issue_key"].strip()
    kb_number = issue_data["kb_number"].strip().upper()
    existing_row = conn.execute("SELECT * FROM known_issues WHERE issue_key = ?", (issue_key,)).fetchone()
    existing = dict(existing_row) if existing_row else None
    now = detected_at or utc_now_iso()

    merged = {
        "issue_key": issue_key,
        "kb_number": kb_number,
        "windows_version": issue_data.get("windows_version") or (existing.get("windows_version") if existing else "Windows 11 24H2"),
        "os_build": issue_data.get("os_build") or (existing.get("os_build") if existing else None),
        "title": issue_data["title"],
        "symptoms": issue_data.get("symptoms") or issue_data["title"],
        "status": issue_data.get("status", "Confirmed"),
        "severity": issue_data.get("severity", "Moderate"),
        "is_severe_failure": 1 if issue_data.get("is_severe_failure", False) else 0,
        "workaround": issue_data.get("workaround"),
        "resolution": issue_data.get("resolution"),
        "has_kir": 1 if issue_data.get("has_kir", False) else 0,
        "kir_restart_required": (
            1 if issue_data.get("kir_restart_required") is True
            else (0 if issue_data.get("kir_restart_required") is False else None)
        ),
        "kir_deployment_method": issue_data.get("kir_deployment_method"),
        "kir_guidance_url": issue_data.get("kir_guidance_url"),
        "kir_gpo_name": issue_data.get("kir_gpo_name"),
        "oob_fix_kb": issue_data.get("oob_fix_kb"),
        "opened_date": issue_data.get("opened_date"),
        "last_updated_date": issue_data.get("last_updated_date") or now[:10],
        "resolved_date": issue_data.get("resolved_date"),
        "source_url": issue_data.get("source_url", "https://learn.microsoft.com/en-us/windows/release-health/"),
        "is_demo": 1 if issue_data.get("is_demo", False) else 0,
    }

    content_hash, changes = record_entity_changes(
        conn=conn,
        entity_type="KNOWN_ISSUE",
        entity_id=issue_key,
        kb_number=kb_number,
        old_record=existing,
        new_record=merged,
        tracked_fields=ISSUE_TRACKED_FIELDS,
        source_url=merged["source_url"],
        is_demo=bool(merged["is_demo"]),
        detected_at=now,
    )

    if existing is None:
        conn.execute(
            """
            INSERT INTO known_issues (
                issue_key, kb_number, windows_version, os_build, title, symptoms,
                status, severity, is_severe_failure, workaround, resolution,
                has_kir, kir_restart_required, kir_deployment_method, kir_guidance_url,
                kir_gpo_name, oob_fix_kb, opened_date, last_updated_date, resolved_date,
                source_url, is_demo, content_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                merged["issue_key"],
                merged["kb_number"],
                merged["windows_version"],
                merged["os_build"],
                merged["title"],
                merged["symptoms"],
                merged["status"],
                merged["severity"],
                merged["is_severe_failure"],
                merged["workaround"],
                merged["resolution"],
                merged["has_kir"],
                merged["kir_restart_required"],
                merged["kir_deployment_method"],
                merged["kir_guidance_url"],
                merged["kir_gpo_name"],
                merged["oob_fix_kb"],
                merged["opened_date"],
                merged["last_updated_date"],
                merged["resolved_date"],
                merged["source_url"],
                merged["is_demo"],
                content_hash,
            ),
        )
    else:
        conn.execute(
            """
            UPDATE known_issues SET
                kb_number = ?, windows_version = ?, os_build = ?, title = ?, symptoms = ?,
                status = ?, severity = ?, is_severe_failure = ?, workaround = ?, resolution = ?,
                has_kir = ?, kir_restart_required = ?, kir_deployment_method = ?, kir_guidance_url = ?,
                kir_gpo_name = ?, oob_fix_kb = ?, opened_date = ?, last_updated_date = ?,
                resolved_date = ?, source_url = ?, is_demo = ?, content_hash = ?
            WHERE issue_key = ?
            """,
            (
                merged["kb_number"],
                merged["windows_version"],
                merged["os_build"],
                merged["title"],
                merged["symptoms"],
                merged["status"],
                merged["severity"],
                merged["is_severe_failure"],
                merged["workaround"],
                merged["resolution"],
                merged["has_kir"],
                merged["kir_restart_required"],
                merged["kir_deployment_method"],
                merged["kir_guidance_url"],
                merged["kir_gpo_name"],
                merged["oob_fix_kb"],
                merged["opened_date"],
                merged["last_updated_date"],
                merged["resolved_date"],
                merged["source_url"],
                merged["is_demo"],
                content_hash,
                merged["issue_key"],
            ),
        )

    # If OOB fix KB is specified on the issue, ensure relationship is linked
    if merged["oob_fix_kb"]:
        add_kb_relationship(
            conn=conn,
            kb_number=kb_number,
            related_kb=merged["oob_fix_kb"],
            relationship_type="oob_replaced_by",
            issue_key=issue_key,
            description=f"Out-of-Band update {merged['oob_fix_kb']} resolves regression '{merged['title']}' in {kb_number}.",
            source_url=merged["source_url"],
        )

    return content_hash, changes


def upsert_cve(
    conn: sqlite3.Connection,
    cve_data: dict[str, Any],
    detected_at: Optional[str] = None,
) -> tuple[str, list[dict[str, Any]]]:
    """Insert or update a CVE-to-KB mapping and record field-level audit trail."""
    cve_id = cve_data["cve_id"].strip().upper()
    kb_number = cve_data["kb_number"].strip().upper()
    existing_row = conn.execute(
        "SELECT * FROM cves WHERE cve_id = ? AND kb_number = ?", (cve_id, kb_number)
    ).fetchone()
    existing = dict(existing_row) if existing_row else None
    now = detected_at or utc_now_iso()

    merged = {
        "cve_id": cve_id,
        "kb_number": kb_number,
        "title": cve_data["title"],
        "severity": cve_data.get("severity", "Important"),
        "cvss_score": cve_data.get("cvss_score"),
        "affected_component": cve_data.get("affected_component", "Microsoft Windows"),
        "exploitability_status": cve_data.get("exploitability_status", "Exploitation Less Likely"),
        "is_exploited": 1 if cve_data.get("is_exploited", False) else 0,
        "publicly_disclosed": 1 if cve_data.get("publicly_disclosed", False) else 0,
        "published_date": cve_data.get("published_date"),
        "source_url": cve_data.get("source_url", f"https://msrc.microsoft.com/update-guide/vulnerability/{cve_id}"),
        "is_demo": 1 if cve_data.get("is_demo", False) else 0,
    }

    content_hash, changes = record_entity_changes(
        conn=conn,
        entity_type="CVE",
        entity_id=f"{cve_id}:{kb_number}",
        kb_number=kb_number,
        old_record=existing,
        new_record=merged,
        tracked_fields=CVE_TRACKED_FIELDS,
        source_url=merged["source_url"],
        is_demo=bool(merged["is_demo"]),
        detected_at=now,
    )

    if existing is None:
        conn.execute(
            """
            INSERT INTO cves (
                cve_id, kb_number, title, severity, cvss_score, affected_component,
                exploitability_status, is_exploited, publicly_disclosed, published_date,
                source_url, is_demo, content_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                merged["cve_id"],
                merged["kb_number"],
                merged["title"],
                merged["severity"],
                merged["cvss_score"],
                merged["affected_component"],
                merged["exploitability_status"],
                merged["is_exploited"],
                merged["publicly_disclosed"],
                merged["published_date"],
                merged["source_url"],
                merged["is_demo"],
                content_hash,
            ),
        )
    else:
        conn.execute(
            """
            UPDATE cves SET
                title = ?, severity = ?, cvss_score = ?, affected_component = ?,
                exploitability_status = ?, is_exploited = ?, publicly_disclosed = ?,
                published_date = ?, source_url = ?, is_demo = ?, content_hash = ?
            WHERE cve_id = ? AND kb_number = ?
            """,
            (
                merged["title"],
                merged["severity"],
                merged["cvss_score"],
                merged["affected_component"],
                merged["exploitability_status"],
                merged["is_exploited"],
                merged["publicly_disclosed"],
                merged["published_date"],
                merged["source_url"],
                merged["is_demo"],
                content_hash,
                merged["cve_id"],
                merged["kb_number"],
            ),
        )

    return content_hash, changes


def add_kb_relationship(
    conn: sqlite3.Connection,
    kb_number: str,
    related_kb: str,
    relationship_type: str,
    issue_key: Optional[str] = None,
    description: Optional[str] = None,
    source_url: Optional[str] = None,
) -> None:
    """Add a relationship between two KBs (e.g. supersedes, superseded_by, oob_replaces, oob_replaced_by)."""
    kb_a = kb_number.strip().upper()
    kb_b = related_kb.strip().upper()
    conn.execute(
        """
        INSERT INTO kb_relationships (kb_number, related_kb, relationship_type, issue_key, description, source_url)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(kb_number, related_kb, relationship_type) DO UPDATE SET
            issue_key = COALESCE(excluded.issue_key, kb_relationships.issue_key),
            description = COALESCE(excluded.description, kb_relationships.description),
            source_url = COALESCE(excluded.source_url, kb_relationships.source_url)
        """,
        (kb_a, kb_b, relationship_type, issue_key, description, source_url),
    )


def add_lifecycle_event(
    conn: sqlite3.Connection,
    kb_number: str,
    event_date: str,
    event_type: str,
    title: str,
    details: str,
    source_url: Optional[str] = None,
) -> None:
    """Record a chronological lifecycle event for a KB."""
    conn.execute(
        """
        INSERT INTO lifecycle_events (kb_number, event_date, event_type, title, details, source_url)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(kb_number, event_date, event_type, title) DO UPDATE SET
            details = excluded.details,
            source_url = COALESCE(excluded.source_url, lifecycle_events.source_url)
        """,
        (kb_number.strip().upper(), event_date, event_type, title, details, source_url),
    )


def create_alert_if_not_exists(
    conn: sqlite3.Connection,
    kb_number: Optional[str],
    windows_version: Optional[str],
    severity: str,
    alert_type: str,
    title: str,
    summary: str,
    source_url: Optional[str] = None,
    is_demo: bool = False,
    created_at: Optional[str] = None,
) -> int:
    """Insert an operational alert if an identical title does not already exist."""
    existing = conn.execute(
        "SELECT id FROM alerts WHERE title = ? AND COALESCE(kb_number, '') = COALESCE(?, '')",
        (title, kb_number),
    ).fetchone()
    if existing:
        return int(existing["id"])
    now = created_at or utc_now_iso()
    cur = conn.execute(
        """
        INSERT INTO alerts (
            kb_number, windows_version, severity, alert_type, title, summary,
            source_url, acknowledged, is_demo, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
        """,
        (
            kb_number,
            windows_version,
            severity,
            alert_type,
            title,
            summary,
            source_url,
            1 if is_demo else 0,
            now,
        ),
    )
    return int(cur.lastrowid or 0)


def _enrich_kb_summary(conn: sqlite3.Connection, row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    """Build a complete KBSummary dict with relationship lists and issue/CVE counts."""
    kb = dict(row)
    kb_num = kb["kb_number"]

    issue_rows = conn.execute(
        "SELECT status, has_kir FROM known_issues WHERE kb_number = ?", (kb_num,)
    ).fetchall()
    total_issues = len(issue_rows)
    active_issues = sum(
        1 for r in issue_rows if (r["status"] or "").lower() not in ("resolved", "mitigated")
    )
    has_kir_from_issues = any(bool(r["has_kir"]) for r in issue_rows)

    cve_rows = conn.execute(
        "SELECT is_exploited FROM cves WHERE kb_number = ?", (kb_num,)
    ).fetchall()
    cve_count = len(cve_rows)
    exploited_cve_count = sum(1 for r in cve_rows if bool(r["is_exploited"]))

    rel_rows = conn.execute(
        "SELECT related_kb, relationship_type FROM kb_relationships WHERE kb_number = ?", (kb_num,)
    ).fetchall()

    supersedes_kbs: list[str] = []
    superseded_by_kbs: list[str] = []
    oob_replaces_kbs: list[str] = []
    oob_replaced_by_kbs: list[str] = []

    for r in rel_rows:
        rtype = r["relationship_type"]
        rel_kb = r["related_kb"]
        if rtype == "supersedes" and rel_kb not in supersedes_kbs:
            supersedes_kbs.append(rel_kb)
        elif rtype == "superseded_by" and rel_kb not in superseded_by_kbs:
            superseded_by_kbs.append(rel_kb)
        elif rtype == "oob_replaces" and rel_kb not in oob_replaces_kbs:
            oob_replaces_kbs.append(rel_kb)
            if rel_kb not in supersedes_kbs:
                supersedes_kbs.append(rel_kb)
        elif rtype == "oob_replaced_by" and rel_kb not in oob_replaced_by_kbs:
            oob_replaced_by_kbs.append(rel_kb)
            if rel_kb not in superseded_by_kbs:
                superseded_by_kbs.append(rel_kb)

    return {
        "kb_number": kb_num,
        "title": kb["title"],
        "windows_version": kb["windows_version"],
        "os_build": kb["os_build"],
        "release_date": kb["release_date"],
        "patch_tuesday_cycle": kb["patch_tuesday_cycle"],
        "update_type": kb["update_type"],
        "is_security_update": bool(kb["is_security_update"]),
        "is_oob": bool(kb["is_oob"]),
        "has_kir": bool(kb["has_kir"]) or has_kir_from_issues,
        "health_status": kb["health_status"],
        "health_rationale": kb["health_rationale"],
        "known_issues_count": total_issues,
        "active_issues_count": active_issues,
        "cve_count": cve_count,
        "exploited_cve_count": exploited_cve_count,
        "supersedes_kbs": supersedes_kbs,
        "superseded_by_kbs": superseded_by_kbs,
        "oob_replaces_kbs": oob_replaces_kbs,
        "oob_replaced_by_kbs": oob_replaced_by_kbs,
        "source_url": kb["source_url"],
        "telemetry_verified": bool(kb["telemetry_verified"]),
        "data_origin": kb["data_origin"],
        "is_demo": bool(kb["is_demo"]),
        "last_checked_at": kb["last_checked_at"],
        "content_hash": kb["content_hash"],
    }


def query_kbs(
    conn: sqlite3.Connection,
    q: Optional[str] = None,
    windows_version: Optional[str] = None,
    status: Optional[str] = None,
    update_type: Optional[str] = None,
    is_oob: Optional[bool] = None,
    has_kir: Optional[bool] = None,
    has_known_issues: Optional[bool] = None,
    security_only: Optional[bool] = None,
    patch_tuesday_cycle: Optional[str] = None,
    sort_by: str = "release_date",
    sort_order: str = "desc",
    page: int = 1,
    page_size: int = 25,
) -> dict[str, Any]:
    """Query KBs with comprehensive filtering, sorting, and pagination."""
    where_clauses: list[str] = []
    params: list[Any] = []

    if q and q.strip():
        term = f"%{q.strip()}%"
        where_clauses.append(
            """(
                kbs.kb_number LIKE ?
                OR kbs.title LIKE ?
                OR kbs.os_build LIKE ?
                OR kbs.windows_version LIKE ?
                OR kbs.health_rationale LIKE ?
                OR EXISTS (
                    SELECT 1 FROM known_issues ki
                    WHERE ki.kb_number = kbs.kb_number
                    AND (ki.title LIKE ? OR ki.symptoms LIKE ?)
                )
                OR EXISTS (
                    SELECT 1 FROM cves c
                    WHERE c.kb_number = kbs.kb_number
                    AND (c.cve_id LIKE ? OR c.title LIKE ? OR c.affected_component LIKE ?)
                )
            )"""
        )
        params.extend([term] * 10)

    if windows_version and windows_version.lower() != "all":
        where_clauses.append("kbs.windows_version = ?")
        params.append(windows_version)

    if status and status.upper() != "ALL":
        where_clauses.append("kbs.health_status = ?")
        params.append(status.upper())

    if update_type and update_type.lower() != "all":
        where_clauses.append("LOWER(kbs.update_type) = LOWER(?)")
        params.append(update_type)

    if is_oob is not None:
        where_clauses.append("kbs.is_oob = ?")
        params.append(1 if is_oob else 0)

    if has_kir is not None:
        if has_kir:
            where_clauses.append(
                "(kbs.has_kir = 1 OR EXISTS (SELECT 1 FROM known_issues ki WHERE ki.kb_number = kbs.kb_number AND ki.has_kir = 1))"
            )
        else:
            where_clauses.append(
                "(kbs.has_kir = 0 AND NOT EXISTS (SELECT 1 FROM known_issues ki WHERE ki.kb_number = kbs.kb_number AND ki.has_kir = 1))"
            )

    if has_known_issues is not None:
        if has_known_issues:
            where_clauses.append("EXISTS (SELECT 1 FROM known_issues ki WHERE ki.kb_number = kbs.kb_number)")
        else:
            where_clauses.append("NOT EXISTS (SELECT 1 FROM known_issues ki WHERE ki.kb_number = kbs.kb_number)")

    if security_only is not None:
        if security_only:
            where_clauses.append("(kbs.is_security_update = 1)")
        else:
            where_clauses.append("(kbs.is_security_update = 0)")

    # Distinct cycles and versions for filter dropdowns (most recent cycle first)
    cycles = [
        r["patch_tuesday_cycle"]
        for r in conn.execute("SELECT DISTINCT patch_tuesday_cycle FROM kbs ORDER BY patch_tuesday_cycle DESC").fetchall()
    ]
    versions = [
        r["windows_version"]
        for r in conn.execute("SELECT DISTINCT windows_version FROM kbs ORDER BY windows_version DESC").fetchall()
    ]

    effective_cycle = patch_tuesday_cycle
    if effective_cycle and effective_cycle.lower() == "latest":
        effective_cycle = cycles[0] if cycles else "all"

    if effective_cycle and effective_cycle.lower() != "all":
        where_clauses.append("kbs.patch_tuesday_cycle = ?")
        params.append(effective_cycle)

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    # Count total matching rows
    count_row = conn.execute(f"SELECT COUNT(*) AS cnt FROM kbs {where_sql}", params).fetchone()
    total = int(count_row["cnt"]) if count_row else 0

    # Safe sort mapping
    status_priority_expr = (
        "CASE kbs.health_status "
        "WHEN 'AFFECTED' THEN 1 "
        "WHEN 'CAUTION' THEN 2 "
        "WHEN 'MONITOR' THEN 3 "
        "WHEN 'UNKNOWN' THEN 4 "
        "WHEN 'SAFE' THEN 5 "
        "ELSE 6 END"
    )
    issue_count_expr = "(SELECT COUNT(*) FROM known_issues ki WHERE ki.kb_number = kbs.kb_number)"
    cve_count_expr = "(SELECT COUNT(*) FROM cves c WHERE c.kb_number = kbs.kb_number)"

    sort_map = {
        "release_date": "kbs.release_date",
        "kb_number": "kbs.kb_number",
        "windows_version": "kbs.windows_version",
        "health_status": status_priority_expr,
        "known_issues_count": issue_count_expr,
        "cve_count": cve_count_expr,
        "last_checked_at": "kbs.last_checked_at",
    }
    order_col = sort_map.get(sort_by, "kbs.release_date")
    direction = "ASC" if sort_order.lower() == "asc" else "DESC"

    page = max(1, page)
    page_size = max(1, min(200, page_size))
    offset = (page - 1) * page_size

    rows = conn.execute(
        f"""
        SELECT kbs.* FROM kbs
        {where_sql}
        ORDER BY {order_col} {direction}, kbs.kb_number DESC
        LIMIT ? OFFSET ?
        """,
        [*params, page_size, offset],
    ).fetchall()

    items = [_enrich_kb_summary(conn, r) for r in rows]

    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": max(1, (total + page_size - 1) // page_size),
        "available_cycles": cycles,
        "selected_cycle": effective_cycle or "all",
        "available_versions": versions,
    }


def get_kb_dossier(conn: sqlite3.Connection, kb_number: str) -> Optional[dict[str, Any]]:
    """Retrieve the complete dossier for a specific KB number."""
    norm_kb = kb_number.strip().upper()
    if not norm_kb.startswith("KB"):
        norm_kb = f"KB{norm_kb}"

    row = conn.execute("SELECT * FROM kbs WHERE UPPER(kb_number) = ?", (norm_kb,)).fetchone()
    if not row:
        return None

    summary = _enrich_kb_summary(conn, row)
    kb_dict = dict(row)

    issues_raw = conn.execute(
        "SELECT * FROM known_issues WHERE kb_number = ? ORDER BY is_severe_failure DESC, id ASC",
        (norm_kb,),
    ).fetchall()
    issues = []
    for ir in issues_raw:
        d = dict(ir)
        d["is_severe_failure"] = bool(d["is_severe_failure"])
        d["has_kir"] = bool(d["has_kir"])
        if d["kir_restart_required"] is not None:
            d["kir_restart_required"] = bool(d["kir_restart_required"])
        issues.append(d)

    cves_raw = conn.execute(
        "SELECT * FROM cves WHERE kb_number = ? ORDER BY is_exploited DESC, cvss_score DESC, cve_id ASC",
        (norm_kb,),
    ).fetchall()
    cves = []
    for cr in cves_raw:
        d = dict(cr)
        d["is_exploited"] = bool(d["is_exploited"])
        d["publicly_disclosed"] = bool(d["publicly_disclosed"])
        cves.append(d)

    rels = [
        dict(r)
        for r in conn.execute(
            "SELECT * FROM kb_relationships WHERE kb_number = ? ORDER BY id ASC", (norm_kb,)
        ).fetchall()
    ]

    lifecycle = [
        dict(r)
        for r in conn.execute(
            "SELECT * FROM lifecycle_events WHERE kb_number = ? ORDER BY event_date ASC, id ASC",
            (norm_kb,),
        ).fetchall()
    ]

    changes_raw = conn.execute(
        "SELECT * FROM change_log WHERE kb_number = ? ORDER BY detected_at DESC, id DESC LIMIT 50",
        (norm_kb,),
    ).fetchall()
    changes = []
    for ch in changes_raw:
        d = dict(ch)
        d["is_demo"] = bool(d["is_demo"])
        changes.append(d)

    eval_res = evaluate_kb_health(
        kb_number=norm_kb,
        telemetry_verified=bool(kb_dict.get("telemetry_verified", 1)),
        is_oob=bool(kb_dict.get("is_oob")),
        known_issues=issues,
        relationships=rels,
        cves=cves,
    )

    return {
        **summary,
        "summary": kb_dict.get("summary"),
        "highlights": kb_dict.get("highlights"),
        "known_issues": issues,
        "cves": cves,
        "relationships": rels,
        "lifecycle": lifecycle,
        "changes": changes,
        "risk_factors": eval_res.factors,
    }


def get_dashboard_stats(
    conn: sqlite3.Connection,
    patch_tuesday_cycle: Optional[str] = None,
) -> dict[str, Any]:
    """Compute operational status counts, version health matrix, advisory banner, and latest alerts (optionally scoped to a Patch Tuesday cycle)."""
    cycles = [
        r["patch_tuesday_cycle"]
        for r in conn.execute("SELECT DISTINCT patch_tuesday_cycle FROM kbs ORDER BY patch_tuesday_cycle DESC").fetchall()
    ]
    effective_cycle = patch_tuesday_cycle
    if effective_cycle and effective_cycle.lower() == "latest":
        effective_cycle = cycles[0] if cycles else "all"

    cycle_where = ""
    cycle_params: list[Any] = []
    if effective_cycle and effective_cycle.lower() != "all":
        cycle_where = "WHERE patch_tuesday_cycle = ?"
        cycle_params = [effective_cycle]

    counts = {
        HealthState.SAFE.value: 0,
        HealthState.MONITOR.value: 0,
        HealthState.CAUTION.value: 0,
        HealthState.AFFECTED.value: 0,
        HealthState.UNKNOWN.value: 0,
    }
    for r in conn.execute(
        f"SELECT health_status, COUNT(*) AS cnt FROM kbs {cycle_where} GROUP BY health_status",
        cycle_params,
    ).fetchall():
        st = r["health_status"]
        if st in counts:
            counts[st] = int(r["cnt"])

    total_kbs = sum(counts.values())
    oob_where = f"{cycle_where} AND is_oob = 1" if cycle_where else "WHERE is_oob = 1"
    oob_count = int(conn.execute(f"SELECT COUNT(*) FROM kbs {oob_where}", cycle_params).fetchone()[0])

    if cycle_where:
        kir_count = int(
            conn.execute(
                """
                SELECT COUNT(DISTINCT ki.kb_number)
                FROM known_issues ki
                JOIN kbs k ON k.kb_number = ki.kb_number
                WHERE k.patch_tuesday_cycle = ? AND ki.has_kir = 1 AND LOWER(ki.status) != 'resolved'
                """,
                cycle_params,
            ).fetchone()[0]
        )
        active_issues_count = int(
            conn.execute(
                """
                SELECT COUNT(*)
                FROM known_issues ki
                JOIN kbs k ON k.kb_number = ki.kb_number
                WHERE k.patch_tuesday_cycle = ? AND LOWER(ki.status) NOT IN ('resolved')
                """,
                cycle_params,
            ).fetchone()[0]
        )
    else:
        kir_count = int(
            conn.execute(
                "SELECT COUNT(DISTINCT kb_number) FROM known_issues WHERE has_kir = 1 AND LOWER(status) != 'resolved'"
            ).fetchone()[0]
        )
        active_issues_count = int(
            conn.execute("SELECT COUNT(*) FROM known_issues WHERE LOWER(status) NOT IN ('resolved')").fetchone()[0]
        )

    total_cves_count = int(conn.execute("SELECT COUNT(DISTINCT cve_id) FROM cves").fetchone()[0])
    exploited_cves_count = int(
        conn.execute("SELECT COUNT(DISTINCT cve_id) FROM cves WHERE is_exploited = 1").fetchone()[0]
    )
    unacked_alerts_count = int(conn.execute("SELECT COUNT(*) FROM alerts WHERE acknowledged = 0").fetchone()[0])

    # Per-Windows-version health summary (scoped to cycle if specified, showing all supported branches)
    all_versions = [
        r["windows_version"]
        for r in conn.execute("SELECT DISTINCT windows_version FROM kbs ORDER BY windows_version DESC").fetchall()
    ]

    version_health: list[dict[str, Any]] = []
    for win_ver in all_versions:
        v_params: list[Any] = [win_ver]
        v_cycle_clause = ""
        if effective_cycle and effective_cycle.lower() != "all":
            v_cycle_clause = "AND patch_tuesday_cycle = ?"
            v_params.append(effective_cycle)

        vr = conn.execute(
            f"""
            SELECT
                COUNT(*) AS total_kbs,
                COALESCE(SUM(CASE WHEN health_status = 'SAFE' THEN 1 ELSE 0 END), 0) AS safe_count,
                COALESCE(SUM(CASE WHEN health_status = 'MONITOR' THEN 1 ELSE 0 END), 0) AS monitor_count,
                COALESCE(SUM(CASE WHEN health_status = 'CAUTION' THEN 1 ELSE 0 END), 0) AS caution_count,
                COALESCE(SUM(CASE WHEN health_status = 'AFFECTED' THEN 1 ELSE 0 END), 0) AS affected_count,
                COALESCE(SUM(CASE WHEN health_status = 'UNKNOWN' THEN 1 ELSE 0 END), 0) AS unknown_count,
                COALESCE(SUM(CASE WHEN is_oob = 1 THEN 1 ELSE 0 END), 0) AS oob_count,
                COALESCE(SUM(CASE WHEN has_kir = 1 THEN 1 ELSE 0 END), 0) AS kir_count,
                MAX(release_date) AS latest_release_date
            FROM kbs
            WHERE windows_version = ? {v_cycle_clause}
            """,
            v_params,
        ).fetchone()
        v_dict = dict(vr)
        v_dict["windows_version"] = win_ver

        if v_dict["total_kbs"] == 0:
            continue

        if v_dict["affected_count"] > 0:
            overall = HealthState.AFFECTED.value
        elif v_dict["caution_count"] > 0:
            overall = HealthState.CAUTION.value
        elif v_dict["monitor_count"] > 0:
            overall = HealthState.MONITOR.value
        elif v_dict["unknown_count"] > 0 and v_dict["safe_count"] == 0:
            overall = HealthState.UNKNOWN.value
        else:
            overall = HealthState.SAFE.value

        latest_kb_row = conn.execute(
            f"SELECT kb_number, os_build, health_status FROM kbs WHERE windows_version = ? {v_cycle_clause} ORDER BY release_date DESC, kb_number DESC LIMIT 1",
            v_params,
        ).fetchone()

        active_iss = int(
            conn.execute(
                f"""
                SELECT COUNT(*)
                FROM known_issues ki
                JOIN kbs k ON k.kb_number = ki.kb_number
                WHERE k.windows_version = ? {v_cycle_clause} AND LOWER(ki.status) != 'resolved'
                """,
                v_params,
            ).fetchone()[0]
        )

        version_health.append(
            {
                **v_dict,
                "overall_status": overall,
                "latest_kb": latest_kb_row["kb_number"] if latest_kb_row else None,
                "latest_build": latest_kb_row["os_build"] if latest_kb_row else None,
                "active_issues": active_iss,
            }
        )

    # Latest alerts
    alerts_raw = conn.execute("SELECT * FROM alerts ORDER BY created_at DESC, id DESC LIMIT 10").fetchall()
    latest_alerts = []
    for ar in alerts_raw:
        d = dict(ar)
        d["acknowledged"] = bool(d["acknowledged"])
        d["is_demo"] = bool(d["is_demo"])
        latest_alerts.append(d)

    # Source health overview
    sources_raw = conn.execute("SELECT * FROM sources ORDER BY id ASC").fetchall()
    sources_ok = sum(1 for s in sources_raw if s["last_status"] == "OK")
    sources_err = sum(1 for s in sources_raw if s["last_status"] == "ERROR")
    last_sync_row = conn.execute("SELECT MAX(last_checked_at) AS last_check FROM sources").fetchone()
    last_checked_at = last_sync_row["last_check"] if last_sync_row else None
    if not last_checked_at:
        run_row = conn.execute("SELECT MAX(finished_at) AS last_fin FROM sync_runs").fetchone()
        last_checked_at = run_row["last_fin"] if run_row else None
    if not last_checked_at:
        kb_row = conn.execute("SELECT MAX(last_checked_at) AS last_kb FROM kbs").fetchone()
        last_checked_at = kb_row["last_kb"] if kb_row else None

    total_all_kbs = int(conn.execute("SELECT COUNT(*) FROM kbs").fetchone()[0])
    demo_count = int(conn.execute("SELECT COUNT(*) FROM kbs WHERE is_demo = 1").fetchone()[0])
    live_count = total_all_kbs - demo_count

    # Build actionable advisory items (KBs in AFFECTED or CAUTION within the selected cycle)
    advisory_kbs_where = (
        f"{cycle_where} AND health_status IN ('AFFECTED', 'CAUTION')"
        if cycle_where
        else "WHERE health_status IN ('AFFECTED', 'CAUTION')"
    )
    adv_kb_rows = conn.execute(
        f"""
        SELECT * FROM kbs
        {advisory_kbs_where}
        ORDER BY CASE health_status WHEN 'AFFECTED' THEN 1 ELSE 2 END, release_date DESC
        """,
        cycle_params,
    ).fetchall()

    advisory_items: list[dict[str, Any]] = []
    for akb in adv_kb_rows:
        enriched = _enrich_kb_summary(conn, akb)
        kb_num = enriched["kb_number"]
        kirs_rows = conn.execute(
            """
            SELECT title, status, severity, has_kir, kir_gpo_name, kir_deployment_method, kir_restart_required, kir_guidance_url, oob_fix_kb, source_url
            FROM known_issues
            WHERE kb_number = ?
            ORDER BY is_severe_failure DESC, id ASC
            """,
            (kb_num,),
        ).fetchall()
        kir_list = []
        issue_summaries = []
        for kr in kirs_rows:
            issue_summaries.append(
                {
                    "title": kr["title"],
                    "status": kr["status"],
                    "severity": kr["severity"],
                    "oob_fix_kb": kr["oob_fix_kb"],
                    "source_url": kr["source_url"],
                }
            )
            if kr["has_kir"]:
                kir_list.append(
                    {
                        "issue_title": kr["title"],
                        "kir_gpo_name": kr["kir_gpo_name"],
                        "kir_deployment_method": kr["kir_deployment_method"],
                        "kir_restart_required": bool(kr["kir_restart_required"]) if kr["kir_restart_required"] is not None else True,
                        "kir_guidance_url": kr["kir_guidance_url"] or kr["source_url"],
                    }
                )
        advisory_items.append(
            {
                "kb_number": kb_num,
                "windows_version": enriched["windows_version"],
                "os_build": enriched["os_build"],
                "health_status": enriched["health_status"],
                "rationale": enriched["health_rationale"],
                "is_oob": enriched["is_oob"],
                "oob_replaced_by_kbs": enriched["oob_replaced_by_kbs"],
                "oob_replaces_kbs": enriched["oob_replaces_kbs"],
                "source_url": enriched["source_url"],
                "kirs": kir_list,
                "issues": issue_summaries,
            }
        )

    cycle_label = effective_cycle if (effective_cycle and effective_cycle.lower() != "all") else "All Cycles"

    # Operational Advisory Banner
    if counts["AFFECTED"] > 0:
        affected_kbs = [item["kb_number"] for item in advisory_items if item["health_status"] == "AFFECTED"]
        advisory_level = "AFFECTED"
        advisory_headline = (
            f"CRITICAL DEPLOYMENT ADVISORY ({cycle_label}): {counts['AFFECTED']} Windows Update(s) ({', '.join(affected_kbs)}) "
            "have confirmed severe regressions or Out-of-Band (OOB) replacements."
        )
        advisory_detail = (
            f"Pause broad deployment of {', '.join(affected_kbs)}. Click any KB, OOB replacement, or Known Issue Rollback (KIR) link below to inspect the deployment rationale and mitigation policy."
        )
    elif counts["CAUTION"] > 0:
        caution_kbs = [item["kb_number"] for item in advisory_items if item["health_status"] == "CAUTION"]
        advisory_level = "CAUTION"
        advisory_headline = (
            f"OPERATIONAL CAUTION ({cycle_label}): {counts['CAUTION']} update(s) ({', '.join(caution_kbs)}) have active Microsoft Known Issues or OOB applicability constraints."
        )
        advisory_detail = "Click the KB or KIR policy links below to verify environment exposure and Group Policy requirements prior to enterprise rollout."
    elif counts["UNKNOWN"] == total_kbs and total_kbs > 0:
        advisory_level = "UNKNOWN"
        advisory_headline = f"TELEMETRY UNVERIFIED ({cycle_label}): Official Microsoft Release Health sources have not been verified."
        advisory_detail = "Automated GitHub Action synchronization runs every 4 hours against Microsoft Release Health and MSRC CVRF."
    else:
        advisory_level = "SAFE"
        advisory_headline = f"NORMAL OPERATIONS ({cycle_label}): No unmitigated critical regressions across tracked Windows branches."
        advisory_detail = "All verified updates in this cycle are clear for standard phased ring deployment."

    return {
        "selected_cycle": effective_cycle or "all",
        "available_cycles": cycles,
        "status_counts": counts,
        "metrics": {
            "total_kbs": total_kbs,
            "oob_updates_count": oob_count,
            "active_kir_count": kir_count,
            "active_known_issues_count": active_issues_count,
            "total_cves_count": total_cves_count,
            "exploited_cves_count": exploited_cves_count,
            "unacknowledged_alerts_count": unacked_alerts_count,
            "sources_total": len(sources_raw),
            "sources_ok": sources_ok,
            "sources_error": sources_err,
            "last_checked_at": last_checked_at,
            "demo_records_count": demo_count,
            "live_records_count": live_count,
            "using_demo_seed": demo_count > 0 and live_count == 0,
        },
        "advisory_banner": {
            "level": advisory_level,
            "headline": advisory_headline,
            "detail": advisory_detail,
            "items": advisory_items,
        },
        "version_health": version_health,
        "latest_alerts": latest_alerts,
    }


def global_search(conn: sqlite3.Connection, query: str) -> dict[str, Any]:
    """Search across KBs, CVEs, Known Issues, and Windows OS Builds."""
    cleaned = (query or "").strip()
    if not cleaned:
        return {"query": "", "total_results": 0, "kbs": [], "cves": [], "known_issues": [], "builds": []}

    term = f"%{cleaned}%"

    kb_rows = conn.execute(
        """
        SELECT * FROM kbs
        WHERE kb_number LIKE ? OR title LIKE ? OR os_build LIKE ? OR windows_version LIKE ? OR health_rationale LIKE ?
        ORDER BY release_date DESC LIMIT 20
        """,
        (term, term, term, term, term),
    ).fetchall()
    kbs = [_enrich_kb_summary(conn, r) for r in kb_rows]

    cve_rows = conn.execute(
        """
        SELECT * FROM cves
        WHERE cve_id LIKE ? OR title LIKE ? OR affected_component LIKE ? OR kb_number LIKE ?
        ORDER BY is_exploited DESC, cve_id DESC LIMIT 25
        """,
        (term, term, term, term),
    ).fetchall()
    cves = []
    for cr in cve_rows:
        d = dict(cr)
        d["is_exploited"] = bool(d["is_exploited"])
        d["publicly_disclosed"] = bool(d["publicly_disclosed"])
        cves.append(d)

    issue_rows = conn.execute(
        """
        SELECT * FROM known_issues
        WHERE title LIKE ? OR symptoms LIKE ? OR kb_number LIKE ? OR windows_version LIKE ? OR COALESCE(oob_fix_kb, '') LIKE ?
        ORDER BY is_severe_failure DESC, id DESC LIMIT 25
        """,
        (term, term, term, term, term),
    ).fetchall()
    issues = []
    for ir in issue_rows:
        d = dict(ir)
        d["is_severe_failure"] = bool(d["is_severe_failure"])
        d["has_kir"] = bool(d["has_kir"])
        issues.append(d)

    build_rows = conn.execute(
        """
        SELECT kb_number, windows_version, os_build, release_date, health_status, title
        FROM kbs
        WHERE os_build LIKE ? OR windows_version LIKE ?
        ORDER BY release_date DESC LIMIT 15
        """,
        (term, term),
    ).fetchall()
    builds = [dict(r) for r in build_rows]

    total = len(kbs) + len(cves) + len(issues) + len(builds)
    return {
        "query": cleaned,
        "total_results": total,
        "kbs": kbs,
        "cves": cves,
        "known_issues": issues,
        "builds": builds,
    }

