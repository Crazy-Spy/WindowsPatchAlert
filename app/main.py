"""FastAPI backend application for PATCH ALERT."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.audit import utc_now_iso
from app.collector import collector_state, run_synchronization
from app.config import DEFAULT_SYNC_INTERVAL_MINUTES, ENABLE_BACKGROUND_SCHEDULER
from app.database import (
    get_connection,
    get_dashboard_stats,
    get_kb_dossier,
    global_search,
    init_db,
    query_kbs,
)
from app.models import KBDossierModel, SourceConfigModel, SourceUpdateInput
from app.rss import generate_rss_xml
from app.seed import seed_demo_data_if_empty

STATIC_DIR = Path(__file__).resolve().parent / "static"


async def _scheduled_sync_loop() -> None:
    """Background task that triggers scheduled synchronization every DEFAULT_SYNC_INTERVAL_MINUTES (4 hours)."""
    interval_seconds = max(300, DEFAULT_SYNC_INTERVAL_MINUTES * 60)
    while True:
        await asyncio.sleep(interval_seconds)
        try:
            if not collector_state.is_running:
                await run_synchronization(trigger_type="scheduled")
        except Exception:
            pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize SQLite schema, seed local reference data if empty, and manage background scheduler."""
    init_db()
    seed_demo_data_if_empty()
    scheduler_task: Optional[asyncio.Task] = None
    if ENABLE_BACKGROUND_SCHEDULER:
        scheduler_task = asyncio.create_task(_scheduled_sync_loop())
    try:
        yield
    finally:
        if scheduler_task:
            scheduler_task.cancel()


app = FastAPI(
    title="PATCH ALERT — Microsoft Windows Desktop Update Intelligence & Operational Patch Health Monitor",
    description=(
        "Operational Patch Health Monitor answering: 'Can I safely deploy this Windows update, "
        "or is Microsoft currently reporting problems with it?'"
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# Allow VS Code Live Server (e.g. 127.0.0.1:5500 / localhost:5500) to communicate with the FastAPI backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", include_in_schema=False)
async def serve_dashboard() -> FileResponse:
    """Serve the main PATCH ALERT operations dashboard."""
    index_file = STATIC_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="Dashboard frontend asset index.html not found.")
    return FileResponse(str(index_file))


@app.get("/styles.css", include_in_schema=False)
async def serve_styles_root() -> FileResponse:
    """Serve styles.css at root so relative paths work in both FastAPI and VS Code Live Server."""
    return FileResponse(str(STATIC_DIR / "styles.css"), media_type="text/css")


@app.get("/app.js", include_in_schema=False)
async def serve_app_js_root() -> FileResponse:
    """Serve app.js at root so relative paths work in both FastAPI and VS Code Live Server."""
    return FileResponse(str(STATIC_DIR / "app.js"), media_type="application/javascript")


@app.get("/api/dashboard/stats", summary="Operational dashboard statistics and Windows version health")
async def api_dashboard_stats(
    patch_tuesday_cycle: Optional[str] = Query(default=None, description="Optional Patch Tuesday cycle (YYYY-MM or 'latest')"),
) -> dict[str, Any]:
    """Return status counts, metrics, per-Windows-version health, advisory banner, and latest alerts."""
    with get_connection() as conn:
        stats = get_dashboard_stats(conn, patch_tuesday_cycle=patch_tuesday_cycle)
    stats["collector"] = collector_state.to_dict()
    return stats


@app.get("/api/kbs", summary="Searchable, filterable, sortable, paginated Windows update list")
async def api_list_kbs(
    q: Optional[str] = Query(default=None, description="Search query across KB, title, build, issues, CVEs"),
    windows_version: Optional[str] = Query(default=None, description="Filter by Windows version (e.g. 'Windows 11 24H2')"),
    status: Optional[str] = Query(default=None, description="Filter by operational health status (SAFE, MONITOR, CAUTION, AFFECTED, UNKNOWN)"),
    update_type: Optional[str] = Query(default=None, description="Filter by update type (Cumulative, Security Only, Preview, Out-of-Band (OOB))"),
    is_oob: Optional[bool] = Query(default=None, description="Filter Out-of-Band (OOB) updates"),
    has_kir: Optional[bool] = Query(default=None, description="Filter updates with Known Issue Rollback (KIR)"),
    has_known_issues: Optional[bool] = Query(default=None, description="Filter updates with reported known issues"),
    security_only: Optional[bool] = Query(default=None, description="Filter security updates"),
    patch_tuesday_cycle: Optional[str] = Query(default=None, description="Filter by Patch Tuesday cycle (YYYY-MM)"),
    sort_by: str = Query(
        default="release_date",
        pattern="^(release_date|kb_number|windows_version|health_status|known_issues_count|cve_count|last_checked_at)$",
    ),
    sort_order: str = Query(default="desc", pattern="^(asc|desc|ASC|DESC)$"),
    page: int = Query(default=1, ge=1, le=10000),
    page_size: int = Query(default=25, ge=1, le=200),
) -> dict[str, Any]:
    """Return a paginated, filtered, and sorted list of tracked Windows KBs."""
    with get_connection() as conn:
        return query_kbs(
            conn=conn,
            q=q,
            windows_version=windows_version,
            status=status,
            update_type=update_type,
            is_oob=is_oob,
            has_kir=has_kir,
            has_known_issues=has_known_issues,
            security_only=security_only,
            patch_tuesday_cycle=patch_tuesday_cycle,
            sort_by=sort_by,
            sort_order=sort_order,
            page=page,
            page_size=page_size,
        )


@app.get("/api/kbs/{kb_number}", response_model=KBDossierModel, summary="Full KB intelligence dossier")
async def api_get_kb_dossier(kb_number: str) -> Any:
    """Return full KB dossier with rationale, known issues, KIR metadata, OOB relationships, CVEs, lifecycle timeline, and change history."""
    with get_connection() as conn:
        dossier = get_kb_dossier(conn, kb_number)
    if not dossier:
        raise HTTPException(status_code=404, detail=f"Windows Update '{kb_number}' not found in local intelligence store.")
    return dossier


@app.get("/api/alerts", summary="List operational alerts")
async def api_list_alerts(
    acknowledged: Optional[bool] = Query(default=None, description="Filter by acknowledgment status"),
    severity: Optional[str] = Query(default=None, description="Filter by alert severity"),
    kb_number: Optional[str] = Query(default=None, description="Filter by related KB number"),
    limit: int = Query(default=50, ge=1, le=500),
) -> dict[str, Any]:
    """Return operational alerts ordered by most recent first."""
    clauses: list[str] = []
    params: list[Any] = []

    if acknowledged is not None:
        clauses.append("acknowledged = ?")
        params.append(1 if acknowledged else 0)
    if severity and severity.upper() != "ALL":
        clauses.append("UPPER(severity) = ?")
        params.append(severity.upper())
    if kb_number:
        norm_kb = kb_number.strip().upper()
        if not norm_kb.startswith("KB"):
            norm_kb = f"KB{norm_kb}"
        clauses.append("UPPER(kb_number) = ?")
        params.append(norm_kb)

    where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    with get_connection() as conn:
        rows = conn.execute(
            f"SELECT * FROM alerts {where_sql} ORDER BY created_at DESC, id DESC LIMIT ?",
            [*params, limit],
        ).fetchall()
        unacked_count = int(conn.execute("SELECT COUNT(*) FROM alerts WHERE acknowledged = 0").fetchone()[0])

    items = []
    for r in rows:
        d = dict(r)
        d["acknowledged"] = bool(d["acknowledged"])
        d["is_demo"] = bool(d["is_demo"])
        items.append(d)

    return {
        "items": items,
        "total": len(items),
        "unacknowledged_count": unacked_count,
    }


@app.post("/api/alerts/{alert_id}/acknowledge", summary="Acknowledge an operational alert")
async def api_acknowledge_alert(alert_id: int) -> dict[str, Any]:
    """Mark an alert as acknowledged with a UTC timestamp."""
    now = utc_now_iso()
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"Alert with id {alert_id} not found.")
        conn.execute(
            "UPDATE alerts SET acknowledged = 1, acknowledged_at = ? WHERE id = ?",
            (now, alert_id),
        )
        updated = dict(conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone())
        updated["acknowledged"] = bool(updated["acknowledged"])
        updated["is_demo"] = bool(updated["is_demo"])
    return {"status": "acknowledged", "alert": updated}


@app.get("/api/changes", summary="Field-level audit change history")
async def api_list_changes(
    kb_number: Optional[str] = Query(default=None, description="Filter by KB number"),
    entity_type: Optional[str] = Query(default=None, description="Filter by entity type (KB, KNOWN_ISSUE, CVE, SOURCE)"),
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    """Return persistent field-level change audit logs with SHA-256 content hashes."""
    clauses: list[str] = []
    params: list[Any] = []
    if kb_number:
        norm_kb = kb_number.strip().upper()
        if not norm_kb.startswith("KB"):
            norm_kb = f"KB{norm_kb}"
        clauses.append("UPPER(kb_number) = ?")
        params.append(norm_kb)
    if entity_type and entity_type.upper() != "ALL":
        clauses.append("UPPER(entity_type) = ?")
        params.append(entity_type.upper())

    where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    with get_connection() as conn:
        rows = conn.execute(
            f"SELECT * FROM change_log {where_sql} ORDER BY detected_at DESC, id DESC LIMIT ?",
            [*params, limit],
        ).fetchall()

    items = []
    for r in rows:
        d = dict(r)
        d["is_demo"] = bool(d["is_demo"])
        items.append(d)

    return {"items": items, "total": len(items)}


@app.get("/api/sources", summary="Configured Microsoft telemetry sources and sync status")
async def api_list_sources() -> dict[str, Any]:
    """Return all configured official Microsoft sources, their SHA-256 content hashes, check intervals, and last status."""
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM sources ORDER BY id ASC").fetchall()
    items = []
    for r in rows:
        d = dict(r)
        d["enabled"] = bool(d["enabled"])
        items.append(d)
    return {
        "items": items,
        "total": len(items),
        "default_schedule_minutes": DEFAULT_SYNC_INTERVAL_MINUTES,
    }


@app.patch("/api/sources/{source_id}", response_model=SourceConfigModel, summary="Update configurable source parameters")
@app.put("/api/sources/{source_id}", response_model=SourceConfigModel, summary="Update configurable source parameters")
async def api_update_source(source_id: int, payload: SourceUpdateInput) -> Any:
    """Update source URL, enabled status, Windows version, or check interval."""
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM sources WHERE id = ?", (source_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"Source {source_id} not found.")
        current = dict(row)

        new_url = payload.url if payload.url is not None else current["url"]
        if not (new_url.startswith("https://") or new_url.startswith("http://")):
            raise HTTPException(status_code=422, detail="Source URL must start with https:// or http://")

        new_enabled = (1 if payload.enabled else 0) if payload.enabled is not None else current["enabled"]
        new_version = payload.windows_version if payload.windows_version is not None else current["windows_version"]
        new_interval = (
            payload.check_interval_minutes
            if payload.check_interval_minutes is not None
            else current["check_interval_minutes"]
        )

        conn.execute(
            """
            UPDATE sources SET
                url = ?,
                enabled = ?,
                windows_version = ?,
                check_interval_minutes = ?
            WHERE id = ?
            """,
            (new_url, new_enabled, new_version, new_interval, source_id),
        )
        updated = dict(conn.execute("SELECT * FROM sources WHERE id = ?", (source_id,)).fetchone())
        updated["enabled"] = bool(updated["enabled"])
    return updated


@app.post("/api/collector/sync-now", summary="Start a manual Microsoft telemetry synchronization")
async def api_collector_sync_now(
    background_tasks: BackgroundTasks,
    wait: bool = Query(default=True, description="Wait for synchronization to finish before returning"),
) -> dict[str, Any]:
    """Trigger immediate synchronization against enabled official Microsoft sources."""
    if collector_state.is_running:
        return {
            "started": False,
            "message": "Synchronization is already running.",
            "status": collector_state.to_dict(),
        }

    if wait:
        result = await run_synchronization(trigger_type="manual")
        return {
            "started": True,
            "message": result.get("last_summary", "Synchronization completed."),
            "status": result,
        }
    else:
        background_tasks.add_task(run_synchronization, trigger_type="manual")
        return {
            "started": True,
            "message": "Manual Microsoft synchronization started in background.",
            "status": collector_state.to_dict(),
        }


@app.get("/api/collector/status", summary="Current synchronization progress and run history")
async def api_collector_status() -> dict[str, Any]:
    """Return active synchronization status and recent sync runs."""
    with get_connection() as conn:
        runs = [
            dict(r)
            for r in conn.execute("SELECT * FROM sync_runs ORDER BY id DESC LIMIT 10").fetchall()
        ]
    state = collector_state.to_dict()
    state["recent_runs"] = runs
    return state


@app.get("/api/search", summary="Global search across KBs, CVEs, Known Issues, and Windows Builds")
async def api_global_search(
    q: str = Query(default="", max_length=200, description="Global search query"),
) -> dict[str, Any]:
    """Search KBs, CVEs, Known Issues, and Windows builds matching the query."""
    with get_connection() as conn:
        return global_search(conn, q)


@app.get("/rss.xml", summary="RSS 2.0 Operational Alert Feed")
@app.get("/feed.xml", summary="RSS 2.0 Operational Alert Feed (Alias)")
async def api_rss_feed(request: Request) -> Response:
    """Serve RSS 2.0 XML feed of PATCH ALERT operational alerts."""
    base_url = str(request.base_url).rstrip("/")
    with get_connection() as conn:
        alerts = [
            dict(r)
            for r in conn.execute("SELECT * FROM alerts ORDER BY created_at DESC, id DESC LIMIT 50").fetchall()
        ]
    xml_content = generate_rss_xml(alerts, base_url=base_url)
    return Response(content=xml_content, media_type="application/rss+xml; charset=utf-8")

