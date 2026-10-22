"""Static snapshot generator for hosting PATCH ALERT on GitHub Pages or VS Code Live Server without a live backend."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any

from app.audit import utc_now_iso
from app.collector import collector_state, run_synchronization
from app.database import (
    get_connection,
    get_dashboard_stats,
    get_kb_dossier,
    init_db,
    query_kbs,
)
from app.rss import generate_rss_xml
from app.seed import seed_demo_data_if_empty

STATIC_DIR = Path(__file__).resolve().parent / "app" / "static"
DATA_DIR = STATIC_DIR / "data"


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def export_static_snapshot(base_url: str = "./") -> dict[str, Any]:
    """Export all SQLite intelligence tables into static JSON files and RSS 2.0 XML inside app/static/."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    (DATA_DIR / "kbs").mkdir(parents=True, exist_ok=True)
    refresh_ts = utc_now_iso()

    with get_connection() as conn:
        # 1. Dashboard stats
        stats = get_dashboard_stats(conn)
        if "metrics" in stats:
            stats["metrics"]["last_refresh_at"] = refresh_ts
            if not stats["metrics"].get("last_checked_at"):
                stats["metrics"]["last_checked_at"] = refresh_ts
        stats["collector"] = collector_state.to_dict()
        _write_json(DATA_DIR / "dashboard_stats.json", stats)

        # 2. Full KB list (unpaginated so static client can filter/sort/paginate in browser)
        kbs_data = query_kbs(conn, page=1, page_size=1000)
        _write_json(DATA_DIR / "kbs.json", kbs_data)

        # 3. Full Dossier per KB + combined dossiers map
        dossiers_map: dict[str, Any] = {}
        for kb_summary in kbs_data.get("items", []):
            kb_num = kb_summary["kb_number"]
            dossier = get_kb_dossier(conn, kb_num)
            if dossier:
                dossiers_map[kb_num] = dossier
                _write_json(DATA_DIR / "kbs" / f"{kb_num}.json", dossier)
        _write_json(DATA_DIR / "dossiers.json", dossiers_map)

        # 4. Alerts
        alert_rows = conn.execute("SELECT * FROM alerts ORDER BY created_at DESC, id DESC LIMIT 200").fetchall()
        alerts_items = []
        for r in alert_rows:
            d = dict(r)
            d["acknowledged"] = bool(d["acknowledged"])
            d["is_demo"] = bool(d["is_demo"])
            alerts_items.append(d)
        unacked_count = sum(1 for a in alerts_items if not a["acknowledged"])
        _write_json(
            DATA_DIR / "alerts.json",
            {
                "items": alerts_items,
                "total": len(alerts_items),
                "unacknowledged_count": unacked_count,
            },
        )

        # 5. Field-level Change Audit Log
        change_rows = conn.execute("SELECT * FROM change_log ORDER BY detected_at DESC, id DESC LIMIT 250").fetchall()
        changes_items = []
        for r in change_rows:
            d = dict(r)
            d["is_demo"] = bool(d["is_demo"])
            changes_items.append(d)
        _write_json(
            DATA_DIR / "changes.json",
            {"items": changes_items, "total": len(changes_items)},
        )

        # 6. Configured Official Microsoft Sources
        source_rows = conn.execute("SELECT * FROM sources ORDER BY id ASC").fetchall()
        sources_items = []
        for r in source_rows:
            d = dict(r)
            d["enabled"] = bool(d["enabled"])
            sources_items.append(d)
        _write_json(
            DATA_DIR / "sources.json",
            {"items": sources_items, "total": len(sources_items), "default_schedule_minutes": 240},
        )

        # 7. Collector Status
        sync_runs = [
            dict(r) for r in conn.execute("SELECT * FROM sync_runs ORDER BY id DESC LIMIT 10").fetchall()
        ]
        col_status = collector_state.to_dict()
        col_status["recent_runs"] = sync_runs
        _write_json(DATA_DIR / "collector_status.json", col_status)

        # 8. RSS 2.0 XML Feeds (rss.xml and feed.xml inside app/static/)
        rss_xml = generate_rss_xml(alerts_items, base_url=base_url)
        (STATIC_DIR / "rss.xml").write_text(rss_xml, encoding="utf-8")
        (STATIC_DIR / "feed.xml").write_text(rss_xml, encoding="utf-8")

    return {
        "kbs_exported": len(dossiers_map),
        "alerts_exported": len(alerts_items),
        "changes_exported": len(changes_items),
        "sources_exported": len(sources_items),
        "output_dir": str(DATA_DIR),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Synchronize Microsoft telemetry and export static JSON/RSS files for GitHub Pages / Live Server."
    )
    parser.add_argument(
        "--sync",
        action="store_true",
        help="Run live Microsoft synchronization (Release Health + MSRC CVRF) before exporting static files",
    )
    parser.add_argument(
        "--no-seed",
        action="store_true",
        help="Do not seed pre-sync reference dataset if database is empty",
    )
    parser.add_argument(
        "--base-url",
        default="https://localhost",
        help="Base URL for RSS 2.0 feed links (e.g. https://<username>.github.io/<repo>)",
    )
    args = parser.parse_args()

    init_db()
    if not args.no_seed:
        seed_demo_data_if_empty()

    if args.sync:
        print("[PATCH ALERT] Running live synchronization against official Microsoft sources...")
        sync_result = asyncio.run(run_synchronization(trigger_type="scheduled_action"))
        print(f"[PATCH ALERT] Sync result: {sync_result.get('last_summary')}")

    summary = export_static_snapshot(base_url=args.base_url)
    print(
        f"[PATCH ALERT] Static snapshot exported to {summary['output_dir']} "
        f"({summary['kbs_exported']} KBs, {summary['alerts_exported']} alerts, {summary['changes_exported']} audit entries)."
    )


if __name__ == "__main__":
    main()

