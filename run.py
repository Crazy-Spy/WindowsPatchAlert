"""Launcher for PATCH ALERT: initializes SQLite storage, seeds reference data if needed, and starts Uvicorn."""

from __future__ import annotations

import argparse
import uvicorn

from app.database import get_db_path, init_db
from app.seed import seed_demo_data_if_empty


def main() -> None:
    parser = argparse.ArgumentParser(
        description="PATCH ALERT — Microsoft Windows Desktop Update Intelligence & Operational Patch Health Monitor"
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Bind port (default: 8000)")
    parser.add_argument("--no-seed", action="store_true", help="Do not seed pre-sync reference dataset if DB is empty")
    parser.add_argument("--reload", action="store_true", help="Enable Uvicorn auto-reload for development")
    parser.add_argument("--init-only", action="store_true", help="Initialize database and exit without starting server")
    args = parser.parse_args()

    print(f"[PATCH ALERT] Initializing SQLite database at {get_db_path()} ...")
    init_db()

    if not args.no_seed:
        seeded = seed_demo_data_if_empty()
        if seeded:
            print("[PATCH ALERT] Seeded pre-sync local reference dataset (clearly marked as Local Reference Dataset).")
        else:
            print("[PATCH ALERT] Existing intelligence dataset found in SQLite.")

    if args.init_only:
        print("[PATCH ALERT] Database initialization complete.")
        return

    print(f"[PATCH ALERT] Starting operational dashboard at http://{args.host}:{args.port}")
    uvicorn.run("app.main:app", host=args.host, port=args.port, reload=args.reload)


if __name__ == "__main__":
    main()

