# PATCH ALERT — Microsoft Windows Desktop Update Intelligence & Operational Patch Health Monitor

**PATCH ALERT** is an operational cybersecurity and patch health monitoring application built for Windows system administrators and security operations teams. It answers the operational question:

> *"Can I safely deploy this Windows update, or is Microsoft currently reporting problems with it?"*

---

## Core Capabilities

1. **Official Microsoft Source Collection**:
   - Collects Windows Release Health advisories, Known Issues, Resolved Issues, and Message Center announcements for **Windows 11 (24H2, 23H2, 22H2)** and **Windows 10 (22H2)** desktop releases.
   - Collects security advisories and CVE mappings from the **Microsoft Security Response Center (MSRC) CVRF v3.0 API**.
   - Supports scheduled background synchronization (default every **4 hours / 240 minutes**) and a manual **"Sync Microsoft"** trigger.
2. **Deterministic Operational Health Engine**:
   - Computes an internal, deterministic operational health status with a transparent, human-readable rationale citing exact Microsoft facts:
     - **`SAFE` (Green)**: Official Microsoft Release Health telemetry verified and zero active known issues reported.
     - **`MONITOR` (Yellow)**: Limited-scope, mitigated (e.g., automatic Windows Update KIR), investigating, or recently resolved issues, or updates addressing actively exploited CVEs with no regression blockers.
     - **`CAUTION` (Orange)**: Confirmed active known issue, Known Issue Rollback (KIR) requiring Enterprise Group Policy MSI deployment, or an Out-of-Band (OOB) update requiring targeted deployment evaluation.
     - **`AFFECTED` (Red)**: Critical confirmed component failure (e.g., BSOD/stop error, boot, authentication, SSH/networking failure) or an update superseded/replaced by an emergency Out-of-Band (OOB) fix.
     - **`UNKNOWN` (Dark/Gray)**: Insufficient or unverified source telemetry. **PATCH ALERT never infers a `SAFE` status from a failed collection attempt.**
3. **Known Issue Rollback (KIR) & Out-of-Band (OOB) Tracking**:
   - Detects KIR advisories, whether a device restart is required, the deployment method (`Automatic via Windows Update` vs. `Group Policy MSI`), Group Policy package names, and official guidance links.
   - Detects Out-of-Band (OOB) emergency updates and preserves bidirectional supersession relationships (`oob_replaces`, `oob_replaced_by`, `supersedes`, `superseded_by`) between the original update, its regression issue, and the OOB replacement.
4. **SHA-256 Normalization & Field-Level Audit Trail**:
   - Normalizes collected payloads, computes deterministic SHA-256 hashes, compares against stored records in SQLite, and logs every field-level change (`old_value` → `new_value`) in a persistent `change_log`.
5. **RSS 2.0 Operational Alert Feed**:
   - Serves a standards-compliant RSS 2.0 XML feed at `/rss.xml` and `/feed.xml`.

---

## Tech Stack

- **Runtime**: Python 3.10+
- **Backend**: FastAPI & Uvicorn
- **Storage**: SQLite (`patch_alert.db` with WAL mode and foreign keys; no external DB server required)
- **Validation**: Pydantic v2
- **Collection**: `httpx` (bounded retries, timeouts, exponential backoff) & `BeautifulSoup4`
- **Frontend**: Plain HTML5, CSS3 (Dark default theme with Dark/Light toggle), and vanilla JavaScript
- **Testing**: `pytest`

---

## Setup & Running the Application

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Launch PATCH ALERT

Use `run.py` to initialize the SQLite schema, seed the clearly labeled pre-sync reference dataset (if the database is empty), and start the server at `http://127.0.0.1:8000`:

```bash
python run.py
```

Optional CLI flags for `run.py`:
- `--host 127.0.0.1` — Bind address (default `127.0.0.1`)
- `--port 8000` — Bind port (default `8000`)
- `--no-seed` — Start with an empty database without pre-sync reference seed data
- `--init-only` — Initialize the SQLite database and exit without starting the HTTP server
- `--reload` — Enable Uvicorn auto-reload for development

You can also start Uvicorn directly:

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open **`http://127.0.0.1:8000`** in your browser. Interactive OpenAPI documentation is available at **`http://127.0.0.1:8000/docs`**.

---

## Running Automated Tests

Run the `pytest` suite from the repository root:

```bash
pytest -v
```

---

## Configured Official Microsoft Data Sources

All sources are stored in the `sources` SQLite table and can be viewed or updated via the UI (**Official Sources & Hashes** tab) or API (`GET /api/sources`, `PATCH /api/sources/{id}`):

| Source Key | Windows Version | Official Microsoft URL | Default Interval |
| :--- | :--- | :--- | :--- |
| `win11_24h2_release_health` | Windows 11 24H2 | `https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-24h2` | 240 min (4h) |
| `win11_23h2_release_health` | Windows 11 23H2 | `https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-23h2` | 240 min (4h) |
| `win11_22h2_release_health` | Windows 11 22H2 | `https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-22h2` | 240 min (4h) |
| `win10_22h2_release_health` | Windows 10 22H2 | `https://learn.microsoft.com/en-us/windows/release-health/status-windows-10-22h2` | 240 min (4h) |
| `windows_message_center` | All Supported Desktop Releases | `https://learn.microsoft.com/en-us/windows/release-health/windows-message-center` | 240 min (4h) |
| `msrc_cvrf_api` | All Supported Desktop Releases | `https://api.msrc.microsoft.com/cvrf/v3.0/updates` | 240 min (4h) |

> **Note on Pre-Sync Reference Seed Data**: When launched on a fresh database prior to the first live sync, PATCH ALERT seeds a local reference dataset (`data_origin = "Local Reference Dataset (Pre-Sync Seed)"`, `is_demo = True`) so the UI and filters are immediately inspectable. Reference records are explicitly badged as `Ref Seed` and never disguised as live telemetry.

---

## Backend API Reference

| Method & Endpoint | Description |
| :--- | :--- |
| `GET /` | Serves the PATCH ALERT cybersecurity operations dashboard. |
| `GET /api/dashboard/stats` | Returns operational status counts (`SAFE`, `MONITOR`, `CAUTION`, `AFFECTED`, `UNKNOWN`), KPI metrics, advisory banner, per-Windows-version health matrix, and latest alerts. |
| `GET /api/kbs` | Searchable, filterable, sortable, paginated KB list. Supports query parameters: `q`, `windows_version`, `status`, `update_type`, `is_oob`, `has_kir`, `has_known_issues`, `security_only`, `patch_tuesday_cycle`, `sort_by`, `sort_order`, `page`, `page_size`. |
| `GET /api/kbs/{kb_number}` | Full KB intelligence dossier including operational rationale, risk factors, known issues, KIR metadata, OOB/supersession relationships, CVEs, lifecycle timeline, and field-level change audit history. |
| `GET /api/alerts` | Lists operational alerts with optional `acknowledged`, `severity`, `kb_number`, and `limit` filters. |
| `POST /api/alerts/{id}/acknowledge` | Marks an operational alert as acknowledged with a UTC timestamp. |
| `GET /api/changes` | Returns the persistent field-level audit log with SHA-256 hashes (`kb_number`, `entity_type`, `limit`). |
| `GET /api/sources` | Lists configured Microsoft sources, last-check timestamps, HTTP status codes, SHA-256 content hashes, and intervals. |
| `PATCH /api/sources/{id}` | Updates configurable source fields (`url`, `enabled`, `windows_version`, `check_interval_minutes`). |
| `POST /api/collector/sync-now` | Triggers an immediate synchronization across enabled Microsoft sources. |
| `GET /api/collector/status` | Returns active synchronization progress and recent synchronization run summaries. |
| `GET /api/search?q={query}` | Global search across KBs, MSRC CVEs, Known Issues, and Windows OS builds. |
| `GET /rss.xml` & `GET /feed.xml` | Serves the RSS 2.0 XML feed of operational patch alerts. |

