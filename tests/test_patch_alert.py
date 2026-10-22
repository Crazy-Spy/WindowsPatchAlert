"""Automated pytest suite for PATCH ALERT covering risk engine, KIR/OOB, change audit, API filters, search, and RSS."""

from __future__ import annotations

from datetime import date
from pathlib import Path
import xml.etree.ElementTree as ET

from fastapi.testclient import TestClient
import httpx
import pytest

from app.audit import calculate_content_hash, compute_field_diffs, record_entity_changes
from app.collector import parse_msrc_cvrf_payload, parse_release_health_html, sync_single_source
from app.database import (
    add_kb_relationship,
    get_connection,
    init_db,
    recalculate_kb_status,
    set_db_path,
    upsert_cve,
    upsert_kb,
    upsert_known_issue,
)
from app.main import app
from app.models import HealthState
from app.risk_engine import (
    derive_patch_tuesday_cycle,
    detect_kir_metadata,
    detect_oob_metadata,
    evaluate_kb_health,
    get_patch_tuesday_date,
    is_patch_tuesday_release,
)
from app.seed import seed_demo_data_if_empty


@pytest.fixture()
def temp_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Create an isolated SQLite database for each test and disable background scheduler loop."""
    db_file = tmp_path / "test_patch_alert.db"
    monkeypatch.setenv("PATCH_ALERT_DB_PATH", str(db_file))
    monkeypatch.setenv("PATCH_ALERT_ENABLE_SCHEDULER", "false")
    set_db_path(db_file)
    init_db(db_file)
    seed_demo_data_if_empty(db_file, force=True)
    return db_file


@pytest.fixture()
def client(temp_db: Path) -> TestClient:
    """Provide a FastAPI TestClient backed by the isolated test SQLite database."""
    with TestClient(app) as tc:
        yield tc


# ---------------------------------------------------------------------------
# 1. Operational Health State & Priority Rules Tests
# ---------------------------------------------------------------------------

def test_risk_engine_never_infers_safe_on_failed_collection():
    """Verify failed collection or unverified telemetry yields UNKNOWN, never SAFE."""
    res_unverified = evaluate_kb_health(
        kb_number="KB5099991",
        telemetry_verified=False,
        source_failed=False,
        known_issues=[],
    )
    assert res_unverified.status == HealthState.UNKNOWN
    assert "never infers a SAFE state" in res_unverified.rationale

    res_failed_source = evaluate_kb_health(
        kb_number="KB5099992",
        telemetry_verified=True,
        source_failed=True,
        known_issues=[],
        source_error_reason="HTTP 503 Service Unavailable from learn.microsoft.com",
    )
    assert res_failed_source.status == HealthState.UNKNOWN
    assert "HTTP 503" in res_failed_source.rationale


def test_risk_engine_priority_rules_and_rationales():
    """Verify deterministic priority: AFFECTED > CAUTION > MONITOR > SAFE when telemetry is verified."""
    # SAFE: Verified telemetry + no known issues
    safe_res = evaluate_kb_health(
        kb_number="KB5043076",
        telemetry_verified=True,
        known_issues=[],
        cves=[{"cve_id": "CVE-2024-38217", "is_exploited": False}],
    )
    assert safe_res.status == HealthState.SAFE
    assert "No active known issues" in safe_res.rationale

    # MONITOR: Mitigated issue via automatic KIR
    monitor_res = evaluate_kb_health(
        kb_number="KB5044273",
        telemetry_verified=True,
        known_issues=[
            {
                "title": "Taskbar jump list delay",
                "status": "Mitigated",
                "severity": "Low",
                "has_kir": True,
                "kir_deployment_method": "Automatic via Windows Update",
            }
        ],
    )
    assert monitor_res.status == HealthState.MONITOR
    assert "Known issue mitigated via automatic Known Issue Rollback (KIR)" in monitor_res.rationale

    # CAUTION: Active confirmed issue or Enterprise Group Policy KIR or OOB update
    caution_res = evaluate_kb_health(
        kb_number="KB5044285",
        telemetry_verified=True,
        known_issues=[
            {
                "title": "USB printer protocol header issue",
                "status": "Confirmed",
                "severity": "High",
                "is_severe_failure": False,
                "has_kir": True,
                "kir_restart_required": True,
                "kir_deployment_method": "Group Policy MSI (Enterprise Managed Devices)",
            }
        ],
    )
    assert caution_res.status == HealthState.CAUTION
    assert "CAUTION" in caution_res.rationale
    assert "USB printer protocol header issue" in caution_res.rationale

    # AFFECTED: Critical component failure OR superseded by an OOB update
    affected_by_oob = evaluate_kb_health(
        kb_number="KB5044284",
        telemetry_verified=True,
        known_issues=[
            {
                "title": "Minor issue",
                "status": "Mitigated",
                "severity": "Low",
            }
        ],
        relationships=[
            {"relationship_type": "oob_replaced_by", "related_kb": "KB5045934"}
        ],
    )
    assert affected_by_oob.status == HealthState.AFFECTED
    assert "KB5045934" in affected_by_oob.rationale
    assert affected_by_oob.has_oob_supersession is True

    affected_by_bsod = evaluate_kb_health(
        kb_number="KB5044999",
        telemetry_verified=True,
        known_issues=[
            {
                "title": "Devices might experience a Blue Screen stop error during boot",
                "symptoms": "BSOD stop error after reboot",
                "status": "Confirmed",
                "severity": "Critical",
                "is_severe_failure": True,
            }
        ],
    )
    assert affected_by_bsod.status == HealthState.AFFECTED
    assert "Confirmed critical component failure" in affected_by_bsod.rationale


# ---------------------------------------------------------------------------
# 2. Known Issue Rollback (KIR) & Out-of-Band (OOB) Detection and Relationships
# ---------------------------------------------------------------------------

def test_kir_and_oob_detection_and_db_relationships(temp_db: Path):
    """Test KIR metadata extraction and OOB supersession relationship preservation."""
    kir_text = (
        "This issue is resolved using Known Issue Rollback (KIR). Please note that it might take up to "
        "24 hours for the resolution to propagate automatically to consumer devices. Enterprise-managed devices "
        "that have installed the update can resolve this by installing and configuring a special Group Policy "
        "'KB5044285 241014_21401 Known Issue Rollback'. A restart is required after applying the Group Policy."
    )
    kir_info = detect_kir_metadata(
        kir_text,
        links=[("KB5044285 KIR MSI", "https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-23h2")],
    )
    assert kir_info["has_kir"] is True
    assert kir_info["kir_restart_required"] is True
    assert "Group Policy" in kir_info["kir_deployment_method"]
    assert kir_info["kir_gpo_name"] == "KB5044285 241014_21401 Known Issue Rollback"
    assert kir_info["kir_guidance_url"].startswith("https://learn.microsoft.com")

    oob_info = detect_oob_metadata(
        "Out-of-Band Update KB5045934 for Windows 11 24H2",
        "This OOB update supersedes KB5044284 and resolves the OpenSSH startup failure.",
        kb_number="KB5045934",
    )
    assert oob_info["is_oob"] is True
    assert "KB5044284" in oob_info["referenced_kbs"]

    # Verify DB relationship between KB5044284 and OOB replacement KB5045934
    with get_connection(temp_db) as conn:
        rels_orig = conn.execute(
            "SELECT * FROM kb_relationships WHERE kb_number = 'KB5044284' AND relationship_type = 'oob_replaced_by'"
        ).fetchall()
        assert len(rels_orig) == 1
        assert rels_orig[0]["related_kb"] == "KB5045934"

        rels_oob = conn.execute(
            "SELECT * FROM kb_relationships WHERE kb_number = 'KB5045934' AND relationship_type = 'oob_replaces'"
        ).fetchall()
        assert len(rels_oob) == 1
        assert rels_oob[0]["related_kb"] == "KB5044284"


# ---------------------------------------------------------------------------
# 3. SHA-256 Normalization and Field-Level Audit Trail Tests
# ---------------------------------------------------------------------------

def test_sha256_hashing_and_field_level_change_detection(temp_db: Path):
    """Verify content normalization, SHA-256 hashing, and field-level diff persistence."""
    h1 = calculate_content_hash({"title": "Update   KB5044285", "status": "Confirmed"})
    h2 = calculate_content_hash({"status": "Confirmed", "title": "Update KB5044285  "})
    assert h1 == h2
    assert len(h1) == 64

    with get_connection(temp_db) as conn:
        # Modify an existing known issue's status from Confirmed -> Resolved and verify audit log
        _, changes = upsert_known_issue(
            conn,
            {
                "issue_key": "ISSUE-KB5044285-USB-PRINT-KIR",
                "kb_number": "KB5044285",
                "windows_version": "Windows 11 23H2",
                "os_build": "22631.4317",
                "title": "Dual-mode USB printers might print unexpected text or fail to initialize over IPP-over-USB",
                "symptoms": "Updated symptoms description.",
                "status": "Resolved",
                "severity": "High",
                "is_severe_failure": False,
                "has_kir": True,
                "kir_restart_required": True,
                "kir_deployment_method": "Group Policy MSI",
                "source_url": "https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-23h2",
            },
            detected_at="2026-10-21T10:00:00Z",
        )
        assert len(changes) >= 2
        changed_fields = {c["field_name"]: c for c in changes}
        assert "status" in changed_fields
        assert changed_fields["status"]["old_value"] == "Confirmed"
        assert changed_fields["status"]["new_value"] == "Resolved"
        assert changed_fields["status"]["change_type"] == "STATUS_CHANGED"

        # Recalculating KB5044285 status should transition it from CAUTION -> MONITOR and log KB change
        recalc = recalculate_kb_status(conn, "KB5044285", detected_at="2026-10-21T10:01:00Z")
        assert recalc is not None
        assert recalc["status"] == "MONITOR"
        kb_changes = {c["field_name"]: c for c in recalc["changes"]}
        assert "health_status" in kb_changes
        assert kb_changes["health_status"]["old_value"] == "CAUTION"
        assert kb_changes["health_status"]["new_value"] == "MONITOR"


# ---------------------------------------------------------------------------
# 4. Patch Tuesday Cycle Calculation Tests
# ---------------------------------------------------------------------------

def test_patch_tuesday_cycle_calculations():
    """Verify second Tuesday of month calculation and cycle derivation."""
    # October 2026: Oct 1 is Thursday -> Tuesdays are Oct 6 and Oct 13 (2nd Tuesday = 2026-10-13)
    pt_oct_2026 = get_patch_tuesday_date(2026, 10)
    assert pt_oct_2026 == date(2026, 10, 13)
    assert is_patch_tuesday_release("2026-10-13") is True
    assert is_patch_tuesday_release("2026-10-16") is False
    assert derive_patch_tuesday_cycle("2026-10-13") == "2026-10"
    assert derive_patch_tuesday_cycle("2026-09-08") == "2026-09"


# ---------------------------------------------------------------------------
# 5. Backend API Endpoints, Filters, Sorting, Dossier, Search, and RSS Tests
# ---------------------------------------------------------------------------

def test_api_dashboard_stats_and_kbs_filters(client: TestClient):
    """Test /api/dashboard/stats and /api/kbs with all supported filters."""
    stats_resp = client.get("/api/dashboard/stats")
    assert stats_resp.status_code == 200
    stats = stats_resp.json()
    assert stats["status_counts"]["AFFECTED"] >= 1
    assert stats["status_counts"]["CAUTION"] >= 1
    assert stats["status_counts"]["MONITOR"] >= 1
    assert stats["status_counts"]["SAFE"] >= 1
    assert stats["status_counts"]["UNKNOWN"] >= 1
    assert len(stats["version_health"]) >= 3

    # Filter by status=AFFECTED
    r_affected = client.get("/api/kbs?status=AFFECTED")
    assert r_affected.status_code == 200
    items_aff = r_affected.json()["items"]
    assert len(items_aff) == 1
    assert items_aff[0]["kb_number"] == "KB5044284"
    assert "KB5045934" in items_aff[0]["oob_replaced_by_kbs"]

    # Filter by is_oob=true
    r_oob = client.get("/api/kbs?is_oob=true")
    assert r_oob.status_code == 200
    items_oob = r_oob.json()["items"]
    assert len(items_oob) == 1
    assert items_oob[0]["kb_number"] == "KB5045934"
    assert "KB5044284" in items_oob[0]["oob_replaces_kbs"]

    # Filter by has_kir=true
    r_kir = client.get("/api/kbs?has_kir=true")
    assert r_kir.status_code == 200
    kir_kbs = {k["kb_number"] for k in r_kir.json()["items"]}
    assert {"KB5044284", "KB5044285", "KB5044273"}.issubset(kir_kbs)

    # Filter by patch_tuesday_cycle=2026-09
    r_cycle = client.get("/api/kbs?patch_tuesday_cycle=2026-09")
    assert r_cycle.status_code == 200
    cycle_kbs = {k["kb_number"] for k in r_cycle.json()["items"]}
    assert cycle_kbs == {"KB5043076", "KB5043064"}

    # Filter by patch_tuesday_cycle=latest (resolves to most recent cycle 2026-10)
    r_latest = client.get("/api/kbs?patch_tuesday_cycle=latest")
    assert r_latest.status_code == 200
    latest_data = r_latest.json()
    assert latest_data["selected_cycle"] == "2026-10"
    assert all(k["patch_tuesday_cycle"] == "2026-10" for k in latest_data["items"])

    # Filter by windows_version and sort by health_status
    r_ver = client.get("/api/kbs", params={"windows_version": "Windows 11 24H2", "sort_by": "health_status", "sort_order": "asc"})
    assert r_ver.status_code == 200
    ver_items = r_ver.json()["items"]
    assert ver_items[0]["kb_number"] == "KB5044284"  # AFFECTED sorts before CAUTION


def test_api_kb_dossier_and_404(client: TestClient):
    """Test GET /api/kbs/{kb_number} full dossier and 404 handling."""
    resp = client.get("/api/kbs/KB5044284")
    assert resp.status_code == 200
    dossier = resp.json()
    assert dossier["kb_number"] == "KB5044284"
    assert dossier["health_status"] == "AFFECTED"
    assert len(dossier["known_issues"]) >= 1
    assert dossier["known_issues"][0]["has_kir"] is True
    assert dossier["known_issues"][0]["kir_restart_required"] is True
    assert len(dossier["cves"]) >= 2
    assert len(dossier["relationships"]) >= 1
    assert len(dossier["lifecycle"]) >= 3
    assert len(dossier["changes"]) >= 1

    not_found = client.get("/api/kbs/KB9999999")
    assert not_found.status_code == 404


def test_api_alerts_acknowledge_changes_and_sources(client: TestClient):
    """Test alerts listing, acknowledging an alert, audit log endpoint, and configurable sources."""
    alerts_resp = client.get("/api/alerts")
    assert alerts_resp.status_code == 200
    alerts_data = alerts_resp.json()
    assert alerts_data["total"] >= 3
    first_alert_id = alerts_data["items"][0]["id"]

    ack_resp = client.post(f"/api/alerts/{first_alert_id}/acknowledge")
    assert ack_resp.status_code == 200
    assert ack_resp.json()["alert"]["acknowledged"] is True
    assert ack_resp.json()["alert"]["acknowledged_at"] is not None

    changes_resp = client.get("/api/changes?kb_number=KB5044284")
    assert changes_resp.status_code == 200
    assert changes_resp.json()["total"] >= 1

    sources_resp = client.get("/api/sources")
    assert sources_resp.status_code == 200
    sources = sources_resp.json()["items"]
    assert len(sources) == 6
    src_id = sources[0]["id"]

    patch_resp = client.patch(
        f"/api/sources/{src_id}",
        json={"check_interval_minutes": 120, "enabled": False},
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["check_interval_minutes"] == 120
    assert patch_resp.json()["enabled"] is False


def test_api_global_search_and_rss_feed(client: TestClient):
    """Test /api/search across KBs, CVEs, issues, builds, and /rss.xml + /feed.xml RSS 2.0 output."""
    search_cve = client.get("/api/search?q=CVE-2024-43573")
    assert search_cve.status_code == 200
    s_data = search_cve.json()
    assert s_data["total_results"] > 0
    assert any(c["cve_id"] == "CVE-2024-43573" for c in s_data["cves"])

    search_build = client.get("/api/search?q=26100.2033")
    assert search_build.status_code == 200
    b_data = search_build.json()
    assert any(b["kb_number"] == "KB5044284" for b in b_data["builds"])

    for endpoint in ("/rss.xml", "/feed.xml"):
        rss_resp = client.get(endpoint)
        assert rss_resp.status_code == 200
        assert "application/rss+xml" in rss_resp.headers["content-type"]
        root = ET.fromstring(rss_resp.text)
        assert root.tag == "rss"
        assert root.attrib.get("version") == "2.0"
        channel = root.find("channel")
        assert channel is not None
        assert channel.find("title") is not None
        items = channel.findall("item")
        assert len(items) >= 3
        first_item = items[0]
        assert first_item.find("title") is not None
        assert first_item.find("guid") is not None
        assert first_item.find("pubDate") is not None


# ---------------------------------------------------------------------------
# 6. Collector HTML & MSRC Parsers and Explicit Failure Handling Tests
# ---------------------------------------------------------------------------

def test_collector_parsers_and_failure_handling(temp_db: Path):
    """Verify Release Health HTML parser, MSRC CVRF parser, and explicit collection error recording."""
    sample_html = """
    <html>
      <body>
        <table>
          <thead>
            <tr><th>Summary</th><th>Originating update</th><th>Status</th><th>Date</th></tr>
          </thead>
          <tbody>
            <tr>
              <td>After installing KB5044300 (OS Build 26100.2100), devices might fail to start OpenSSH. Resolved via Known Issue Rollback (KIR) Group Policy 'KB5044300 Rollback'. Restart required.</td>
              <td>KB5044300</td>
              <td>Confirmed</td>
              <td>2026-10-18</td>
            </tr>
          </tbody>
        </table>
      </body>
    </html>
    """
    parsed = parse_release_health_html(
        sample_html,
        windows_version="Windows 11 24H2",
        source_url="https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-24h2",
    )
    assert len(parsed["kbs"]) == 1
    assert parsed["kbs"][0]["kb_number"] == "KB5044300"
    assert parsed["kbs"][0]["os_build"] == "26100.2100"
    assert len(parsed["known_issues"]) == 1
    issue = parsed["known_issues"][0]
    assert issue["has_kir"] is True
    assert issue["kir_restart_required"] is True
    assert issue["is_severe_failure"] is True

    sample_msrc = """
    {
      "Vulnerability": [
        {
          "CVE": "CVE-2026-99991",
          "Title": {"Value": "Windows Kernel Elevation of Privilege Vulnerability"},
          "Threats": [{"Description": {"Value": "Exploited:Yes; Publicly Disclosed:No"}}],
          "Remediations": [{"Description": {"Value": "KB5044300"}}]
        }
      ]
    }
    """
    msrc_parsed = parse_msrc_cvrf_payload(sample_msrc, "https://api.msrc.microsoft.com/cvrf/v3.0/updates")
    assert len(msrc_parsed["cves"]) == 1
    assert msrc_parsed["cves"][0]["cve_id"] == "CVE-2026-99991"
    assert msrc_parsed["cves"][0]["is_exploited"] is True
    assert msrc_parsed["cves"][0]["kb_number"] == "KB5044300"


def test_collector_sync_single_source_success_and_failure(temp_db: Path):
    """Test sync_single_source with MockTransport for both successful HTML collection and HTTP 500 error."""
    import asyncio

    def handler(request: httpx.Request) -> httpx.Response:
        if "fail-source" in str(request.url):
            return httpx.Response(500, text="Internal Server Error")
        return httpx.Response(
            200,
            text="""
            <html><body>
              <table>
                <tr><th>Summary</th><th>Originating update</th><th>Status</th><th>Date</th></tr>
                <tr>
                  <td>Issue after KB5044888 (OS Build 26100.2200) mitigated via Known Issue Rollback (KIR).</td>
                  <td>KB5044888</td>
                  <td>Mitigated</td>
                  <td>2026-10-19</td>
                </tr>
              </table>
            </body></html>
            """,
        )

    transport = httpx.MockTransport(handler)

    async def _run_checks():
        async with httpx.AsyncClient(transport=transport) as mock_client:
            with get_connection(temp_db) as conn:
                src_ok = dict(conn.execute("SELECT * FROM sources WHERE id = 1").fetchone())

            res_ok = await sync_single_source(mock_client, src_ok, db_path=str(temp_db))
            assert res_ok["status"] == "OK"
            assert res_ok["http_code"] == 200
            assert res_ok["items_collected"] >= 2
            assert res_ok["content_hash"] is not None

            # Test explicit failure handling (never fabricates data, records error)
            src_fail = dict(src_ok)
            src_fail["url"] = "https://learn.microsoft.com/fail-source"
            res_err = await sync_single_source(mock_client, src_fail, db_path=str(temp_db))
            assert res_err["status"] == "ERROR"
            assert "500" in (res_err["error"] or "")

    asyncio.run(_run_checks())


def test_dashboard_root_and_collector_status_endpoint(client: TestClient):
    """Verify GET / serves dashboard HTML and GET /api/collector/status returns sync state."""
    root_resp = client.get("/")
    assert root_resp.status_code == 200
    assert "PATCH ALERT" in root_resp.text

    status_resp = client.get("/api/collector/status")
    assert status_resp.status_code == 200
    data = status_resp.json()
    assert "is_running" in data
    assert "schedule_interval_minutes" in data

