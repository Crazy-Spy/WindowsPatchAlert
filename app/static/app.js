/* PATCH ALERT — Frontend Application Logic */

(function () {
  "use strict";

  const state = {
    q: "",
    windows_version: "all",
    status: "ALL",
    update_type: "all",
    patch_tuesday_cycle: "latest",
    latest_cycle: null,
    is_oob: null,
    has_kir: null,
    has_known_issues: null,
    security_only: null,
    sort_by: "release_date",
    sort_order: "desc",
    page: 1,
    page_size: 25,
    total_pages: 1,
  };

  function escapeHtml(val) {
    if (val === null || val === undefined) return "";
    return String(val)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  let refreshCountdownTimer = null;

  function parseUtcDate(isoStr) {
    if (!isoStr) return null;
    const cleaned = String(isoStr).trim();
    const withT = cleaned.replace(/^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2})/, "$1T$2");
    const normalized =
      withT.includes("T") && !withT.endsWith("Z") && !/[+-]\d{2}:?\d{2}$/.test(withT)
        ? `${withT}Z`
        : withT;
    const dt = new Date(normalized);
    return Number.isNaN(dt.getTime()) ? null : dt;
  }

  function startRefreshCountdown(refreshIsoStr) {
    const syncTsEl = document.getElementById("lastSyncTimestamp");
    if (!syncTsEl) return;

    if (refreshCountdownTimer) {
      clearInterval(refreshCountdownTimer);
      refreshCountdownTimer = null;
    }

    const lastDt = parseUtcDate(refreshIsoStr);
    if (!lastDt) {
      syncTsEl.textContent = "Last Refresh: Pending • Next Refresh: —";
      return;
    }

    const CYCLE_MS = 4 * 60 * 60 * 1000; // 4 hours in milliseconds
    const nextRefreshMs = lastDt.getTime() + CYCLE_MS;
    const nextDt = new Date(nextRefreshMs);
    const formattedLast = formatLocalDateTime(refreshIsoStr, true);
    const formattedNextAt = formatLocalDateTime(nextDt.toISOString(), true);
    const pad = (n) => String(n).padStart(2, "0");

    const updateTick = () => {
      const diffMs = nextRefreshMs - Date.now();
      let countdownText = "";
      if (diffMs > 0) {
        const totalSec = Math.floor(diffMs / 1000);
        const hh = pad(Math.floor(totalSec / 3600));
        const mm = pad(Math.floor((totalSec % 3600) / 60));
        const ss = pad(totalSec % 60);
        countdownText = `${hh}h ${mm}m ${ss}s`;
      } else {
        countdownText = "Due now (Syncing soon)";
      }
      syncTsEl.textContent = `Last Refresh: ${formattedLast} • Next Refresh: ${countdownText}`;
      syncTsEl.title = `Auto-Sync: Every 4h (GitHub Actions) | Next Scheduled Refresh: ${formattedNextAt} | Raw UTC: ${refreshIsoStr}`;
    };

    updateTick();
    refreshCountdownTimer = setInterval(updateTick, 1000);
  }

  function formatLocalDateTime(isoStr, includeTz = true) {
    if (!isoStr) return "—";
    const cleaned = String(isoStr).trim();
    if (/^\d{4}-\d{2}-\d{2}$/.test(cleaned)) {
      return cleaned;
    }
    const withT = cleaned.replace(/^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2})/, "$1T$2");
    const normalized =
      withT.includes("T") && !withT.endsWith("Z") && !/[+-]\d{2}:?\d{2}$/.test(withT)
        ? `${withT}Z`
        : withT;
    const dt = new Date(normalized);
    if (Number.isNaN(dt.getTime())) {
      return cleaned.slice(0, 16).replace("T", " ");
    }
    const pad = (n) => String(n).padStart(2, "0");
    const yyyy = dt.getFullYear();
    const mm = pad(dt.getMonth() + 1);
    const dd = pad(dt.getDate());
    const hh = pad(dt.getHours());
    const min = pad(dt.getMinutes());
    if (!includeTz) {
      return `${yyyy}-${mm}-${dd} ${hh}:${min}`;
    }
    const offsetMin = -dt.getTimezoneOffset();
    const sign = offsetMin >= 0 ? "+" : "-";
    const absMin = Math.abs(offsetMin);
    const offH = pad(Math.floor(absMin / 60));
    const offM = absMin % 60;
    const tzLabel = offM ? `UTC${sign}${offH}:${pad(offM)}` : `UTC${sign}${Number(offH)}`;
    return `${yyyy}-${mm}-${dd} ${hh}:${min} (${tzLabel})`;
  }

  function getKbSupportUrl(kbNumber) {
    const num = String(kbNumber || "").replace(/^KB/i, "").trim();
    return num ? `https://support.microsoft.com/help/${encodeURIComponent(num)}` : "https://support.microsoft.com";
  }

  function getKbCatalogUrl(kbNumber) {
    const clean = String(kbNumber || "").trim().toUpperCase();
    return `https://www.catalog.update.microsoft.com/Search.aspx?q=${encodeURIComponent(clean)}`;
  }

  function getSpecificKirUrl(rawUrl, kbNumber) {
    const u = String(rawUrl || "").trim();
    if (u && (u.includes("#") || u.toLowerCase().includes(".msi") || u.includes("support.microsoft.com/help/"))) {
      return u;
    }
    return `${getKbSupportUrl(kbNumber)}#known-issues-in-this-update`;
  }

  function showError(message) {
    const banner = document.getElementById("globalErrorBanner");
    const text = document.getElementById("globalErrorText");
    if (banner && text) {
      text.textContent = message;
      banner.classList.remove("hidden");
    }
  }

  function clearError() {
    const banner = document.getElementById("globalErrorBanner");
    if (banner) {
      banner.classList.add("hidden");
    }
  }

  // Hybrid Mode:
  // - When served by FastAPI (port 8000), calls live /api/... endpoints.
  // - When hosted on GitHub Pages (*.github.io) or opened in VS Code Live Server (e.g. port 5500),
  //   loads directly from "./data/*.json" generated by export_static.py / GitHub Actions!
  const IS_FASTAPI_HOST = window.location.port === "8000";

  const staticCache = {
    stats: null,
    kbs: null,
    dossiers: null,
    alerts: null,
    changes: null,
    sources: null,
    bustParam: "",
  };

  function getAckedAlertMap() {
    try {
      return JSON.parse(localStorage.getItem("patch_alert_acked_alerts") || "{}");
    } catch (_) {
      return {};
    }
  }

  function saveAckedAlert(id, timestamp) {
    const map = getAckedAlertMap();
    map[String(id)] = timestamp;
    localStorage.setItem("patch_alert_acked_alerts", JSON.stringify(map));
  }

  function getSourceOverrides() {
    try {
      return JSON.parse(localStorage.getItem("patch_alert_source_overrides") || "{}");
    } catch (_) {
      return {};
    }
  }

  function saveSourceOverride(id, patch) {
    const map = getSourceOverrides();
    map[String(id)] = Object.assign({}, map[String(id)] || {}, patch);
    localStorage.setItem("patch_alert_source_overrides", JSON.stringify(map));
  }

  async function fetchStaticJson(relPath) {
    const sep = relPath.includes("?") ? "&" : "?";
    const url = staticCache.bustParam ? `${relPath}${sep}_t=${staticCache.bustParam}` : relPath;
    const resp = await fetch(url, { headers: { Accept: "application/json" } });
    if (!resp.ok) {
      throw new Error(`Failed to load static telemetry file ${relPath} (HTTP ${resp.status})`);
    }
    return resp.json();
  }

  async function ensureStaticDataLoaded() {
    if (!staticCache.kbs || !staticCache.dossiers) {
      const [kbs, dossiers] = await Promise.all([
        fetchStaticJson("./data/kbs.json"),
        fetchStaticJson("./data/dossiers.json"),
      ]);
      staticCache.kbs = kbs;
      staticCache.dossiers = dossiers;
    }
  }

  async function handleStaticGet(url) {
    const parsed = new URL(url, window.location.origin);
    const path = parsed.pathname;
    const params = parsed.searchParams;

    if (path === "/api/dashboard/stats") {
      await ensureStaticDataLoaded();
      const baseStats = await fetchStaticJson("./data/dashboard_stats.json");
      const allKbs = (staticCache.kbs.items || []).slice();
      const dossiers = staticCache.dossiers || {};
      const availCycles = staticCache.kbs.available_cycles || [];

      let reqCycle = params.get("patch_tuesday_cycle") || "all";
      if (reqCycle.toLowerCase() === "latest") {
        reqCycle = availCycles[0] || "all";
      }

      const cycleKbs =
        reqCycle && reqCycle.toLowerCase() !== "all"
          ? allKbs.filter((k) => k.patch_tuesday_cycle === reqCycle)
          : allKbs;

      const counts = { SAFE: 0, MONITOR: 0, CAUTION: 0, AFFECTED: 0, UNKNOWN: 0 };
      cycleKbs.forEach((k) => {
        if (counts[k.health_status] !== undefined) counts[k.health_status] += 1;
      });

      // Recompute per-version health for the selected cycle
      const allVersions = staticCache.kbs.available_versions || [];
      const versionHealth = [];
      allVersions.forEach((ver) => {
        const vKbs = cycleKbs.filter((k) => k.windows_version === ver);
        if (!vKbs.length) return;
        const safeCount = vKbs.filter((k) => k.health_status === "SAFE").length;
        const monitorCount = vKbs.filter((k) => k.health_status === "MONITOR").length;
        const cautionCount = vKbs.filter((k) => k.health_status === "CAUTION").length;
        const affectedCount = vKbs.filter((k) => k.health_status === "AFFECTED").length;
        const unknownCount = vKbs.filter((k) => k.health_status === "UNKNOWN").length;
        const oobCount = vKbs.filter((k) => k.is_oob).length;
        const kirCount = vKbs.filter((k) => k.has_kir).length;

        let overall = "SAFE";
        if (affectedCount > 0) overall = "AFFECTED";
        else if (cautionCount > 0) overall = "CAUTION";
        else if (monitorCount > 0) overall = "MONITOR";
        else if (unknownCount > 0 && safeCount === 0) overall = "UNKNOWN";

        const sortedVKbs = vKbs.slice().sort((a, b) => (a.release_date < b.release_date ? 1 : -1));
        const latestKb = sortedVKbs[0];
        const activeIssues = vKbs.reduce((acc, k) => acc + (k.active_issues_count || 0), 0);

        versionHealth.push({
          windows_version: ver,
          total_kbs: vKbs.length,
          safe_count: safeCount,
          monitor_count: monitorCount,
          caution_count: cautionCount,
          affected_count: affectedCount,
          unknown_count: unknownCount,
          oob_count: oobCount,
          kir_count: kirCount,
          overall_status: overall,
          latest_kb: latestKb ? latestKb.kb_number : null,
          latest_build: latestKb ? latestKb.os_build : null,
          active_issues: activeIssues,
        });
      });

      // Build actionable advisory items for AFFECTED or CAUTION KBs in this cycle
      const advKbs = cycleKbs
        .filter((k) => k.health_status === "AFFECTED" || k.health_status === "CAUTION")
        .sort((a, b) => (a.health_status === "AFFECTED" && b.health_status !== "AFFECTED" ? -1 : 1));

      const advisoryItems = advKbs.map((k) => {
        const d = dossiers[k.kb_number] || {};
        const kirs = (d.known_issues || [])
          .filter((iss) => iss.has_kir)
          .map((iss) => ({
            issue_title: iss.title,
            kir_gpo_name: iss.kir_gpo_name,
            kir_deployment_method: iss.kir_deployment_method,
            kir_restart_required: iss.kir_restart_required,
            kir_guidance_url: iss.kir_guidance_url || iss.source_url,
          }));
        return {
          kb_number: k.kb_number,
          windows_version: k.windows_version,
          os_build: k.os_build,
          health_status: k.health_status,
          rationale: k.health_rationale,
          is_oob: k.is_oob,
          oob_replaced_by_kbs: k.oob_replaced_by_kbs || [],
          oob_replaces_kbs: k.oob_replaces_kbs || [],
          source_url: k.source_url,
          kirs: kirs,
        };
      });

      const cycleLabel = reqCycle && reqCycle.toLowerCase() !== "all" ? reqCycle : "All Cycles";
      let advLevel = "SAFE";
      let advHeadline = `NORMAL OPERATIONS (${cycleLabel}): No unmitigated critical regressions across tracked Windows branches.`;
      let advDetail = "All verified updates in this cycle are clear for standard phased ring deployment.";

      if (counts.AFFECTED > 0) {
        const affList = advisoryItems.filter((i) => i.health_status === "AFFECTED").map((i) => i.kb_number);
        advLevel = "AFFECTED";
        advHeadline = `CRITICAL DEPLOYMENT ADVISORY (${cycleLabel}): ${counts.AFFECTED} Windows Update(s) (${affList.join(", ")}) have confirmed severe regressions or Out-of-Band (OOB) replacements.`;
        advDetail = `Pause broad deployment of ${affList.join(", ")}. Click any KB, OOB replacement, or Known Issue Rollback (KIR) link below to inspect the deployment rationale and mitigation policy.`;
      } else if (counts.CAUTION > 0) {
        const cautList = advisoryItems.filter((i) => i.health_status === "CAUTION").map((i) => i.kb_number);
        advLevel = "CAUTION";
        advHeadline = `OPERATIONAL CAUTION (${cycleLabel}): ${counts.CAUTION} update(s) (${cautList.join(", ")}) have active Microsoft Known Issues or OOB applicability constraints.`;
        advDetail = "Click the KB or KIR policy links below to verify environment exposure and Group Policy requirements prior to enterprise rollout.";
      } else if (counts.UNKNOWN === cycleKbs.length && cycleKbs.length > 0) {
        advLevel = "UNKNOWN";
        advHeadline = `TELEMETRY UNVERIFIED (${cycleLabel}): Official Microsoft Release Health sources have not been verified.`;
        advDetail = "Automated GitHub Action synchronization runs every 4 hours against Microsoft Release Health and MSRC CVRF.";
      }

      const ackMap = getAckedAlertMap();
      const latestAlerts = (baseStats.latest_alerts || []).map((a) => {
        if (ackMap[String(a.id)]) {
          return Object.assign({}, a, { acknowledged: true, acknowledged_at: ackMap[String(a.id)] });
        }
        return a;
      });

      const metrics = Object.assign({}, baseStats.metrics || {}, {
        total_kbs: cycleKbs.length,
        oob_updates_count: cycleKbs.filter((k) => k.is_oob).length,
        active_kir_count: cycleKbs.filter((k) => k.has_kir).length,
        unacknowledged_alerts_count: latestAlerts.filter((a) => !a.acknowledged).length,
      });

      return {
        selected_cycle: reqCycle,
        available_cycles: availCycles,
        status_counts: counts,
        metrics: metrics,
        advisory_banner: {
          level: advLevel,
          headline: advHeadline,
          detail: advDetail,
          items: advisoryItems,
        },
        version_health: versionHealth,
        latest_alerts: latestAlerts,
      };
    }

    if (path === "/api/kbs") {
      await ensureStaticDataLoaded();
      const allItems = (staticCache.kbs.items || []).slice();
      const dossiers = staticCache.dossiers || {};

      const q = (params.get("q") || "").trim().toLowerCase();
      const winVer = params.get("windows_version");
      const status = params.get("status");
      const updateType = params.get("update_type");
      const availCycles = staticCache.kbs.available_cycles || [];
      let cycle = params.get("patch_tuesday_cycle");
      if (cycle && cycle.toLowerCase() === "latest") {
        cycle = availCycles[0] || "all";
      }
      const isOob = params.get("is_oob");
      const hasKir = params.get("has_kir");
      const hasIssues = params.get("has_known_issues");
      const secOnly = params.get("security_only");

      const filtered = allItems.filter((kb) => {
        if (winVer && winVer.toLowerCase() !== "all" && kb.windows_version !== winVer) return false;
        if (status && status.toUpperCase() !== "ALL" && kb.health_status !== status.toUpperCase()) return false;
        if (updateType && updateType.toLowerCase() !== "all" && kb.update_type.toLowerCase() !== updateType.toLowerCase()) return false;
        if (cycle && cycle.toLowerCase() !== "all" && kb.patch_tuesday_cycle !== cycle) return false;
        if (isOob === "true" && !kb.is_oob) return false;
        if (hasKir === "true" && !kb.has_kir) return false;
        if (hasIssues === "true" && !(kb.known_issues_count > 0)) return false;
        if (secOnly === "true" && !kb.is_security_update) return false;

        if (q) {
          const d = dossiers[kb.kb_number] || {};
          const hay = [
            kb.kb_number,
            kb.title,
            kb.os_build,
            kb.windows_version,
            kb.health_rationale,
            ...(d.known_issues || []).map((i) => `${i.title} ${i.symptoms}`),
            ...(d.cves || []).map((c) => `${c.cve_id} ${c.title} ${c.affected_component}`),
          ]
            .join(" ")
            .toLowerCase();
          if (!hay.includes(q)) return false;
        }
        return true;
      });

      const sortBy = params.get("sort_by") || "release_date";
      const sortOrder = (params.get("sort_order") || "desc").toLowerCase();
      const dir = sortOrder === "asc" ? 1 : -1;
      const statusPriority = { AFFECTED: 1, CAUTION: 2, MONITOR: 3, UNKNOWN: 4, SAFE: 5 };

      filtered.sort((a, b) => {
        let va, vb;
        if (sortBy === "health_status") {
          va = statusPriority[a.health_status] || 6;
          vb = statusPriority[b.health_status] || 6;
        } else {
          va = a[sortBy] ?? "";
          vb = b[sortBy] ?? "";
        }
        if (va < vb) return -1 * dir;
        if (va > vb) return 1 * dir;
        return a.kb_number < b.kb_number ? 1 : -1;
      });

      const page = Math.max(1, parseInt(params.get("page") || "1", 10));
      const pageSize = Math.max(1, parseInt(params.get("page_size") || "25", 10));
      const total = filtered.length;
      const totalPages = Math.max(1, Math.ceil(total / pageSize));
      const slice = filtered.slice((page - 1) * pageSize, page * pageSize);

      return {
        items: slice,
        total: total,
        page: page,
        page_size: pageSize,
        total_pages: totalPages,
        available_cycles: staticCache.kbs.available_cycles || [],
        available_versions: staticCache.kbs.available_versions || [],
      };
    }

    if (path.startsWith("/api/kbs/")) {
      const kbNum = decodeURIComponent(path.replace("/api/kbs/", "")).trim().toUpperCase();
      const normKb = kbNum.startsWith("KB") ? kbNum : `KB${kbNum}`;
      await ensureStaticDataLoaded();
      if (staticCache.dossiers && staticCache.dossiers[normKb]) {
        return staticCache.dossiers[normKb];
      }
      return fetchStaticJson(`./data/kbs/${normKb}.json`);
    }

    if (path === "/api/alerts") {
      const data = await fetchStaticJson("./data/alerts.json");
      const ackMap = getAckedAlertMap();
      const items = (data.items || []).map((a) => {
        if (ackMap[String(a.id)]) {
          return Object.assign({}, a, { acknowledged: true, acknowledged_at: ackMap[String(a.id)] });
        }
        return a;
      });
      return {
        items: items,
        total: items.length,
        unacknowledged_count: items.filter((a) => !a.acknowledged).length,
      };
    }

    if (path === "/api/changes") {
      return fetchStaticJson("./data/changes.json");
    }

    if (path === "/api/sources") {
      const data = await fetchStaticJson("./data/sources.json");
      const overrides = getSourceOverrides();
      const items = (data.items || []).map((s) =>
        overrides[String(s.id)] ? Object.assign({}, s, overrides[String(s.id)]) : s
      );
      return Object.assign({}, data, { items });
    }

    if (path === "/api/search") {
      const q = (params.get("q") || "").trim().toLowerCase();
      if (!q) return { query: "", total_results: 0, kbs: [], cves: [], known_issues: [], builds: [] };
      await ensureStaticDataLoaded();
      const kbs = [];
      const cves = [];
      const issues = [];
      const builds = [];

      Object.values(staticCache.dossiers || {}).forEach((d) => {
        if (
          d.kb_number.toLowerCase().includes(q) ||
          (d.title || "").toLowerCase().includes(q) ||
          (d.os_build || "").toLowerCase().includes(q) ||
          (d.windows_version || "").toLowerCase().includes(q) ||
          (d.health_rationale || "").toLowerCase().includes(q)
        ) {
          kbs.push(d);
        }
        if ((d.os_build || "").toLowerCase().includes(q) || (d.windows_version || "").toLowerCase().includes(q)) {
          builds.push({
            kb_number: d.kb_number,
            windows_version: d.windows_version,
            os_build: d.os_build,
            release_date: d.release_date,
            health_status: d.health_status,
            title: d.title,
          });
        }
        (d.cves || []).forEach((c) => {
          if (
            c.cve_id.toLowerCase().includes(q) ||
            (c.title || "").toLowerCase().includes(q) ||
            (c.affected_component || "").toLowerCase().includes(q) ||
            (c.kb_number || "").toLowerCase().includes(q)
          ) {
            cves.push(c);
          }
        });
        (d.known_issues || []).forEach((i) => {
          if (
            (i.title || "").toLowerCase().includes(q) ||
            (i.symptoms || "").toLowerCase().includes(q) ||
            (i.kb_number || "").toLowerCase().includes(q)
          ) {
            issues.push(i);
          }
        });
      });

      return {
        query: q,
        total_results: kbs.length + cves.length + issues.length + builds.length,
        kbs,
        cves,
        known_issues: issues,
        builds,
      };
    }

    if (path === "/api/collector/status") {
      return fetchStaticJson("./data/collector_status.json");
    }

    throw new Error(`Unsupported static route: ${path}`);
  }

  async function apiGet(url) {
    if (!IS_FASTAPI_HOST) {
      return handleStaticGet(url);
    }
    try {
      const resp = await fetch(url, { headers: { Accept: "application/json" } });
      if (!resp.ok) {
        let detail = `HTTP ${resp.status}`;
        try {
          const errJson = await resp.json();
          if (errJson && errJson.detail) detail = errJson.detail;
        } catch (_) {}
        throw new Error(`Request to ${url} failed: ${detail}`);
      }
      return await resp.json();
    } catch (err) {
      // Fallback to static snapshot if FastAPI is unreachable
      return handleStaticGet(url);
    }
  }

  async function apiPost(url, bodyObj) {
    if (!IS_FASTAPI_HOST) {
      if (url.includes("/acknowledge")) {
        const match = url.match(/\/api\/alerts\/(\d+)\/acknowledge/);
        if (match) {
          const nowIso = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
          saveAckedAlert(match[1], nowIso);
          return { status: "acknowledged", alert: { id: Number(match[1]), acknowledged: true, acknowledged_at: nowIso } };
        }
      }
      if (url.includes("/api/collector/sync-now")) {
        staticCache.bustParam = String(Date.now());
        staticCache.kbs = null;
        staticCache.dossiers = null;
        return {
          started: true,
          message: "Static snapshot reloaded (Automated Microsoft sync runs every 4h via GitHub Actions).",
        };
      }
    }

    const opts = {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
    };
    if (bodyObj !== undefined) {
      opts.body = JSON.stringify(bodyObj);
    }
    const resp = await fetch(url, opts);
    if (!resp.ok) {
      let detail = `HTTP ${resp.status}`;
      try {
        const errJson = await resp.json();
        if (errJson && errJson.detail) detail = errJson.detail;
      } catch (_) {}
      throw new Error(`POST ${url} failed: ${detail}`);
    }
    return resp.json();
  }

  async function apiPatch(url, bodyObj) {
    if (!IS_FASTAPI_HOST) {
      const match = url.match(/\/api\/sources\/(\d+)/);
      if (match) {
        saveSourceOverride(match[1], bodyObj || {});
        return Object.assign({ id: Number(match[1]) }, bodyObj);
      }
    }

    const resp = await fetch(url, {
      method: "PATCH",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify(bodyObj),
    });
    if (!resp.ok) {
      let detail = `HTTP ${resp.status}`;
      try {
        const errJson = await resp.json();
        if (errJson && errJson.detail) detail = errJson.detail;
      } catch (_) {}
      throw new Error(`PATCH ${url} failed: ${detail}`);
    }
    return resp.json();
  }

  /* THEME MANAGEMENT */
  function initTheme() {
    const saved = localStorage.getItem("patch_alert_theme") || "dark";
    applyTheme(saved);
    const btn = document.getElementById("themeToggleBtn");
    if (btn) {
      btn.addEventListener("click", () => {
        const current = document.documentElement.getAttribute("data-theme") || "dark";
        const next = current === "dark" ? "light" : "dark";
        applyTheme(next);
        localStorage.setItem("patch_alert_theme", next);
      });
    }
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    const label = document.getElementById("themeToggleText");
    if (label) {
      label.textContent = theme === "dark" ? "Light Mode" : "Dark Mode";
    }
  }

  /* DASHBOARD STATS, CARDS & VERSION HEALTH */
  async function loadDashboardStats() {
    try {
      const cycleParam = state.patch_tuesday_cycle || "latest";
      const data = await apiGet(`/api/dashboard/stats?patch_tuesday_cycle=${encodeURIComponent(cycleParam)}`);
      clearError();

      const resolvedCycle = data.selected_cycle || cycleParam;
      const healthTitleEl = document.getElementById("healthSectionTitle");
      if (healthTitleEl) {
        const cycleLabel = resolvedCycle && resolvedCycle.toLowerCase() !== "all" ? `CYCLE: ${resolvedCycle}` : "ALL CYCLES";
        healthTitleEl.textContent = `OPERATIONAL PATCH HEALTH STATES (${cycleLabel})`;
      }

      const counts = data.status_counts || {};
      ["SAFE", "MONITOR", "CAUTION", "AFFECTED", "UNKNOWN"].forEach((st) => {
        const el = document.getElementById(`count-${st}`);
        if (el) el.textContent = counts[st] !== undefined ? counts[st] : 0;
      });

      // Advisory Banner
      const adv = data.advisory_banner || {};
      const bannerEl = document.getElementById("advisoryBanner");
      const badgeEl = document.getElementById("advisoryBadge");
      const headlineEl = document.getElementById("advisoryHeadline");
      const detailEl = document.getElementById("advisoryDetail");
      const advItemsEl = document.getElementById("advisoryItemsList");
      const level = adv.level || "UNKNOWN";

      if (bannerEl) {
        bannerEl.className = `advisory-banner advisory-${level}`;
      }
      if (badgeEl) {
        badgeEl.className = `status-badge badge-${level}`;
        badgeEl.textContent = level;
      }
      if (headlineEl) headlineEl.textContent = adv.headline || "";
      if (detailEl) detailEl.textContent = adv.detail || "";

      // Actionable KB, OOB & KIR items inside the Advisory Banner
      const advItems = adv.items || [];
      if (advItemsEl) {
        if (advItems.length > 0) {
          advItemsEl.classList.remove("hidden");
          advItemsEl.innerHTML = advItems
            .map((item) => {
              const oobLinks = (item.oob_replaced_by_kbs || [])
                .map(
                  (oobKb) =>
                    `<button type="button" class="adv-action-pill pill-oob adv-kb-btn" data-kb="${escapeHtml(oobKb)}" title="Open Out-of-Band Replacement Dossier">OOB Fix: ${escapeHtml(oobKb)} &rarr;</button>`
                )
                .join("");

              const oobReplacesLinks = (item.oob_replaces_kbs || [])
                .map(
                  (origKb) =>
                    `<button type="button" class="adv-action-pill adv-kb-btn" data-kb="${escapeHtml(origKb)}" title="Open Superseded KB Dossier">Replaces: ${escapeHtml(origKb)}</button>`
                )
                .join("");

              const kirBadges = (item.kirs || [])
                .map((kir) => {
                  const gpoLabel = kir.kir_gpo_name ? `KIR GPO: ${kir.kir_gpo_name}` : "Known Issue Rollback (KIR)";
                  const restartLabel = kir.kir_restart_required ? " (Restart Required)" : "";
                  return `<span class="adv-action-pill pill-kir" style="cursor:default;" title="Known Issue Rollback (KIR) active for ${escapeHtml(item.kb_number)}">${escapeHtml(gpoLabel + restartLabel)}</span>`;
                })
                .join("");

              return `
                <div class="advisory-item-card">
                  <div class="advisory-item-header">
                    <div class="advisory-item-links">
                      <span class="status-badge badge-${escapeHtml(item.health_status)}">${escapeHtml(item.health_status)}</span>
                      <button type="button" class="adv-action-pill adv-kb-btn" data-kb="${escapeHtml(item.kb_number)}" title="Click to inspect full KB Dossier &amp; Deployment Rationale">
                        ${escapeHtml(item.kb_number)} (${escapeHtml(item.windows_version)}) — Why Not Deploy / Details &rarr;
                      </button>
                      ${oobLinks}
                      ${oobReplacesLinks}
                      ${kirBadges}
                    </div>
                    <div class="advisory-item-links">
                      <a href="${escapeHtml(getKbSupportUrl(item.kb_number))}" target="_blank" rel="noopener noreferrer" class="adv-action-pill" title="Open Official Microsoft KB Support Page">
                        Microsoft KB Article (${escapeHtml(item.kb_number)}) &nearr;
                      </a>
                      <a href="${escapeHtml(item.source_url)}" target="_blank" rel="noopener noreferrer" class="adv-action-pill">Release Health &nearr;</a>
                    </div>
                  </div>
                  <div class="advisory-item-rationale">${escapeHtml(item.rationale)}</div>
                </div>
              `;
            })
            .join("");

          advItemsEl.querySelectorAll(".adv-kb-btn").forEach((btn) => {
            btn.addEventListener("click", () => {
              openKbModal(btn.getAttribute("data-kb"));
            });
          });
        } else {
          advItemsEl.classList.add("hidden");
          advItemsEl.innerHTML = "";
        }
      }

      // Header Provenance & Last Check
      const m = data.metrics || {};
      const provEl = document.getElementById("dataProvenancePill");
      if (provEl) {
        if (m.using_demo_seed) {
          provEl.textContent = `Dataset: Reference Seed (${m.demo_records_count} KBs)`;
        } else if (m.live_records_count > 0 && m.demo_records_count > 0) {
          provEl.textContent = `Dataset: ${m.live_records_count} Live MS + ${m.demo_records_count} Seed`;
        } else {
          provEl.textContent = `Dataset: Live Microsoft (${m.live_records_count} KBs)`;
        }
      }
      const refreshTs = m.last_refresh_at || m.last_checked_at;
      startRefreshCountdown(refreshTs);

      // Header source pill
      const srcDot = document.getElementById("sourceStatusDot");
      const srcTxt = document.getElementById("sourceStatusText");
      if (srcDot && srcTxt) {
        if (m.sources_error > 0) {
          srcDot.className = "status-dot dot-affected";
          srcTxt.textContent = `Sources: ${m.sources_ok}/${m.sources_total} OK (${m.sources_error} Err)`;
        } else if (m.sources_ok > 0) {
          srcDot.className = "status-dot dot-safe";
          srcTxt.textContent = `Sources: ${m.sources_ok}/${m.sources_total} Verified`;
        } else {
          srcDot.className = "status-dot dot-unknown";
          srcTxt.textContent = `Sources: ${m.sources_total} Configured`;
        }
      }

      // KPI Mini Row
      const kpiMini = document.getElementById("kpiMiniSummary");
      if (kpiMini) {
        kpiMini.innerHTML = `
          <span class="mini-pill">OOB Updates: <strong>${m.oob_updates_count || 0}</strong></span>
          <span class="mini-pill">Active KIRs: <strong>${m.active_kir_count || 0}</strong></span>
          <span class="mini-pill">Exploited CVEs: <strong>${m.exploited_cves_count || 0}</strong></span>
        `;
      }

      // Version Health List
      renderVersionHealth(data.version_health || []);

      // Unacknowledged Alerts Counter
      const alertBadge = document.getElementById("unackedAlertBadge");
      if (alertBadge) {
        alertBadge.textContent = m.unacknowledged_alerts_count || 0;
      }
    } catch (err) {
      showError(err.message);
    }
  }

  function renderVersionHealth(versions) {
    const container = document.getElementById("versionHealthList");
    if (!container) return;
    if (!versions.length) {
      container.innerHTML = `<div class="empty-state">No Windows release telemetry available for this cycle.</div>`;
      return;
    }

    container.innerHTML = versions
      .map((v) => {
        const isSelected = state.windows_version === v.windows_version;
        const st = v.overall_status || "UNKNOWN";
        const oobSlot =
          v.oob_count > 0
            ? `<span class="flag-tag flag-oob">${v.oob_count} OOB</span>`
            : `<span class="ver-tag-empty">&mdash;</span>`;
        const kirSlot =
          v.kir_count > 0
            ? `<span class="flag-tag flag-kir">${v.kir_count} KIR</span>`
            : `<span class="ver-tag-empty">&mdash;</span>`;

        return `
          <div class="version-row ${isSelected ? "active-version" : ""}" data-version="${escapeHtml(v.windows_version)}" role="button" tabindex="0">
            <div>
              <div class="version-name">${escapeHtml(v.windows_version)}</div>
              <div class="version-meta">
                Latest: <strong>${escapeHtml(v.latest_kb || "—")}</strong> (Build ${escapeHtml(v.latest_build || "—")})
                &bull; ${v.total_kbs} KB(s) &bull; ${v.active_issues || 0} Active Issue(s)
              </div>
            </div>
            <div class="ver-tag-slot">${oobSlot}</div>
            <div class="ver-tag-slot">${kirSlot}</div>
            <div class="ver-status-slot">
              <span class="status-badge badge-${escapeHtml(st)}">${escapeHtml(st)}</span>
            </div>
          </div>
        `;
      })
      .join("");

    container.querySelectorAll(".version-row").forEach((row) => {
      row.addEventListener("click", () => {
        const ver = row.getAttribute("data-version");
        state.windows_version = state.windows_version === ver ? "all" : ver;
        const sel = document.getElementById("filterVersion");
        if (sel) sel.value = state.windows_version;
        state.page = 1;
        loadKBs();
        loadDashboardStats();
      });
    });
  }

  /* ALERTS, AUDIT LOG & SOURCES TABS */
  async function loadAlerts() {
    const container = document.getElementById("alertsListContainer");
    if (!container) return;
    try {
      const data = await apiGet("/api/alerts?limit=25");
      const items = data.items || [];
      const badge = document.getElementById("unackedAlertBadge");
      if (badge) badge.textContent = data.unacknowledged_count || 0;

      if (!items.length) {
        container.innerHTML = `<div class="empty-state">No operational alerts recorded.</div>`;
        return;
      }

      container.innerHTML = items
        .map((a) => {
          const st = a.severity || "INFO";
          const kbBtn = a.kb_number
            ? `<button type="button" class="kb-code-btn alert-kb-link" data-kb="${escapeHtml(a.kb_number)}">${escapeHtml(a.kb_number)}</button>`
            : "";
          const ackTime = a.acknowledged_at ? formatLocalDateTime(a.acknowledged_at, false) : "";
          const ackControl = a.acknowledged
            ? `<span class="acked-pill" title="UTC: ${escapeHtml(a.acknowledged_at || "")}"><span class="acked-check">&#10003;</span> Acked${ackTime ? ` &bull; ${escapeHtml(ackTime)}` : ""}</span>`
            : `<button type="button" class="btn btn-secondary btn-sm ack-alert-btn" data-id="${a.id}">Acknowledge</button>`;

          return `
            <div class="feed-item">
              <div class="alert-line-1">
                ${kbBtn}
                <span class="feed-item-title">${escapeHtml(a.title)}</span>
              </div>
              <div class="alert-line-2">
                <span class="status-badge badge-${escapeHtml(st)}">${escapeHtml(st)}</span>
                ${ackControl}
              </div>
              <div class="feed-item-summary">${escapeHtml(a.summary)}</div>
              <div class="feed-item-meta">
                <span>${escapeHtml(a.windows_version || "All Supported Releases")} &bull; ${escapeHtml(a.alert_type)}</span>
                <span title="UTC: ${escapeHtml(a.created_at || "")}">
                  ${escapeHtml(formatLocalDateTime(a.created_at, true))}
                  ${a.source_url ? ` &bull; <a href="${escapeHtml(a.source_url)}" target="_blank" rel="noopener noreferrer">Microsoft Source &nearr;</a>` : ""}
                </span>
              </div>
            </div>
          `;
        })
        .join("");

      container.querySelectorAll(".ack-alert-btn").forEach((btn) => {
        btn.addEventListener("click", async (e) => {
          e.stopPropagation();
          const id = btn.getAttribute("data-id");
          btn.disabled = true;
          try {
            await apiPost(`/api/alerts/${id}/acknowledge`);
            await loadAlerts();
            await loadDashboardStats();
          } catch (err) {
            showError(err.message);
          }
        });
      });

      container.querySelectorAll(".alert-kb-link").forEach((btn) => {
        btn.addEventListener("click", () => {
          openKbModal(btn.getAttribute("data-kb"));
        });
      });
    } catch (err) {
      container.innerHTML = `<div class="empty-state">Failed to load alerts: ${escapeHtml(err.message)}</div>`;
    }
  }

  async function loadAuditChanges() {
    const container = document.getElementById("auditListContainer");
    if (!container) return;
    try {
      const data = await apiGet("/api/changes?limit=40");
      const items = data.items || [];
      if (!items.length) {
        container.innerHTML = `<div class="empty-state">No field-level changes recorded yet.</div>`;
        return;
      }

      container.innerHTML = items
        .map((c) => {
          const kbLink = c.kb_number
            ? `<button type="button" class="kb-code-btn audit-kb-link" data-kb="${escapeHtml(c.kb_number)}">${escapeHtml(c.kb_number)}</button>`
            : `<span class="mini-pill">${escapeHtml(c.entity_id)}</span>`;
          const hashShort = (c.content_hash || "").slice(0, 12);
          return `
            <div class="feed-item">
              <div class="feed-item-top">
                <div>
                  <span class="mini-pill">${escapeHtml(c.entity_type)}</span>
                  ${kbLink}
                  <span class="feed-item-title">Field <code>${escapeHtml(c.field_name)}</code> (${escapeHtml(c.change_type)})</span>
                </div>
                <span class="mini-pill" title="SHA-256 Content Hash: ${escapeHtml(c.content_hash)}">SHA256: ${escapeHtml(hashShort)}&hellip;</span>
              </div>
              <div class="feed-item-summary">
                ${c.old_value ? `Old: <code>${escapeHtml(c.old_value.slice(0, 120))}</code> &rarr; ` : ""}
                New: <code>${escapeHtml((c.new_value || "").slice(0, 160))}</code>
              </div>
              <div class="feed-item-meta">
                <span title="UTC: ${escapeHtml(c.detected_at || "")}">Detected: ${escapeHtml(formatLocalDateTime(c.detected_at, true))}</span>
                ${c.source_url ? `<a href="${escapeHtml(c.source_url)}" target="_blank" rel="noopener noreferrer">Source &nearr;</a>` : ""}
              </div>
            </div>
          `;
        })
        .join("");

      container.querySelectorAll(".audit-kb-link").forEach((btn) => {
        btn.addEventListener("click", () => openKbModal(btn.getAttribute("data-kb")));
      });
    } catch (err) {
      container.innerHTML = `<div class="empty-state">Failed to load audit log: ${escapeHtml(err.message)}</div>`;
    }
  }

  async function loadSources() {
    const container = document.getElementById("sourcesListContainer");
    if (!container) return;
    try {
      const data = await apiGet("/api/sources");
      const items = data.items || [];
      if (!items.length) {
        container.innerHTML = `<div class="empty-state">No Microsoft sources configured.</div>`;
        return;
      }

      container.innerHTML = items
        .map((s) => {
          const stBadge =
            s.last_status === "OK"
              ? "SAFE"
              : s.last_status === "ERROR"
              ? "AFFECTED"
              : "UNKNOWN";
          const hashShort = s.content_hash ? `${s.content_hash.slice(0, 14)}…` : "Not hashed yet";
          return `
            <div class="feed-item">
              <div class="feed-item-top">
                <div>
                  <span class="status-badge badge-${stBadge}">${escapeHtml(s.last_status)}</span>
                  <span class="feed-item-title">${escapeHtml(s.name)}</span>
                </div>
                <div style="display:flex; gap:6px; align-items:center;">
                  <span class="mini-pill">Every ${s.check_interval_minutes}m</span>
                  <button type="button" class="btn btn-secondary btn-sm toggle-source-btn" data-id="${s.id}" data-enabled="${s.enabled}">
                    ${s.enabled ? "Enabled" : "Disabled"}
                  </button>
                </div>
              </div>
              <div class="feed-item-summary">
                <a href="${escapeHtml(s.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(s.url)} &nearr;</a>
                ${s.last_error ? `<div style="color:var(--affected-fg); margin-top:3px;">Error: ${escapeHtml(s.last_error)}</div>` : ""}
              </div>
              <div class="feed-item-meta">
                <span title="UTC: ${escapeHtml(s.last_checked_at || "")}">Version: ${escapeHtml(s.windows_version)} &bull; Last Check: ${escapeHtml(s.last_checked_at ? formatLocalDateTime(s.last_checked_at, true) : "Never")}</span>
                <span title="${escapeHtml(s.content_hash || "")}">SHA-256: ${escapeHtml(hashShort)}</span>
              </div>
            </div>
          `;
        })
        .join("");

      container.querySelectorAll(".toggle-source-btn").forEach((btn) => {
        btn.addEventListener("click", async () => {
          const id = btn.getAttribute("data-id");
          const curEnabled = btn.getAttribute("data-enabled") === "true";
          try {
            await apiPatch(`/api/sources/${id}`, { enabled: !curEnabled });
            await loadSources();
            await loadDashboardStats();
          } catch (err) {
            showError(err.message);
          }
        });
      });
    } catch (err) {
      container.innerHTML = `<div class="empty-state">Failed to load sources: ${escapeHtml(err.message)}</div>`;
    }
  }

  /* KB INTELLIGENCE TABLE */
  async function loadKBs() {
    const tbody = document.getElementById("kbTableBody");
    if (!tbody) return;

    const params = new URLSearchParams();
    if (state.q) params.set("q", state.q);
    if (state.windows_version && state.windows_version !== "all") params.set("windows_version", state.windows_version);
    if (state.status && state.status !== "ALL") params.set("status", state.status);
    if (state.update_type && state.update_type !== "all") params.set("update_type", state.update_type);
    if (state.patch_tuesday_cycle && state.patch_tuesday_cycle !== "all") params.set("patch_tuesday_cycle", state.patch_tuesday_cycle);
    if (state.is_oob === true) params.set("is_oob", "true");
    if (state.has_kir === true) params.set("has_kir", "true");
    if (state.has_known_issues === true) params.set("has_known_issues", "true");
    if (state.security_only === true) params.set("security_only", "true");
    params.set("sort_by", state.sort_by);
    params.set("sort_order", state.sort_order);
    params.set("page", String(state.page));
    params.set("page_size", String(state.page_size));

    try {
      const data = await apiGet(`/api/kbs?${params.toString()}`);
      clearError();
      populateCycleDropdown(data.available_cycles || []);

      const items = data.items || [];
      state.total_pages = data.total_pages || 1;

      updateHealthCardSelection();
      updatePaginationControls(data.total || 0, data.page || 1, data.total_pages || 1);

      if (!items.length) {
        tbody.innerHTML = `<tr><td colspan="10" class="empty-state">No Windows updates match the active filters.</td></tr>`;
        return;
      }

      tbody.innerHTML = items
        .map((kb) => {
          const flags = [];
          if (kb.is_oob) flags.push(`<span class="flag-tag flag-oob">OOB</span>`);
          if (kb.has_kir) flags.push(`<span class="flag-tag flag-kir">KIR</span>`);
          if ((kb.oob_replaced_by_kbs || []).length > 0) {
            flags.push(`<span class="flag-tag flag-oob">REPLACED BY OOB</span>`);
          }
          if (!flags.length) flags.push(`<span style="color:var(--text-muted)">—</span>`);

          const supersessionParts = [];
          if ((kb.oob_replaces_kbs || []).length) {
            supersessionParts.push(`<div><strong>OOB Replaces:</strong> ${kb.oob_replaces_kbs.map(escapeHtml).join(", ")}</div>`);
          }
          if ((kb.oob_replaced_by_kbs || []).length) {
            supersessionParts.push(`<div style="color:var(--affected-fg)"><strong>OOB Replaced By:</strong> ${kb.oob_replaced_by_kbs.map(escapeHtml).join(", ")}</div>`);
          }
          if ((kb.supersedes_kbs || []).length && !(kb.oob_replaces_kbs || []).length) {
            supersessionParts.push(`<div>Supersedes: ${kb.supersedes_kbs.map(escapeHtml).join(", ")}</div>`);
          }
          if ((kb.superseded_by_kbs || []).length && !(kb.oob_replaced_by_kbs || []).length) {
            supersessionParts.push(`<div style="color:var(--text-secondary)">Superseded by: ${kb.superseded_by_kbs.map(escapeHtml).join(", ")}</div>`);
          }
          const supersessionHtml = supersessionParts.length
            ? supersessionParts.join("")
            : `<span style="color:var(--text-muted)">Current Branch Head</span>`;

          const secHtml = `
            <div>
              ${kb.is_security_update ? `<span class="flag-tag flag-sec">Security</span>` : `<span class="mini-pill">Non-Security</span>`}
              ${kb.exploited_cve_count > 0 ? `<span class="flag-tag flag-exploited">${kb.exploited_cve_count} Zero-Day</span>` : ""}
            </div>
            <div style="font-size:11.5px; color:var(--text-secondary); margin-top:2px;">
              ${kb.cve_count} CVE(s) mapped
            </div>
          `;

          const issuesHtml =
            kb.known_issues_count > 0
              ? `<div><strong>${kb.known_issues_count} Issue(s)</strong> (${kb.active_issues_count} Active)</div>`
              : `<span style="color:var(--safe-fg)">0 Known Issues</span>`;

          const originBadge = kb.is_demo
            ? `<span class="flag-tag flag-demo" title="Seeded Local Reference Dataset">Ref Seed</span>`
            : `<span class="flag-tag flag-sec" title="Verified Live Microsoft Sync">Live MS</span>`;

          return `
            <tr data-kb="${escapeHtml(kb.kb_number)}">
              <td>
                <button type="button" class="kb-code-btn">${escapeHtml(kb.kb_number)}</button>
                <div style="font-size:11.5px; color:var(--text-secondary); max-width:250px; margin-top:2px;">
                  ${escapeHtml(kb.title)}
                </div>
              </td>
              <td style="font-family:var(--font-mono); white-space:nowrap;">
                <div>${escapeHtml(kb.release_date)}</div>
                <div style="font-size:11px; color:var(--text-muted);">Cycle: ${escapeHtml(kb.patch_tuesday_cycle)}</div>
              </td>
              <td>
                <div style="font-weight:600;">${escapeHtml(kb.windows_version)}</div>
                <div style="font-family:var(--font-mono); font-size:11.5px; color:var(--text-secondary);">Build ${escapeHtml(kb.os_build)}</div>
              </td>
              <td>${escapeHtml(kb.update_type)}</td>
              <td>${secHtml}</td>
              <td>${issuesHtml}</td>
              <td>
                <span class="status-badge badge-${escapeHtml(kb.health_status)}">${escapeHtml(kb.health_status)}</span>
                <div style="font-size:11px; color:var(--text-secondary); max-width:240px; margin-top:4px;">
                  ${escapeHtml((kb.health_rationale || "").slice(0, 95))}${(kb.health_rationale || "").length > 95 ? "&hellip;" : ""}
                </div>
              </td>
              <td>${flags.join("")}</td>
              <td style="font-family:var(--font-mono); font-size:11.5px;">${supersessionHtml}</td>
              <td style="font-size:11.5px;">
                <div>${originBadge}</div>
                <div style="color:var(--text-muted); font-family:var(--font-mono); margin-top:2px;" title="UTC: ${escapeHtml(kb.last_checked_at || "")}">
                  ${escapeHtml(kb.last_checked_at ? formatLocalDateTime(kb.last_checked_at, false) : "—")}
                </div>
              </td>
            </tr>
          `;
        })
        .join("");

      tbody.querySelectorAll("tr[data-kb]").forEach((row) => {
        row.addEventListener("click", () => {
          openKbModal(row.getAttribute("data-kb"));
        });
      });
    } catch (err) {
      showError(err.message);
      tbody.innerHTML = `<tr><td colspan="10" class="empty-state">Error loading updates: ${escapeHtml(err.message)}</td></tr>`;
    }
  }

  function populateCycleDropdown(cycles) {
    const sel = document.getElementById("filterCycle");
    if (!sel) return;
    const sortedCycles = (cycles || []).filter(Boolean).slice().sort().reverse();
    if (sortedCycles.length > 0) {
      state.latest_cycle = sortedCycles[0];
      if (state.patch_tuesday_cycle === "latest") {
        state.patch_tuesday_cycle = sortedCycles[0];
      }
    } else if (state.patch_tuesday_cycle === "latest") {
      state.patch_tuesday_cycle = "all";
    }

    sel.innerHTML = "";
    sortedCycles.forEach((c, idx) => {
      const opt = document.createElement("option");
      opt.value = c;
      opt.textContent = idx === 0 ? `${c} (Latest)` : c;
      sel.appendChild(opt);
    });
    const allOpt = document.createElement("option");
    allOpt.value = "all";
    allOpt.textContent = "All Cycles";
    sel.appendChild(allOpt);

    sel.value = state.patch_tuesday_cycle;
  }

  function updateHealthCardSelection() {
    document.querySelectorAll(".health-card").forEach((card) => {
      const cardSt = card.getAttribute("data-status");
      const active = state.status === cardSt;
      card.classList.toggle("active-filter", active);
      card.setAttribute("aria-pressed", active ? "true" : "false");
    });
  }

  function updatePaginationControls(total, page, totalPages) {
    const info = document.getElementById("paginationInfo");
    const indicator = document.getElementById("pageIndicator");
    const prevBtn = document.getElementById("prevPageBtn");
    const nextBtn = document.getElementById("nextPageBtn");

    if (info) info.textContent = `Matching Windows Updates: ${total}`;
    if (indicator) indicator.textContent = `Page ${page} of ${totalPages}`;
    if (prevBtn) prevBtn.disabled = page <= 1;
    if (nextBtn) nextBtn.disabled = page >= totalPages;
  }

  /* HUMAN-FRIENDLY STAGE TIMELINE HELPERS */
  function formatStageDate(dateStr) {
    if (!dateStr) return { main: "—", sub: "" };
    const clean = String(dateStr).trim();
    const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

    // Date-only (YYYY-MM-DD): preserve exact calendar day without timezone shifting
    const dateOnlyMatch = clean.match(/^(\d{4})-(\d{2})-(\d{2})$/);
    if (dateOnlyMatch) {
      const year = dateOnlyMatch[1];
      const mon = months[parseInt(dateOnlyMatch[2], 10) - 1] || dateOnlyMatch[2];
      const day = dateOnlyMatch[3];
      return { main: `${mon} ${day}`, sub: year };
    }

    // Date with time: convert UTC timestamp to browser's local timezone
    const withT = clean.replace(/^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2})/, "$1T$2");
    const normalized =
      withT.includes("T") && !withT.endsWith("Z") && !/[+-]\d{2}:?\d{2}$/.test(withT)
        ? `${withT}Z`
        : withT;
    const dt = new Date(normalized);
    if (!Number.isNaN(dt.getTime())) {
      const pad = (n) => String(n).padStart(2, "0");
      const mon = months[dt.getMonth()];
      const day = pad(dt.getDate());
      const year = dt.getFullYear();
      const hh = pad(dt.getHours());
      const min = pad(dt.getMinutes());
      const offsetMin = -dt.getTimezoneOffset();
      const sign = offsetMin >= 0 ? "+" : "-";
      const absMin = Math.abs(offsetMin);
      const offH = pad(Math.floor(absMin / 60));
      const offM = absMin % 60;
      const tzLabel = offM ? `UTC${sign}${offH}:${pad(offM)}` : `UTC${sign}${Number(offH)}`;
      return {
        main: `${mon} ${day}`,
        sub: `${year} • ${hh}:${min} (${tzLabel})`,
      };
    }

    return { main: clean, sub: "" };
  }

  function getStageSvgIcon(type) {
    switch (type) {
      case "release":
        return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/></svg>`;
      case "issue":
        return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
      case "kir":
        return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>`;
      case "oob":
        return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>`;
      default:
        return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>`;
    }
  }

  function buildStageTimelineEvents(d) {
    const stages = [];
    const seenKeys = new Set();

    // 1. Convert lifecycle milestones into human-friendly timeline stages
    (d.lifecycle || []).forEach((ev) => {
      const et = String(ev.event_type || "").toUpperCase();
      let theme = "stage-theme-blue";
      let iconType = "release";
      let kicker = "OFFICIAL LIFECYCLE EVENT";

      if (et.includes("ISSUE") || et.includes("REGRESSION")) {
        theme = "stage-theme-red";
        iconType = "issue";
        kicker = "REGRESSION DETECTED";
      } else if (et.includes("KIR") || et.includes("MITIGATION")) {
        theme = "stage-theme-amber";
        iconType = "kir";
        kicker = "KNOWN ISSUE ROLLBACK (KIR)";
      } else if (et.includes("OOB") || et.includes("HOTFIX")) {
        theme = "stage-theme-purple";
        iconType = "oob";
        kicker = "OUT-OF-BAND REMEDIATION";
      } else if (et.includes("RESOLV") || et.includes("RELEASE")) {
        theme = "stage-theme-blue";
        iconType = "release";
        kicker = "MICROSOFT RELEASE MILESTONE";
      }

      const key = `${ev.event_date}|${ev.title}`;
      seenKeys.add(key);
      stages.push({
        sortDate: ev.event_date || "",
        dateObj: formatStageDate(ev.event_date),
        theme,
        iconSvg: getStageSvgIcon(iconType),
        kicker,
        title: ev.title || et,
        desc: ev.details || "",
        auditBadge: `Source: Microsoft Release Health`,
      });
    });

    // 2. Group field-level audit changes by (detected_at, entity_type, entity_id)
    // so multiple fields changed in the same sync become one coherent story card
    const groupedChanges = new Map();
    (d.changes || []).forEach((ch) => {
      const gKey = `${ch.detected_at}|${ch.entity_type}|${ch.entity_id}`;
      if (!groupedChanges.has(gKey)) {
        groupedChanges.set(gKey, {
          detected_at: ch.detected_at,
          entity_type: ch.entity_type,
          entity_id: ch.entity_id,
          change_type: ch.change_type,
          new_hash: ch.new_hash,
          fields: {},
          rawList: [],
        });
      }
      const grp = groupedChanges.get(gKey);
      grp.fields[ch.field_name] = { old: ch.old_value, new: ch.new_value, type: ch.change_type };
      grp.rawList.push(ch);
    });

    groupedChanges.forEach((grp) => {
      const f = grp.fields;
      let theme = "stage-theme-blue";
      let iconType = "audit";
      let kicker = "TELEMETRY AUDIT SNAPSHOT";
      let title = "";
      let desc = "";

      if (grp.entity_type === "KB") {
        if (grp.change_type === "ADDED" || f.release_date) {
          theme = "stage-theme-green";
          iconType = "release";
          kicker = "INITIAL TELEMETRY INGESTION";
          title = `${d.kb_number} Indexed in Patch Alert`;
          const updType = f.update_type ? f.update_type.new : d.update_type;
          const osBuild = f.os_build ? f.os_build.new : d.os_build;
          desc = `Microsoft published ${d.kb_number} (${updType || "Cumulative Update"}, OS Build ${osBuild || d.os_build}). Initial cryptographic SHA-256 baseline recorded.`;
        } else {
          theme = "stage-theme-blue";
          iconType = "audit";
          kicker = "KB METADATA UPDATED";
          title = `Microsoft Updated ${d.kb_number} Advisory Metadata`;
          const changedNames = Object.keys(f).join(", ");
          desc = `Automated collector detected modifications in official Microsoft advisory fields (${changedNames}).`;
        }
      } else if (grp.entity_type === "KNOWN_ISSUE") {
        const issTitle = f.title ? f.title.new : null;
        const issSeverity = f.severity ? f.severity.new : null;
        const issStatus = f.status ? f.status.new : null;
        const hasKir = f.has_kir ? f.has_kir.new === "True" || f.has_kir.new === "1" : false;

        // Avoid duplicating an identical event if already described by lifecycle on same day,
        // or enrich it as the verified audit checkpoint
        if (hasKir) {
          theme = "stage-theme-amber";
          iconType = "kir";
          kicker = "AUTOMATED ROLLBACK DETECTED";
          title = issTitle ? `KIR Activated: ${issTitle}` : `Known Issue Rollback (KIR) Published`;
          desc = `Microsoft enabled a Known Issue Rollback (KIR) for this regression${issStatus ? ` (Status: ${issStatus})` : ""}. Managed enterprise devices may require the Group Policy MSI template.`;
        } else if (issSeverity === "Critical" || issSeverity === "High") {
          theme = "stage-theme-red";
          iconType = "issue";
          kicker = `CONFIRMED REGRESSION (${(issSeverity || "HIGH").toUpperCase()} IMPACT)`;
          title = issTitle || `Known Issue Logged on ${d.kb_number}`;
          desc = `Microsoft Release Health logged an active regression affecting ${d.kb_number}${issStatus ? ` with status "${issStatus}"` : ""}. Deployment should be paused or evaluated against mitigations.`;
        } else {
          theme = "stage-theme-amber";
          iconType = "issue";
          kicker = "KNOWN ISSUE TELEMETRY";
          title = issTitle || `Known Issue Status Updated (${grp.entity_id})`;
          desc = `Issue telemetry recorded${issStatus ? ` — Current status: ${issStatus}` : ""}${issSeverity ? `, Impact: ${issSeverity}` : ""}.`;
        }
      } else if (grp.entity_type === "CVE") {
        const cveCode = String(grp.entity_id || "").split(":")[0] || "CVE";
        const cveTitle = f.title ? f.title.new : "Security Vulnerability Advisory";
        const cveSev = f.severity ? f.severity.new : "";
        const exploited = f.is_exploited && (f.is_exploited.new === "True" || f.is_exploited.new === "1");
        theme = exploited ? "stage-theme-red" : "stage-theme-blue";
        iconType = exploited ? "issue" : "kir";
        kicker = exploited ? "MSRC EXPLOITED VULNERABILITY MAPPED" : "MSRC SECURITY ADVISORY MAPPED";
        title = `${cveCode} — ${cveTitle}`;
        desc = `Mapped official MSRC security advisory to ${d.kb_number}${cveSev ? ` (Severity: ${cveSev})` : ""}${exploited ? ". Confirmed exploited in the wild." : "."}`;
      } else {
        title = `${grp.entity_type} Change Detected`;
        desc = `Field-level change recorded for ${grp.entity_id}.`;
      }

      const shortHash = grp.new_hash ? grp.new_hash.slice(0, 12) : "verified";
      stages.push({
        sortDate: grp.detected_at || "",
        dateObj: formatStageDate(grp.detected_at),
        theme,
        iconSvg: getStageSvgIcon(iconType),
        kicker,
        title,
        desc,
        auditBadge: `SHA-256: ${shortHash}… (${grp.rawList.length} field${grp.rawList.length > 1 ? "s" : ""} verified)`,
      });
    });

    // Sort reverse-chronologically (most recent at the top)
    stages.sort((a, b) => String(b.sortDate).localeCompare(String(a.sortDate)));
    return stages;
  }

  /* KB DOSSIER DETAIL MODAL */
  async function openKbModal(kbNumber) {
    if (!kbNumber) return;
    const backdrop = document.getElementById("kbModalBackdrop");
    const body = document.getElementById("modalBodyContent");
    const titleEl = document.getElementById("modalKbTitle");
    const metaEl = document.getElementById("modalKbMeta");
    const badgesEl = document.getElementById("modalTopBadges");

    if (!backdrop || !body) return;
    backdrop.classList.remove("hidden");
    body.innerHTML = `<div class="empty-state">Loading full intelligence dossier for ${escapeHtml(kbNumber)}...</div>`;

    try {
      const d = await apiGet(`/api/kbs/${encodeURIComponent(kbNumber)}`);
      const kbSupportUrl = getKbSupportUrl(d.kb_number);
      const kbCatalogUrl = getKbCatalogUrl(d.kb_number);

      if (badgesEl) {
        badgesEl.innerHTML = `
          <span class="status-badge badge-${escapeHtml(d.health_status)}">${escapeHtml(d.health_status)}</span>
          <span class="mini-pill">${escapeHtml(d.windows_version)}</span>
          <span class="mini-pill">OS Build ${escapeHtml(d.os_build)}</span>
          <span class="mini-pill">${escapeHtml(d.update_type)}</span>
          ${d.is_oob ? `<span class="flag-tag flag-oob">OUT-OF-BAND (OOB)</span>` : ""}
          ${d.has_kir ? `<span class="flag-tag flag-kir">KNOWN ISSUE ROLLBACK (KIR)</span>` : ""}
          <span class="mini-pill">${escapeHtml(d.data_origin)}</span>
        `;
      }
      if (titleEl) titleEl.textContent = `${d.kb_number} — ${d.title}`;
      if (metaEl) {
        metaEl.innerHTML = `
          Released: <strong>${escapeHtml(d.release_date)}</strong> (Patch Tuesday Cycle: ${escapeHtml(d.patch_tuesday_cycle)})
          &bull; Telemetry Verified: <strong>${d.telemetry_verified ? "Yes" : "No (Unverified)"}</strong>
          &bull; <a href="${escapeHtml(kbSupportUrl)}" target="_blank" rel="noopener noreferrer" style="font-weight:700;">Official KB Article (${escapeHtml(d.kb_number)}) &nearr;</a>
        `;
      }

      // 0. Quick Official Microsoft Links Bar (Support KB URL, Release Health, Update Catalog)
      const linksBarHtml = `
        <div class="kb-links-bar">
          <div class="kb-links-bar-label">Official Microsoft Resources</div>
          <div class="kb-links-actions">
            <a href="${escapeHtml(kbSupportUrl)}" target="_blank" rel="noopener noreferrer" class="kb-ext-btn btn-ms-support" title="Open official Microsoft Support article for ${escapeHtml(d.kb_number)}">
              <span>Microsoft Support Article (${escapeHtml(d.kb_number)})</span>
              <span>&nearr;</span>
            </a>
            <a href="${escapeHtml(d.source_url)}" target="_blank" rel="noopener noreferrer" class="kb-ext-btn" title="Open Windows Release Health dashboard for ${escapeHtml(d.windows_version)}">
              <span>Windows Release Health (${escapeHtml(d.windows_version)})</span>
              <span>&nearr;</span>
            </a>
            <a href="${escapeHtml(kbCatalogUrl)}" target="_blank" rel="noopener noreferrer" class="kb-ext-btn" title="Download standalone MSU/CAB package from Microsoft Update Catalog">
              <span>Microsoft Update Catalog (.msu)</span>
              <span>&nearr;</span>
            </a>
          </div>
        </div>
      `;

      // 1. Operational Health Rationale ("Why this status?")
      const factorsList = (d.risk_factors || [])
        .map((f) => `<li>${escapeHtml(f)}</li>`)
        .join("");

      // 2. Known Issues & Mitigations + KIR (Human-friendly)
      const issuesHtml = (d.known_issues || []).length
        ? d.known_issues
            .map((iss) => {
              const kirBlock = iss.has_kir
                ? `
                  <div style="margin-top:10px; padding:10px 12px; border-radius:6px; background:var(--caution-bg); border:1px solid var(--caution-border);">
                    <div style="font-weight:800; color:var(--caution-fg); display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:6px;">
                      <span>🛡 Known Issue Rollback (KIR) Active</span>
                      <span class="mini-pill" style="color:var(--caution-fg); border-color:var(--caution-border);">
                        ${iss.kir_restart_required ? "Reboot Required to Apply" : "No Reboot Required"}
                      </span>
                    </div>
                    <div style="font-size:12px; margin-top:6px; line-height:1.5;">
                      <div><strong>How it is deployed:</strong> ${escapeHtml(iss.kir_deployment_method || "Delivered automatically via Windows Update to unmanaged devices.")}</div>
                      ${iss.kir_gpo_name ? `<div style="margin-top:3px;"><strong>For Domain / Intune / GPO Admins:</strong> Deploy Group Policy MSI template <code>${escapeHtml(iss.kir_gpo_name)}</code></div>` : ""}
                    </div>
                  </div>
                `
                : "";

              return `
                <div class="dossier-card">
                  <div style="display:flex; justify-content:space-between; gap:8px; flex-wrap:wrap; margin-bottom:6px; align-items:flex-start;">
                    <strong style="font-size:13.5px; color:var(--text-primary);">${escapeHtml(iss.title)}</strong>
                    <div style="display:flex; gap:6px; align-items:center; flex-wrap:wrap;">
                      <span class="mini-pill">Status: <strong>${escapeHtml(iss.status)}</strong></span>
                      <span class="mini-pill">Impact: <strong>${escapeHtml(iss.severity)}</strong></span>
                      ${iss.oob_fix_kb ? `<button type="button" class="kb-code-btn modal-kb-jump" data-kb="${escapeHtml(iss.oob_fix_kb)}">Fixed in OOB ${escapeHtml(iss.oob_fix_kb)}</button>` : ""}
                    </div>
                  </div>
                  <div style="font-size:12.5px; color:var(--text-secondary); margin-bottom:8px; line-height:1.55;">
                    <strong>What happens:</strong> ${escapeHtml(iss.symptoms)}
                  </div>
                  ${iss.workaround ? `<div style="font-size:12.5px; margin-bottom:4px; line-height:1.5;"><strong>Recommended Workaround / Mitigation:</strong> ${escapeHtml(iss.workaround)}</div>` : ""}
                  ${iss.resolution ? `<div style="font-size:12.5px; margin-bottom:4px; line-height:1.5;"><strong>Official Resolution:</strong> ${escapeHtml(iss.resolution)}</div>` : ""}
                  ${kirBlock}
                  <div style="font-size:11px; color:var(--text-muted); margin-top:8px; font-family:var(--font-mono); display:flex; justify-content:space-between; flex-wrap:wrap; gap:6px;">
                    <span>Reported: ${escapeHtml(iss.opened_date || "—")} &bull; Last Updated: ${escapeHtml(iss.last_updated_date || "—")}</span>
                  </div>
                </div>
              `;
            })
            .join("")
        : `<div class="empty-state">No active or recent known issues reported by Microsoft for ${escapeHtml(d.kb_number)}.</div>`;

      // 3. OOB & Supersession Relationships (Human-friendly + support.microsoft.com link)
      const relLabelMap = {
        oob_replaces: "Out-of-Band Replacement For",
        replaced_by_oob: "Replaced by Out-of-Band Hotfix",
        supersedes: "Supersedes Previous Update",
        superseded_by: "Superseded By Newer Update",
      };
      const relsHtml = (d.relationships || []).length
        ? d.relationships
            .map((r) => {
              const friendlyRel = relLabelMap[r.relationship_type] || r.relationship_type.replace(/_/g, " ").toUpperCase();
              const relatedSupportUrl = getKbSupportUrl(r.related_kb);
              return `
              <div class="dossier-card" style="display:flex; justify-content:space-between; align-items:center; gap:10px; flex-wrap:wrap;">
                <div>
                  <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
                    <span class="mini-pill" style="font-weight:700;">${escapeHtml(friendlyRel)}</span>
                    <button type="button" class="kb-code-btn modal-kb-jump" data-kb="${escapeHtml(r.related_kb)}" title="Inspect ${escapeHtml(r.related_kb)} in Patch Alert">
                      ${escapeHtml(r.related_kb)}
                    </button>
                  </div>
                  <div style="font-size:12.5px; color:var(--text-secondary); margin-top:5px;">
                    ${escapeHtml(r.description || "")}
                  </div>
                </div>
                <div style="display:flex; gap:6px; align-items:center;">
                  <a href="${escapeHtml(relatedSupportUrl)}" target="_blank" rel="noopener noreferrer" class="btn btn-secondary btn-sm" title="Open Microsoft Support page for ${escapeHtml(r.related_kb)}">
                    MS Support (${escapeHtml(r.related_kb)}) &nearr;
                  </a>
                </div>
              </div>
            `;
            })
            .join("")
        : `<div class="empty-state">No Out-of-Band hotfix replacements or supersession issues recorded for this KB.</div>`;

      // 4. MSRC CVEs
      const cvesHtml = (d.cves || []).length
        ? d.cves
            .map(
              (c) => `
              <div class="dossier-card">
                <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:6px;">
                  <div>
                    <strong style="font-family:var(--font-mono); font-size:13px;">${escapeHtml(c.cve_id)}</strong>
                    — <span style="font-weight:600;">${escapeHtml(c.title)}</span>
                  </div>
                  <div style="display:flex; gap:6px; align-items:center;">
                    ${c.is_exploited ? `<span class="flag-tag flag-exploited">EXPLOITED IN THE WILD</span>` : ""}
                    <span class="mini-pill">${escapeHtml(c.severity)} ${c.cvss_score ? `(CVSS ${c.cvss_score})` : ""}</span>
                  </div>
                </div>
                <div style="font-size:12px; color:var(--text-secondary); margin-top:6px; display:flex; justify-content:space-between; flex-wrap:wrap; gap:6px;">
                  <span><strong>Affected Component:</strong> ${escapeHtml(c.affected_component)} &bull; <strong>Exploitability:</strong> ${escapeHtml(c.exploitability_status)}</span>
                  <a href="${escapeHtml(c.source_url)}" target="_blank" rel="noopener noreferrer" style="font-weight:600;">Official MSRC CVE Advisory &nearr;</a>
                </div>
              </div>
            `
            )
            .join("")
        : `<div class="empty-state">No MSRC CVEs mapped to this update (or non-security preview release).</div>`;

      // 5. Visual Central-Spine Alternating Timeline (Lifecycle + Audit History, newest at top)
      const stages = buildStageTimelineEvents(d);
      const stageTimelineHtml = stages.length
        ? `<div class="stage-timeline">` +
          stages
            .map((st, idx) => {
              const sideClass = idx % 2 === 0 ? "stage-left" : "stage-right";
              const stageNum = stages.length - idx;
              const latestTag = idx === 0 ? "LATEST &bull; " : "";
              return `
                <div class="stage-row ${sideClass} ${escapeHtml(st.theme)}">
                  <div class="stage-node" title="Stage ${stageNum}"></div>
                  <div class="stage-card">
                    <div class="stage-card-meta">
                      <div class="stage-date-main">${escapeHtml(st.dateObj.main)}</div>
                      ${st.dateObj.sub ? `<div class="stage-date-sub">${escapeHtml(st.dateObj.sub)}</div>` : ""}
                      <div class="stage-icon-box" aria-hidden="true">
                        ${st.iconSvg}
                      </div>
                    </div>
                    <div class="stage-card-content">
                      <div class="stage-card-kicker">${latestTag}STAGE ${stageNum} &bull; ${escapeHtml(st.kicker)}</div>
                      <div class="stage-card-title">${escapeHtml(st.title)}</div>
                      <div class="stage-card-desc">${escapeHtml(st.desc)}</div>
                      <div class="stage-card-audit">${escapeHtml(st.auditBadge)}</div>
                    </div>
                  </div>
                </div>
              `;
            })
            .join("") +
          `</div>`
        : `<div class="empty-state">No timeline or audit events recorded for this KB yet.</div>`;

      // Optional collapsible raw technical field diff table for auditors
      const rawAuditHtml = (d.changes || []).length
        ? `
          <details class="raw-audit-details">
            <summary>View Raw Cryptographic Field-Level Diffs (${d.changes.length} database records)</summary>
            <div style="margin-top:8px; display:flex; flex-direction:column; gap:6px;">
              ${d.changes
                .map(
                  (ch) => `
                  <div class="dossier-card" style="font-size:11.5px; margin-bottom:0; padding:8px 10px;">
                    <div style="display:flex; justify-content:space-between; font-family:var(--font-mono); color:var(--text-muted);">
                      <span><strong>${escapeHtml(ch.entity_type)}</strong> (${escapeHtml(ch.entity_id)}) &bull; Field: <code>${escapeHtml(ch.field_name)}</code> [${escapeHtml(ch.change_type)}]</span>
                      <span title="UTC: ${escapeHtml(ch.detected_at || "")}">${escapeHtml(formatLocalDateTime(ch.detected_at, true))}</span>
                    </div>
                    <div style="color:var(--text-secondary); margin-top:3px; font-family:var(--font-mono);">
                      ${ch.old_value ? `Old: <code>${escapeHtml(ch.old_value)}</code> &rarr; ` : ""}
                      New: <code>${escapeHtml(ch.new_value || "")}</code>
                    </div>
                  </div>
                `
                )
                .join("")}
            </div>
          </details>
        `
        : "";

      body.innerHTML = `
        ${linksBarHtml}

        <div class="rationale-box rationale-${escapeHtml(d.health_status)}">
          <div style="font-weight:800; font-size:13px; margin-bottom:4px; letter-spacing:0.03em;">
            ADMIN DEPLOYMENT GUIDANCE — WHY IS ${escapeHtml(d.kb_number)} MARKED AS ${escapeHtml(d.health_status)}?
          </div>
          <p style="font-size:13px; margin-bottom:8px; line-height:1.55;">${escapeHtml(d.health_rationale)}</p>
          ${factorsList ? `<ul style="padding-left:18px; font-size:12.5px; color:var(--text-secondary); line-height:1.55;">${factorsList}</ul>` : ""}
        </div>

        ${d.summary || d.highlights ? `
          <div class="dossier-section">
            <div class="dossier-section-title">What Is Included in This Update</div>
            ${d.summary ? `<p style="margin-bottom:6px; font-size:13px; line-height:1.55;">${escapeHtml(d.summary)}</p>` : ""}
            ${d.highlights ? `<p style="color:var(--text-secondary); font-size:12.5px; line-height:1.55;"><strong>Key Highlights:</strong> ${escapeHtml(d.highlights)}</p>` : ""}
          </div>
        ` : ""}

        <div class="dossier-section">
          <div class="dossier-section-title">Known Issues, Workarounds &amp; Rollback (KIR) (${(d.known_issues || []).length})</div>
          ${issuesHtml}
        </div>

        <div class="dossier-grid-2">
          <div class="dossier-section">
            <div class="dossier-section-title">Out-of-Band (OOB) &amp; Supersession Chain (${(d.relationships || []).length})</div>
            ${relsHtml}
          </div>

          <div class="dossier-section">
            <div class="dossier-section-title">Mapped MSRC Security Advisories &amp; CVEs (${(d.cves || []).length})</div>
            ${cvesHtml}
          </div>
        </div>

        <div class="dossier-section">
          <div class="dossier-section-title">Update History &amp; Audit Timeline (${stages.length} Stages)</div>
          <p style="font-size:12px; color:var(--text-secondary); margin-bottom:10px;">
            Chronological history of Microsoft releases, reported regressions, rollbacks, and automated telemetry snapshots for <strong>${escapeHtml(d.kb_number)}</strong>.
          </p>
          ${stageTimelineHtml}
          ${rawAuditHtml}
        </div>
      `;

      body.querySelectorAll(".modal-kb-jump").forEach((btn) => {
        btn.addEventListener("click", (e) => {
          e.stopPropagation();
          openKbModal(btn.getAttribute("data-kb"));
        });
      });
    } catch (err) {
      body.innerHTML = `<div class="empty-state" style="color:var(--affected-fg)">Failed to load KB dossier: ${escapeHtml(err.message)}</div>`;
    }
  }

  function closeKbModal() {
    const backdrop = document.getElementById("kbModalBackdrop");
    if (backdrop) backdrop.classList.add("hidden");
  }

  /* GLOBAL SEARCH */
  async function runGlobalSearch(query) {
    const dropdown = document.getElementById("globalSearchDropdown");
    if (!dropdown) return;
    const cleaned = (query || "").trim();
    if (!cleaned) {
      dropdown.classList.add("hidden");
      return;
    }

    try {
      const data = await apiGet(`/api/search?q=${encodeURIComponent(cleaned)}`);
      dropdown.classList.remove("hidden");
      if (!data.total_results) {
        dropdown.innerHTML = `<div class="empty-state">No KBs, CVEs, Known Issues, or OS Builds match "${escapeHtml(cleaned)}".</div>`;
        return;
      }

      let html = "";
      if ((data.kbs || []).length) {
        html += `<div class="search-section-title">Windows Updates (${data.kbs.length})</div>`;
        html += data.kbs
          .map(
            (k) => `
            <div class="search-result-item" data-kb="${escapeHtml(k.kb_number)}">
              <div>
                <strong style="font-family:var(--font-mono); color:var(--accent-primary);">${escapeHtml(k.kb_number)}</strong>
                <span>${escapeHtml(k.windows_version)} (${escapeHtml(k.os_build)})</span>
              </div>
              <span class="status-badge badge-${escapeHtml(k.health_status)}">${escapeHtml(k.health_status)}</span>
            </div>
          `
          )
          .join("");
      }

      if ((data.cves || []).length) {
        html += `<div class="search-section-title">MSRC CVEs (${data.cves.length})</div>`;
        html += data.cves
          .map(
            (c) => `
            <div class="search-result-item" data-kb="${escapeHtml(c.kb_number)}">
              <div>
                <strong style="font-family:var(--font-mono);">${escapeHtml(c.cve_id)}</strong>
                <span>${escapeHtml(c.title)} (${escapeHtml(c.kb_number)})</span>
              </div>
              <span class="mini-pill">${escapeHtml(c.severity)}</span>
            </div>
          `
          )
          .join("");
      }

      if ((data.known_issues || []).length) {
        html += `<div class="search-section-title">Known Issues (${data.known_issues.length})</div>`;
        html += data.known_issues
          .map(
            (i) => `
            <div class="search-result-item" data-kb="${escapeHtml(i.kb_number)}">
              <div>
                <strong>${escapeHtml(i.kb_number)}:</strong>
                <span>${escapeHtml(i.title.slice(0, 90))}</span>
              </div>
              <span class="mini-pill">${escapeHtml(i.status)}</span>
            </div>
          `
          )
          .join("");
      }

      dropdown.innerHTML = html;
      dropdown.querySelectorAll(".search-result-item[data-kb]").forEach((item) => {
        item.addEventListener("click", () => {
          dropdown.classList.add("hidden");
          openKbModal(item.getAttribute("data-kb"));
        });
      });
    } catch (err) {
      showError(err.message);
    }
  }

  /* MANUAL SYNC ACTION */
  async function triggerManualSync() {
    const btn = document.getElementById("syncNowBtn");
    const spinner = document.getElementById("syncSpinner");
    const label = document.getElementById("syncBtnLabel");
    if (!btn) return;

    btn.disabled = true;
    if (spinner) spinner.classList.remove("hidden");
    if (label) label.textContent = "Syncing Microsoft...";

    try {
      await apiPost("/api/collector/sync-now?wait=true");
      await Promise.all([
        loadDashboardStats(),
        loadKBs(),
        loadAlerts(),
        loadAuditChanges(),
        loadSources(),
      ]);
    } catch (err) {
      showError(err.message);
    } finally {
      btn.disabled = false;
      if (spinner) spinner.classList.add("hidden");
      if (label) label.textContent = "Sync Microsoft";
    }
  }

  /* EVENT BINDINGS */
  function bindEvents() {
    // Health cards click-to-filter
    document.querySelectorAll(".health-card").forEach((card) => {
      card.addEventListener("click", () => {
        const targetStatus = card.getAttribute("data-status");
        state.status = state.status === targetStatus ? "ALL" : targetStatus;
        const statusSelect = document.getElementById("filterStatus");
        if (statusSelect) statusSelect.value = state.status;
        state.page = 1;
        loadKBs();
      });
    });

    // Tabs switching
    document.querySelectorAll(".tab-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        const targetTab = btn.getAttribute("data-tab");
        document.querySelectorAll(".tab-btn").forEach((b) => {
          b.classList.toggle("active", b === btn);
          b.setAttribute("aria-selected", b === btn ? "true" : "false");
        });
        document.querySelectorAll(".tab-pane").forEach((pane) => {
          pane.classList.toggle("hidden", pane.id !== targetTab);
          pane.classList.toggle("active", pane.id === targetTab);
        });
      });
    });

    // Header Source Status button switches to Sources tab
    const srcPillBtn = document.getElementById("sourceStatusBtn");
    if (srcPillBtn) {
      srcPillBtn.addEventListener("click", () => {
        const sourcesTabBtn = document.querySelector('.tab-btn[data-tab="sourcesTab"]');
        if (sourcesTabBtn) {
          sourcesTabBtn.click();
          sourcesTabBtn.scrollIntoView({ behavior: "smooth", block: "center" });
        }
      });
    }

    // Filter inputs
    const kbSearchInput = document.getElementById("kbSearchInput");
    let filterDebounce = null;
    if (kbSearchInput) {
      kbSearchInput.addEventListener("input", () => {
        clearTimeout(filterDebounce);
        filterDebounce = setTimeout(() => {
          state.q = kbSearchInput.value.trim();
          state.page = 1;
          loadKBs();
        }, 220);
      });
    }

    const bindSelect = (id, key) => {
      const el = document.getElementById(id);
      if (el) {
        el.addEventListener("change", () => {
          state[key] = el.value;
          state.page = 1;
          loadKBs();
          if (key === "patch_tuesday_cycle") {
            loadDashboardStats();
          }
        });
      }
    };

    bindSelect("filterVersion", "windows_version");
    bindSelect("filterStatus", "status");
    bindSelect("filterUpdateType", "update_type");
    bindSelect("filterCycle", "patch_tuesday_cycle");
    bindSelect("sortBySelect", "sort_by");
    bindSelect("sortOrderSelect", "sort_order");

    const bindCheckbox = (id, key) => {
      const el = document.getElementById(id);
      if (el) {
        el.addEventListener("change", () => {
          state[key] = el.checked ? true : null;
          state.page = 1;
          loadKBs();
        });
      }
    };

    bindCheckbox("toggleOobOnly", "is_oob");
    bindCheckbox("toggleKirOnly", "has_kir");
    bindCheckbox("toggleIssuesOnly", "has_known_issues");
    bindCheckbox("toggleSecurityOnly", "security_only");

    // Reset filters
    const resetBtn = document.getElementById("resetFiltersBtn");
    if (resetBtn) {
      resetBtn.addEventListener("click", () => {
        state.q = "";
        state.windows_version = "all";
        state.status = "ALL";
        state.update_type = "all";
        state.patch_tuesday_cycle = state.latest_cycle || "latest";
        state.is_oob = null;
        state.has_kir = null;
        state.has_known_issues = null;
        state.security_only = null;
        state.sort_by = "release_date";
        state.sort_order = "desc";
        state.page = 1;

        if (kbSearchInput) kbSearchInput.value = "";
        document.getElementById("filterVersion").value = "all";
        document.getElementById("filterStatus").value = "ALL";
        document.getElementById("filterUpdateType").value = "all";
        document.getElementById("filterCycle").value = state.patch_tuesday_cycle;
        document.getElementById("sortBySelect").value = "release_date";
        document.getElementById("sortOrderSelect").value = "desc";
        document.getElementById("toggleOobOnly").checked = false;
        document.getElementById("toggleKirOnly").checked = false;
        document.getElementById("toggleIssuesOnly").checked = false;
        document.getElementById("toggleSecurityOnly").checked = false;

        loadKBs();
        loadDashboardStats();
      });
    }

    // Pagination buttons
    const prevBtn = document.getElementById("prevPageBtn");
    const nextBtn = document.getElementById("nextPageBtn");
    if (prevBtn) {
      prevBtn.addEventListener("click", () => {
        if (state.page > 1) {
          state.page -= 1;
          loadKBs();
        }
      });
    }
    if (nextBtn) {
      nextBtn.addEventListener("click", () => {
        if (state.page < state.total_pages) {
          state.page += 1;
          loadKBs();
        }
      });
    }

    // Global Search
    const gInput = document.getElementById("globalSearchInput");
    const gBtn = document.getElementById("globalSearchBtn");
    let globalDebounce = null;
    if (gInput) {
      gInput.addEventListener("input", () => {
        clearTimeout(globalDebounce);
        globalDebounce = setTimeout(() => runGlobalSearch(gInput.value), 200);
      });
    }
    if (gBtn && gInput) {
      gBtn.addEventListener("click", () => runGlobalSearch(gInput.value));
    }
    document.addEventListener("click", (e) => {
      const wrap = document.querySelector(".header-search-wrap");
      const dropdown = document.getElementById("globalSearchDropdown");
      if (wrap && dropdown && !wrap.contains(e.target)) {
        dropdown.classList.add("hidden");
      }
    });

    // Sync button
    const syncBtn = document.getElementById("syncNowBtn");
    if (syncBtn) {
      syncBtn.addEventListener("click", triggerManualSync);
    }

    // Modal close
    const closeBtn = document.getElementById("closeModalBtn");
    const backdrop = document.getElementById("kbModalBackdrop");
    if (closeBtn) closeBtn.addEventListener("click", closeKbModal);
    if (backdrop) {
      backdrop.addEventListener("click", (e) => {
        if (e.target === backdrop) closeKbModal();
      });
    }
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") closeKbModal();
    });
  }

  async function init() {
    initTheme();
    bindEvents();
    await Promise.all([
      loadDashboardStats(),
      loadKBs(),
      loadAlerts(),
      loadAuditChanges(),
      loadSources(),
    ]);

    // Support ?kb=KB5044284 deep link
    const urlParams = new URLSearchParams(window.location.search);
    const deepKb = urlParams.get("kb");
    if (deepKb) {
      openKbModal(deepKb);
    }
  }

  document.addEventListener("DOMContentLoaded", init);
})();

