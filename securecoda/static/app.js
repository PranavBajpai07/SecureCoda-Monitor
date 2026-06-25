const state = {
  alerts: [],
  selected: null,
  refreshTimer: null,
};

const elements = {
  scanState: document.querySelector("#scan-state"),
  statusFilter: document.querySelector("#status-filter"),
  autoRefresh: document.querySelector("#auto-refresh"),
  scanButton: document.querySelector("#scan-button"),
  body: document.querySelector("#alerts-body"),
  empty: document.querySelector("#empty-state"),
  critical: document.querySelector("#critical-count"),
  high: document.querySelector("#high-count"),
  medium: document.querySelector("#medium-count"),
  open: document.querySelector("#open-count"),
  detailTitle: document.querySelector("#detail-title"),
  detailLocation: document.querySelector("#detail-location"),
  detailRemediation: document.querySelector("#detail-remediation"),
  detailJson: document.querySelector("#detail-json"),
  toast: document.querySelector("#toast"),
};

async function fetchJson(url, options = {}) {
  const response = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload.detail || response.statusText);
  }
  return response.json();
}

function formatDate(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function severityClass(value) {
  return ["critical", "high", "medium", "low"].includes(value) ? value : "low";
}

function renderSummary(summary) {
  const severity = summary.bySeverity || {};
  elements.critical.textContent = severity.critical || 0;
  elements.high.textContent = severity.high || 0;
  elements.medium.textContent = severity.medium || 0;
  elements.open.textContent = summary.open || 0;
}

function renderScanState(latestScan) {
  if (!latestScan) {
    elements.scanState.textContent = "No scan has completed yet";
    return;
  }
  const suffix = latestScan.errors?.length ? `, ${latestScan.errors.length} error(s)` : "";
  elements.scanState.textContent =
    `${latestScan.status} at ${formatDate(latestScan.finished_at || latestScan.started_at)} ` +
    `with ${latestScan.alerts_found} active alert(s)${suffix}`;
}

function renderAlerts(alerts) {
  elements.body.innerHTML = "";
  elements.empty.hidden = alerts.length > 0;

  for (const alert of alerts) {
    const row = document.createElement("tr");
    row.tabIndex = 0;
    row.innerHTML = `
      <td><span class="badge ${severityClass(alert.severity)}">${alert.severity}</span></td>
      <td>${escapeHtml(alert.rule)}</td>
      <td>
        <strong>${escapeHtml(alert.doc_name)}</strong>
        <div class="muted">${escapeHtml(alert.doc_id)}</div>
      </td>
      <td>
        ${escapeHtml(alert.object_type)}
        <div class="muted">${escapeHtml(alert.object_name)}</div>
      </td>
      <td class="summary-cell">${escapeHtml(alert.summary)}</td>
      <td>${formatDate(alert.last_seen)}</td>
      <td>
        <div class="row-actions">
          ${alert.browser_link ? `<button class="ghost" data-open="${escapeAttr(alert.browser_link)}">Open</button>` : ""}
          <button class="danger" data-remediate="${escapeAttr(alert.id)}">Fix</button>
        </div>
      </td>
    `;
    row.addEventListener("click", (event) => {
      if (event.target.closest("button")) return;
      selectAlert(alert);
    });
    row.addEventListener("keydown", (event) => {
      if (event.key === "Enter") selectAlert(alert);
    });
    elements.body.appendChild(row);
  }
}

function selectAlert(alert) {
  state.selected = alert;
  elements.detailTitle.textContent = alert.summary;
  elements.detailLocation.textContent = alert.location || "-";
  elements.detailRemediation.textContent = alert.remediation?.action || "-";
  elements.detailJson.textContent = JSON.stringify(alert.details || {}, null, 2);
}

async function loadAlerts() {
  const status = elements.statusFilter.value;
  const payload = await fetchJson(`/api/alerts?status=${encodeURIComponent(status)}`);
  state.alerts = payload.items;
  renderSummary(payload.summary);
  renderScanState(payload.latestScan);
  renderAlerts(payload.items);
  if (!state.selected && payload.items.length) {
    selectAlert(payload.items[0]);
  }
}

async function triggerScan() {
  elements.scanButton.disabled = true;
  try {
    await fetchJson("/api/scans", { method: "POST" });
    showToast("Scan queued.");
    setTimeout(loadAlerts, 1200);
  } catch (error) {
    showToast(error.message);
  } finally {
    elements.scanButton.disabled = false;
  }
}

async function remediate(alertId, button) {
  button.disabled = true;
  try {
    const result = await fetchJson(`/api/alerts/${encodeURIComponent(alertId)}/remediate`, { method: "POST" });
    showToast(result.message);
    await loadAlerts();
  } catch (error) {
    showToast(error.message);
  } finally {
    button.disabled = false;
  }
}

function showToast(message) {
  elements.toast.textContent = message;
  elements.toast.hidden = false;
  clearTimeout(showToast.timeout);
  showToast.timeout = setTimeout(() => {
    elements.toast.hidden = true;
  }, 4200);
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[char];
  });
}

function escapeAttr(value) {
  return escapeHtml(value).replace(/`/g, "&#096;");
}

elements.statusFilter.addEventListener("change", loadAlerts);
elements.scanButton.addEventListener("click", triggerScan);
elements.body.addEventListener("click", (event) => {
  const open = event.target.closest("[data-open]");
  if (open) {
    window.open(open.dataset.open, "_blank", "noopener");
    return;
  }
  const fix = event.target.closest("[data-remediate]");
  if (fix) remediate(fix.dataset.remediate, fix);
});

elements.autoRefresh.addEventListener("change", () => {
  if (state.refreshTimer) {
    clearInterval(state.refreshTimer);
    state.refreshTimer = null;
  }
  if (elements.autoRefresh.checked) {
    state.refreshTimer = setInterval(loadAlerts, 15000);
  }
});

state.refreshTimer = setInterval(loadAlerts, 15000);
loadAlerts().catch((error) => showToast(error.message));

