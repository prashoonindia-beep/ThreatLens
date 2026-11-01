const API = "/iocs/";
const $ = (id) => document.getElementById(id);
let indicators = [];
let severityChart = null;
let typeChart = null;

function message(text, kind = "info") {
    const el = $("message");
    el.textContent = text;
    el.className = `message ${kind}`;
    el.hidden = false;
    window.clearTimeout(message.timer);
    message.timer = window.setTimeout(() => { el.hidden = true; }, 5000);
}

async function request(url, options = {}) {
    const response = await fetch(url, {
        ...options,
        headers: { ...(options.headers || {}) }
    });
    const body = await response.text();
    let data = null;
    try { data = body ? JSON.parse(body) : null; } catch { data = body; }
    if (!response.ok) throw new Error(data?.detail || data?.message || `HTTP ${response.status}`);
    return data;
}

function setText(id, value) {
    const el = $(id);
    if (el) el.textContent = value === null || value === undefined ? "" : String(value);
}

function cell(value) {
    const td = document.createElement("td");
    td.textContent = value === null || value === undefined || value === "" ? "—" : String(value);
    return td;
}

function dateText(value) {
    if (!value) return "—";
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? String(value) : d.toLocaleString("en-IN");
}

function jsonArray(id, label) {
    const raw = $(id).value.trim() || "[]";
    let parsed;
    try { parsed = JSON.parse(raw); } catch { throw new Error(`${label} must be valid JSON.`); }
    if (!Array.isArray(parsed)) throw new Error(`${label} must be a JSON array.`);
    return JSON.stringify(parsed);
}

function formPayload(edit = false) {
    const ids = edit
        ? { indicator: "editIndicator", type: "editIndicatorType", severity: "editIndicatorSeverity", confidence: "editConfidence", source: "editSource", tlp: "editTlp", status: "editStatus", tags: "editTags", techniques: "editAttackTechniques", notes: "editAnalystNotes" }
        : { indicator: "indicator", type: "indicatorType", severity: "indicatorSeverity", confidence: "confidence", source: null, tlp: "tlp", status: "iocStatus", tags: "tags", techniques: "attackTechniques", notes: "analystNotes" };
    const indicator = $(ids.indicator).value.trim();
    const confidence = Number($(ids.confidence).value);
    if (!indicator) throw new Error("Indicator is required.");
    if (!Number.isInteger(confidence) || confidence < 0 || confidence > 100) {
        throw new Error("Confidence must be between 0 and 100.");
    }
    return {
        indicator,
        indicator_type: $(ids.type).value,
        severity: $(ids.severity).value,
        confidence,
        source: edit ? $(ids.source).value.trim() : "manual",
        tlp: $(ids.tlp).value,
        status: $(ids.status).value,
        tags: jsonArray(ids.tags, "Tags"),
        attack_techniques: jsonArray(ids.techniques, "MITRE ATT&CK IDs"),
        analyst_notes: $(ids.notes).value.trim() || null
    };
}

async function checkHealth() {
    try {
        await request("/health");
        setText("apiStatus", "● API connected");
        $("apiStatus").classList.add("online");
    } catch {
        setText("apiStatus", "● API unavailable");
        $("apiStatus").classList.remove("online");
    }
}

async function loadIndicators() {
    try {
        indicators = await request(API);
        renderIndicators();
        updateDashboard();
    } catch (error) {
        message(`Could not load indicators: ${error.message}`, "error");
        $("iocTable").innerHTML = `<tr><td colspan="9">API request failed.</td></tr>`;
    }
}

function filteredRecords() {
    const search = $("search").value.trim().toLowerCase();
    const type = $("type").value;
    const severity = $("severity").value;
    const status = $("status").value;
    const tlp = $("filterTlp").value;
    return indicators.filter(item => {
        const text = `${item.indicator} ${item.source} ${item.analyst_notes || ""}`.toLowerCase();
        return (!search || text.includes(search))
            && (!type || item.indicator_type === type)
            && (!severity || item.severity === severity)
            && (!status || item.status === status)
            && (!tlp || item.tlp === tlp);
    });
}

function renderIndicators() {
    const tbody = $("iocTable");
    const rows = filteredRecords();
    tbody.replaceChildren();
    setText("count", `${rows.length} of ${indicators.length} indicators`);
    if (!rows.length) {
        const tr = document.createElement("tr");
        const td = cell("No matching indicators found.");
        td.colSpan = 9;
        tr.appendChild(td);
        tbody.appendChild(tr);
        return;
    }
    rows.forEach(item => {
        const tr = document.createElement("tr");
        tr.append(cell(item.indicator), cell(item.indicator_type.toUpperCase()));
        const severity = cell(item.severity);
        severity.innerHTML = "";
        const badge = document.createElement("span");
        badge.className = `badge ${item.severity}`;
        badge.textContent = item.severity;
        severity.appendChild(badge);
        tr.append(severity, cell(item.threat_score), cell(item.source),
            cell(item.confidence), cell(item.tlp), cell(item.status));
        const actions = document.createElement("td");
        const edit = document.createElement("button");
        edit.type = "button";
        edit.className = "table-button";
        edit.textContent = "Edit";
        edit.addEventListener("click", () => openEdit(item));
        const remove = document.createElement("button");
        remove.type = "button";
        remove.className = "table-button danger-button";
        remove.textContent = "Delete";
        remove.addEventListener("click", () => deleteIOC(item.id));
        actions.append(edit, remove);
        tr.appendChild(actions);
        tbody.appendChild(tr);
    });
}

function updateDashboard() {
    const count = (severity) => indicators.filter(x => x.severity === severity).length;
    setText("total", indicators.length);
    setText("high", count("critical") + count("high"));
    setText("medium", count("medium"));
    setText("low", count("low"));
    renderCharts();
    renderRecent();
}

function renderCharts() {
    if (typeof Chart === "undefined") return;
    const severityEl = $("severityChart");
    const typeEl = $("typeChart");
    if (severityChart) severityChart.destroy();
    if (typeChart) typeChart.destroy();
    severityChart = new Chart(severityEl, {
        type: "bar",
        data: {
            labels: ["Critical", "High", "Medium", "Low"],
            datasets: [{ label: "Indicators", data: ["critical", "high", "medium", "low"].map(x => indicators.filter(i => i.severity === x).length), backgroundColor: ["#f06479", "#f49a65", "#e8c36d", "#39c9a5"], borderRadius: 7 }]
        },
        options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { ticks: { color: "#9aabc1" }, grid: { display: false } }, y: { beginAtZero: true, ticks: { precision: 0, color: "#9aabc1" }, grid: { color: "#263449" } } } }
    });
    const types = ["ip", "domain", "url", "hash", "email", "cve"];
    typeChart = new Chart(typeEl, {
        type: "doughnut",
        data: { labels: types.map(x => x.toUpperCase()), datasets: [{ data: types.map(x => indicators.filter(i => i.indicator_type === x).length), borderWidth: 0 }] },
        options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: "bottom", labels: { color: "#cbd5e1", padding: 14 } } } }
    });
}

function renderRecent() {
    const box = $("recentActivity");
    box.replaceChildren();
    const recent = [...indicators].sort((a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0)).slice(0, 6);
    if (!recent.length) {
        box.textContent = "No indicators have been recorded yet.";
        return;
    }
    recent.forEach(item => {
        const row = document.createElement("div");
        row.className = "activity-item";
        const left = document.createElement("div");
        const strong = document.createElement("strong");
        strong.textContent = item.indicator;
        const small = document.createElement("small");
        small.textContent = `${item.indicator_type.toUpperCase()} · ${item.source}`;
        left.append(strong, small);
        const right = document.createElement("span");
        right.className = `badge ${item.severity}`;
        right.textContent = item.severity;
        row.append(left, right);
        box.appendChild(row);
    });
}

async function addIOC(event) {
    event.preventDefault();
    try {
        const payload = formPayload(false);
        await request(API, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
        $("addForm").reset();
        $("confidence").value = 50;
        $("tags").value = "[]";
        $("attackTechniques").value = "[]";
        message("Indicator added successfully.", "success");
        await loadIndicators();
        await loadAudit();
    } catch (error) { message(error.message, "error"); }
}

function openEdit(item) {
    $("editId").value = item.id;
    $("editIndicator").value = item.indicator;
    $("editIndicatorType").value = item.indicator_type;
    $("editIndicatorSeverity").value = item.severity;
    $("editSource").value = item.source || "manual";
    $("editConfidence").value = item.confidence ?? 50;
    $("editTlp").value = item.tlp || "clear";
    $("editStatus").value = item.status || "active";
    $("editTags").value = item.tags || "[]";
    $("editAttackTechniques").value = item.attack_techniques || "[]";
    $("editAnalystNotes").value = item.analyst_notes || "";
    $("editModal").hidden = false;
}

function closeEdit() { $("editModal").hidden = true; }

async function updateIOC(event) {
    event.preventDefault();
    try {
        const id = $("editId").value;
        await request(`${API}${id}`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(formPayload(true))
        });
        closeEdit();
        message("Indicator updated successfully.", "success");
        await loadIndicators();
        await loadAudit();
    } catch (error) { message(error.message, "error"); }
}

async function deleteIOC(id) {
    if (!window.confirm("Delete this indicator? This action cannot be undone.")) return;
    try {
        await request(`${API}${id}`, { method: "DELETE" });
        message("Indicator deleted.", "success");
        await loadIndicators();
        await loadAudit();
    } catch (error) { message(error.message, "error"); }
}

async function loadFeeds() {
    try {
        const feeds = await request("/feeds");
        const select = $("feedSelect");
        const catalog = $("feedCatalog");
        select.replaceChildren();
        catalog.replaceChildren();
        feeds.forEach(feed => {
            const option = document.createElement("option");
            option.value = feed.key;
            option.textContent = `${feed.name}${feed.configured ? "" : " (API key required)"}`;
            select.appendChild(option);

            const card = document.createElement("article");
            card.className = "feed-card";
            const title = document.createElement("strong");
            title.textContent = feed.name;
            const description = document.createElement("p");
            description.textContent = feed.description;
            const state = document.createElement("small");
            state.textContent = feed.configured ? "Connector available" : "Configure OTX_API_KEY";
            card.append(title, description, state);
            catalog.appendChild(card);
        });
    } catch (error) {
        setText("feedStatus", `Could not load feed catalog: ${error.message}`);
    }
}

async function syncFeed() {
    const button = $("syncFeedBtn");
    const feedKey = $("feedSelect").value;
    const feedName = $("feedSelect").selectedOptions[0]?.textContent || feedKey;
    button.disabled = true;
    button.textContent = "Synchronizing…";
    setText("feedStatus", `Contacting ${feedName}…`);
    try {
        const result = await request(`/feeds/${encodeURIComponent(feedKey)}/sync`, { method: "POST" });
        $("feedResults").hidden = false;
        setText("feedFetched", result.fetched);
        setText("feedAdded", result.added);
        setText("feedDuplicates", result.duplicates);
        setText("feedInvalid", result.invalid);
        setText("feedStatus", `${result.feed}: synchronization completed.`);
        message(`${result.feed} synchronization completed.`, "success");
        await loadIndicators();
        await loadFeedHistory();
        await loadAudit();
        await loadOperations();
    } catch (error) {
        setText("feedStatus", `Sync failed: ${error.message}`);
        message(error.message, "error");
        await loadFeedHistory();
    } finally {
        button.disabled = false;
        button.textContent = "↻ Sync Selected Feed";
    }
}

async function loadFeedHistory() {
    const tbody = $("feedHistory");
    try {
        const runs = await request("/iocs/feeds/history");
        tbody.replaceChildren();
        if (!runs.length) {
            const tr = document.createElement("tr");
            const td = cell("No synchronization history yet.");
            td.colSpan = 6;
            tr.appendChild(td);
            tbody.appendChild(tr);
            setText("lastSync", "Last sync: Not available");
            return;
        }
        runs.forEach(run => {
            const tr = document.createElement("tr");
            tr.append(cell(run.feed_name), cell(run.status), cell(run.fetched), cell(run.added), cell(run.duplicates), cell(dateText(run.completed_at || run.started_at)));
            tbody.appendChild(tr);
        });
        setText("lastSync", `Last sync: ${dateText(runs[0].completed_at || runs[0].started_at)}`);
    } catch (error) {
        tbody.innerHTML = "";
        const tr = document.createElement("tr");
        const td = cell(`Could not load feed history: ${error.message}`);
        td.colSpan = 6;
        tr.appendChild(td);
        tbody.appendChild(tr);
    }
}

async function loadAudit() {
    const tbody = $("auditTable");
    try {
        const rows = await request("/audit?limit=50");
        tbody.replaceChildren();
        if (!rows.length) {
            const tr = document.createElement("tr");
            const td = cell("No audit events recorded yet.");
            td.colSpan = 5;
            tr.appendChild(td);
            tbody.appendChild(tr);
            return;
        }
        rows.forEach(row => {
            const tr = document.createElement("tr");
            tr.append(cell(row.action), cell(row.entity_type), cell(row.entity_id), cell(row.details), cell(dateText(row.created_at)));
            tbody.appendChild(tr);
        });
    } catch (error) {
        tbody.innerHTML = "";
        const tr = document.createElement("tr");
        const td = cell(`Could not load audit log: ${error.message}`);
        td.colSpan = 5;
        tr.appendChild(td);
        tbody.appendChild(tr);
    }
}


async function loadOperations() {
    try {
        const [alerts, incidents, metrics] = await Promise.all([
            request("/alerts?limit=100"),
            request("/incidents"),
            request("/metrics")
        ]);
        setText("openAlerts", alerts.filter(x => !["resolved", "closed"].includes(x.status)).length);
        setText("openIncidents", metrics.open_incidents);
        setText("correlatedEvents", metrics.events);

        const alertBody = $("alertsTable");
        alertBody.replaceChildren();
        if (!alerts.length) {
            const row = document.createElement("tr");
            const td = cell("No alerts recorded.");
            td.colSpan = 6;
            row.appendChild(td);
            alertBody.appendChild(row);
        }
        alerts.forEach(alert => {
            const row = document.createElement("tr");
            row.append(cell(alert.title), cell(alert.severity), cell(alert.status),
                cell(alert.assignee), cell(dateText(alert.created_at)));
            const action = document.createElement("td");
            const select = document.createElement("select");
            ["new", "acknowledged", "in-progress", "resolved", "closed"].forEach(status => {
                const option = document.createElement("option");
                option.value = status;
                option.textContent = status;
                option.selected = alert.status === status;
                select.appendChild(option);
            });
            select.addEventListener("change", async () => {
                try {
                    await request(`/alerts/${alert.id}`, {
                        method: "PATCH",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ status: select.value })
                    });
                    message("Alert lifecycle updated.", "success");
                    await loadOperations();
                    await loadAudit();
                } catch (error) {
                    message(error.message, "error");
                }
            });
            action.appendChild(select);
            row.appendChild(action);
            alertBody.appendChild(row);
        });

        const incidentBody = $("incidentsTable");
        incidentBody.replaceChildren();
        if (!incidents.length) {
            const row = document.createElement("tr");
            const td = cell("No incidents created.");
            td.colSpan = 5;
            row.appendChild(td);
            incidentBody.appendChild(row);
        }
        incidents.forEach(incident => {
            const row = document.createElement("tr");
            row.append(cell(incident.id), cell(incident.title), cell(incident.severity),
                cell(incident.status), cell(incident.owner));
            incidentBody.appendChild(row);
        });
    } catch (error) {
        message(`Operations data unavailable: ${error.message}`, "error");
    }
}

async function createIncident(event) {
    event.preventDefault();
    try {
        await request("/incidents", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                title: $("incidentTitle").value.trim(),
                severity: $("incidentSeverity").value,
                owner: $("incidentOwner").value.trim()
            })
        });
        $("incidentForm").reset();
        message("Incident created.", "success");
        await loadOperations();
        await loadAudit();
    } catch (error) {
        message(error.message, "error");
    }
}

async function exportPDF() {
    try {
        const response = await fetch("/reports/summary.pdf");
        if (!response.ok) {
            const data = await response.json().catch(() => ({}));
            throw new Error(data.detail || `HTTP ${response.status}`);
        }
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = "threatlens_summary.pdf";
        link.click();
        URL.revokeObjectURL(url);
        message("PDF report downloaded.", "success");
    } catch (error) {
        message(`PDF export failed: ${error.message}`, "error");
    }
}

function downloadFile(filename, content, type) {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
}

function exportCSV() {
    if (!indicators.length) { message("No indicators to export.", "error"); return; }
    const columns = ["id", "indicator", "indicator_type", "severity", "threat_score", "confidence", "source", "tlp", "status", "tags", "attack_techniques", "analyst_notes", "created_at"];
    const escape = value => {
        let text = value === null || value === undefined ? "" : String(value);
        if (/^[=+\-@]/.test(text)) text = "'" + text;
        return `"${text.replace(/"/g, '""')}"`;
    };
    const exportable = indicators.filter(item => item.tlp !== "red");
    const csv = [columns.join(","), ...exportable.map(item => columns.map(key => escape(item[key])).join(","))].join("\r\n");
    downloadFile("threatlens-indicators.csv", csv, "text/csv;charset=utf-8");
    message("CSV export downloaded.", "success");
}

async function exportSTIX() {
    try {
        const data = await request("/export/stix");
        downloadFile("threatlens-stix-bundle.json", JSON.stringify(data, null, 2), "application/json");
        message("STIX 2.1 bundle downloaded.", "success");
    } catch (error) { message(`STIX export failed: ${error.message}`, "error"); }
}

function clearFilters() {
    $("filterForm").reset();
    renderIndicators();
}

function setup() {
    $("addForm").addEventListener("submit", addIOC);
    $("editForm").addEventListener("submit", updateIOC);
    $("filterForm").addEventListener("submit", event => { event.preventDefault(); renderIndicators(); });
    ["search", "type", "severity", "status", "filterTlp"].forEach(id => {
        $(id).addEventListener("input", renderIndicators);
        $(id).addEventListener("change", renderIndicators);
    });
    $("refreshBtn").addEventListener("click", async () => { await checkHealth(); await loadIndicators(); await loadFeedHistory(); await loadFeeds(); await loadOperations(); });
    $("syncFeedBtn").addEventListener("click", syncFeed);
    $("incidentForm").addEventListener("submit", createIncident);
    $("pdfBtn").addEventListener("click", exportPDF);
    $("refreshOpsBtn").addEventListener("click", loadOperations);
    $("exportBtn").addEventListener("click", exportCSV);
    $("stixBtn").addEventListener("click", exportSTIX);
    $("clearBtn").addEventListener("click", clearFilters);
    $("closeModal").addEventListener("click", closeEdit);
    $("cancelEditBtn").addEventListener("click", closeEdit);
    $("auditRefreshBtn").addEventListener("click", loadAudit);
    $("editModal").addEventListener("click", event => { if (event.target === $("editModal")) closeEdit(); });
    document.querySelectorAll(".nav").forEach(link => link.addEventListener("click", () => {
        document.querySelectorAll(".nav").forEach(x => x.classList.remove("active"));
        link.classList.add("active");
    }));
}

document.addEventListener("DOMContentLoaded", async () => {
    setup();
    await checkHealth();
    await loadIndicators();
    await loadFeedHistory();
    await loadFeeds();
    await loadAudit();
    await loadOperations();
});
