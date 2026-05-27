const state = {
  apkPath: null,
  activeRunId: null,
  pollTimer: null,
};

const els = {
  healthList: document.querySelector("#healthList"),
  subagentList: document.querySelector("#subagentList"),
  refreshHealth: document.querySelector("#refreshHealth"),
  apkFile: document.querySelector("#apkFile"),
  selectedApk: document.querySelector("#selectedApk"),
  includeDeviceChecks: document.querySelector("#includeDeviceChecks"),
  objective: document.querySelector("#objective"),
  useBifrost: document.querySelector("#useBifrost"),
  gatewayUrl: document.querySelector("#gatewayUrl"),
  modelsUrl: document.querySelector("#modelsUrl"),
  modelSelect: document.querySelector("#modelSelect"),
  loadModels: document.querySelector("#loadModels"),
  apiKey: document.querySelector("#apiKey"),
  mobsfUrl: document.querySelector("#mobsfUrl"),
  mobsfKey: document.querySelector("#mobsfKey"),
  startRun: document.querySelector("#startRun"),
  runState: document.querySelector("#runState"),
  eventCount: document.querySelector("#eventCount"),
  timeline: document.querySelector("#timeline"),
  finalReport: document.querySelector("#finalReport"),
};

async function api(path, options = {}) {
  const response = await fetch(path, options);
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error || `Request failed: ${response.status}`);
  }
  return payload;
}

async function loadHealth() {
  const payload = await api("/api/health");
  els.healthList.innerHTML = "";
  for (const [name, info] of Object.entries(payload.tools)) {
    const row = document.createElement("div");
    row.className = "health-item";
    row.innerHTML = `
      <strong>${escapeHtml(name)}</strong>
      <span class="${info.available ? "success" : "warning"}">${info.available ? "ready" : "missing"}</span>
    `;
    row.title = info.path || "Not found on PATH";
    els.healthList.appendChild(row);
  }
  els.subagentList.innerHTML = "";
  for (const subagent of payload.subagents || []) {
    const row = document.createElement("div");
    row.className = "health-item";
    row.innerHTML = `
      <strong>${escapeHtml(subagent.name)}</strong>
      <span class="success">${escapeHtml((subagent.tool_names || []).length)} tools</span>
    `;
    row.title = subagent.mission;
    els.subagentList.appendChild(row);
  }
}

async function loadModels() {
  if (!els.gatewayUrl.value || !els.apiKey.value) {
    setStateText("Bifrost URL and key are required to load models", "error");
    return;
  }

  els.loadModels.disabled = true;
  els.loadModels.textContent = "Loading";
  try {
    const payload = await api("/api/bifrost/models", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        gateway_url: els.gatewayUrl.value,
        models_url: els.modelsUrl.value,
        api_key: els.apiKey.value,
      }),
    });

    els.modelSelect.innerHTML = "";
    for (const model of payload.models || []) {
      const option = document.createElement("option");
      option.value = model;
      option.textContent = model;
      els.modelSelect.appendChild(option);
    }
    if (!payload.models || payload.models.length === 0) {
      const option = document.createElement("option");
      option.value = "";
      option.textContent = "No models returned";
      els.modelSelect.appendChild(option);
    }
    setStateText(`Loaded ${payload.models.length} models`, "success");
  } finally {
    els.loadModels.disabled = false;
    els.loadModels.textContent = "Load";
  }
}

async function uploadApk(file) {
  const form = new FormData();
  form.append("apk", file);
  els.selectedApk.textContent = "Uploading...";
  const payload = await api("/api/upload", {
    method: "POST",
    body: form,
  });
  state.apkPath = payload.apk_path;
  els.selectedApk.textContent = `${payload.filename} (${formatBytes(payload.size)})`;
}

async function startRun() {
  const useBifrost = els.useBifrost.checked;
  const payload = {
    objective: els.objective.value,
    apk_path: state.apkPath,
    include_device_checks: els.includeDeviceChecks.checked,
    bifrost: {
      enabled: useBifrost,
      gateway_url: els.gatewayUrl.value,
      model: els.modelSelect.value,
      api_key: els.apiKey.value,
    },
    mobsf: {
      base_url: els.mobsfUrl.value,
      api_key: els.mobsfKey.value,
    },
  };

  if (useBifrost && (!payload.bifrost.gateway_url || !payload.bifrost.api_key || !payload.bifrost.model)) {
    setStateText("Bifrost URL, key, and model are required", "error");
    return;
  }

  els.startRun.disabled = true;
  els.timeline.innerHTML = "";
  els.finalReport.textContent = "{}";
  setStateText("Starting", "warning");

  const run = await api("/api/runs", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  state.activeRunId = run.run_id;
  pollRun();
  state.pollTimer = window.setInterval(pollRun, 1200);
}

async function pollRun() {
  if (!state.activeRunId) return;
  const run = await api(`/api/run?id=${encodeURIComponent(state.activeRunId)}`);
  renderRun(run);
  if (["completed", "max_iterations", "error"].includes(run.status)) {
    window.clearInterval(state.pollTimer);
    els.startRun.disabled = false;
  }
}

function renderRun(run) {
  const statusClass = run.status === "completed" ? "success" : run.status === "error" ? "error" : "warning";
  setStateText(`${run.status} / ${run.run_id}`, statusClass);
  els.eventCount.textContent = `${run.event_count} events`;
  els.timeline.innerHTML = "";
  for (const event of run.events || []) {
    els.timeline.appendChild(renderEvent(event));
  }
  els.finalReport.textContent = JSON.stringify(run.final_answer || { error: run.error }, null, 2);
}

function renderEvent(event) {
  const item = document.createElement("article");
  item.className = "event";
  const observation = event.observation || {};
  const action = event.action || {};
  const status = observation.status || event.phase;
  const statusClass = status === "success" ? "success" : status === "error" || status === "validation_error" ? "error" : "warning";
  const summary = observation.summary || event.thought || "";
  item.innerHTML = `
    <div class="event-top">
      <strong>${escapeHtml(event.phase || "event")}</strong>
      <span class="badge ${statusClass}">${escapeHtml(status)}</span>
    </div>
    ${action.tool_name ? `<div>tool: <span class="success">${escapeHtml(action.tool_name)}</span></div>` : ""}
    ${summary ? `<div>${escapeHtml(summary)}</div>` : ""}
    ${observation.error ? `<div class="error">${escapeHtml(observation.error)}</div>` : ""}
  `;
  return item;
}

function setStateText(text, className) {
  els.runState.textContent = text;
  els.runState.className = className;
}

function formatBytes(bytes) {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / 1024 ** index).toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

els.refreshHealth.addEventListener("click", loadHealth);
els.loadModels.addEventListener("click", () => loadModels().catch((error) => {
  setStateText(error.message, "error");
}));
els.apkFile.addEventListener("change", () => {
  const file = els.apkFile.files[0];
  if (file) {
    uploadApk(file).catch((error) => {
      state.apkPath = null;
      els.selectedApk.textContent = error.message;
    });
  }
});
els.startRun.addEventListener("click", () => startRun().catch((error) => {
  els.startRun.disabled = false;
  setStateText(error.message, "error");
}));

loadHealth().catch((error) => {
  els.healthList.textContent = error.message;
});
