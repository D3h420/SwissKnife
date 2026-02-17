const FALLBACK_MENU = {
  main: [
    {
      id: "recon",
      label: "Recon",
      icon: "RCN",
      type: "group",
      description: "Passive discovery of APs and clients.",
      items: [
        {
          id: "recon_scan",
          label: "Scanner",
          type: "module",
          module_id: "recon_scan",
          description: "Timed scan of nearby APs and stations.",
          controls: [
            {
              id: "interface",
              label: "Interface",
              kind: "select",
              source: "tool_interfaces",
              arg: "--interface",
              required: true,
              default: "auto",
            },
            {
              id: "duration",
              label: "Timeout",
              kind: "range",
              arg: "--duration",
              min: 8,
              max: 120,
              step: 2,
              default: 24,
              suffix: "s",
            },
          ],
        },
        {
          id: "recon_sniff",
          label: "Sniffer",
          type: "module",
          module_id: "recon_sniff",
          description: "Channel-hopping sniffer with timed stop.",
          controls: [
            {
              id: "interface",
              label: "Interface",
              kind: "select",
              source: "tool_interfaces",
              arg: "--interface",
              required: true,
              default: "auto",
            },
            {
              id: "duration",
              label: "Timeout",
              kind: "range",
              arg: "--duration",
              min: 15,
              max: 300,
              step: 5,
              default: 90,
              suffix: "s",
            },
            {
              id: "update_interval",
              label: "Refresh",
              kind: "range",
              arg: "--update-interval",
              min: 0.2,
              max: 2,
              step: 0.1,
              default: 0.8,
              suffix: "s",
            },
          ],
        },
      ],
    },
    {
      id: "attacks",
      label: "Attacks",
      icon: "ATK",
      type: "group",
      description: "Attack workflows available in SwissKnife.",
      items: [
        { id: "deauth", label: "Deauth", type: "module", module_id: "deauth", description: "Deauthentication workflow." },
        { id: "portal", label: "Portal", type: "module", module_id: "portal", description: "Captive portal workflow." },
        { id: "twins", label: "Evil Twin", type: "module", module_id: "twins", description: "Rogue AP + portal workflow." },
        {
          id: "handshaker",
          label: "Handshaker",
          type: "module",
          module_id: "handshaker",
          description: "Under construction module.",
          under_construction: true,
        },
        { id: "karma", label: "Karma", type: "module", description: "Under construction module.", disabled: true, under_construction: true },
      ],
    },
    {
      id: "bluetooth",
      label: "Bluetooth",
      icon: "BT",
      type: "module",
      module_id: "bluetooth",
      description: "Bluetooth and BLE workflows.",
    },
    {
      id: "exit",
      label: "Exit",
      icon: "EXT",
      type: "info",
      description: "Equivalent of exit option in CLI launcher.",
    },
  ],
};

const state = {
  token: localStorage.getItem("swissknife.webui.token") || "",
  authRequired: false,
  menu: FALLBACK_MENU.main,
  selectedSectionId: null,
  moduleById: {},
  interfaces: {
    builtin_interface: "",
    all_wireless: [],
    tool_interfaces: [],
  },
  tasks: [],
  activeTaskId: null,
  resultByTask: {},
  pollHandle: null,
};

const dom = {
  tokenInput: document.getElementById("tokenInput"),
  saveTokenBtn: document.getElementById("saveTokenBtn"),
  authHint: document.getElementById("authHint"),
  refreshMenuBtn: document.getElementById("refreshMenuBtn"),
  mainMenu: document.getElementById("mainMenu"),
  sectionTitle: document.getElementById("sectionTitle"),
  sectionDescription: document.getElementById("sectionDescription"),
  sectionBody: document.getElementById("sectionBody"),
  globalArgsInput: document.getElementById("globalArgsInput"),
  refreshTasksBtn: document.getElementById("refreshTasksBtn"),
  tasksList: document.getElementById("tasksList"),
  activeTaskChip: document.getElementById("activeTaskChip"),
  stopTaskBtn: document.getElementById("stopTaskBtn"),
  resultsView: document.getElementById("resultsView"),
};

function setHint(message, level = "") {
  dom.authHint.textContent = message;
  dom.authHint.classList.remove("success", "error");
  if (level) {
    dom.authHint.classList.add(level);
  }
}

function isUnauthorizedError(error) {
  return typeof error?.message === "string" && error.message === "UNAUTHORIZED";
}

async function apiFetch(path, options = {}) {
  const headers = Object.assign({}, options.headers || {});
  if (state.token) {
    headers["X-SwissKnife-Token"] = state.token;
  }
  if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
  }

  const response = await fetch(path, {
    method: options.method || "GET",
    headers,
    body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
  });

  if (response.status === 401) {
    throw new Error("UNAUTHORIZED");
  }
  if (!response.ok) {
    const payload = await response.json().catch(() => ({ detail: response.statusText }));
    throw new Error(payload.detail || `HTTP ${response.status}`);
  }
  return response.json().catch(() => ({}));
}

function parseTime(timestamp) {
  if (!timestamp) {
    return "-";
  }
  return new Date(timestamp * 1000).toLocaleTimeString();
}

function getSectionById(sectionId) {
  return state.menu.find((item) => item.id === sectionId) || null;
}

function getTaskById(taskId) {
  return state.tasks.find((task) => task.task_id === taskId) || null;
}

function resolveModuleInfo(moduleId) {
  return state.moduleById[moduleId] || null;
}

function formatControlValue(control, value) {
  if (value === null || value === undefined || value === "") {
    return "-";
  }
  if (control.suffix) {
    return `${value}${control.suffix}`;
  }
  return String(value);
}

function resolveControlOptions(control) {
  if (Array.isArray(control.options) && control.options.length) {
    return control.options.map((entry) => {
      if (typeof entry === "string") {
        return { value: entry, label: entry };
      }
      return {
        value: String(entry.value),
        label: entry.label || String(entry.value),
      };
    });
  }

  if (control.source === "tool_interfaces") {
    const items = Array.isArray(state.interfaces.tool_interfaces) ? state.interfaces.tool_interfaces : [];
    const options = [];
    if (control.default === "auto") {
      options.push({ value: "auto", label: "auto (external adapter)" });
    }
    items.forEach((iface) => {
      options.push({ value: iface, label: iface });
    });
    return options;
  }

  return [];
}

function createControlField(control) {
  const wrap = document.createElement("label");
  wrap.className = "control-field";

  const caption = document.createElement("span");
  caption.className = "control-label";
  caption.textContent = control.label || control.id;
  wrap.appendChild(caption);

  if (control.kind === "select") {
    const select = document.createElement("select");
    select.dataset.controlId = control.id;
    const options = resolveControlOptions(control);
    if (!options.length) {
      const empty = document.createElement("option");
      empty.value = "";
      empty.textContent = "No interfaces";
      select.appendChild(empty);
      select.disabled = true;
    } else {
      options.forEach((entry) => {
        const option = document.createElement("option");
        option.value = entry.value;
        option.textContent = entry.label;
        select.appendChild(option);
      });
      const defaultValue = control.default !== undefined ? String(control.default) : "";
      if (defaultValue && options.some((entry) => entry.value === defaultValue)) {
        select.value = defaultValue;
      }
    }
    wrap.appendChild(select);
    return wrap;
  }

  if (control.kind === "range") {
    const row = document.createElement("div");
    row.className = "range-row";

    const input = document.createElement("input");
    input.type = "range";
    input.dataset.controlId = control.id;
    input.min = String(control.min ?? 0);
    input.max = String(control.max ?? 100);
    input.step = String(control.step ?? 1);
    input.value = String(control.default ?? control.min ?? 0);

    const badge = document.createElement("strong");
    badge.className = "range-value";
    badge.textContent = formatControlValue(control, input.value);

    input.addEventListener("input", () => {
      badge.textContent = formatControlValue(control, input.value);
    });

    row.appendChild(input);
    row.appendChild(badge);
    wrap.appendChild(row);
    return wrap;
  }

  const input = document.createElement("input");
  input.type = "text";
  input.dataset.controlId = control.id;
  input.value = control.default !== undefined ? String(control.default) : "";
  wrap.appendChild(input);
  return wrap;
}

function collectModuleArgs(item, card) {
  const controls = Array.isArray(item.controls) ? item.controls : [];
  const args = [];

  for (const control of controls) {
    const field = card.querySelector(`[data-control-id="${control.id}"]`);
    if (!field) {
      continue;
    }

    let value = field.value;
    if (typeof value === "string") {
      value = value.trim();
    }

    if (!value) {
      if (control.required) {
        throw new Error(`Missing value for ${control.label || control.id}.`);
      }
      continue;
    }

    if (control.arg) {
      args.push(control.arg, String(value));
    }
  }

  return args;
}

function createActionCard(item) {
  const card = document.createElement("article");
  card.className = "action-card";

  const title = document.createElement("h3");
  title.textContent = item.label;
  card.appendChild(title);

  const description = document.createElement("p");
  description.textContent = item.description || "";
  card.appendChild(description);

  if (Array.isArray(item.controls) && item.controls.length) {
    const controlsWrap = document.createElement("div");
    controlsWrap.className = "control-grid";
    item.controls.forEach((control) => {
      controlsWrap.appendChild(createControlField(control));
    });
    card.appendChild(controlsWrap);
  }

  const meta = document.createElement("div");
  meta.className = "action-meta";

  const status = document.createElement("span");
  status.className = "status-chip";

  if (item.under_construction) {
    status.classList.add("warn");
    status.textContent = "UNDER CONSTRUCTION";
  } else if (item.disabled) {
    status.classList.add("bad");
    status.textContent = "DISABLED";
  } else {
    status.textContent = "READY";
  }
  meta.appendChild(status);

  const button = document.createElement("button");
  button.type = "button";
  button.className = "primary";
  button.textContent = "Run";
  button.disabled = Boolean(item.disabled);

  if (item.type === "module" && item.module_id) {
    const moduleInfo = resolveModuleInfo(item.module_id);
    if (!moduleInfo || moduleInfo.exists === false) {
      button.disabled = true;
      status.className = "status-chip bad";
      status.textContent = "MISSING SCRIPT";
    }
    const needsToolInterface = Array.isArray(item.controls) && item.controls.some((control) => control.source === "tool_interfaces");
    if (needsToolInterface && (!Array.isArray(state.interfaces.tool_interfaces) || state.interfaces.tool_interfaces.length === 0)) {
      button.disabled = true;
      status.className = "status-chip bad";
      status.textContent = "NO TOOL IFACE";
    }

    button.addEventListener("click", async () => {
      if (button.disabled) {
        return;
      }
      try {
        const args = collectModuleArgs(item, card);
        await startModule(item.module_id, args);
      } catch (error) {
        setHint(`Start failed: ${error.message}`, "error");
      }
    });
  } else {
    button.disabled = true;
  }

  meta.appendChild(button);
  card.appendChild(meta);
  return card;
}

function renderSection() {
  const section = getSectionById(state.selectedSectionId);
  if (!section) {
    return;
  }

  dom.sectionTitle.textContent = section.label;
  dom.sectionDescription.textContent = section.description || "";
  dom.sectionBody.innerHTML = "";

  if (section.id === "recon" && state.interfaces.builtin_interface) {
    const notice = document.createElement("div");
    notice.className = "muted-block";
    notice.textContent = `AP/WebUI uses ${state.interfaces.builtin_interface}. Recon controls target external adapters.`;
    dom.sectionBody.appendChild(notice);
  }

  if (section.type === "module") {
    const grid = document.createElement("div");
    grid.className = "action-grid";
    grid.appendChild(createActionCard(section));
    dom.sectionBody.appendChild(grid);
    return;
  }

  if (section.type === "group") {
    const items = Array.isArray(section.items) ? section.items : [];
    if (!items.length) {
      const muted = document.createElement("div");
      muted.className = "muted-block";
      muted.textContent = "No items in this section.";
      dom.sectionBody.appendChild(muted);
      return;
    }
    const grid = document.createElement("div");
    grid.className = "action-grid";
    items.forEach((item) => grid.appendChild(createActionCard(item)));
    dom.sectionBody.appendChild(grid);
    return;
  }

  const info = document.createElement("div");
  info.className = "muted-block";
  info.textContent = section.description || "Section information.";
  dom.sectionBody.appendChild(info);
}

function renderMenu() {
  dom.mainMenu.innerHTML = "";

  if (!state.menu.length) {
    const muted = document.createElement("div");
    muted.className = "muted-block";
    muted.textContent = "No menu schema loaded.";
    dom.mainMenu.appendChild(muted);
    return;
  }

  state.menu.forEach((section) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `menu-btn${section.id === state.selectedSectionId ? " active" : ""}`;
    const tag = document.createElement("span");
    tag.className = "tag";
    tag.textContent = section.icon || section.label.slice(0, 3).toUpperCase();
    const label = document.createElement("span");
    label.textContent = section.label;
    button.appendChild(tag);
    button.appendChild(label);
    button.addEventListener("click", () => {
      state.selectedSectionId = section.id;
      renderMenu();
      renderSection();
    });
    dom.mainMenu.appendChild(button);
  });
}

function renderTasks() {
  dom.tasksList.innerHTML = "";

  if (!state.tasks.length) {
    const item = document.createElement("li");
    item.className = "task-item";
    item.textContent = "No tasks yet.";
    dom.tasksList.appendChild(item);
    dom.activeTaskChip.textContent = "No task selected";
    return;
  }

  state.tasks.forEach((task) => {
    const item = document.createElement("li");
    item.className = `task-item${task.task_id === state.activeTaskId ? " active" : ""}`;
    item.addEventListener("click", () => selectTask(task.task_id));

    const row = document.createElement("div");
    row.className = "task-row";
    const title = document.createElement("strong");
    title.textContent = `${task.module_name} (${task.task_id})`;
    row.appendChild(title);

    const status = document.createElement("span");
    status.className = `task-state ${task.running ? "running" : "stopped"}`;
    status.textContent = task.running ? "RUNNING" : "STOPPED";
    row.appendChild(status);
    item.appendChild(row);

    const detail = document.createElement("div");
    detail.className = "task-detail";
    detail.textContent = `Started ${parseTime(task.started_at)} | Return code ${task.returncode ?? "-"}`;
    item.appendChild(detail);

    dom.tasksList.appendChild(item);
  });

  if (state.activeTaskId) {
    dom.activeTaskChip.textContent = `Active: ${state.activeTaskId}`;
  } else {
    dom.activeTaskChip.textContent = "No task selected";
  }
}

function clientText(clients) {
  if (!Array.isArray(clients) || clients.length === 0) {
    return "-";
  }
  if (clients.length <= 4) {
    return clients.join(", ");
  }
  return `${clients.slice(0, 4).join(", ")} +${clients.length - 4}`;
}

function createSummaryPill(label, value) {
  const pill = document.createElement("span");
  pill.className = "pill";
  pill.textContent = `${label}: ${value}`;
  return pill;
}

function buildNetworkTable(networks) {
  const table = document.createElement("table");
  table.className = "result-table";

  const head = document.createElement("thead");
  head.innerHTML = "<tr><th>SSID</th><th>BSSID</th><th>Ch</th><th>Enc</th><th>RSSI</th><th>Clients</th></tr>";
  table.appendChild(head);

  const body = document.createElement("tbody");
  const rows = Array.isArray(networks) ? networks : [];
  if (!rows.length) {
    const empty = document.createElement("tr");
    empty.innerHTML = '<td colspan="6" class="cell-muted">No networks found.</td>';
    body.appendChild(empty);
    table.appendChild(body);
    return table;
  }

  rows.forEach((network) => {
    const tr = document.createElement("tr");
    const ssid = network.ssid || "<hidden>";
    const bssid = network.bssid || "-";
    const channel = network.channel ?? "?";
    const encryption = network.encryption || "UNKNOWN";
    const rssi = network.rssi !== null && network.rssi !== undefined ? `${network.rssi} dBm` : "?";
    const clients = clientText(network.clients);
    [ssid, bssid, String(channel), encryption, rssi, clients].forEach((value) => {
      const cell = document.createElement("td");
      cell.textContent = value;
      tr.appendChild(cell);
    });
    body.appendChild(tr);
  });

  table.appendChild(body);
  return table;
}

function renderReconScanResult(result, task) {
  dom.resultsView.innerHTML = "";

  const summary = document.createElement("div");
  summary.className = "result-summary";
  summary.appendChild(createSummaryPill("Mode", "Scanner"));
  summary.appendChild(createSummaryPill("Interface", result.interface || "-"));
  summary.appendChild(createSummaryPill("Networks", result.network_count ?? 0));
  summary.appendChild(createSummaryPill("Task", task.task_id));
  dom.resultsView.appendChild(summary);
  dom.resultsView.appendChild(buildNetworkTable(result.networks));
}

function renderReconSniffResult(result, task) {
  dom.resultsView.innerHTML = "";

  const summary = document.createElement("div");
  summary.className = "result-summary";
  summary.appendChild(createSummaryPill("Mode", "Sniffer"));
  summary.appendChild(createSummaryPill("Interface", result.interface || "-"));
  summary.appendChild(createSummaryPill("Packets", result.packet_count ?? 0));
  summary.appendChild(createSummaryPill("Probes", result.probe_total ?? 0));
  summary.appendChild(createSummaryPill("Task", task.task_id));
  dom.resultsView.appendChild(summary);
  dom.resultsView.appendChild(buildNetworkTable(result.networks));

  const probes = document.createElement("div");
  probes.className = "probe-list";
  const entries = Array.isArray(result.probes) ? result.probes : [];
  if (!entries.length) {
    probes.textContent = "No probe requests observed.";
  } else {
    const top = entries.slice(0, 20);
    probes.textContent = top
      .map((entry) => `${entry.ssid || "<hidden>"} (${entry.count || 0})`)
      .join(" • ");
  }
  dom.resultsView.appendChild(probes);
}

function renderResultView() {
  dom.resultsView.innerHTML = "";

  const task = getTaskById(state.activeTaskId);
  if (!task) {
    const empty = document.createElement("div");
    empty.className = "muted-block";
    empty.textContent = "Select task to see parsed scan results.";
    dom.resultsView.appendChild(empty);
    return;
  }

  const result = state.resultByTask[task.task_id] || null;
  if (!result) {
    const waiting = document.createElement("div");
    waiting.className = "muted-block";
    waiting.textContent = task.running
      ? "Task is running. Results will appear after completion."
      : "No structured results available for this task.";
    dom.resultsView.appendChild(waiting);
    return;
  }

  if (result.kind === "recon_scan") {
    renderReconScanResult(result, task);
    return;
  }
  if (result.kind === "recon_sniff") {
    renderReconSniffResult(result, task);
    return;
  }

  const unsupported = document.createElement("div");
  unsupported.className = "muted-block";
  unsupported.textContent = "This module does not expose structured UI results yet.";
  dom.resultsView.appendChild(unsupported);
}

async function loadMeta() {
  try {
    const data = await fetch("/api/meta").then((response) => response.json());
    state.authRequired = Boolean(data.auth_required);
    if (state.authRequired) {
      setHint("Token required. Paste token and click Apply.");
    } else {
      setHint("Auth disabled on server.", "success");
    }
  } catch (_error) {
    setHint("Meta unavailable. Open panel through web server, not local file path.", "error");
  }
}

async function loadMenu() {
  try {
    const data = await apiFetch("/api/menu");
    const main = Array.isArray(data.main) ? data.main : FALLBACK_MENU.main;
    state.menu = main;
  } catch (error) {
    if (isUnauthorizedError(error)) {
      setHint("Unauthorized. Provide valid token.", "error");
      state.menu = FALLBACK_MENU.main;
    } else {
      state.menu = FALLBACK_MENU.main;
      setHint("Using fallback menu schema (server unreachable).", "error");
    }
  }

  if (!state.selectedSectionId || !getSectionById(state.selectedSectionId)) {
    state.selectedSectionId = state.menu[0]?.id || null;
  }
  renderMenu();
  renderSection();
}

async function loadModules() {
  try {
    const data = await apiFetch("/api/modules");
    const modules = Array.isArray(data.modules) ? data.modules : [];
    state.moduleById = {};
    modules.forEach((entry) => {
      state.moduleById[entry.module_id] = entry;
    });
    renderSection();
  } catch (error) {
    if (isUnauthorizedError(error)) {
      setHint("Unauthorized. Provide valid token.", "error");
      return;
    }
    setHint(`Failed to load modules: ${error.message}`, "error");
  }
}

async function loadInterfaces() {
  try {
    const data = await apiFetch("/api/interfaces");
    state.interfaces = {
      builtin_interface: data.builtin_interface || "",
      all_wireless: Array.isArray(data.all_wireless) ? data.all_wireless : [],
      tool_interfaces: Array.isArray(data.tool_interfaces) ? data.tool_interfaces : [],
    };
    renderSection();
  } catch (error) {
    if (isUnauthorizedError(error)) {
      setHint("Unauthorized. Provide valid token.", "error");
      return;
    }
    setHint(`Failed to load interfaces: ${error.message}`, "error");
  }
}

async function loadTaskResult(taskId, silent = false) {
  if (!taskId) {
    renderResultView();
    return;
  }

  try {
    const data = await apiFetch(`/api/tasks/${taskId}/result`);
    state.resultByTask[taskId] = data.result || null;
    renderResultView();
  } catch (error) {
    if (isUnauthorizedError(error)) {
      if (!silent) {
        setHint("Unauthorized. Provide valid token.", "error");
      }
      return;
    }
    if (!silent) {
      setHint(`Failed to load results: ${error.message}`, "error");
    }
  }
}

async function loadTasks() {
  try {
    const data = await apiFetch("/api/tasks");
    state.tasks = Array.isArray(data.tasks) ? data.tasks : [];

    if (!state.tasks.length) {
      state.activeTaskId = null;
      renderTasks();
      renderResultView();
      return;
    }

    if (!state.activeTaskId || !getTaskById(state.activeTaskId)) {
      state.activeTaskId = state.tasks[0].task_id;
    }

    renderTasks();
    await loadTaskResult(state.activeTaskId, true);
  } catch (error) {
    if (isUnauthorizedError(error)) {
      setHint("Unauthorized. Provide valid token.", "error");
      return;
    }
    setHint(`Failed to load tasks: ${error.message}`, "error");
  }
}

async function startModule(moduleId, args = []) {
  try {
    const data = await apiFetch("/api/tasks/start", {
      method: "POST",
      body: {
        module_id: moduleId,
        args,
        raw_args: dom.globalArgsInput.value.trim(),
      },
    });
    const task = data.task;
    await loadTasks();
    if (task?.task_id) {
      state.activeTaskId = task.task_id;
      renderTasks();
      await loadTaskResult(task.task_id, true);
      setHint(`Started ${moduleId} as task ${task.task_id}.`, "success");
    }
  } catch (error) {
    if (isUnauthorizedError(error)) {
      setHint("Unauthorized. Provide valid token.", "error");
      return;
    }
    setHint(`Start failed: ${error.message}`, "error");
  }
}

async function stopActiveTask() {
  if (!state.activeTaskId) {
    setHint("Select task first.", "error");
    return;
  }

  try {
    await apiFetch(`/api/tasks/${state.activeTaskId}/stop`, { method: "POST" });
    await loadTasks();
    setHint(`Stop signal sent to ${state.activeTaskId}.`, "success");
  } catch (error) {
    if (isUnauthorizedError(error)) {
      setHint("Unauthorized. Provide valid token.", "error");
      return;
    }
    setHint(`Stop failed: ${error.message}`, "error");
  }
}

function selectTask(taskId) {
  state.activeTaskId = taskId;
  renderTasks();
  loadTaskResult(taskId, true);
}

function installHandlers() {
  dom.tokenInput.value = state.token;

  dom.saveTokenBtn.addEventListener("click", async () => {
    state.token = dom.tokenInput.value.trim();
    localStorage.setItem("swissknife.webui.token", state.token);
    await Promise.all([loadMenu(), loadModules(), loadInterfaces(), loadTasks()]);
  });

  dom.refreshMenuBtn.addEventListener("click", async () => {
    await loadMenu();
    await loadModules();
    await loadInterfaces();
  });

  dom.refreshTasksBtn.addEventListener("click", loadTasks);
  dom.stopTaskBtn.addEventListener("click", stopActiveTask);
}

async function bootstrap() {
  installHandlers();
  await loadMeta();
  await loadMenu();
  await loadModules();
  await loadInterfaces();
  await loadTasks();

  if (state.pollHandle) {
    clearInterval(state.pollHandle);
  }
  state.pollHandle = setInterval(loadTasks, 3500);
}

bootstrap();
