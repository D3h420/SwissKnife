const FALLBACK_MENU = {
  main: [
    {
      id: "recon",
      label: "Recon",
      icon: "RCN",
      type: "module",
      module_id: "recon",
      description: "Passive discovery of APs and clients.",
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
      id: "webui",
      label: "Web UI",
      icon: "UI",
      type: "group",
      description: "Web control section.",
      items: [{ id: "launcher", label: "Legacy Launcher", type: "module", module_id: "launcher", description: "Start original CLI menu." }],
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
  tasks: [],
  activeTaskId: null,
  ws: null,
  cursorByTask: {},
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
  clearConsoleBtn: document.getElementById("clearConsoleBtn"),
  stopTaskBtn: document.getElementById("stopTaskBtn"),
  consoleOutput: document.getElementById("consoleOutput"),
  taskInputForm: document.getElementById("taskInputForm"),
  taskInputField: document.getElementById("taskInputField"),
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

function setConsoleText(lines) {
  dom.consoleOutput.textContent = lines.join("\n");
  dom.consoleOutput.scrollTop = dom.consoleOutput.scrollHeight;
}

function appendConsole(lines) {
  if (!lines.length) {
    return;
  }
  const text = lines.join("\n");
  dom.consoleOutput.textContent += (dom.consoleOutput.textContent ? "\n" : "") + text;
  if (dom.consoleOutput.textContent.length > 220000) {
    dom.consoleOutput.textContent = dom.consoleOutput.textContent.slice(-220000);
  }
  dom.consoleOutput.scrollTop = dom.consoleOutput.scrollHeight;
}

function resolveModuleInfo(moduleId) {
  return state.moduleById[moduleId] || null;
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
    button.addEventListener("click", () => startModule(item.module_id));
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

async function loadTasks() {
  try {
    const data = await apiFetch("/api/tasks");
    state.tasks = Array.isArray(data.tasks) ? data.tasks : [];
    renderTasks();
  } catch (error) {
    if (isUnauthorizedError(error)) {
      setHint("Unauthorized. Provide valid token.", "error");
      return;
    }
    setHint(`Failed to load tasks: ${error.message}`, "error");
  }
}

async function startModule(moduleId) {
  try {
    const data = await apiFetch("/api/tasks/start", {
      method: "POST",
      body: {
        module_id: moduleId,
        raw_args: dom.globalArgsInput.value.trim(),
      },
    });
    const task = data.task;
    await loadTasks();
    if (task?.task_id) {
      selectTask(task.task_id);
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

async function sendInput(text) {
  if (!state.activeTaskId) {
    setHint("Select task first.", "error");
    return;
  }
  try {
    await apiFetch(`/api/tasks/${state.activeTaskId}/input`, {
      method: "POST",
      body: { text },
    });
  } catch (error) {
    if (isUnauthorizedError(error)) {
      setHint("Unauthorized. Provide valid token.", "error");
      return;
    }
    setHint(`Input failed: ${error.message}`, "error");
  }
}

function closeLogsSocket() {
  if (!state.ws) {
    return;
  }
  state.ws.onclose = null;
  state.ws.close();
  state.ws = null;
}

function selectTask(taskId) {
  state.activeTaskId = taskId;
  state.cursorByTask[taskId] = state.cursorByTask[taskId] || 0;
  renderTasks();
  setConsoleText([]);
  connectLogsSocket(taskId);
}

function connectLogsSocket(taskId) {
  closeLogsSocket();
  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  const params = new URLSearchParams();
  params.set("since", String(state.cursorByTask[taskId] || 0));
  if (state.token) {
    params.set("token", state.token);
  }
  const wsUrl = `${protocol}://${window.location.host}/ws/tasks/${encodeURIComponent(taskId)}?${params.toString()}`;
  const ws = new WebSocket(wsUrl);
  state.ws = ws;

  ws.onmessage = (event) => {
    let payload = null;
    try {
      payload = JSON.parse(event.data);
    } catch (_error) {
      return;
    }
    if (payload.type === "logs") {
      const entries = Array.isArray(payload.entries) ? payload.entries : [];
      appendConsole(entries.map((entry) => entry.line));
      if (typeof payload.cursor === "number") {
        state.cursorByTask[taskId] = payload.cursor;
      }
      return;
    }
    if (payload.type === "task") {
      loadTasks();
      return;
    }
    if (payload.type === "error") {
      setHint(`Socket error: ${payload.message}`, "error");
    }
  };

  ws.onclose = (event) => {
    if (event.code === 1008) {
      setHint("Socket auth failed. Verify token.", "error");
      return;
    }
    if (state.activeTaskId !== taskId) {
      return;
    }
    setTimeout(() => {
      if (state.activeTaskId === taskId) {
        connectLogsSocket(taskId);
      }
    }, 1500);
  };
}

function installHandlers() {
  dom.tokenInput.value = state.token;

  dom.saveTokenBtn.addEventListener("click", async () => {
    state.token = dom.tokenInput.value.trim();
    localStorage.setItem("swissknife.webui.token", state.token);
    closeLogsSocket();
    if (state.activeTaskId) {
      connectLogsSocket(state.activeTaskId);
    }
    await Promise.all([loadMenu(), loadModules(), loadTasks()]);
  });

  dom.refreshMenuBtn.addEventListener("click", async () => {
    await loadMenu();
    await loadModules();
  });
  dom.refreshTasksBtn.addEventListener("click", loadTasks);
  dom.clearConsoleBtn.addEventListener("click", () => setConsoleText([]));
  dom.stopTaskBtn.addEventListener("click", stopActiveTask);

  dom.taskInputForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const value = dom.taskInputField.value;
    if (!value.trim()) {
      return;
    }
    await sendInput(value);
    dom.taskInputField.value = "";
    dom.taskInputField.focus();
  });
}

async function bootstrap() {
  installHandlers();
  await loadMeta();
  await loadMenu();
  await loadModules();
  await loadTasks();

  if (state.pollHandle) {
    clearInterval(state.pollHandle);
  }
  state.pollHandle = setInterval(loadTasks, 3500);
}

bootstrap();
