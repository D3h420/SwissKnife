const state = {
  token: localStorage.getItem("swissknife.webui.token") || "",
  authRequired: false,
  modules: [],
  tasks: [],
  activeTaskId: null,
  ws: null,
  cursorByTask: {},
  keepPollingHandle: null,
};

const dom = {
  tokenInput: document.getElementById("tokenInput"),
  saveTokenBtn: document.getElementById("saveTokenBtn"),
  authHint: document.getElementById("authHint"),
  globalArgsInput: document.getElementById("globalArgsInput"),
  refreshModulesBtn: document.getElementById("refreshModulesBtn"),
  modulesGrid: document.getElementById("modulesGrid"),
  refreshTasksBtn: document.getElementById("refreshTasksBtn"),
  tasksList: document.getElementById("tasksList"),
  clearConsoleBtn: document.getElementById("clearConsoleBtn"),
  stopTaskBtn: document.getElementById("stopTaskBtn"),
  consoleOutput: document.getElementById("consoleOutput"),
  taskInputForm: document.getElementById("taskInputForm"),
  taskInputField: document.getElementById("taskInputField"),
};

function setHint(message, level = "") {
  dom.authHint.textContent = message;
  dom.authHint.classList.remove("error", "success");
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
  const date = new Date(timestamp * 1000);
  return date.toLocaleTimeString();
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
  if (dom.consoleOutput.textContent.length > 180000) {
    dom.consoleOutput.textContent = dom.consoleOutput.textContent.slice(-180000);
  }
  dom.consoleOutput.scrollTop = dom.consoleOutput.scrollHeight;
}

function renderModules() {
  dom.modulesGrid.innerHTML = "";

  if (!state.modules.length) {
    const empty = document.createElement("p");
    empty.textContent = "No modules loaded.";
    empty.className = "module-status";
    dom.modulesGrid.appendChild(empty);
    return;
  }

  state.modules.forEach((module) => {
    const card = document.createElement("div");
    card.className = "module-card";

    const title = document.createElement("h3");
    title.textContent = module.name;
    card.appendChild(title);

    const descr = document.createElement("p");
    descr.textContent = module.description;
    card.appendChild(descr);

    const footer = document.createElement("div");
    footer.className = "module-meta";

    const status = document.createElement("span");
    status.className = "module-status";
    status.textContent = module.exists ? module.script : `Missing script: ${module.script}`;
    footer.appendChild(status);

    const button = document.createElement("button");
    button.type = "button";
    button.textContent = "Start";
    button.className = module.exists ? "primary" : "secondary";
    button.disabled = !module.exists;
    button.addEventListener("click", () => startModule(module.module_id));
    footer.appendChild(button);

    card.appendChild(footer);
    dom.modulesGrid.appendChild(card);
  });
}

function renderTasks() {
  dom.tasksList.innerHTML = "";

  if (!state.tasks.length) {
    const item = document.createElement("li");
    item.className = "task-item";
    item.textContent = "No tasks yet.";
    dom.tasksList.appendChild(item);
    return;
  }

  state.tasks.forEach((task) => {
    const li = document.createElement("li");
    li.className = `task-item${task.task_id === state.activeTaskId ? " active" : ""}`;
    li.dataset.taskId = task.task_id;
    li.addEventListener("click", () => selectTask(task.task_id));

    const row = document.createElement("div");
    row.className = "task-row";

    const name = document.createElement("span");
    name.className = "task-name";
    name.textContent = `${task.module_name} (${task.task_id})`;
    row.appendChild(name);

    const status = document.createElement("span");
    status.className = `task-state ${task.running ? "running" : "stopped"}`;
    status.textContent = task.running ? "RUNNING" : "STOPPED";
    row.appendChild(status);

    const detail = document.createElement("div");
    detail.className = "task-detail";
    detail.textContent = `Started ${parseTime(task.started_at)}  Return code: ${task.returncode ?? "-"}`;

    li.appendChild(row);
    li.appendChild(detail);
    dom.tasksList.appendChild(li);
  });
}

async function loadMeta() {
  try {
    const data = await fetch("/api/meta").then((response) => response.json());
    state.authRequired = Boolean(data.auth_required);
    if (state.authRequired) {
      setHint("Token auth enabled. Save token to use the API.");
    } else {
      setHint("Auth disabled on server.", "success");
    }
  } catch (error) {
    setHint(`Failed to read server meta: ${error.message}`, "error");
  }
}

async function loadModules() {
  try {
    const data = await apiFetch("/api/modules");
    state.modules = data.modules || [];
    renderModules();
    setHint("Modules loaded.", "success");
  } catch (error) {
    if (isUnauthorizedError(error)) {
      setHint("Unauthorized: set a valid token.", "error");
      return;
    }
    setHint(`Failed to load modules: ${error.message}`, "error");
  }
}

async function loadTasks() {
  try {
    const data = await apiFetch("/api/tasks");
    state.tasks = data.tasks || [];
    renderTasks();
  } catch (error) {
    if (isUnauthorizedError(error)) {
      setHint("Unauthorized: set a valid token.", "error");
      return;
    }
    setHint(`Failed to load tasks: ${error.message}`, "error");
  }
}

async function startModule(moduleId) {
  try {
    const rawArgs = dom.globalArgsInput.value.trim();
    const data = await apiFetch("/api/tasks/start", {
      method: "POST",
      body: {
        module_id: moduleId,
        raw_args: rawArgs,
      },
    });
    const task = data.task;
    await loadTasks();
    if (task?.task_id) {
      selectTask(task.task_id);
      setHint(`Task ${task.task_id} started.`, "success");
    }
  } catch (error) {
    if (isUnauthorizedError(error)) {
      setHint("Unauthorized: set a valid token.", "error");
      return;
    }
    setHint(`Failed to start module: ${error.message}`, "error");
  }
}

async function stopActiveTask() {
  if (!state.activeTaskId) {
    setHint("Select a task first.", "error");
    return;
  }
  try {
    await apiFetch(`/api/tasks/${state.activeTaskId}/stop`, { method: "POST" });
    await loadTasks();
    setHint(`Task ${state.activeTaskId} stop signal sent.`, "success");
  } catch (error) {
    if (isUnauthorizedError(error)) {
      setHint("Unauthorized: set a valid token.", "error");
      return;
    }
    setHint(`Failed to stop task: ${error.message}`, "error");
  }
}

async function sendInputToActiveTask(text) {
  if (!state.activeTaskId) {
    setHint("Select a task first.", "error");
    return;
  }
  try {
    await apiFetch(`/api/tasks/${state.activeTaskId}/input`, {
      method: "POST",
      body: { text },
    });
  } catch (error) {
    if (isUnauthorizedError(error)) {
      setHint("Unauthorized: set a valid token.", "error");
      return;
    }
    setHint(`Failed to send input: ${error.message}`, "error");
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

  const socketUrl = `${protocol}://${window.location.host}/ws/tasks/${encodeURIComponent(taskId)}?${params.toString()}`;
  const ws = new WebSocket(socketUrl);
  state.ws = ws;

  ws.onmessage = (event) => {
    let payload;
    try {
      payload = JSON.parse(event.data);
    } catch (_error) {
      return;
    }

    if (payload.type === "logs") {
      const entries = payload.entries || [];
      const lines = entries.map((entry) => entry.line);
      appendConsole(lines);
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
    await Promise.all([loadModules(), loadTasks()]);
  });

  dom.refreshModulesBtn.addEventListener("click", loadModules);
  dom.refreshTasksBtn.addEventListener("click", loadTasks);
  dom.clearConsoleBtn.addEventListener("click", () => setConsoleText([]));
  dom.stopTaskBtn.addEventListener("click", stopActiveTask);

  dom.taskInputForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const text = dom.taskInputField.value;
    if (!text.trim()) {
      return;
    }
    await sendInputToActiveTask(text);
    dom.taskInputField.value = "";
    dom.taskInputField.focus();
  });
}

async function bootstrap() {
  installHandlers();
  await loadMeta();
  await loadModules();
  await loadTasks();

  if (state.keepPollingHandle) {
    clearInterval(state.keepPollingHandle);
  }
  state.keepPollingHandle = setInterval(loadTasks, 4000);
}

bootstrap();

