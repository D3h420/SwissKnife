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
        {
          id: "deauth",
          label: "Deauth",
          type: "module",
          module_id: "deauth",
          description: "Deauthentication workflow.",
          controls: [
            {
              id: "interface",
              label: "Interface",
              kind: "select",
              source: "tool_interfaces",
              default: "auto",
            },
            {
              id: "scan_depth",
              label: "Scan Depth",
              kind: "range",
              min: 10,
              max: 90,
              step: 5,
              default: 25,
              suffix: "s",
            },
            {
              id: "method",
              label: "Method",
              kind: "select",
              options: [
                { value: "deauth", label: "deauth" },
                { value: "mdk4", label: "mdk4" },
                { value: "bully", label: "bully" },
              ],
              default: "deauth",
            },
          ],
        },
        {
          id: "portal",
          label: "Portal",
          type: "module",
          module_id: "portal",
          description: "Captive portal workflow.",
          controls: [
            {
              id: "ap_interface",
              label: "AP Interface",
              kind: "select",
              source: "tool_interfaces",
              default: "auto",
            },
            {
              id: "scan_duration",
              label: "Scan Time",
              kind: "range",
              min: 10,
              max: 120,
              step: 5,
              default: 25,
              suffix: "s",
            },
            {
              id: "portal_type",
              label: "Portal",
              kind: "select",
              options: [
                { value: "default", label: "default" },
                { value: "router", label: "router style" },
                { value: "custom", label: "custom" },
              ],
              default: "default",
            },
          ],
        },
        {
          id: "twins",
          label: "Evil Twin",
          type: "module",
          module_id: "twins",
          description: "Rogue AP + portal workflow.",
          controls: [
            {
              id: "attack_interface",
              label: "Attack Interface",
              kind: "select",
              source: "tool_interfaces",
              default: "auto",
            },
            {
              id: "ap_interface",
              label: "AP Interface",
              kind: "select",
              source: "tool_interfaces",
              default: "auto",
            },
            {
              id: "scan_duration",
              label: "Recon Time",
              kind: "range",
              min: 10,
              max: 120,
              step: 5,
              default: 25,
              suffix: "s",
            },
          ],
        },
        {
          id: "handshaker",
          label: "Handshaker",
          type: "module",
          module_id: "handshaker",
          description: "Under construction module.",
          under_construction: true,
          controls: [
            {
              id: "interface",
              label: "Interface",
              kind: "select",
              source: "tool_interfaces",
              default: "auto",
            },
            {
              id: "scan_duration",
              label: "Scan Time",
              kind: "range",
              min: 10,
              max: 120,
              step: 5,
              default: 25,
              suffix: "s",
            },
          ],
        },
        {
          id: "karma",
          label: "Karma",
          type: "module",
          description: "Under construction module.",
          disabled: true,
          under_construction: true,
        },
      ],
    },
    {
      id: "bluetooth",
      label: "Bluetooth",
      icon: "BT",
      type: "module",
      module_id: "bluetooth",
      description: "Bluetooth and BLE workflows.",
      controls: [
        {
          id: "scan_mode",
          label: "Mode",
          kind: "select",
          options: [
            { value: "bt", label: "Bluetooth" },
            { value: "ble", label: "BLE" },
          ],
          default: "bt",
        },
        {
          id: "timeout",
          label: "Timeout",
          kind: "range",
          min: 10,
          max: 180,
          step: 5,
          default: 30,
          suffix: "s",
        },
      ],
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
    all_interfaces: [],
    tool_interfaces: [],
    tool_interface_names: [],
  },
  tasks: [],
  activeTaskId: null,
  resultByTask: {},
  logCursorByTask: {},
  recentLogsByTask: {},
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

function isReconModule(moduleId) {
  return moduleId === "recon_scan" || moduleId === "recon_sniff";
}

function stripAnsi(text) {
  if (typeof text !== "string") {
    return "";
  }
  return text.replace(/\x1B\[[0-9;]*[mKHFJ]/g, "").trim();
}

function shortLine(text, limit = 88) {
  const clean = stripAnsi(text);
  if (!clean) {
    return "";
  }
  if (clean.length <= limit) {
    return clean;
  }
  return `${clean.slice(0, limit - 1)}…`;
}

function toText(value) {
  if (typeof value === "string") {
    return value.trim();
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  return "";
}

function interfaceNameFrom(value) {
  const direct = toText(value);
  if (direct) {
    return direct;
  }
  if (!value || typeof value !== "object") {
    return "";
  }
  const keys = ["name", "interface", "iface", "device", "id", "value", "key"];
  for (const key of keys) {
    const candidate = toText(value[key]);
    if (candidate) {
      return candidate;
    }
  }
  return "";
}

function normalizeInterfaceEntry(rawEntry) {
  if (rawEntry === null || rawEntry === undefined) {
    return null;
  }
  if (typeof rawEntry === "string" || typeof rawEntry === "number") {
    const name = interfaceNameFrom(rawEntry);
    if (!name) {
      return null;
    }
    return {
      name,
      label: name,
      driver: "",
      bus_info: "",
      is_builtin: false,
    };
  }
  if (typeof rawEntry !== "object") {
    return null;
  }

  const name = interfaceNameFrom(rawEntry);
  const driver = toText(rawEntry.driver || rawEntry.chipset || rawEntry.vendor || "");
  const busInfo = toText(rawEntry.bus_info || rawEntry.busInfo || rawEntry.bus || "");
  const isBuiltin = Boolean(rawEntry.is_builtin || rawEntry.builtin || rawEntry.isBuiltin);

  let label = toText(rawEntry.label || rawEntry.display || rawEntry.title || rawEntry.text || "");
  const driverKnown = driver && driver.toLowerCase() !== "unknown";
  if (!label) {
    label = name;
    if (driverKnown) {
      label = `${label} · ${driver}`;
    }
    if (busInfo) {
      label = `${label} (${busInfo})`;
    }
  }

  if (!name) {
    return null;
  }

  return {
    name,
    label: label || name,
    driver: driverKnown ? driver : "",
    bus_info: busInfo,
    is_builtin: isBuiltin,
  };
}

function normalizeInterfaceList(rawList) {
  const rows = Array.isArray(rawList) ? rawList : [];
  const dedupe = new Map();
  rows.forEach((rawEntry) => {
    const entry = normalizeInterfaceEntry(rawEntry);
    if (!entry || !entry.name) {
      return;
    }
    const prev = dedupe.get(entry.name);
    if (!prev) {
      dedupe.set(entry.name, entry);
      return;
    }
    const prevLabel = toText(prev.label);
    const nextLabel = toText(entry.label);
    dedupe.set(entry.name, {
      name: entry.name,
      label: nextLabel.length >= prevLabel.length ? nextLabel : prevLabel,
      driver: prev.driver || entry.driver,
      bus_info: prev.bus_info || entry.bus_info,
      is_builtin: prev.is_builtin || entry.is_builtin,
    });
  });
  return Array.from(dedupe.values()).sort((left, right) => {
    const leftName = toText(left?.name);
    const rightName = toText(right?.name);
    const leftRank = leftName.startsWith("wlan") ? 0 : 1;
    const rightRank = rightName.startsWith("wlan") ? 0 : 1;
    if (leftRank !== rightRank) {
      return leftRank - rightRank;
    }
    return leftName.localeCompare(rightName);
  });
}

function normalizeBuiltinInterface(rawBuiltin, allInterfaces) {
  const direct = interfaceNameFrom(rawBuiltin);
  if (direct) {
    return direct;
  }
  const builtin = (Array.isArray(allInterfaces) ? allInterfaces : []).find((entry) => entry && entry.is_builtin);
  return builtin?.name || "";
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
    items.forEach((entry) => {
      if (typeof entry === "string") {
        options.push({ value: entry, label: entry });
        return;
      }
      const name = entry.name || "";
      if (!name) {
        return;
      }
      const label = entry.label || `${name}${entry.driver ? ` · ${entry.driver}` : ""}`;
      options.push({ value: name, label });
    });
    return options;
  }

  if (control.source === "all_interfaces") {
    const items = Array.isArray(state.interfaces.all_interfaces) ? state.interfaces.all_interfaces : [];
    return items
      .map((entry) => {
        if (typeof entry === "string") {
          return { value: entry, label: entry };
        }
        const name = entry.name || "";
        if (!name) {
          return null;
        }
        const label = entry.label || `${name}${entry.driver ? ` · ${entry.driver}` : ""}`;
        return { value: name, label };
      })
      .filter(Boolean);
  }

  return [];
}

function getInterfaceLabel(name) {
  if (!name) {
    return "";
  }
  const targetName = interfaceNameFrom(name);
  if (!targetName) {
    return "";
  }
  const all = Array.isArray(state.interfaces.all_interfaces) ? state.interfaces.all_interfaces : [];
  const entry = all.find((item) => item && typeof item !== "string" && item.name === targetName);
  if (!entry) {
    return targetName;
  }
  return entry.label || `${entry.name}${entry.driver ? ` · ${entry.driver}` : ""}` || targetName;
}

function buildInterfaceLegend(includeBuiltin = false) {
  const entries = normalizeInterfaceList(state.interfaces.all_interfaces);
  const filtered = includeBuiltin ? entries : entries.filter((entry) => !entry?.is_builtin);
  if (!filtered.length) {
    return null;
  }

  const wrap = document.createElement("div");
  wrap.className = "adapter-strip";
  filtered.forEach((entry) => {
    const chip = document.createElement("span");
    chip.className = "adapter-chip";
    const label = entry?.label || entry?.name || "";
    chip.textContent = entry?.is_builtin ? `${label} (builtin/AP)` : label;
    wrap.appendChild(chip);
  });
  return wrap;
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
      empty.textContent = "No options";
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
    if (control.source === "tool_interfaces" || control.source === "all_interfaces") {
      const note = document.createElement("span");
      note.className = "control-note";
      const refreshNote = () => {
        const selected = options.find((entry) => entry.value === select.value);
        note.textContent = selected ? selected.label : "";
      };
      select.addEventListener("change", refreshNote);
      refreshNote();
      wrap.appendChild(note);
    }
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

function createActionCard(item, sectionId) {
  const card = document.createElement("article");
  card.className = "action-card";

  const title = document.createElement("h3");
  title.textContent = item.label;
  card.appendChild(title);

  const description = document.createElement("p");
  description.textContent = item.description || "";
  card.appendChild(description);

  const controls = Array.isArray(item.controls) ? item.controls : [];
  if (controls.length) {
    const controlsWrap = document.createElement("div");
    controlsWrap.className = "control-grid";
    controls.forEach((control) => {
      controlsWrap.appendChild(createControlField(control));
    });
    card.appendChild(controlsWrap);
  }

  if (sectionId === "attacks") {
    const touchHint = document.createElement("p");
    touchHint.className = "touch-hint";
    touchHint.textContent = "After Run: use touch buttons below (no keyboard typing).";
    card.appendChild(touchHint);
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
    const needsToolInterface = controls.some((control) => control.source === "tool_interfaces");
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
  dom.sectionBody.dataset.sectionId = section.id || "";

  if (section.id === "recon") {
    if (state.interfaces.builtin_interface) {
      const notice = document.createElement("div");
      notice.className = "muted-block";
      notice.textContent = `AP/WebUI uses ${getInterfaceLabel(state.interfaces.builtin_interface)}. Recon controls target external adapters.`;
      dom.sectionBody.appendChild(notice);
    }
    const adapterLegend = buildInterfaceLegend(false);
    if (adapterLegend) {
      dom.sectionBody.appendChild(adapterLegend);
    } else {
      const missing = document.createElement("div");
      missing.className = "muted-block";
      missing.textContent = "No external wireless adapters detected for Recon.";
      dom.sectionBody.appendChild(missing);
    }
  }

  if (section.id === "attacks") {
    const adapterLegend = buildInterfaceLegend(true);
    if (adapterLegend) {
      dom.sectionBody.appendChild(adapterLegend);
    } else {
      const missing = document.createElement("div");
      missing.className = "muted-block";
      missing.textContent = "No wireless interfaces detected.";
      dom.sectionBody.appendChild(missing);
    }
  }

  if (section.type === "module") {
    const grid = document.createElement("div");
    grid.className = "action-grid";
    grid.appendChild(createActionCard(section, section.id));
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
    items.forEach((item) => grid.appendChild(createActionCard(item, section.id)));
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

function renderLogFeed(taskId) {
  const lines = Array.isArray(state.recentLogsByTask[taskId]) ? state.recentLogsByTask[taskId] : [];
  const wrap = document.createElement("div");
  wrap.className = "log-feed";
  if (!lines.length) {
    wrap.textContent = "No short status lines yet.";
    return wrap;
  }

  const list = document.createElement("ul");
  list.className = "status-list";
  lines.slice(-10).forEach((line) => {
    const li = document.createElement("li");
    li.textContent = shortLine(line);
    list.appendChild(li);
  });
  wrap.appendChild(list);
  return wrap;
}

function renderReconScanResult(result, task) {
  dom.resultsView.innerHTML = "";

  const summary = document.createElement("div");
  summary.className = "result-summary";
  summary.appendChild(createSummaryPill("Mode", "Scanner"));
  summary.appendChild(createSummaryPill("Interface", getInterfaceLabel(result.interface) || "-"));
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
  summary.appendChild(createSummaryPill("Interface", getInterfaceLabel(result.interface) || "-"));
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
    probes.textContent = entries
      .slice(0, 18)
      .map((entry) => `${entry.ssid || "<hidden>"} (${entry.count || 0})`)
      .join(" • ");
  }
  dom.resultsView.appendChild(probes);
}

async function sendTaskInput(taskId, text, successLabel = "Command sent") {
  try {
    await apiFetch(`/api/tasks/${taskId}/input`, {
      method: "POST",
      body: { text },
    });
    setHint(successLabel, "success");
    await loadTaskLogs(taskId, true);
  } catch (error) {
    if (isUnauthorizedError(error)) {
      setHint("Unauthorized. Provide valid token.", "error");
      return;
    }
    setHint(`Input failed: ${error.message}`, "error");
  }
}

function buildQuickButton(taskId, label, payload, successLabel = "Command sent") {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "quick-btn";
  button.textContent = label;
  button.addEventListener("click", () => {
    sendTaskInput(taskId, payload, successLabel);
  });
  return button;
}

function latestPrompt(taskId) {
  const lines = Array.isArray(state.recentLogsByTask[taskId]) ? state.recentLogsByTask[taskId] : [];
  for (let index = lines.length - 1; index >= 0; index -= 1) {
    const line = lines[index];
    if (!line) {
      continue;
    }
    if (line.includes("choice") || line.includes("Select") || line.includes("Press Enter") || line.includes("Proceed")) {
      return shortLine(line, 140);
    }
  }
  return "";
}

function touchPadRowsForModule(moduleId) {
  if (moduleId === "deauth") {
    return [
      [
        { label: "1", payload: "1", success: "Sent 1" },
        { label: "2", payload: "2", success: "Sent 2" },
        { label: "3", payload: "3", success: "Sent 3" },
        { label: "Enter", payload: "", success: "Sent Enter", accent: true },
      ],
      [
        { label: "Rescan", payload: "r", success: "Sent rescan" },
        { label: "Yes", payload: "y", success: "Sent yes" },
        { label: "No", payload: "n", success: "Sent no" },
        { label: "Back", payload: "b", success: "Sent back" },
      ],
    ];
  }

  if (moduleId === "portal" || moduleId === "twins") {
    return [
      [
        { label: "1", payload: "1", success: "Sent 1" },
        { label: "2", payload: "2", success: "Sent 2" },
        { label: "3", payload: "3", success: "Sent 3" },
        { label: "4", payload: "4", success: "Sent 4" },
      ],
      [
        { label: "Rescan", payload: "r", success: "Sent rescan" },
        { label: "Manual", payload: "m", success: "Sent manual" },
        { label: "Yes", payload: "y", success: "Sent yes" },
        { label: "No", payload: "n", success: "Sent no" },
      ],
      [
        { label: "Enter", payload: "", success: "Sent Enter", accent: true },
        { label: "Back", payload: "b", success: "Sent back" },
      ],
    ];
  }

  if (moduleId === "bluetooth") {
    return [
      [
        { label: "Scan BT", payload: "1", success: "Sent scan BT" },
        { label: "BLE Poet", payload: "2", success: "Sent BLE Poet" },
        { label: "Back", payload: "3", success: "Sent back" },
      ],
      [
        { label: "Yes", payload: "y", success: "Sent yes" },
        { label: "No", payload: "n", success: "Sent no" },
        { label: "Enter", payload: "", success: "Sent Enter", accent: true },
      ],
    ];
  }

  return [
    [
      { label: "1", payload: "1", success: "Sent 1" },
      { label: "2", payload: "2", success: "Sent 2" },
      { label: "3", payload: "3", success: "Sent 3" },
      { label: "4", payload: "4", success: "Sent 4" },
    ],
    [
      { label: "5", payload: "5", success: "Sent 5" },
      { label: "6", payload: "6", success: "Sent 6" },
      { label: "Yes", payload: "y", success: "Sent yes" },
      { label: "No", payload: "n", success: "Sent no" },
    ],
    [
      { label: "Enter", payload: "", success: "Sent Enter", accent: true },
      { label: "Back", payload: "b", success: "Sent back" },
    ],
  ];
}

function renderInteractiveControls(task) {
  dom.resultsView.innerHTML = "";

  const summary = document.createElement("div");
  summary.className = "result-summary";
  summary.appendChild(createSummaryPill("Module", task.module_name));
  summary.appendChild(createSummaryPill("Task", task.task_id));
  summary.appendChild(createSummaryPill("State", task.running ? "RUNNING" : "STOPPED"));
  dom.resultsView.appendChild(summary);

  const prompt = latestPrompt(task.task_id);
  if (prompt) {
    const promptBar = document.createElement("div");
    promptBar.className = "prompt-bar";
    promptBar.textContent = `Prompt: ${prompt}`;
    dom.resultsView.appendChild(promptBar);
  }

  const pad = document.createElement("div");
  pad.className = "wizard-pad";
  const rows = touchPadRowsForModule(task.module_id);
  rows.forEach((items) => {
    const row = document.createElement("div");
    row.className = "wizard-row";
    items.forEach((item) => {
      const button = buildQuickButton(task.task_id, item.label, item.payload, item.success);
      if (item.accent) {
        button.classList.add("accent");
      }
      row.appendChild(button);
    });
    pad.appendChild(row);
  });

  dom.resultsView.appendChild(pad);
  dom.resultsView.appendChild(renderLogFeed(task.task_id));
}

function renderReconLiveStatus(task) {
  dom.resultsView.innerHTML = "";
  const summary = document.createElement("div");
  summary.className = "result-summary";
  summary.appendChild(createSummaryPill("Mode", task.module_name));
  summary.appendChild(createSummaryPill("Task", task.task_id));
  summary.appendChild(createSummaryPill("State", task.running ? "RUNNING" : "STOPPED"));
  dom.resultsView.appendChild(summary);
  dom.resultsView.appendChild(renderLogFeed(task.task_id));
}

function renderResultView() {
  dom.resultsView.innerHTML = "";

  const task = getTaskById(state.activeTaskId);
  if (!task) {
    const empty = document.createElement("div");
    empty.className = "muted-block";
    empty.textContent = "Select task to see module output.";
    dom.resultsView.appendChild(empty);
    return;
  }

  const result = state.resultByTask[task.task_id] || null;

  if (isReconModule(task.module_id)) {
    if (result?.kind === "recon_scan") {
      renderReconScanResult(result, task);
      return;
    }
    if (result?.kind === "recon_sniff") {
      renderReconSniffResult(result, task);
      return;
    }
    renderReconLiveStatus(task);
    return;
  }

  renderInteractiveControls(task);
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
    const allInterfaces = normalizeInterfaceList(data.all_interfaces);
    const allWirelessFallback = normalizeInterfaceList(data.all_wireless);
    if (!allInterfaces.length && allWirelessFallback.length) {
      allInterfaces.push(...allWirelessFallback);
    }

    const builtinInterface = normalizeBuiltinInterface(data.builtin_interface, allInterfaces);
    if (builtinInterface) {
      const idx = allInterfaces.findIndex((entry) => entry.name === builtinInterface);
      if (idx >= 0) {
        allInterfaces[idx] = { ...allInterfaces[idx], is_builtin: true };
      } else {
        allInterfaces.unshift({
          name: builtinInterface,
          label: builtinInterface,
          driver: "",
          bus_info: "",
          is_builtin: true,
        });
      }
    }

    let toolInterfaces = normalizeInterfaceList(data.tool_interfaces);
    toolInterfaces = toolInterfaces.filter((entry) => entry.name && entry.name !== builtinInterface);
    if (!toolInterfaces.length) {
      toolInterfaces = allInterfaces.filter((entry) => !entry.is_builtin);
    }

    state.interfaces = {
      builtin_interface: builtinInterface,
      all_wireless: allInterfaces.map((entry) => entry.name),
      all_interfaces: allInterfaces,
      tool_interfaces: toolInterfaces,
      tool_interface_names: toolInterfaces.map((entry) => entry.name),
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

async function loadTaskLogs(taskId, silent = false) {
  if (!taskId) {
    return;
  }

  const since = state.logCursorByTask[taskId] || 0;
  try {
    const data = await apiFetch(`/api/tasks/${taskId}/logs?since=${since}`);
    const entries = Array.isArray(data.entries) ? data.entries : [];
    if (typeof data.cursor === "number") {
      state.logCursorByTask[taskId] = data.cursor;
    }

    const bucket = Array.isArray(state.recentLogsByTask[taskId]) ? state.recentLogsByTask[taskId] : [];
    entries.forEach((entry) => {
      const line = shortLine(entry.line || "");
      if (!line) {
        return;
      }
      if (line.startsWith("[webui-result]")) {
        return;
      }
      bucket.push(line);
    });
    state.recentLogsByTask[taskId] = bucket.slice(-20);
  } catch (error) {
    if (isUnauthorizedError(error)) {
      if (!silent) {
        setHint("Unauthorized. Provide valid token.", "error");
      }
      return;
    }
    if (!silent) {
      setHint(`Failed to load logs: ${error.message}`, "error");
    }
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
    await Promise.all([
      loadTaskResult(state.activeTaskId, true),
      loadTaskLogs(state.activeTaskId, true),
    ]);
    renderResultView();
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
    if (task?.task_id) {
      state.activeTaskId = task.task_id;
      state.logCursorByTask[task.task_id] = 0;
      state.recentLogsByTask[task.task_id] = [];
    }
    await loadTasks();
    if (task?.task_id) {
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
  if (state.logCursorByTask[taskId] === undefined) {
    state.logCursorByTask[taskId] = 0;
  }
  if (!Array.isArray(state.recentLogsByTask[taskId])) {
    state.recentLogsByTask[taskId] = [];
  }
  renderTasks();
  Promise.all([
    loadTaskResult(taskId, true),
    loadTaskLogs(taskId, true),
  ]).then(renderResultView);
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
  state.pollHandle = setInterval(loadTasks, 2500);
}

bootstrap();
