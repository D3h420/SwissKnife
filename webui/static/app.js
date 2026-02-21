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
              arg: "--ap-interface",
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
              arg: "--scan-duration",
            },
            {
              id: "ap_ssid",
              label: "AP Name",
              kind: "text",
              default: "",
              placeholder: "np. Free_WiFi",
              arg: "--ap-ssid",
            },
            {
              id: "portal_file",
              label: "Portal",
              kind: "select",
              source: "portal_templates",
              options: [{ value: "portal.html", label: "portal.html" }],
              default: "portal.html",
              arg: "--portal-file",
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
            {
              id: "portal_file",
              label: "Portal",
              kind: "select",
              source: "portal_templates",
              options: [{ value: "portal.html", label: "portal.html" }],
              default: "portal.html",
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
      id: "loot",
      label: "Loot",
      icon: "LOT",
      type: "info",
      description: "Captured files and logs from /log.",
    },
  ],
};

const MENU_ICON_FILES = {
  recon: "recon_icon.PNG",
  attacks: "attack_icon.PNG",
  bluetooth: "bluetooth_icon.PNG",
  loot: "loot_icon.PNG",
};

const state = {
  token: localStorage.getItem("swissknife.webui.token") || "",
  panelSession: localStorage.getItem("swissknife.webui.panel_session") || "",
  authRequired: false,
  devNoCache: false,
  unlocked: false,
  menu: FALLBACK_MENU.main,
  selectedSectionId: null,
  selectedItemBySection: {},
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
  expandedAttackId: null,
  portalTemplates: [],
  lootFiles: [],
  lootLoaded: false,
  selectedLootFile: "",
  lootContentByFile: {},
  attackTaskSig: "",
  pollHandle: null,
  deauthStateByTask: {},
  portalStateByTask: {},
  twinsStateByTask: {},
  handshakerStateByTask: {},
  bluetoothStateByTask: {},
  attackControlDraftByModule: {},
  attackUiLockUntil: 0,
  sectionUiLockUntil: 0,
};

const ATTACK_UI_LOCK_MS = 12000;
const SECTION_UI_LOCK_MS = 8000;

const matrix = {
  fontSize: 18,
  chars: "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789#$%*+=<>[]{}",
  rafId: 0,
  lastTick: 0,
  columns: 0,
  drops: [],
  running: false,
};

const dom = {
  appShell: document.getElementById("appShell"),
  introGate: document.getElementById("introGate"),
  matrixCanvas: document.getElementById("matrixCanvas"),
  introLoginForm: document.getElementById("introLoginForm"),
  introPasswordInput: document.getElementById("introPasswordInput"),
  introLoginBtn: document.getElementById("introLoginBtn"),
  introHint: document.getElementById("introHint"),
  settingsToggleBtn: document.getElementById("settingsToggleBtn"),
  settingsMenu: document.getElementById("settingsMenu"),
  openPasswordChangeBtn: document.getElementById("openPasswordChangeBtn"),
  passwordChangePanel: document.getElementById("passwordChangePanel"),
  newPasswordInput: document.getElementById("newPasswordInput"),
  changePasswordBtn: document.getElementById("changePasswordBtn"),
  turnOffBtn: document.getElementById("turnOffBtn"),
  authHint: document.getElementById("authHint"),
  interfaceSummary: document.getElementById("interfaceSummary"),
  refreshMenuBtn: document.getElementById("refreshMenuBtn"),
  mainMenu: document.getElementById("mainMenu"),
  subMenu: document.getElementById("subMenu"),
  centerPanel: document.getElementById("centerPanel"),
  sectionTitle: document.getElementById("sectionTitle"),
  sectionBody: document.getElementById("sectionBody"),
  tasksHead: document.getElementById("tasksHead"),
  refreshTasksBtn: document.getElementById("refreshTasksBtn"),
  tasksList: document.getElementById("tasksList"),
  resultsHead: document.getElementById("resultsHead"),
  activeTaskChip: document.getElementById("activeTaskChip"),
  stopTaskBtn: document.getElementById("stopTaskBtn"),
  resultsView: document.getElementById("resultsView"),
};

function setHint(message, level = "") {
  if (!dom.authHint) {
    return;
  }
  dom.authHint.textContent = message;
  dom.authHint.classList.remove("success", "error");
  if (level) {
    dom.authHint.classList.add(level);
  }
}

function setIntroHint(message, level = "") {
  if (!dom.introHint) {
    return;
  }
  dom.introHint.textContent = message;
  dom.introHint.classList.remove("success", "error");
  if (level) {
    dom.introHint.classList.add(level);
  }
}

function resetMatrix() {
  if (!dom.matrixCanvas) {
    return;
  }
  const canvas = dom.matrixCanvas;
  const ctx = canvas.getContext("2d");
  if (!ctx) {
    return;
  }

  const dpr = window.devicePixelRatio || 1;
  const width = Math.max(1, window.innerWidth);
  const height = Math.max(1, window.innerHeight);
  canvas.width = Math.floor(width * dpr);
  canvas.height = Math.floor(height * dpr);
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.fillStyle = "#020a03";
  ctx.fillRect(0, 0, width, height);

  matrix.columns = Math.max(1, Math.floor(width / matrix.fontSize));
  matrix.drops = Array.from({ length: matrix.columns }, () => Math.floor(Math.random() * -30));
}

function drawMatrixFrame(timestamp = 0) {
  if (!matrix.running || !dom.matrixCanvas) {
    return;
  }

  const delta = timestamp - matrix.lastTick;
  if (delta < 42) {
    matrix.rafId = window.requestAnimationFrame(drawMatrixFrame);
    return;
  }
  matrix.lastTick = timestamp;

  const canvas = dom.matrixCanvas;
  const ctx = canvas.getContext("2d");
  if (!ctx) {
    matrix.rafId = window.requestAnimationFrame(drawMatrixFrame);
    return;
  }

  const width = canvas.width / (window.devicePixelRatio || 1);
  const height = canvas.height / (window.devicePixelRatio || 1);

  ctx.fillStyle = "rgba(2, 10, 4, 0.14)";
  ctx.fillRect(0, 0, width, height);
  ctx.font = `${matrix.fontSize}px "JetBrains Mono", monospace`;
  ctx.fillStyle = "#7aff96";

  for (let index = 0; index < matrix.columns; index += 1) {
    const char = matrix.chars[Math.floor(Math.random() * matrix.chars.length)];
    const x = index * matrix.fontSize;
    const y = matrix.drops[index] * matrix.fontSize;
    ctx.fillText(char, x, y);

    if (y > height && Math.random() > 0.976) {
      matrix.drops[index] = 0;
    } else {
      matrix.drops[index] += 1;
    }
  }

  matrix.rafId = window.requestAnimationFrame(drawMatrixFrame);
}

function startMatrixRain() {
  if (matrix.running) {
    return;
  }
  matrix.running = true;
  matrix.lastTick = 0;
  resetMatrix();
  matrix.rafId = window.requestAnimationFrame(drawMatrixFrame);
}

function stopMatrixRain() {
  matrix.running = false;
  if (matrix.rafId) {
    window.cancelAnimationFrame(matrix.rafId);
    matrix.rafId = 0;
  }
}

function showIntro(message = "") {
  state.unlocked = false;
  if (dom.appShell) {
    dom.appShell.hidden = true;
  }
  if (dom.introGate) {
    dom.introGate.hidden = false;
  }
  if (dom.settingsMenu) {
    dom.settingsMenu.hidden = true;
  }
  if (dom.passwordChangePanel) {
    dom.passwordChangePanel.hidden = true;
  }
  if (message) {
    setIntroHint(message, "error");
  } else {
    setIntroHint("");
  }
  startMatrixRain();
  if (dom.introPasswordInput) {
    dom.introPasswordInput.value = "";
    dom.introPasswordInput.focus();
  }
}

function showApp() {
  state.unlocked = true;
  if (dom.introGate) {
    dom.introGate.hidden = true;
  }
  if (dom.appShell) {
    dom.appShell.hidden = false;
  }
  stopMatrixRain();
  setIntroHint("");
}

function lockPanel(message = "Session expired. Enter password again.") {
  state.unlocked = false;
  state.panelSession = "";
  localStorage.removeItem("swissknife.webui.panel_session");
  showIntro(message);
}

function isUnauthorizedError(error) {
  return typeof error?.message === "string" && error.message === "UNAUTHORIZED";
}

async function apiFetch(path, options = {}) {
  const headers = Object.assign({}, options.headers || {});
  if (state.token) {
    headers["X-SwissKnife-Token"] = state.token;
  }
  if (state.panelSession) {
    headers["X-SwissKnife-Panel-Session"] = state.panelSession;
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

function parseIsoTime(value) {
  if (!value) {
    return "-";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "-";
  }
  return `${date.toLocaleDateString()} ${date.toLocaleTimeString()}`;
}

function formatBytes(bytes) {
  const value = Number(bytes);
  if (!Number.isFinite(value) || value <= 0) {
    return "0 B";
  }
  const units = ["B", "KB", "MB", "GB"];
  let idx = 0;
  let size = value;
  while (size >= 1024 && idx < units.length - 1) {
    size /= 1024;
    idx += 1;
  }
  return `${size.toFixed(size >= 10 || idx === 0 ? 0 : 1)} ${units[idx]}`;
}

function getSectionById(sectionId) {
  return state.menu.find((item) => item.id === sectionId) || null;
}

function getSectionItems(section) {
  if (!section || !Array.isArray(section.items)) {
    return [];
  }
  return section.items;
}

function getSelectedSectionItem(section) {
  const items = getSectionItems(section);
  if (!items.length) {
    return null;
  }
  const sectionId = section.id || "";
  const currentId = state.selectedItemBySection[sectionId];
  if (currentId && items.some((item) => item.id === currentId)) {
    return items.find((item) => item.id === currentId) || null;
  }
  const fallback = items[0] || null;
  if (fallback && sectionId) {
    state.selectedItemBySection[sectionId] = fallback.id;
  }
  return fallback;
}

function getTaskById(taskId) {
  return state.tasks.find((task) => task.task_id === taskId) || null;
}

function getLatestTaskForModule(moduleId) {
  const candidates = state.tasks
    .filter((task) => task.module_id === moduleId)
    .sort((left, right) => (right.started_at || 0) - (left.started_at || 0));
  return candidates[0] || null;
}

function getRunningTaskForModule(moduleId) {
  const running = state.tasks
    .filter((task) => task.module_id === moduleId && task.running)
    .sort((left, right) => (right.started_at || 0) - (left.started_at || 0));
  return running[0] || null;
}

function setAttackPanelsHidden(hidden) {
  const targets = [dom.tasksHead, dom.tasksList, dom.resultsHead, dom.resultsView];
  targets.forEach((target) => {
    if (target) {
      target.hidden = hidden;
    }
  });
}

function markAttackUiInteraction(extraMs = ATTACK_UI_LOCK_MS) {
  const lockUntil = Date.now() + Math.max(1200, Number(extraMs) || ATTACK_UI_LOCK_MS);
  state.attackUiLockUntil = Math.max(state.attackUiLockUntil || 0, lockUntil);
}

function markSectionUiInteraction(extraMs = SECTION_UI_LOCK_MS) {
  const lockUntil = Date.now() + Math.max(1200, Number(extraMs) || SECTION_UI_LOCK_MS);
  state.sectionUiLockUntil = Math.max(state.sectionUiLockUntil || 0, lockUntil);
}

function isSectionUiLocked() {
  return Date.now() < (state.sectionUiLockUntil || 0);
}

function isSectionFormFocused() {
  if (!dom.sectionBody) {
    return false;
  }
  const active = document.activeElement;
  if (!(active instanceof Element)) {
    return false;
  }
  if (!dom.sectionBody.contains(active)) {
    return false;
  }
  return Boolean(active.closest(".control-field, .control-grid, .attack-quick-grid, .attack-focus-card"));
}

function isAttackUiLocked() {
  if (state.selectedSectionId !== "attacks") {
    return false;
  }
  return Date.now() < (state.attackUiLockUntil || 0);
}

function isAttackFormFocused() {
  if (state.selectedSectionId !== "attacks") {
    return false;
  }
  return isSectionFormFocused();
}

function shouldPauseAttackRefresh() {
  return isAttackUiLocked() || isSectionUiLocked() || isAttackFormFocused();
}

function shouldPauseSectionRefresh() {
  if (state.selectedSectionId === "attacks") {
    return shouldPauseAttackRefresh();
  }
  return isSectionUiLocked() || isSectionFormFocused();
}

function getAttackControlDraft(moduleId) {
  if (!moduleId) {
    return {};
  }
  if (!state.attackControlDraftByModule[moduleId]) {
    state.attackControlDraftByModule[moduleId] = {};
  }
  return state.attackControlDraftByModule[moduleId];
}

function setAttackControlDraft(moduleId, controlId, value) {
  if (!moduleId || !controlId) {
    return;
  }
  const draft = getAttackControlDraft(moduleId);
  draft[controlId] = value;
  state.attackControlDraftByModule[moduleId] = draft;
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
  if (control.source === "portal_templates") {
    const templates = Array.isArray(state.portalTemplates) ? state.portalTemplates : [];
    if (templates.length) {
      return templates.map((name) => ({ value: name, label: name }));
    }
  }

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

function shortDriverLabel(entry) {
  const raw = String(entry?.driver || "").trim();
  if (!raw) {
    return "unknown";
  }
  return raw.split(/\s|,|\/|;/)[0] || raw;
}

function renderInterfaceSummary() {
  if (!dom.interfaceSummary) {
    return;
  }

  const entries = normalizeInterfaceList(state.interfaces.all_interfaces);
  if (!entries.length) {
    dom.interfaceSummary.innerHTML = "";
    dom.interfaceSummary.hidden = true;
    return;
  }

  dom.interfaceSummary.hidden = false;
  dom.interfaceSummary.innerHTML = "";

  const icon = document.createElement("span");
  icon.className = "iface-icon";
  icon.textContent = "\u25C9";
  dom.interfaceSummary.appendChild(icon);

  const chips = document.createElement("div");
  chips.className = "iface-chip-list";
  entries.forEach((entry) => {
    const chip = document.createElement("span");
    chip.className = `iface-chip${entry?.is_builtin ? " builtin" : ""}`;
    const name = entry?.name || "iface";
    const prefix = entry?.is_builtin ? "AP " : "";
    chip.textContent = `${prefix}${name}: ${shortDriverLabel(entry)}`;
    chips.appendChild(chip);
  });
  dom.interfaceSummary.appendChild(chips);
}

function createControlField(control, context = {}) {
  const sectionId = String(context.sectionId || "");
  const moduleId = String(context.moduleId || "");
  const isAttackControl = sectionId === "attacks" && moduleId;
  const hasModuleControl = Boolean(moduleId);
  const attackDraft = hasModuleControl ? getAttackControlDraft(moduleId) : null;

  const markTouched = () => {
    markSectionUiInteraction();
    if (isAttackControl) {
      markAttackUiInteraction();
    }
  };

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
      const draftValue = attackDraft ? String(attackDraft[control.id] ?? "") : "";
      if (draftValue && options.some((entry) => String(entry.value) === draftValue)) {
        select.value = draftValue;
      }
    }
    select.addEventListener("focus", markTouched);
    select.addEventListener("pointerdown", markTouched);
    select.addEventListener("mousedown", markTouched);
    select.addEventListener("touchstart", markTouched, { passive: true });
    select.addEventListener("change", () => {
      if (hasModuleControl) {
        setAttackControlDraft(moduleId, control.id, select.value);
      }
      markTouched();
    });
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
    if (attackDraft && attackDraft[control.id] !== undefined) {
      input.value = String(attackDraft[control.id]);
    }

    const badge = document.createElement("strong");
    badge.className = "range-value";
    badge.textContent = formatControlValue(control, input.value);

    input.addEventListener("input", () => {
      badge.textContent = formatControlValue(control, input.value);
      if (hasModuleControl) {
        setAttackControlDraft(moduleId, control.id, input.value);
      }
      markTouched();
    });
    input.addEventListener("focus", markTouched);
    input.addEventListener("pointerdown", markTouched);
    input.addEventListener("mousedown", markTouched);
    input.addEventListener("touchstart", markTouched, { passive: true });

    row.appendChild(input);
    row.appendChild(badge);
    wrap.appendChild(row);
    return wrap;
  }

  const input = document.createElement("input");
  input.type = "text";
  input.dataset.controlId = control.id;
  input.value = control.default !== undefined ? String(control.default) : "";
  if (attackDraft && attackDraft[control.id] !== undefined) {
    input.value = String(attackDraft[control.id]);
  }
  if (control.placeholder) {
    input.placeholder = control.placeholder;
  }
  input.addEventListener("focus", markTouched);
  input.addEventListener("pointerdown", markTouched);
  input.addEventListener("mousedown", markTouched);
  input.addEventListener("touchstart", markTouched, { passive: true });
  input.addEventListener("input", () => {
    if (hasModuleControl) {
      setAttackControlDraft(moduleId, control.id, input.value);
    }
    markTouched();
  });
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

function evaluateActionAvailability(item, controls) {
  let statusClass = "";
  let statusText = "READY";
  let disabled = Boolean(item.disabled);

  if (item.under_construction) {
    statusClass = "warn";
    statusText = "UNDER CONSTRUCTION";
  } else if (item.disabled) {
    statusClass = "bad";
    statusText = "DISABLED";
  }

  if (item.type !== "module" || !item.module_id) {
    return {
      disabled: true,
      statusClass: statusClass || "bad",
      statusText: statusText === "READY" ? "DISABLED" : statusText,
    };
  }

  const moduleInfo = resolveModuleInfo(item.module_id);
  if (!moduleInfo || moduleInfo.exists === false) {
    return { disabled: true, statusClass: "bad", statusText: "MISSING SCRIPT" };
  }

  const needsToolInterface = controls.some((control) => control.source === "tool_interfaces");
  if (needsToolInterface && (!Array.isArray(state.interfaces.tool_interfaces) || state.interfaces.tool_interfaces.length === 0)) {
    return { disabled: true, statusClass: "bad", statusText: "NO TOOL IFACE" };
  }

  return { disabled, statusClass, statusText };
}

function createStatusChip(statusClass, statusText) {
  const status = document.createElement("span");
  status.className = "status-chip";
  if (statusClass) {
    status.classList.add(statusClass);
  }
  status.textContent = statusText;
  return status;
}

function readControlValue(card, controlId, fallback = "") {
  const field = card?.querySelector?.(`[data-control-id="${controlId}"]`);
  if (!field) {
    return fallback;
  }
  const value = field.value;
  if (value === undefined || value === null || value === "") {
    return fallback;
  }
  return value;
}

function collectAutomationPreset(item, card) {
  if (!item?.module_id) {
    return null;
  }
  if (item.module_id === "deauth") {
    return {
      interfaceName: resolvePreferredAttackInterface(readControlValue(card, "interface", "auto")),
      scanDuration: normalizePositiveInt(readControlValue(card, "scan_depth", 25), 25, 5),
      selectedNetworkIndex: null,
      autoSelectNetwork: false,
    };
  }
  if (item.module_id === "portal") {
    return {
      apInterface: resolvePreferredAttackInterface(readControlValue(card, "ap_interface", "auto")),
      scanDuration: normalizePositiveInt(readControlValue(card, "scan_duration", 25), 25, 1),
      apSsid: String(readControlValue(card, "ap_ssid", "")).trim(),
      portalFile: String(readControlValue(card, "portal_file", "portal.html")).trim() || "portal.html",
      selectedNetworkIndex: null,
    };
  }
  if (item.module_id === "twins") {
    const attackInterface = resolvePreferredAttackInterface(readControlValue(card, "attack_interface", "auto"));
    return {
      attackInterface,
      apInterface: resolveSecondaryAttackInterface(readControlValue(card, "ap_interface", "auto"), attackInterface),
      scanDuration: normalizePositiveInt(readControlValue(card, "scan_duration", 25), 25, 1),
      portalFile: String(readControlValue(card, "portal_file", "portal.html")).trim() || "portal.html",
      selectedNetworkIndex: null,
    };
  }
  if (item.module_id === "handshaker") {
    return {
      interfaceName: resolvePreferredAttackInterface(readControlValue(card, "interface", "auto")),
      scanDuration: normalizePositiveInt(readControlValue(card, "scan_duration", 25), 25, 1),
      captureDuration: 45,
      selectedTargetIndex: null,
    };
  }
  if (item.module_id === "bluetooth") {
    const modeRaw = String(readControlValue(card, "scan_mode", "bt")).trim().toLowerCase();
    return {
      mode: modeRaw === "ble" ? "ble" : "bt",
      timeout: normalizePositiveInt(readControlValue(card, "timeout", 30), 30, 5),
    };
  }
  return null;
}

function applyAutomationPreset(taskId, moduleId, preset) {
  if (!taskId || !moduleId || !preset || typeof preset !== "object") {
    return;
  }
  if (moduleId === "deauth") {
    setDeauthState(taskId, {
      interfaceName: resolvePreferredAttackInterface(preset.interfaceName || "auto"),
      scanDuration: normalizePositiveInt(preset.scanDuration, 25, 5),
      interfaceSent: false,
      managedEnterSent: false,
      scanDurationSent: false,
      scanStartSent: false,
      networkSelected: false,
      monitorEnterSent: false,
      selectedNetworkIndex: preset.selectedNetworkIndex || null,
      pendingNetworkIndex: null,
      autoSelectNetwork: Boolean(preset.autoSelectNetwork),
      rescanAttempts: 0,
      lastPromptLine: "",
      lastNetworkCount: 0,
      renderPending: false,
      autoLock: false,
      lastActionByKey: {},
    });
    return;
  }
  if (moduleId === "portal") {
    setPortalState(taskId, {
      apInterface: resolvePreferredAttackInterface(preset.apInterface || "auto"),
      scanDuration: normalizePositiveInt(preset.scanDuration, 25, 1),
      apSsid: String(preset.apSsid || "").trim(),
      portalFile: String(preset.portalFile || "portal.html").trim() || "portal.html",
      interfaceSent: false,
      sourceSent: false,
      manualSsidSent: false,
      scanDurationSent: false,
      scanEnterSent: false,
      networkSent: false,
      selectedNetworkIndex: preset.selectedNetworkIndex || null,
      portalFileSent: false,
      startSent: false,
      finishChoiceSent: false,
      rescanAttempts: 0,
      autoLock: false,
      lastActionByKey: {},
    });
    return;
  }
  if (moduleId === "twins") {
    const attackInterface = resolvePreferredAttackInterface(preset.attackInterface || "auto");
    setTwinsState(taskId, {
      attackInterface,
      apInterface: resolveSecondaryAttackInterface(preset.apInterface || "auto", attackInterface),
      scanDuration: normalizePositiveInt(preset.scanDuration, 25, 1),
      portalFile: String(preset.portalFile || "portal.html").trim() || "portal.html",
      interfaceSent: false,
      monitorEnterSent: false,
      scanDurationSent: false,
      scanEnterSent: false,
      scanStartedAt: 0,
      networkSent: false,
      selectedNetworkIndex: preset.selectedNetworkIndex || null,
      selectedNetworkIndexes: [],
      pendingNetworkIndexes: [],
      rescanAttempts: 0,
      apInterfaceSent: false,
      apNameSent: false,
      proceedSent: false,
      portalSent: false,
      startSent: false,
      finishChoiceSent: false,
      lastPromptLine: "",
      lastNetworkCount: 0,
      renderPending: false,
      autoLock: false,
      lastActionByKey: {},
    });
    return;
  }
  if (moduleId === "handshaker") {
    setHandshakerState(taskId, {
      interfaceName: resolvePreferredAttackInterface(preset.interfaceName || "auto"),
      scanDuration: normalizePositiveInt(preset.scanDuration, 25, 1),
      captureDuration: normalizePositiveInt(preset.captureDuration, 45, 20),
      interfaceSent: false,
      monitorEnterSent: false,
      scanDurationSent: false,
      scanEnterSent: false,
      targetSent: false,
      selectedTargetIndex: preset.selectedTargetIndex || null,
      captureDurationSent: false,
      captureStartSent: false,
      exitSent: false,
      autoLock: false,
      lastActionByKey: {},
    });
    return;
  }
  if (moduleId === "bluetooth") {
    setBluetoothState(taskId, {
      mode: String(preset.mode || "bt").toLowerCase() === "ble" ? "ble" : "bt",
      timeout: normalizePositiveInt(preset.timeout, 30, 5),
      menuChoiceSent: false,
      startSent: false,
      scanStartedAt: 0,
      scanStopSent: false,
      returnSent: false,
      backSent: false,
      proceedSent: false,
      poetStartSent: false,
      poetStartedAt: 0,
      poetStopRequested: false,
      poetReturnSent: false,
      autoLock: false,
      lastActionByKey: {},
    });
  }
}

function createDeauthFlowPanel(task) {
  const wrap = document.createElement("div");
  wrap.className = "attack-runtime-body";

  const deauth = getDeauthState(task.task_id);

  const promptText = latestPrompt(task.task_id);
  if (promptText) {
    const promptBar = document.createElement("div");
    promptBar.className = "attack-prompt";
    promptBar.textContent = promptText;
    wrap.appendChild(promptBar);
  }

  const waitingNetwork = isLatestPrompt(task.task_id, /Select network.*R to rescan/i);
  const waitingRescan = isLatestPrompt(task.task_id, /Rescan\? \(Y\/N\)/i);
  const waitingStop = isLatestPrompt(task.task_id, /Press Enter to stop attack and exit/i);
  const networks = parseDeauthNetworks(task.task_id);

  if (waitingNetwork) {
    const modeInfo = document.createElement("div");
    modeInfo.className = "attack-runtime-state";
    modeInfo.textContent = "Single target mode: select one network, then tap Start Deauth.";
    wrap.appendChild(modeInfo);

    if (networks.length) {
      const networkGrid = document.createElement("div");
      networkGrid.className = "attack-network-grid";
      networks.forEach((entry) => {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "attack-network-btn";
        if (
          deauth.pendingNetworkIndex === entry.index
          || (!deauth.pendingNetworkIndex && deauth.selectedNetworkIndex === entry.index)
        ) {
          button.classList.add("active");
        }
        button.addEventListener("click", () => {
          markAttackUiInteraction();
          setDeauthState(task.task_id, {
            pendingNetworkIndex: entry.index,
            autoSelectNetwork: false,
          });
          renderSection();
        });
        const title = document.createElement("strong");
        title.textContent = `${entry.index}) ${entry.ssid}`;
        button.appendChild(title);
        const meta = document.createElement("span");
        meta.className = "attack-network-meta";
        meta.textContent = `${entry.bssid} | ch ${entry.channel} | ${entry.signal}`;
        button.appendChild(meta);
        networkGrid.appendChild(button);
      });
      wrap.appendChild(networkGrid);

      const actions = document.createElement("div");
      actions.className = "panel-actions";

      const startBtn = document.createElement("button");
      startBtn.type = "button";
      startBtn.className = "primary";
      startBtn.textContent = "Start Deauth";
      startBtn.disabled = !deauth.pendingNetworkIndex;
      startBtn.addEventListener("click", async () => {
        if (!deauth.pendingNetworkIndex) {
          return;
        }
        markAttackUiInteraction(6000);
        const ok = await sendTaskInput(
          task.task_id,
          String(deauth.pendingNetworkIndex),
          `Target ${deauth.pendingNetworkIndex} confirmed`,
        );
        if (!ok) {
          return;
        }
        setDeauthState(task.task_id, {
          networkSelected: true,
          selectedNetworkIndex: deauth.pendingNetworkIndex,
          pendingNetworkIndex: null,
          autoSelectNetwork: false,
        });
        await loadTaskLogs(task.task_id, true);
        renderSection();
      });
      actions.appendChild(startBtn);

      const rescanBtn = document.createElement("button");
      rescanBtn.type = "button";
      rescanBtn.textContent = "Rescan";
      rescanBtn.addEventListener("click", () => {
        markAttackUiInteraction();
        setDeauthState(task.task_id, {
          networkSelected: false,
          selectedNetworkIndex: null,
          pendingNetworkIndex: null,
        });
        sendTaskInput(task.task_id, "r", "Rescan requested");
      });
      actions.appendChild(rescanBtn);

      wrap.appendChild(actions);
    } else {
      const waiting = document.createElement("div");
      waiting.className = "attack-runtime-state";
      waiting.textContent = "Scanning... waiting for network list.";
      wrap.appendChild(waiting);
    }
  } else if (waitingRescan) {
    const actions = document.createElement("div");
    actions.className = "panel-actions";
    const yesBtn = document.createElement("button");
    yesBtn.type = "button";
    yesBtn.textContent = "Rescan";
    yesBtn.addEventListener("click", () => {
      markAttackUiInteraction();
      sendTaskInput(task.task_id, "y", "Rescan confirmed");
    });
    const noBtn = document.createElement("button");
    noBtn.type = "button";
    noBtn.className = "danger";
    noBtn.textContent = "Cancel";
    noBtn.addEventListener("click", () => {
      markAttackUiInteraction();
      sendTaskInput(task.task_id, "n", "Rescan canceled");
    });
    actions.appendChild(yesBtn);
    actions.appendChild(noBtn);
    wrap.appendChild(actions);
  } else if (waitingStop) {
    const active = document.createElement("div");
    active.className = "attack-runtime-state";
    const targetLabel = deauth.selectedNetworkIndex
      ? `target #${deauth.selectedNetworkIndex}`
      : "target selected";
    active.textContent = `Deauth active | ${targetLabel}`;
    wrap.appendChild(active);
  } else if (task.running && deauth.networkSelected) {
    const active = document.createElement("div");
    active.className = "attack-runtime-state";
    const targetLabel = deauth.selectedNetworkIndex
      ? `target #${deauth.selectedNetworkIndex}`
      : "target selected";
    active.textContent = `Deauth running | ${targetLabel}`;
    wrap.appendChild(active);
  } else {
    const status = document.createElement("div");
    status.className = "attack-runtime-state";
    status.textContent = "Flow automation active. Waiting for next deauth step.";
    wrap.appendChild(status);
  }

  return wrap;
}

function createIndexedChoiceGrid(task, entries, selectedIndex, onSelectText) {
  const grid = document.createElement("div");
  grid.className = "attack-network-grid";
  entries.forEach((entry) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "attack-network-btn";
    if (selectedIndex === entry.index) {
      button.classList.add("active");
    }
    button.addEventListener("click", async () => {
      markAttackUiInteraction();
      let successLabel = "Target selected";
      let onSelected = null;
      const payload = onSelectText(entry);
      if (typeof payload === "string") {
        successLabel = payload;
      } else if (payload && typeof payload === "object") {
        if (payload.label) {
          successLabel = payload.label;
        }
        if (typeof payload.onSelected === "function") {
          onSelected = payload.onSelected;
        }
      }
      const sent = await sendTaskInput(task.task_id, String(entry.index), successLabel);
      if (sent && onSelected) {
        onSelected(entry);
      }
      renderSection();
    });
    const title = document.createElement("strong");
    title.textContent = `${entry.index}) ${entry.ssid || "<hidden>"}`;
    button.appendChild(title);
    const meta = document.createElement("span");
    meta.className = "attack-network-meta";
    if (entry.bssid) {
      meta.textContent = `${entry.bssid} | ch ${entry.channel || "?"} | ${entry.signal || entry.meta || "-"}`;
    } else {
      meta.textContent = entry.signal || entry.meta || "-";
    }
    button.appendChild(meta);
    grid.appendChild(button);
  });
  return grid;
}

function createPortalFlowPanel(task) {
  const wrap = document.createElement("div");
  wrap.className = "attack-runtime-body";
  const portal = getPortalState(task.task_id);
  const prompt = latestPrompt(task.task_id);
  if (prompt) {
    const promptBar = document.createElement("div");
    promptBar.className = "attack-prompt";
    promptBar.textContent = prompt;
    wrap.appendChild(promptBar);
  }

  if (hasPrompt(task.task_id, /Select network.*R to rescan.*M for manual/i)) {
    const networks = parsePortalNetworks(task.task_id);
    if (networks.length) {
      wrap.appendChild(
        createIndexedChoiceGrid(task, networks, portal.selectedNetworkIndex, (entry) => ({
          label: `Portal target: ${entry.ssid}`,
          onSelected: () => setPortalState(task.task_id, { selectedNetworkIndex: entry.index, networkSent: true }),
        })),
      );
    }
    const actions = document.createElement("div");
    actions.className = "panel-actions";
    const rescan = document.createElement("button");
    rescan.type = "button";
    rescan.textContent = "Rescan";
    rescan.addEventListener("click", () => {
      markAttackUiInteraction();
      sendTaskInput(task.task_id, "r", "Portal rescan requested");
    });
    actions.appendChild(rescan);
    wrap.appendChild(actions);
    return wrap;
  }

  const status = document.createElement("div");
  status.className = "attack-runtime-state";
  status.textContent = "Flow automation active. Waiting for next portal step.";
  wrap.appendChild(status);
  return wrap;
}

function getTwinsScanRemainingSeconds(task, twins) {
  if (!task?.running) {
    return 0;
  }
  const startedAt = Number(twins?.scanStartedAt || 0);
  if (!Number.isFinite(startedAt) || startedAt <= 0) {
    return 0;
  }
  const duration = normalizePositiveInt(twins?.scanDuration, 25, 1);
  const elapsed = Math.max(0, Math.floor((Date.now() - startedAt) / 1000));
  return Math.max(0, duration - elapsed);
}

function normalizeTwinsSelection(rawIndexes) {
  const rows = Array.isArray(rawIndexes) ? rawIndexes : [];
  const indexes = rows
    .map((value) => normalizePositiveInt(value, 0, 0))
    .filter((value) => value > 0);
  return Array.from(new Set(indexes)).sort((left, right) => left - right);
}

function createTwinsFlowPanel(task) {
  const wrap = document.createElement("div");
  wrap.className = "attack-runtime-body";
  const twins = getTwinsState(task.task_id);
  const prompt = latestPrompt(task.task_id);
  if (prompt) {
    const promptBar = document.createElement("div");
    promptBar.className = "attack-prompt";
    promptBar.textContent = prompt;
    wrap.appendChild(promptBar);
  }

  const networks = parseTwinsNetworks(task.task_id);
  const waitingTargets = task.running && !twins.networkSent && (
    hasPrompt(task.task_id, /Select network\(s\).*R to rescan/i, 220)
    || (task.running && twins.scanEnterSent && networks.length > 0)
  );
  const waitingRescan = task.running && !twins.networkSent
    && hasPrompt(task.task_id, /Rescan\? \(Y\/N\)/i, 140)
    && networks.length === 0;

  if (waitingTargets) {
    if (networks.length) {
      const picked = normalizeTwinsSelection(
        twins.pendingNetworkIndexes?.length ? twins.pendingNetworkIndexes : twins.selectedNetworkIndexes,
      );
      const grid = document.createElement("div");
      grid.className = "attack-network-grid";
      networks.forEach((entry) => {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "attack-network-btn";
        if (picked.includes(entry.index)) {
          button.classList.add("active");
        }
        button.addEventListener("click", () => {
          markAttackUiInteraction();
          const current = new Set(picked);
          if (current.has(entry.index)) {
            current.delete(entry.index);
          } else {
            current.add(entry.index);
          }
          setTwinsState(task.task_id, {
            pendingNetworkIndexes: Array.from(current).sort((left, right) => left - right),
          });
          renderSection();
        });

        const title = document.createElement("strong");
        title.textContent = `${entry.index}) ${entry.ssid || "<hidden>"}`;
        button.appendChild(title);
        const meta = document.createElement("span");
        meta.className = "attack-network-meta";
        meta.textContent = `${entry.bssid} | ch ${entry.channel || "?"} | ${entry.signal || entry.meta || "-"}`;
        button.appendChild(meta);
        grid.appendChild(button);
      });
      wrap.appendChild(grid);

      const actions = document.createElement("div");
      actions.className = "panel-actions";

      const start = document.createElement("button");
      start.type = "button";
      start.className = "primary";
      start.textContent = "Start Evil Twin";
      start.disabled = picked.length === 0;
      start.addEventListener("click", async () => {
        const selected = normalizeTwinsSelection(picked);
        if (!selected.length) {
          return;
        }
        markAttackUiInteraction(7000);
        const payload = selected.join(",");
        const sent = await sendTaskInput(task.task_id, payload, `Evil Twin targets: ${payload}`);
        if (!sent) {
          return;
        }
        setTwinsState(task.task_id, {
          networkSent: true,
          selectedNetworkIndex: selected[0] || null,
          selectedNetworkIndexes: selected,
          pendingNetworkIndexes: selected,
          scanStartedAt: 0,
        });
        await loadTaskLogs(task.task_id, true);
        renderSection();
      });
      actions.appendChild(start);

      const rescan = document.createElement("button");
      rescan.type = "button";
      rescan.textContent = "Rescan";
      rescan.addEventListener("click", async () => {
        markAttackUiInteraction();
        setTwinsState(task.task_id, {
          networkSent: false,
          selectedNetworkIndex: null,
          selectedNetworkIndexes: [],
          pendingNetworkIndexes: [],
          scanStartedAt: Date.now(),
        });
        await sendTaskInput(task.task_id, "r", "Evil Twin rescan requested");
      });
      actions.appendChild(rescan);
      wrap.appendChild(actions);
    } else {
      const waiting = document.createElement("div");
      waiting.className = "attack-runtime-state";
      waiting.textContent = "Scanning... waiting for target list.";
      wrap.appendChild(waiting);
    }
    return wrap;
  }

  if (waitingRescan) {
    const actions = document.createElement("div");
    actions.className = "panel-actions";
    const yesBtn = document.createElement("button");
    yesBtn.type = "button";
    yesBtn.textContent = "Rescan";
    yesBtn.addEventListener("click", async () => {
      markAttackUiInteraction();
      setTwinsState(task.task_id, { scanStartedAt: Date.now() });
      await sendTaskInput(task.task_id, "y", "Rescan confirmed");
    });
    actions.appendChild(yesBtn);
    const noBtn = document.createElement("button");
    noBtn.type = "button";
    noBtn.className = "danger";
    noBtn.textContent = "Cancel";
    noBtn.addEventListener("click", async () => {
      markAttackUiInteraction();
      await sendTaskInput(task.task_id, "n", "Rescan canceled");
    });
    actions.appendChild(noBtn);
    wrap.appendChild(actions);
    return wrap;
  }

  if (task.running && twins.scanEnterSent && !twins.networkSent) {
    const remaining = getTwinsScanRemainingSeconds(task, twins);
    const scanning = document.createElement("div");
    scanning.className = "attack-runtime-state";
    scanning.textContent = remaining > 0
      ? `Recon scan in progress... ${remaining}s left`
      : "Recon scan in progress...";
    wrap.appendChild(scanning);
    return wrap;
  }

  if (task.running && twins.networkSent && !twins.startSent) {
    const selected = normalizeTwinsSelection(
      twins.selectedNetworkIndexes?.length ? twins.selectedNetworkIndexes : [twins.selectedNetworkIndex],
    );
    const preparing = document.createElement("div");
    preparing.className = "attack-runtime-state";
    preparing.textContent = selected.length
      ? `Targets locked: ${selected.join(", ")}. Preparing Evil Twin...`
      : "Target selected. Preparing Evil Twin...";
    wrap.appendChild(preparing);
    return wrap;
  }

  if (task.running && twins.startSent) {
    const selected = normalizeTwinsSelection(
      twins.selectedNetworkIndexes?.length ? twins.selectedNetworkIndexes : [twins.selectedNetworkIndex],
    );
    const active = document.createElement("div");
    active.className = "attack-runtime-state";
    active.textContent = selected.length
      ? `Evil Twin active | targets ${selected.join(", ")}`
      : "Evil Twin active";
    wrap.appendChild(active);
    return wrap;
  }

  const status = document.createElement("div");
  status.className = "attack-runtime-state";
  status.textContent = "Flow automation active. Waiting for next Evil Twin step.";
  wrap.appendChild(status);
  return wrap;
}

function createHandshakerFlowPanel(task) {
  const wrap = document.createElement("div");
  wrap.className = "attack-runtime-body";
  const hand = getHandshakerState(task.task_id);
  const prompt = latestPrompt(task.task_id);
  if (prompt) {
    const promptBar = document.createElement("div");
    promptBar.className = "attack-prompt";
    promptBar.textContent = prompt;
    wrap.appendChild(promptBar);
  }

  if (hasPrompt(task.task_id, /Select target AP.*number/i)) {
    const targets = parseHandshakerTargets(task.task_id);
    if (targets.length) {
      wrap.appendChild(
        createIndexedChoiceGrid(task, targets, hand.selectedTargetIndex, (entry) => ({
          label: `Handshaker target: ${entry.ssid}`,
          onSelected: () => setHandshakerState(task.task_id, { selectedTargetIndex: entry.index, targetSent: true }),
        })),
      );
    }
    return wrap;
  }

  const status = document.createElement("div");
  status.className = "attack-runtime-state";
  status.textContent = "Flow automation active. Waiting for next handshaker step.";
  wrap.appendChild(status);
  return wrap;
}

function createAttackRuntimePanel(item) {
  if (!item.module_id) {
    return null;
  }

  const task = getRunningTaskForModule(item.module_id) || getLatestTaskForModule(item.module_id);
  const runtime = document.createElement("div");
  runtime.className = "attack-runtime";

  const head = document.createElement("div");
  head.className = "attack-runtime-head";
  const status = document.createElement("span");
  status.className = "attack-runtime-state";
  if (!task) {
    status.textContent = "idle";
  } else {
    status.textContent = `${task.running ? "running" : "stopped"} | task ${task.task_id}`;
  }
  head.appendChild(status);

  if (task?.running) {
    const stop = document.createElement("button");
    stop.type = "button";
    stop.className = "danger";
    stop.textContent = "Stop";
    stop.addEventListener("click", () => {
      markAttackUiInteraction();
      stopTaskById(task.task_id);
    });
    head.appendChild(stop);
  }
  runtime.appendChild(head);

  if (!task) {
    const hint = document.createElement("div");
    hint.className = "attack-runtime-state";
    hint.textContent = "Run attack to start workflow.";
    runtime.appendChild(hint);
    return runtime;
  }

  if (item.module_id === "deauth") {
    runtime.appendChild(createDeauthFlowPanel(task));
  } else if (item.module_id === "portal") {
    runtime.appendChild(createPortalFlowPanel(task));
  } else if (item.module_id === "twins") {
    runtime.appendChild(createTwinsFlowPanel(task));
  } else if (item.module_id === "handshaker") {
    runtime.appendChild(createHandshakerFlowPanel(task));
  } else {
    const prompt = latestPrompt(task.task_id);
    if (prompt) {
      const promptBar = document.createElement("div");
      promptBar.className = "attack-prompt";
      promptBar.textContent = prompt;
      runtime.appendChild(promptBar);
    }
  }

  return runtime;
}

function appendCardBody(contentWrap, item, sectionId, card, controls, availability) {
  if (controls.length) {
    const controlsWrap = document.createElement("div");
    controlsWrap.className = "control-grid";
    controls.forEach((control) => {
      controlsWrap.appendChild(
        createControlField(control, {
          sectionId,
          moduleId: item.module_id || "",
        }),
      );
    });
    contentWrap.appendChild(controlsWrap);
  }

  const meta = document.createElement("div");
  meta.className = "action-meta";
  meta.appendChild(createStatusChip(availability.statusClass, availability.statusText));

  const button = document.createElement("button");
  button.type = "button";
  button.className = "primary";
  button.textContent = "Run";
  button.disabled = availability.disabled;

  if (item.type === "module" && item.module_id) {
    button.addEventListener("click", async () => {
      if (button.disabled) {
        return;
      }
      if (sectionId === "attacks") {
        markAttackUiInteraction(9000);
      }
      try {
        const automationPreset = collectAutomationPreset(item, card);
        const args = collectModuleArgs(item, card);
        const task = await startModule(item.module_id, args);
        if (task?.task_id && automationPreset) {
          applyAutomationPreset(task.task_id, item.module_id, automationPreset);
        }
        if (task?.task_id) {
          await loadTaskLogs(task.task_id, true);
          await maybeDriveInteractiveTask(task);
          if (sectionId === "attacks" || sectionId === "bluetooth") {
            renderSection();
          }
        }
      } catch (error) {
        setHint(`Start failed: ${error.message}`, "error");
      }
    });
  } else {
    button.disabled = true;
  }

  meta.appendChild(button);
  contentWrap.appendChild(meta);

  if (sectionId === "attacks") {
    const runtime = createAttackRuntimePanel(item);
    if (runtime) {
      contentWrap.appendChild(runtime);
    }
  }
}

function createActionCard(item, sectionId) {
  const card = document.createElement("article");
  card.className = "action-card";

  const title = document.createElement("h3");
  title.textContent = item.label;
  card.appendChild(title);

  const controls = Array.isArray(item.controls) ? item.controls : [];
  const availability = evaluateActionAvailability(item, controls);
  appendCardBody(card, item, sectionId, card, controls, availability);
  return card;
}

function createAttackQuickButton(item) {
  const isActive = state.expandedAttackId === item.id;
  const controls = Array.isArray(item.controls) ? item.controls : [];
  const availability = evaluateActionAvailability(item, controls);

  const button = document.createElement("button");
  button.type = "button";
  button.className = `attack-quick-btn${isActive ? " active" : ""}`;
  button.dataset.attackId = item.id || "";
  button.setAttribute("aria-pressed", isActive ? "true" : "false");

  const title = document.createElement("h3");
  title.textContent = item.label;
  title.className = "attack-quick-title";
  button.appendChild(title);

  const status = document.createElement("span");
  status.className = "attack-quick-status";
  status.textContent = availability.statusText;
  button.appendChild(status);

  button.addEventListener("click", () => {
    markAttackUiInteraction(4000);
    state.expandedAttackId = item.id;
    renderSection();
  });
  return button;
}

function renderAttacksSection(items) {
  if (!state.expandedAttackId || !items.some((item) => item.id === state.expandedAttackId)) {
    state.expandedAttackId = items[0]?.id || null;
  }

  const workspace = document.createElement("div");
  workspace.className = "attacks-workspace";

  const quickGrid = document.createElement("div");
  quickGrid.className = "attack-quick-grid";
  items.forEach((item) => quickGrid.appendChild(createAttackQuickButton(item)));
  workspace.appendChild(quickGrid);

  const selected = items.find((item) => item.id === state.expandedAttackId) || null;
  if (selected) {
    const detailWrap = document.createElement("div");
    detailWrap.className = "attack-detail-wrap";
    const selectedCard = createActionCard(selected, "attacks");
    selectedCard.classList.add("attack-focus-card");
    detailWrap.appendChild(selectedCard);
    workspace.appendChild(detailWrap);
  }

  dom.sectionBody.appendChild(workspace);
}

function renderSection() {
  const section = getSectionById(state.selectedSectionId);
  if (!section) {
    return;
  }

  renderSubMenu(section);
  setAttackPanelsHidden(section.id === "attacks");

  dom.sectionTitle.textContent = section.label;
  dom.sectionBody.innerHTML = "";
  dom.sectionBody.dataset.sectionId = section.id || "";
  if (dom.centerPanel) {
    dom.centerPanel.dataset.section = section.id || "";
  }

  if (section.id === "loot") {
    renderLootSection();
    if (!state.lootLoaded) {
      loadLootFiles(true);
    }
    return;
  }

  if (section.type === "module") {
    const grid = document.createElement("div");
    grid.className = "action-grid";
    grid.appendChild(createActionCard(section, section.id));
    dom.sectionBody.appendChild(grid);
    return;
  }

  if (section.type === "group") {
    const items = getSectionItems(section);
    if (!items.length) {
      const muted = document.createElement("div");
      muted.className = "muted-block";
      muted.textContent = "No items in this section.";
      dom.sectionBody.appendChild(muted);
      return;
    }

    const selected = getSelectedSectionItem(section);
    if (!selected) {
      const muted = document.createElement("div");
      muted.className = "muted-block";
      muted.textContent = "No module selected.";
      dom.sectionBody.appendChild(muted);
      return;
    }

    const grid = document.createElement("div");
    grid.className = "action-grid";
    grid.appendChild(createActionCard(selected, section.id));
    dom.sectionBody.appendChild(grid);
    return;
  }

  const info = document.createElement("div");
  info.className = "muted-block";
  info.textContent = section.description || "Section information.";
  dom.sectionBody.appendChild(info);
}

function renderLootSection() {
  const wrap = document.createElement("div");
  wrap.className = "loot-layout";

  const listPanel = document.createElement("div");
  listPanel.className = "loot-panel";

  const listHead = document.createElement("div");
  listHead.className = "loot-head";
  const listTitle = document.createElement("strong");
  listTitle.textContent = "Log Files (/log)";
  listHead.appendChild(listTitle);

  const refreshBtn = document.createElement("button");
  refreshBtn.type = "button";
  refreshBtn.textContent = "Refresh";
  refreshBtn.addEventListener("click", () => loadLootFiles());
  listHead.appendChild(refreshBtn);
  listPanel.appendChild(listHead);

  const files = Array.isArray(state.lootFiles) ? state.lootFiles : [];
  if (!files.length) {
    const muted = document.createElement("div");
    muted.className = "muted-block";
    muted.textContent = "No files found in /log.";
    listPanel.appendChild(muted);
  } else {
    const list = document.createElement("div");
    list.className = "loot-list";
    files.forEach((file) => {
      const row = document.createElement("div");
      row.className = "loot-row";

      const fileBtn = document.createElement("button");
      fileBtn.type = "button";
      fileBtn.className = `loot-file-btn${state.selectedLootFile === file.name ? " active" : ""}`;
      fileBtn.addEventListener("click", async () => {
        state.selectedLootFile = file.name;
        await loadLootContent(file.name, true);
        renderSection();
      });

      const fileName = document.createElement("span");
      fileName.className = "loot-file-name";
      fileName.textContent = file.name;
      fileBtn.appendChild(fileName);

      const fileMeta = document.createElement("span");
      fileMeta.className = "loot-file-meta";
      fileMeta.textContent = `${formatBytes(file.size_bytes)} · ${parseIsoTime(file.modified_at)}`;
      fileBtn.appendChild(fileMeta);

      const deleteBtn = document.createElement("button");
      deleteBtn.type = "button";
      deleteBtn.className = "loot-delete-btn danger";
      deleteBtn.title = `Delete ${file.name}`;
      deleteBtn.setAttribute("aria-label", `Delete ${file.name}`);

      const icon = document.createElement("span");
      icon.className = "trash-icon";
      deleteBtn.appendChild(icon);

      deleteBtn.addEventListener("click", async () => {
        const accepted = window.confirm(`Delete file ${file.name}?`);
        if (!accepted) {
          return;
        }
        await deleteLootFile(file.name);
      });

      row.appendChild(fileBtn);
      row.appendChild(deleteBtn);
      list.appendChild(row);
    });
    listPanel.appendChild(list);
  }

  const previewPanel = document.createElement("div");
  previewPanel.className = "loot-preview";
  const selectedName = state.selectedLootFile;
  if (!selectedName) {
    const empty = document.createElement("div");
    empty.className = "muted-block";
    empty.textContent = "Select file to preview content.";
    previewPanel.appendChild(empty);
  } else {
    const content = state.lootContentByFile[selectedName] || null;
    const title = document.createElement("div");
    title.className = "loot-preview-head";
    const headLabel = document.createElement("strong");
    headLabel.textContent = selectedName;
    title.appendChild(headLabel);

    if (content) {
      const details = document.createElement("span");
      details.className = "loot-preview-meta";
      details.textContent = `${formatBytes(content.size_bytes)} · ${parseIsoTime(content.modified_at)}`;
      title.appendChild(details);
    }
    previewPanel.appendChild(title);

    if (!content) {
      const loading = document.createElement("div");
      loading.className = "muted-block";
      loading.textContent = "Loading file preview...";
      previewPanel.appendChild(loading);
    } else {
      if (content.truncated) {
        const trunc = document.createElement("div");
        trunc.className = "loot-truncate";
        trunc.textContent = "Showing last 300 lines.";
        previewPanel.appendChild(trunc);
      }
      const pre = document.createElement("pre");
      pre.className = "loot-text";
      pre.textContent = content.text || "(empty file)";
      previewPanel.appendChild(pre);
    }
  }

  wrap.appendChild(listPanel);
  wrap.appendChild(previewPanel);
  dom.sectionBody.appendChild(wrap);
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

    const tagText = document.createElement("span");
    tagText.className = "tag-text";
    tagText.textContent = section.icon || section.label.slice(0, 3).toUpperCase();
    tag.appendChild(tagText);

    const iconFile = MENU_ICON_FILES[section.id];
    if (iconFile) {
      const icon = document.createElement("img");
      icon.className = "tag-img";
      icon.alt = "";
      icon.loading = "lazy";
      icon.decoding = "async";
      icon.src = `/static/assets/menu_icons/${iconFile}`;
      icon.addEventListener("load", () => {
        tag.classList.add("with-image");
      });
      icon.addEventListener("error", () => {
        icon.remove();
      });
      tag.appendChild(icon);
    }

    const label = document.createElement("span");
    label.textContent = section.label;

    button.appendChild(tag);
    button.appendChild(label);
    button.addEventListener("click", () => {
      state.selectedSectionId = section.id;
      if (section.type === "group") {
        const selected = getSelectedSectionItem(section);
        if (selected?.id) {
          state.selectedItemBySection[section.id] = selected.id;
        }
      }
      renderMenu();
      renderSection();
      if (section.id === "attacks") {
        loadPortalTemplates(true);
      }
      if (section.id === "loot") {
        loadLootFiles(true);
      }
    });
    dom.mainMenu.appendChild(button);
  });
}

function renderSubMenu(section) {
  if (!dom.subMenu) {
    return;
  }
  const items = getSectionItems(section);
  if (section?.type !== "group" || !items.length) {
    dom.subMenu.innerHTML = "";
    dom.subMenu.hidden = true;
    return;
  }

  const selected = getSelectedSectionItem(section);
  dom.subMenu.innerHTML = "";
  dom.subMenu.hidden = false;

  items.forEach((item) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `sub-menu-btn${selected?.id === item.id ? " active" : ""}`;
    button.dataset.section = section.id || "";
    button.dataset.itemId = item.id || "";
    button.textContent = item.label || item.id || "Item";
    button.addEventListener("click", () => {
      state.selectedItemBySection[section.id] = item.id;
      if (section.id === "attacks") {
        state.expandedAttackId = item.id;
      }

      if (item.module_id) {
        const moduleTask = getRunningTaskForModule(item.module_id) || getLatestTaskForModule(item.module_id);
        if (moduleTask?.task_id) {
          selectTask(moduleTask.task_id);
        }
      }
      renderSubMenu(section);
      renderSection();
    });
    dom.subMenu.appendChild(button);
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

    const title = document.createElement("span");
    title.className = "task-name";
    title.textContent = `${task.module_name} · ${task.task_id}`;
    row.appendChild(title);

    const meta = document.createElement("span");
    meta.className = "task-meta";
    meta.textContent = `${parseTime(task.started_at)} · rc ${task.returncode ?? "-"}`;
    row.appendChild(meta);

    const status = document.createElement("span");
    status.className = `task-state ${task.running ? "running" : "stopped"}`;
    status.textContent = task.running ? "RUNNING" : "STOPPED";
    row.appendChild(status);

    item.appendChild(row);

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

function normalizedClients(network) {
  const rows = Array.isArray(network?.clients) ? network.clients : [];
  return rows
    .map((client) => String(client || "").trim().toLowerCase())
    .filter((client) => client.length > 0);
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
  head.innerHTML = "<tr><th>SSID</th><th>BSSID</th><th>Ch</th><th>Enc</th><th>RSSI</th></tr>";
  table.appendChild(head);

  const body = document.createElement("tbody");
  const rows = Array.isArray(networks) ? networks : [];
  if (!rows.length) {
    const empty = document.createElement("tr");
    empty.innerHTML = '<td colspan="5" class="cell-muted">No networks found.</td>';
    body.appendChild(empty);
    table.appendChild(body);
    return table;
  }

  rows.forEach((network) => {
    const tr = document.createElement("tr");
    tr.className = "result-net-row";
    const ssid = network.ssid || "<hidden>";
    const bssid = network.bssid || "-";
    const channel = network.channel ?? "?";
    const encryption = network.encryption || "UNKNOWN";
    const rssi = network.rssi !== null && network.rssi !== undefined ? `${network.rssi} dBm` : "?";
    [ssid, bssid, String(channel), encryption, rssi].forEach((value) => {
      const cell = document.createElement("td");
      cell.textContent = value;
      tr.appendChild(cell);
    });
    body.appendChild(tr);

    const clients = normalizedClients(network);
    if (clients.length) {
      const clientsRow = document.createElement("tr");
      clientsRow.className = "result-clients-row";
      const clientsCell = document.createElement("td");
      clientsCell.colSpan = 5;

      const clientsWrap = document.createElement("div");
      clientsWrap.className = "client-list";
      const prefix = document.createElement("span");
      prefix.className = "client-prefix";
      prefix.textContent = `Clients (${clients.length}):`;
      clientsWrap.appendChild(prefix);

      clients.slice(0, 18).forEach((client) => {
        const chip = document.createElement("span");
        chip.className = "client-chip";
        chip.textContent = client;
        clientsWrap.appendChild(chip);
      });
      if (clients.length > 18) {
        const more = document.createElement("span");
        more.className = "client-chip more";
        more.textContent = `+${clients.length - 18}`;
        clientsWrap.appendChild(more);
      }

      clientsCell.appendChild(clientsWrap);
      clientsRow.appendChild(clientsCell);
      body.appendChild(clientsRow);
    }
  });

  table.appendChild(body);
  return table;
}

function buildProbePairsTable(probePairs) {
  const table = document.createElement("table");
  table.className = "result-table";

  const head = document.createElement("thead");
  head.innerHTML = "<tr><th>Probe SSID</th><th>Station MAC</th><th>Hits</th></tr>";
  table.appendChild(head);

  const body = document.createElement("tbody");
  const rows = Array.isArray(probePairs) ? probePairs : [];
  if (!rows.length) {
    const empty = document.createElement("tr");
    empty.innerHTML = '<td colspan="3" class="cell-muted">No probe requests observed yet.</td>';
    body.appendChild(empty);
    table.appendChild(body);
    return table;
  }

  rows.slice(0, 120).forEach((entry) => {
    const tr = document.createElement("tr");
    const ssid = entry.ssid || "<hidden>";
    const station = entry.station || "-";
    const count = entry.count ?? 0;
    [ssid, station, String(count)].forEach((value) => {
      const cell = document.createElement("td");
      cell.textContent = value;
      tr.appendChild(cell);
    });
    body.appendChild(tr);
  });

  table.appendChild(body);
  return table;
}

function getCommandArgNumber(task, flag, fallback = 0) {
  const command = Array.isArray(task?.command) ? task.command : [];
  const idx = command.findIndex((part) => part === flag);
  if (idx < 0 || idx + 1 >= command.length) {
    return fallback;
  }
  const parsed = Number(command[idx + 1]);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  return parsed;
}

function getReconDurationSeconds(task, result) {
  const resultDuration = Number(result?.duration);
  if (Number.isFinite(resultDuration) && resultDuration > 0) {
    return Math.round(resultDuration);
  }
  const fromCommand = getCommandArgNumber(task, "--duration", 0);
  if (Number.isFinite(fromCommand) && fromCommand > 0) {
    return Math.round(fromCommand);
  }
  return 0;
}

function getReconRemainingSeconds(task, result) {
  if (!task?.running) {
    return 0;
  }
  const resultRemaining = Number(result?.remaining);
  if (Number.isFinite(resultRemaining) && resultRemaining >= 0) {
    return Math.max(0, Math.round(resultRemaining));
  }
  const duration = getReconDurationSeconds(task, result);
  if (duration <= 0) {
    return 0;
  }
  const elapsed = Math.max(0, Math.floor(Date.now() / 1000 - Number(task.started_at || 0)));
  return Math.max(0, duration - elapsed);
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
  summary.appendChild(createSummaryPill("State", task.running ? "RUNNING" : "STOPPED"));
  const remaining = getReconRemainingSeconds(task, result);
  const duration = getReconDurationSeconds(task, result);
  if (task.running && duration > 0) {
    summary.appendChild(createSummaryPill("Timeout", `${remaining}s left`));
  } else if (duration > 0) {
    summary.appendChild(createSummaryPill("Timeout", `${duration}s`));
  }
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
  summary.appendChild(createSummaryPill("Pairs", result.probe_pairs_total ?? 0));
  summary.appendChild(createSummaryPill("State", task.running ? "RUNNING" : "STOPPED"));
  const remaining = getReconRemainingSeconds(task, result);
  const duration = getReconDurationSeconds(task, result);
  if (task.running && duration > 0) {
    summary.appendChild(createSummaryPill("Timeout", `${remaining}s left`));
  } else if (duration > 0) {
    summary.appendChild(createSummaryPill("Timeout", `${duration}s`));
  }
  summary.appendChild(createSummaryPill("Task", task.task_id));
  dom.resultsView.appendChild(summary);
  dom.resultsView.appendChild(buildNetworkTable(result.networks));
  dom.resultsView.appendChild(buildProbePairsTable(result.probe_pairs));
}

async function sendTaskInput(taskId, text, successLabel = "Command sent") {
  try {
    await postTaskInput(taskId, text);
    setHint(successLabel, "success");
    await loadTaskLogs(taskId, true);
    return true;
  } catch (error) {
    if (isUnauthorizedError(error)) {
      lockPanel("Session expired. Enter password again.");
      return false;
    }
    setHint(`Input failed: ${error.message}`, "error");
    return false;
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
  const line = latestPromptLine(taskId, 90);
  return line ? shortLine(line, 140) : "";
}

function isPromptLikeLine(line) {
  if (!line) {
    return false;
  }
  const text = String(line).trim();
  if (!text) {
    return false;
  }
  if (/[:?]\s*$/i.test(text)) {
    return true;
  }
  return /(select|press enter|rescan|your choice|scan duration|back to main menu|proceed)/i.test(text);
}

function latestPromptLine(taskId, lookback = 80) {
  const lines = Array.isArray(state.recentLogsByTask[taskId]) ? state.recentLogsByTask[taskId] : [];
  const span = Math.max(12, Number(lookback) || 80);
  const start = Math.max(0, lines.length - span);
  let latestNonEmpty = "";
  for (let index = lines.length - 1; index >= start; index -= 1) {
    const line = stripAnsi(lines[index] || "");
    if (!line) {
      continue;
    }
    if (!latestNonEmpty) {
      latestNonEmpty = line;
    }
    if (isPromptLikeLine(line)) {
      return line;
    }
  }
  return latestNonEmpty;
}

function findPromptLine(taskId, pattern, lookback = 80) {
  if (!(pattern instanceof RegExp)) {
    return "";
  }
  const lines = Array.isArray(state.recentLogsByTask[taskId]) ? state.recentLogsByTask[taskId] : [];
  const span = Math.max(12, Number(lookback) || 80);
  const start = Math.max(0, lines.length - span);
  for (let index = lines.length - 1; index >= start; index -= 1) {
    const clean = stripAnsi(lines[index] || "");
    if (pattern.test(clean)) {
      return clean;
    }
  }
  return "";
}

function parseDeauthNetworks(taskId) {
  const lines = Array.isArray(state.recentLogsByTask[taskId]) ? state.recentLogsByTask[taskId] : [];
  const networksByIndex = new Map();
  const regex = /^\s*(\d+)\)\s+(.+?)\s+\(([0-9a-f]{2}(?::[0-9a-f]{2}){5})\)\s*-\s*ch\s*([0-9?]+)\s*(.*)$/i;

  lines.forEach((line) => {
    const clean = stripAnsi(line);
    const match = clean.match(regex);
    if (!match) {
      return;
    }
    const index = Number(match[1]);
    if (!Number.isFinite(index) || index <= 0) {
      return;
    }
    networksByIndex.set(index, {
      index,
      ssid: (match[2] || "").trim() || "<hidden>",
      bssid: (match[3] || "").toLowerCase(),
      channel: (match[4] || "?").trim(),
      signal: (match[5] || "").trim() || "signal unknown",
    });
  });

  return Array.from(networksByIndex.values()).sort((left, right) => left.index - right.index);
}

function hasPrompt(taskId, pattern, lookback = 80) {
  return Boolean(findPromptLine(taskId, pattern, lookback));
}

function isLatestPrompt(taskId, pattern, lookback = 80) {
  if (!(pattern instanceof RegExp)) {
    return false;
  }
  const latest = latestPromptLine(taskId, lookback);
  if (!latest) {
    return false;
  }
  return pattern.test(latest);
}

function resolvePreferredAttackInterface(rawValue) {
  const value = String(rawValue || "").trim();
  if (value && value !== "auto") {
    return value;
  }
  const tool = Array.isArray(state.interfaces.tool_interface_names) ? state.interfaces.tool_interface_names : [];
  if (tool.length) {
    return tool[0];
  }
  const all = Array.isArray(state.interfaces.all_interfaces) ? state.interfaces.all_interfaces : [];
  const fallback = all.find((entry) => entry && !entry.is_builtin);
  return fallback?.name || "";
}

function resolveSecondaryAttackInterface(rawValue, avoidInterface = "") {
  const value = String(rawValue || "").trim();
  const tool = Array.isArray(state.interfaces.tool_interface_names) ? state.interfaces.tool_interface_names : [];
  if (value && value !== "auto" && value !== avoidInterface) {
    return value;
  }
  const fallback = tool.find((entry) => entry && entry !== avoidInterface);
  if (fallback) {
    return fallback;
  }
  return resolvePreferredAttackInterface("auto");
}

function normalizePositiveInt(value, fallback, minimum = 1) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return Math.max(minimum, Number(fallback) || minimum);
  }
  return Math.max(minimum, Math.round(parsed));
}

function markAutoAction(autoState, key, cooldownMs = 1200) {
  if (!autoState || !key) {
    return false;
  }
  const now = Date.now();
  if (!autoState.lastActionByKey || typeof autoState.lastActionByKey !== "object") {
    autoState.lastActionByKey = {};
  }
  const last = Number(autoState.lastActionByKey[key] || 0);
  if (now - last < Math.max(300, Number(cooldownMs) || 1200)) {
    return false;
  }
  autoState.lastActionByKey[key] = now;
  return true;
}

async function autoSendTaskInput(taskId, autoState, actionKey, text, options = {}) {
  if (!taskId || !autoState || !actionKey) {
    return false;
  }
  const cooldownMs = Number(options.cooldownMs || 1200);
  if (!markAutoAction(autoState, actionKey, cooldownMs)) {
    return false;
  }
  if (autoState.autoLock) {
    return false;
  }
  autoState.autoLock = true;
  try {
    await postTaskInput(taskId, text);
    if (options.successHint) {
      setHint(options.successHint, "success");
    }
    return true;
  } catch (error) {
    if (isUnauthorizedError(error)) {
      lockPanel("Session expired. Enter password again.");
      return false;
    }
    if (!options.silentError) {
      setHint(`Automation failed: ${error.message}`, "error");
    }
    return false;
  } finally {
    autoState.autoLock = false;
  }
}

function getDeauthState(taskId) {
  if (!state.deauthStateByTask[taskId]) {
    state.deauthStateByTask[taskId] = {
      interfaceName: resolvePreferredAttackInterface("auto"),
      scanDuration: 25,
      interfaceSent: false,
      managedEnterSent: false,
      scanDurationSent: false,
      scanStartSent: false,
      networkSelected: false,
      monitorEnterSent: false,
      selectedNetworkIndex: null,
      pendingNetworkIndex: null,
      autoSelectNetwork: false,
      rescanAttempts: 0,
      lastPromptLine: "",
      lastNetworkCount: 0,
      renderPending: false,
      autoLock: false,
      lastActionByKey: {},
    };
  }
  return state.deauthStateByTask[taskId];
}

function setDeauthState(taskId, patch) {
  const current = getDeauthState(taskId);
  state.deauthStateByTask[taskId] = { ...current, ...patch };
}

function getPortalState(taskId) {
  if (!state.portalStateByTask[taskId]) {
    state.portalStateByTask[taskId] = {
      apInterface: resolvePreferredAttackInterface("auto"),
      scanDuration: 25,
      apSsid: "",
      portalFile: "portal.html",
      interfaceSent: false,
      sourceSent: false,
      manualSsidSent: false,
      scanDurationSent: false,
      scanEnterSent: false,
      networkSent: false,
      selectedNetworkIndex: null,
      portalFileSent: false,
      startSent: false,
      finishChoiceSent: false,
      rescanAttempts: 0,
      autoLock: false,
      lastActionByKey: {},
    };
  }
  return state.portalStateByTask[taskId];
}

function setPortalState(taskId, patch) {
  const current = getPortalState(taskId);
  state.portalStateByTask[taskId] = { ...current, ...patch };
}

function getTwinsState(taskId) {
  if (!state.twinsStateByTask[taskId]) {
    const attackInterface = resolvePreferredAttackInterface("auto");
    state.twinsStateByTask[taskId] = {
      attackInterface,
      apInterface: resolveSecondaryAttackInterface("auto", attackInterface),
      scanDuration: 25,
      portalFile: "portal.html",
      interfaceSent: false,
      monitorEnterSent: false,
      scanDurationSent: false,
      scanEnterSent: false,
      scanStartedAt: 0,
      networkSent: false,
      selectedNetworkIndex: null,
      selectedNetworkIndexes: [],
      pendingNetworkIndexes: [],
      rescanAttempts: 0,
      apInterfaceSent: false,
      apNameSent: false,
      proceedSent: false,
      portalSent: false,
      startSent: false,
      finishChoiceSent: false,
      lastPromptLine: "",
      lastNetworkCount: 0,
      renderPending: false,
      autoLock: false,
      lastActionByKey: {},
    };
  }
  return state.twinsStateByTask[taskId];
}

function setTwinsState(taskId, patch) {
  const current = getTwinsState(taskId);
  state.twinsStateByTask[taskId] = { ...current, ...patch };
}

function getHandshakerState(taskId) {
  if (!state.handshakerStateByTask[taskId]) {
    state.handshakerStateByTask[taskId] = {
      interfaceName: resolvePreferredAttackInterface("auto"),
      scanDuration: 25,
      captureDuration: 45,
      interfaceSent: false,
      monitorEnterSent: false,
      scanDurationSent: false,
      scanEnterSent: false,
      targetSent: false,
      selectedTargetIndex: null,
      captureDurationSent: false,
      captureStartSent: false,
      exitSent: false,
      autoLock: false,
      lastActionByKey: {},
    };
  }
  return state.handshakerStateByTask[taskId];
}

function setHandshakerState(taskId, patch) {
  const current = getHandshakerState(taskId);
  state.handshakerStateByTask[taskId] = { ...current, ...patch };
}

function getBluetoothState(taskId) {
  if (!state.bluetoothStateByTask[taskId]) {
    state.bluetoothStateByTask[taskId] = {
      mode: "bt",
      timeout: 30,
      menuChoiceSent: false,
      startSent: false,
      scanStartedAt: 0,
      scanStopSent: false,
      returnSent: false,
      backSent: false,
      proceedSent: false,
      poetStartSent: false,
      poetStartedAt: 0,
      poetStopRequested: false,
      poetReturnSent: false,
      autoLock: false,
      lastActionByKey: {},
    };
  }
  return state.bluetoothStateByTask[taskId];
}

function setBluetoothState(taskId, patch) {
  const current = getBluetoothState(taskId);
  state.bluetoothStateByTask[taskId] = { ...current, ...patch };
}

function parsePortalNetworks(taskId) {
  const lines = Array.isArray(state.recentLogsByTask[taskId]) ? state.recentLogsByTask[taskId] : [];
  const byIndex = new Map();
  const regex = /^\s*(\d+)\)\s+(.+?)\s*-\s*(-?\d+(?:\.\d+)?\s*dBm|signal unknown)\s*$/i;
  lines.forEach((line) => {
    const clean = stripAnsi(line);
    const match = clean.match(regex);
    if (!match) {
      return;
    }
    const index = Number(match[1]);
    if (!Number.isFinite(index) || index <= 0) {
      return;
    }
    byIndex.set(index, {
      index,
      ssid: (match[2] || "").trim() || "<hidden>",
      signal: (match[3] || "").trim() || "signal unknown",
    });
  });
  return Array.from(byIndex.values()).sort((left, right) => left.index - right.index);
}

function parseTwinsNetworks(taskId) {
  return parseDeauthNetworks(taskId);
}

function parseHandshakerTargets(taskId) {
  const lines = Array.isArray(state.recentLogsByTask[taskId]) ? state.recentLogsByTask[taskId] : [];
  const byIndex = new Map();
  const regex = /^\s*(\d+)\)\s+(.+?)\s+\(([0-9a-f]{2}(?::[0-9a-f]{2}){5})\)\s*-\s*ch\s*([0-9?]+)\s*\|\s*(.*)$/i;
  lines.forEach((line) => {
    const clean = stripAnsi(line);
    const match = clean.match(regex);
    if (!match) {
      return;
    }
    const index = Number(match[1]);
    if (!Number.isFinite(index) || index <= 0) {
      return;
    }
    byIndex.set(index, {
      index,
      ssid: (match[2] || "").trim() || "<hidden>",
      bssid: (match[3] || "").toLowerCase(),
      channel: (match[4] || "?").trim(),
      meta: (match[5] || "").trim(),
    });
  });
  return Array.from(byIndex.values()).sort((left, right) => left.index - right.index);
}

async function postTaskInput(taskId, text) {
  await apiFetch(`/api/tasks/${taskId}/input`, {
    method: "POST",
    body: { text },
  });
}

async function maybeDriveDeauth(task) {
  if (!task || task.module_id !== "deauth" || !task.running) {
    return;
  }
  const taskId = task.task_id;
  let deauth = getDeauthState(taskId);

  if (deauth.renderPending && state.selectedSectionId === "attacks" && !shouldPauseAttackRefresh()) {
    setDeauthState(taskId, { renderPending: false });
    renderSection();
    deauth = getDeauthState(taskId);
  }

  const promptLine = latestPromptLine(taskId, 100);
  const networkCount = parseDeauthNetworks(taskId).length;
  if (promptLine !== deauth.lastPromptLine || networkCount !== deauth.lastNetworkCount) {
    const patch = {
      lastPromptLine: promptLine,
      lastNetworkCount: networkCount,
    };
    if (state.selectedSectionId === "attacks") {
      if (!shouldPauseAttackRefresh()) {
        patch.renderPending = false;
        setDeauthState(taskId, patch);
        renderSection();
      } else {
        patch.renderPending = true;
        setDeauthState(taskId, patch);
      }
    } else {
      setDeauthState(taskId, patch);
    }
  }

  const selectInterfacePrompt = isLatestPrompt(taskId, /Select interface.*number or name/i);
  if (selectInterfacePrompt && !deauth.interfaceSent) {
    const interfaceName = resolvePreferredAttackInterface(deauth.interfaceName);
    if (!interfaceName) {
      return;
    }
    if (
      await autoSendTaskInput(taskId, deauth, "select-interface", interfaceName, {
        successHint: `Deauth: selected interface ${interfaceName}.`,
      })
    ) {
      setDeauthState(taskId, {
        interfaceName,
        interfaceSent: true,
      });
    }
    return;
  }

  const managedPrompt = isLatestPrompt(taskId, /Press Enter.*managed mode for scanning/i);
  if (managedPrompt && !deauth.managedEnterSent) {
    if (
      await autoSendTaskInput(taskId, deauth, "managed-enter", "", {
        cooldownMs: 1400,
        silentError: true,
      })
    ) {
      setDeauthState(taskId, { managedEnterSent: true });
    }
    return;
  }

  const scanDurationPrompt = isLatestPrompt(taskId, /Scan duration.*seconds/i);
  if (scanDurationPrompt && !deauth.scanDurationSent) {
    const duration = Math.max(5, Number(deauth.scanDuration) || 25);
    if (
      await autoSendTaskInput(taskId, deauth, "scan-duration", String(duration), {
        silentError: true,
      })
    ) {
      setDeauthState(taskId, { scanDurationSent: true, scanDuration: duration });
    }
    return;
  }

  const scanStartPrompt = isLatestPrompt(taskId, /Press Enter.*scan networks/i);
  if (scanStartPrompt && !deauth.scanStartSent) {
    if (
      await autoSendTaskInput(taskId, deauth, "scan-start-enter", "", {
        cooldownMs: 1400,
        silentError: true,
      })
    ) {
      setDeauthState(taskId, { scanStartSent: true });
    }
    return;
  }

  const waitingNetwork = isLatestPrompt(taskId, /Select network.*R to rescan/i);
  if (waitingNetwork && !deauth.networkSelected) {
    if (deauth.autoSelectNetwork) {
      const networks = parseDeauthNetworks(taskId);
      let targetIndex = normalizePositiveInt(deauth.selectedNetworkIndex, 0, 0);
      if (!targetIndex && networks.length) {
        targetIndex = networks[0].index;
      }
      if (targetIndex > 0) {
        if (
          await autoSendTaskInput(taskId, deauth, "network-select", String(targetIndex), {
            successHint: `Deauth: auto target ${targetIndex}.`,
            cooldownMs: 1500,
            silentError: true,
          })
        ) {
          setDeauthState(taskId, {
            selectedNetworkIndex: targetIndex,
            networkSelected: true,
          });
        }
      }
    }
    return;
  }

  const rescanPrompt = isLatestPrompt(taskId, /Rescan\? \(Y\/N\)/i);
  if (rescanPrompt && !deauth.networkSelected) {
    const retries = normalizePositiveInt(deauth.rescanAttempts, 0, 0);
    const payload = retries < 2 ? "y" : "n";
    if (
      await autoSendTaskInput(taskId, deauth, "rescan-answer", payload, {
        cooldownMs: 1400,
        silentError: true,
      })
    ) {
      setDeauthState(taskId, { rescanAttempts: retries + 1 });
    }
    return;
  }

  const monitorPrompt = isLatestPrompt(taskId, /Press Enter.*monitor mode for attack/i);
  if (monitorPrompt && !deauth.monitorEnterSent) {
    if (
      await autoSendTaskInput(taskId, deauth, "monitor-enter", "", {
        cooldownMs: 1400,
        silentError: true,
      })
    ) {
      setDeauthState(taskId, { monitorEnterSent: true });
    }
    return;
  }

  const stopPrompt = isLatestPrompt(taskId, /Press Enter to stop attack and exit/i);
  if (stopPrompt) {
    return;
  }
}

function resolvePortalTemplateIndex(portalFile) {
  const templates = Array.isArray(state.portalTemplates) ? state.portalTemplates : [];
  const target = String(portalFile || "").trim();
  if (!target || !templates.length) {
    return 1;
  }
  const idx = templates.findIndex((entry) => String(entry).trim() === target);
  if (idx < 0) {
    return 1;
  }
  return idx + 1;
}

async function maybeDrivePortal(task) {
  if (!task || task.module_id !== "portal" || !task.running) {
    return;
  }
  const taskId = task.task_id;
  const portal = getPortalState(taskId);

  if (hasPrompt(taskId, /Select AP interface.*number or name/i) && !portal.interfaceSent) {
    const iface = resolvePreferredAttackInterface(portal.apInterface);
    if (
      iface
      && await autoSendTaskInput(taskId, portal, "portal-select-interface", iface, {
        successHint: `Portal: selected AP interface ${iface}.`,
        silentError: true,
      })
    ) {
      setPortalState(taskId, { apInterface: iface, interfaceSent: true });
    }
    return;
  }

  if (hasPrompt(taskId, /SSID source.*Scan.*Manual/i) && !portal.sourceSent) {
    const useManual = Boolean(String(portal.apSsid || "").trim());
    if (
      await autoSendTaskInput(taskId, portal, "portal-ssid-source", useManual ? "m" : "s", {
        silentError: true,
      })
    ) {
      setPortalState(taskId, { sourceSent: true });
    }
    return;
  }

  if (hasPrompt(taskId, /Enter SSID/i) && !portal.manualSsidSent) {
    const ssid = String(portal.apSsid || "").trim() || "SwissKnife-Portal";
    if (
      await autoSendTaskInput(taskId, portal, "portal-manual-ssid", ssid, {
        silentError: true,
      })
    ) {
      setPortalState(taskId, { apSsid: ssid, manualSsidSent: true });
    }
    return;
  }

  if (hasPrompt(taskId, /Scan duration.*seconds/i) && !portal.scanDurationSent) {
    const duration = normalizePositiveInt(portal.scanDuration, 25, 1);
    if (
      await autoSendTaskInput(taskId, portal, "portal-scan-duration", String(duration), {
        silentError: true,
      })
    ) {
      setPortalState(taskId, { scanDuration: duration, scanDurationSent: true });
    }
    return;
  }

  if (hasPrompt(taskId, /Press Enter.*scan networks/i) && !portal.scanEnterSent) {
    if (
      await autoSendTaskInput(taskId, portal, "portal-scan-enter", "", {
        cooldownMs: 1400,
        silentError: true,
      })
    ) {
      setPortalState(taskId, { scanEnterSent: true });
    }
    return;
  }

  if (hasPrompt(taskId, /Select network.*R to rescan.*M for manual/i) && !portal.networkSent) {
    const networks = parsePortalNetworks(taskId);
    let selected = normalizePositiveInt(portal.selectedNetworkIndex, 0, 0);
    if (!selected && networks.length) {
      selected = networks[0].index;
    }
    if (selected > 0) {
      if (
        await autoSendTaskInput(taskId, portal, "portal-select-network", String(selected), {
          successHint: `Portal: selected network ${selected}.`,
          silentError: true,
        })
      ) {
        setPortalState(taskId, { selectedNetworkIndex: selected, networkSent: true });
      }
    }
    return;
  }

  if (hasPrompt(taskId, /Rescan.*Manual SSID.*Exit/i)) {
    const retries = normalizePositiveInt(portal.rescanAttempts, 0, 0);
    const hasManual = Boolean(String(portal.apSsid || "").trim());
    const payload = hasManual ? "m" : retries < 2 ? "r" : "e";
    if (
      await autoSendTaskInput(taskId, portal, "portal-rescan-menu", payload, {
        cooldownMs: 1400,
        silentError: true,
      })
    ) {
      setPortalState(taskId, { rescanAttempts: retries + 1 });
    }
    return;
  }

  if (hasPrompt(taskId, /Select portal HTML.*number/i) && !portal.portalFileSent) {
    const index = resolvePortalTemplateIndex(portal.portalFile);
    if (
      await autoSendTaskInput(taskId, portal, "portal-select-template", String(index), {
        silentError: true,
      })
    ) {
      setPortalState(taskId, { portalFileSent: true });
    }
    return;
  }

  if (hasPrompt(taskId, /Press Enter.*start captive portal/i) && !portal.startSent) {
    if (
      await autoSendTaskInput(taskId, portal, "portal-start-enter", "", {
        cooldownMs: 1400,
        silentError: true,
      })
    ) {
      setPortalState(taskId, { startSent: true });
    }
    return;
  }

  if (hasPrompt(taskId, /Back to main menu.*restart/i) && !portal.finishChoiceSent) {
    if (
      await autoSendTaskInput(taskId, portal, "portal-finish-choice", "b", {
        silentError: true,
      })
    ) {
      setPortalState(taskId, { finishChoiceSent: true });
    }
  }
}

async function maybeDriveTwins(task) {
  if (!task || task.module_id !== "twins" || !task.running) {
    return;
  }
  const taskId = task.task_id;
  let twins = getTwinsState(taskId);

  if (twins.renderPending && state.selectedSectionId === "attacks" && !shouldPauseAttackRefresh()) {
    setTwinsState(taskId, { renderPending: false });
    renderSection();
    twins = getTwinsState(taskId);
  }

  const promptLine = latestPromptLine(taskId, 100);
  const networkCount = parseTwinsNetworks(taskId).length;
  if (promptLine !== twins.lastPromptLine || networkCount !== twins.lastNetworkCount) {
    const patch = {
      lastPromptLine: promptLine,
      lastNetworkCount: networkCount,
    };
    if (state.selectedSectionId === "attacks") {
      if (!shouldPauseAttackRefresh()) {
        patch.renderPending = false;
        setTwinsState(taskId, patch);
        renderSection();
      } else {
        patch.renderPending = true;
        setTwinsState(taskId, patch);
      }
    } else {
      setTwinsState(taskId, patch);
    }
  }

  if (isLatestPrompt(taskId, /Select attack interface.*number or name/i) && !twins.interfaceSent) {
    const iface = resolvePreferredAttackInterface(twins.attackInterface);
    if (
      iface
      && await autoSendTaskInput(taskId, twins, "twins-attack-interface", iface, {
        successHint: `Evil Twin: selected attack interface ${iface}.`,
        silentError: true,
      })
    ) {
      setTwinsState(taskId, {
        attackInterface: iface,
        interfaceSent: true,
        apInterface: resolveSecondaryAttackInterface(twins.apInterface, iface),
      });
    }
    return;
  }

  if (isLatestPrompt(taskId, /Press Enter.*switch .*monitor mode/i) && !twins.monitorEnterSent) {
    if (
      await autoSendTaskInput(taskId, twins, "twins-monitor-enter", "", {
        cooldownMs: 1400,
        silentError: true,
      })
    ) {
      setTwinsState(taskId, { monitorEnterSent: true });
    }
    return;
  }

  if (isLatestPrompt(taskId, /Scan duration.*seconds/i) && !twins.scanDurationSent) {
    const duration = normalizePositiveInt(twins.scanDuration, 25, 1);
    if (
      await autoSendTaskInput(taskId, twins, "twins-scan-duration", String(duration), {
        silentError: true,
      })
    ) {
      setTwinsState(taskId, { scanDuration: duration, scanDurationSent: true });
    }
    return;
  }

  if (isLatestPrompt(taskId, /Press Enter.*scan networks/i) && !twins.scanEnterSent) {
    if (
      await autoSendTaskInput(taskId, twins, "twins-scan-enter", "", {
        cooldownMs: 1400,
        silentError: true,
      })
    ) {
      setTwinsState(taskId, {
        scanEnterSent: true,
        scanStartedAt: Date.now(),
        networkSent: false,
        selectedNetworkIndex: null,
        selectedNetworkIndexes: [],
        pendingNetworkIndexes: [],
      });
    }
    return;
  }

  if (hasPrompt(taskId, /Select network\(s\).*R to rescan/i, 220) && !twins.networkSent) {
    return;
  }

  if (isLatestPrompt(taskId, /Rescan\? \(Y\/N\)/i) && !twins.networkSent) {
    return;
  }

  if (twins.networkSent && isLatestPrompt(taskId, /Select AP interface.*number or name/i) && !twins.apInterfaceSent) {
    const iface = resolveSecondaryAttackInterface(twins.apInterface, twins.attackInterface);
    if (
      iface
      && await autoSendTaskInput(taskId, twins, "twins-ap-interface", iface, {
        silentError: true,
      })
    ) {
      setTwinsState(taskId, { apInterface: iface, apInterfaceSent: true, scanStartedAt: 0 });
    }
    return;
  }

  if (twins.networkSent && isLatestPrompt(taskId, /Select AP name.*number/i) && !twins.apNameSent) {
    if (
      await autoSendTaskInput(taskId, twins, "twins-ap-name", "1", {
        silentError: true,
      })
    ) {
      setTwinsState(taskId, { apNameSent: true });
    }
    return;
  }

  if (twins.networkSent && isLatestPrompt(taskId, /Proceed.*\(Y\/N\)/i) && !twins.proceedSent) {
    if (
      await autoSendTaskInput(taskId, twins, "twins-proceed", "y", {
        silentError: true,
      })
    ) {
      setTwinsState(taskId, { proceedSent: true });
    }
    return;
  }

  if (twins.networkSent && isLatestPrompt(taskId, /Select portal HTML.*number/i) && !twins.portalSent) {
    const index = resolvePortalTemplateIndex(twins.portalFile);
    if (
      await autoSendTaskInput(taskId, twins, "twins-portal-template", String(index), {
        silentError: true,
      })
    ) {
      setTwinsState(taskId, { portalSent: true });
    }
    return;
  }

  if (twins.networkSent && isLatestPrompt(taskId, /Press Enter.*start Evil Twin/i) && !twins.startSent) {
    if (
      await autoSendTaskInput(taskId, twins, "twins-start-enter", "", {
        cooldownMs: 1400,
        silentError: true,
      })
    ) {
      setTwinsState(taskId, { startSent: true });
    }
    return;
  }

  if (isLatestPrompt(taskId, /Back to main menu.*restart/i) && !twins.finishChoiceSent) {
    if (
      await autoSendTaskInput(taskId, twins, "twins-finish-choice", "b", {
        silentError: true,
      })
    ) {
      setTwinsState(taskId, { finishChoiceSent: true });
    }
  }
}

async function maybeDriveHandshaker(task) {
  if (!task || task.module_id !== "handshaker" || !task.running) {
    return;
  }
  const taskId = task.task_id;
  const hand = getHandshakerState(taskId);

  if (hasPrompt(taskId, /Select interface.*number or name/i) && !hand.interfaceSent) {
    const iface = resolvePreferredAttackInterface(hand.interfaceName);
    if (
      iface
      && await autoSendTaskInput(taskId, hand, "hand-interface", iface, {
        successHint: `Handshaker: selected interface ${iface}.`,
        silentError: true,
      })
    ) {
      setHandshakerState(taskId, { interfaceName: iface, interfaceSent: true });
    }
    return;
  }

  if (hasPrompt(taskId, /Press Enter.*monitor mode/i) && !hand.monitorEnterSent) {
    if (
      await autoSendTaskInput(taskId, hand, "hand-monitor-enter", "", {
        cooldownMs: 1400,
        silentError: true,
      })
    ) {
      setHandshakerState(taskId, { monitorEnterSent: true });
    }
    return;
  }

  if (hasPrompt(taskId, /Scan duration.*seconds/i) && !hand.scanDurationSent) {
    const duration = normalizePositiveInt(hand.scanDuration, 25, 1);
    if (
      await autoSendTaskInput(taskId, hand, "hand-scan-duration", String(duration), {
        silentError: true,
      })
    ) {
      setHandshakerState(taskId, { scanDuration: duration, scanDurationSent: true });
    }
    return;
  }

  if (hasPrompt(taskId, /Press Enter.*start scanning/i) && !hand.scanEnterSent) {
    if (
      await autoSendTaskInput(taskId, hand, "hand-scan-enter", "", {
        cooldownMs: 1400,
        silentError: true,
      })
    ) {
      setHandshakerState(taskId, { scanEnterSent: true });
    }
    return;
  }

  if (hasPrompt(taskId, /Select target AP.*number/i) && !hand.targetSent) {
    const targets = parseHandshakerTargets(taskId);
    let selected = normalizePositiveInt(hand.selectedTargetIndex, 0, 0);
    if (!selected && targets.length) {
      selected = targets[0].index;
    }
    if (selected > 0) {
      if (
        await autoSendTaskInput(taskId, hand, "hand-select-target", String(selected), {
          successHint: `Handshaker: selected AP ${selected}.`,
          silentError: true,
        })
      ) {
        setHandshakerState(taskId, { selectedTargetIndex: selected, targetSent: true });
      }
    }
    return;
  }

  if (hasPrompt(taskId, /Total capture time.*seconds/i) && !hand.captureDurationSent) {
    const duration = normalizePositiveInt(hand.captureDuration, 45, 20);
    if (
      await autoSendTaskInput(taskId, hand, "hand-capture-duration", String(duration), {
        silentError: true,
      })
    ) {
      setHandshakerState(taskId, { captureDuration: duration, captureDurationSent: true });
    }
    return;
  }

  if (hasPrompt(taskId, /Press Enter.*start deauth \+ capture/i) && !hand.captureStartSent) {
    if (
      await autoSendTaskInput(taskId, hand, "hand-capture-start", "", {
        cooldownMs: 1400,
        silentError: true,
      })
    ) {
      setHandshakerState(taskId, { captureStartSent: true });
    }
    return;
  }

  if (hasPrompt(taskId, /Press Enter to exit/i) && !hand.exitSent) {
    if (
      await autoSendTaskInput(taskId, hand, "hand-exit-enter", "", {
        cooldownMs: 1400,
        silentError: true,
      })
    ) {
      setHandshakerState(taskId, { exitSent: true });
    }
  }
}

async function maybeDriveBluetooth(task) {
  if (!task || task.module_id !== "bluetooth" || !task.running) {
    return;
  }
  const taskId = task.task_id;
  const bt = getBluetoothState(taskId);
  const mode = String(bt.mode || "bt").toLowerCase() === "ble" ? "ble" : "bt";
  const timeoutSeconds = normalizePositiveInt(bt.timeout, 30, 5);

  if (hasPrompt(taskId, /Your choice \(1-3\)/i) && !bt.menuChoiceSent) {
    const choice = mode === "ble" ? "2" : "1";
    if (
      await autoSendTaskInput(taskId, bt, "bt-menu-choice", choice, {
        silentError: true,
      })
    ) {
      setBluetoothState(taskId, { menuChoiceSent: true });
    }
    return;
  }

  if (mode === "bt") {
    if (hasPrompt(taskId, /Press Enter.*start live BT scan/i) && !bt.startSent) {
      if (
        await autoSendTaskInput(taskId, bt, "bt-start-enter", "", {
          cooldownMs: 1400,
          silentError: true,
        })
      ) {
        setBluetoothState(taskId, { startSent: true, scanStartedAt: Date.now() });
      }
      return;
    }

    if (bt.startSent && !bt.scanStopSent && bt.scanStartedAt > 0) {
      const elapsedMs = Date.now() - bt.scanStartedAt;
      if (elapsedMs >= timeoutSeconds * 1000) {
        if (
          await autoSendTaskInput(taskId, bt, "bt-stop-enter", "", {
            cooldownMs: 2000,
            silentError: true,
          })
        ) {
          setBluetoothState(taskId, { scanStopSent: true });
        }
        return;
      }
    }

    if (hasPrompt(taskId, /Press Enter to return/i) && !bt.returnSent) {
      if (
        await autoSendTaskInput(taskId, bt, "bt-return-enter", "", {
          cooldownMs: 1400,
          silentError: true,
        })
      ) {
        setBluetoothState(taskId, { returnSent: true });
      }
      return;
    }
  } else {
    if (hasPrompt(taskId, /Proceed.*\(Y\/N\)/i) && !bt.proceedSent) {
      if (
        await autoSendTaskInput(taskId, bt, "ble-proceed", "y", {
          silentError: true,
        })
      ) {
        setBluetoothState(taskId, { proceedSent: true });
      }
      return;
    }

    if (hasPrompt(taskId, /Press Enter.*start BLE Poet/i) && !bt.poetStartSent) {
      if (
        await autoSendTaskInput(taskId, bt, "ble-start-enter", "", {
          cooldownMs: 1400,
          silentError: true,
        })
      ) {
        setBluetoothState(taskId, { poetStartSent: true, poetStartedAt: Date.now() });
      }
      return;
    }

    if (bt.poetStartSent && !bt.poetStopRequested && bt.poetStartedAt > 0) {
      const elapsedMs = Date.now() - bt.poetStartedAt;
      if (elapsedMs >= timeoutSeconds * 1000) {
        setBluetoothState(taskId, { poetStopRequested: true });
        await stopTaskById(taskId);
        return;
      }
    }

    if (hasPrompt(taskId, /Press Enter to return/i) && !bt.poetReturnSent) {
      if (
        await autoSendTaskInput(taskId, bt, "ble-return-enter", "", {
          cooldownMs: 1400,
          silentError: true,
        })
      ) {
        setBluetoothState(taskId, { poetReturnSent: true });
      }
      return;
    }
  }

  if (
    hasPrompt(taskId, /Your choice \(1-3\)/i)
    && bt.menuChoiceSent
    && !bt.backSent
    && ((mode === "bt" && bt.returnSent) || (mode === "ble" && bt.poetReturnSent))
  ) {
    if (
      await autoSendTaskInput(taskId, bt, "bt-back-menu", "3", {
        silentError: true,
      })
    ) {
      setBluetoothState(taskId, { backSent: true });
    }
  }
}

async function maybeDriveInteractiveTask(task) {
  if (!task || !task.running) {
    return;
  }
  if (task.module_id === "deauth") {
    await maybeDriveDeauth(task);
    return;
  }
  if (task.module_id === "portal") {
    await maybeDrivePortal(task);
    return;
  }
  if (task.module_id === "twins") {
    await maybeDriveTwins(task);
    return;
  }
  if (task.module_id === "handshaker") {
    await maybeDriveHandshaker(task);
    return;
  }
  if (task.module_id === "bluetooth") {
    await maybeDriveBluetooth(task);
  }
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
  summary.appendChild(createSummaryPill("State", task.running ? "RUNNING" : "STOPPED"));
  const duration = getReconDurationSeconds(task, null);
  if (task.running && duration > 0) {
    summary.appendChild(createSummaryPill("Timeout", `${getReconRemainingSeconds(task, null)}s left`));
  } else if (duration > 0) {
    summary.appendChild(createSummaryPill("Timeout", `${duration}s`));
  }
  summary.appendChild(createSummaryPill("Task", task.task_id));
  dom.resultsView.appendChild(summary);

  const waiting = document.createElement("div");
  waiting.className = "muted-block";
  waiting.textContent = "Collecting recon data...";
  dom.resultsView.appendChild(waiting);
}

function getResultTaskForCurrentSection() {
  const activeTask = getTaskById(state.activeTaskId);
  if (state.selectedSectionId === "recon") {
    if (activeTask && isReconModule(activeTask.module_id)) {
      return activeTask;
    }
    return state.tasks.find((task) => isReconModule(task.module_id)) || null;
  }
  return activeTask;
}

function renderResultView() {
  dom.resultsView.innerHTML = "";

  const task = getResultTaskForCurrentSection();
  if (!task) {
    const empty = document.createElement("div");
    empty.className = "muted-block";
    empty.textContent = state.selectedSectionId === "recon"
      ? "Run scanner or sniffer to see recon output."
      : "Select task to see module output.";
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
    const data = await fetch("/api/meta", { cache: "no-store" }).then((response) => response.json());
    state.authRequired = Boolean(data.auth_required);
    state.devNoCache = Boolean(data.dev_no_cache);
    setHint("Panel ready.", "success");
  } catch (_error) {
    setHint("Meta unavailable. Open panel through web server, not local file path.", "error");
  }
}

async function gateLogin(password) {
  const response = await fetch("/api/gate/login", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ password }),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.detail || "Login failed.");
  }

  const sessionToken = String(payload.session_token || "").trim();
  if (!sessionToken) {
    throw new Error("Missing panel session token.");
  }
  state.panelSession = sessionToken;
  localStorage.setItem("swissknife.webui.panel_session", sessionToken);

  if (payload.api_token) {
    state.token = String(payload.api_token);
    localStorage.setItem("swissknife.webui.token", state.token);
  }
}

async function restorePanelSession() {
  if (!state.panelSession) {
    return false;
  }
  try {
    const headers = {
      "X-SwissKnife-Panel-Session": state.panelSession,
    };
    const response = await fetch("/api/gate/session", { headers });
    if (response.status === 401) {
      return false;
    }
    const payload = await response.json().catch(() => ({}));
    if (!response.ok || !payload.ok) {
      return false;
    }
    if (payload.api_token) {
      state.token = String(payload.api_token);
      localStorage.setItem("swissknife.webui.token", state.token);
    }
    return true;
  } catch (_error) {
    return false;
  }
}

async function changePanelPassword() {
  const nextPassword = (dom.newPasswordInput?.value || "").trim();
  if (nextPassword.length < 4) {
    setHint("Password must be at least 4 characters.", "error");
    return;
  }
  try {
    const payload = await apiFetch("/api/gate/change-password", {
      method: "POST",
      body: {
        new_password: nextPassword,
      },
    });
    const sessionToken = String(payload.session_token || "").trim();
    if (sessionToken) {
      state.panelSession = sessionToken;
      localStorage.setItem("swissknife.webui.panel_session", sessionToken);
    }
    if (dom.newPasswordInput) {
      dom.newPasswordInput.value = "";
    }
    if (dom.passwordChangePanel) {
      dom.passwordChangePanel.hidden = true;
    }
    if (dom.settingsMenu) {
      dom.settingsMenu.hidden = true;
    }
    setHint("Password changed.", "success");
  } catch (error) {
    if (isUnauthorizedError(error)) {
      lockPanel("Session expired. Enter password again.");
      return;
    }
    setHint(`Password change failed: ${error.message}`, "error");
  }
}

async function turnOffSystem() {
  try {
    await apiFetch("/api/system/turn-off", { method: "POST" });
    if (dom.settingsMenu) {
      dom.settingsMenu.hidden = true;
    }
    setHint("Turn off requested. Closing services...", "success");
    setTimeout(() => {
      window.location.reload();
    }, 2000);
  } catch (error) {
    if (isUnauthorizedError(error)) {
      lockPanel("Session expired. Enter password again.");
      return;
    }
    setHint(`Turn off failed: ${error.message}`, "error");
  }
}

async function loadMenu() {
  try {
    const data = await apiFetch("/api/menu");
    const main = Array.isArray(data.main) ? data.main : FALLBACK_MENU.main;
    state.menu = main;
  } catch (error) {
    if (isUnauthorizedError(error)) {
      lockPanel("Session expired. Enter password again.");
      state.menu = FALLBACK_MENU.main;
    } else {
      state.menu = FALLBACK_MENU.main;
      setHint("Using fallback menu schema (server unreachable).", "error");
    }
  }

  if (!state.selectedSectionId || !getSectionById(state.selectedSectionId)) {
    state.selectedSectionId = state.menu[0]?.id || null;
  }

  state.menu.forEach((section) => {
    if (section?.type !== "group") {
      return;
    }
    const selected = getSelectedSectionItem(section);
    if (selected?.id) {
      state.selectedItemBySection[section.id] = selected.id;
    }
  });

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
      lockPanel("Session expired. Enter password again.");
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
    renderInterfaceSummary();
    renderSection();
  } catch (error) {
    if (isUnauthorizedError(error)) {
      lockPanel("Session expired. Enter password again.");
      return;
    }
    renderInterfaceSummary();
    setHint(`Failed to load interfaces: ${error.message}`, "error");
  }
}

async function loadPortalTemplates(silent = false) {
  try {
    const data = await apiFetch("/api/portals");
    const templates = Array.isArray(data.templates) ? data.templates : [];
    state.portalTemplates = templates.filter((entry) => typeof entry === "string" && entry.trim());
    if (state.selectedSectionId === "attacks") {
      renderSection();
    }
  } catch (error) {
    if (isUnauthorizedError(error)) {
      if (!silent) {
        lockPanel("Session expired. Enter password again.");
      }
      return;
    }
    if (!silent) {
      setHint(`Failed to load portal templates: ${error.message}`, "error");
    }
  }
}

async function loadLootContent(fileName, silent = false) {
  if (!fileName) {
    return;
  }
  try {
    const name = encodeURIComponent(fileName);
    const data = await apiFetch(`/api/loot/view?name=${name}&tail=300`);
    state.lootContentByFile[fileName] = data;
  } catch (error) {
    if (isUnauthorizedError(error)) {
      if (!silent) {
        lockPanel("Session expired. Enter password again.");
      }
      return;
    }
    if (!silent) {
      setHint(`Failed to load loot content: ${error.message}`, "error");
    }
  }
}

async function loadLootFiles(silent = false) {
  try {
    const data = await apiFetch("/api/loot");
    const files = Array.isArray(data.files) ? data.files : [];
    state.lootFiles = files
      .filter((entry) => entry && typeof entry.name === "string")
      .sort((left, right) => String(right.modified_at || "").localeCompare(String(left.modified_at || "")));
    state.lootLoaded = true;

    if (!state.lootFiles.length) {
      state.selectedLootFile = "";
      state.lootContentByFile = {};
    } else if (
      !state.selectedLootFile
      || !state.lootFiles.some((entry) => entry.name === state.selectedLootFile)
    ) {
      state.selectedLootFile = state.lootFiles[0].name;
      await loadLootContent(state.selectedLootFile, true);
    } else if (!state.lootContentByFile[state.selectedLootFile]) {
      await loadLootContent(state.selectedLootFile, true);
    }

    if (state.selectedSectionId === "loot") {
      renderSection();
    }
  } catch (error) {
    if (isUnauthorizedError(error)) {
      if (!silent) {
        lockPanel("Session expired. Enter password again.");
      }
      return;
    }
    if (!silent) {
      setHint(`Failed to load loot files: ${error.message}`, "error");
    }
  }
}

async function deleteLootFile(fileName) {
  try {
    const name = encodeURIComponent(fileName);
    await apiFetch(`/api/loot?name=${name}`, { method: "DELETE" });
    delete state.lootContentByFile[fileName];
    setHint(`Deleted ${fileName}.`, "success");
    await loadLootFiles(true);
    if (state.selectedSectionId === "loot") {
      renderSection();
    }
  } catch (error) {
    if (isUnauthorizedError(error)) {
      lockPanel("Session expired. Enter password again.");
      return;
    }
    setHint(`Delete failed: ${error.message}`, "error");
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
      const line = stripAnsi(entry.line || "").trim();
      if (!line) {
        return;
      }
      if (line.startsWith("[webui-result]")) {
        return;
      }
      bucket.push(line);
    });
    state.recentLogsByTask[taskId] = bucket.slice(-180);

    const task = getTaskById(taskId);
    if (task?.running) {
      await maybeDriveInteractiveTask(task);
    }
  } catch (error) {
    if (isUnauthorizedError(error)) {
      if (!silent) {
        lockPanel("Session expired. Enter password again.");
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
        lockPanel("Session expired. Enter password again.");
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
    const attackSig = state.tasks
      .map((task) => `${task.task_id}:${task.running ? 1 : 0}:${task.returncode ?? "-"}`)
      .join("|");

    if (!state.tasks.length) {
      state.activeTaskId = null;
      renderTasks();
      renderResultView();
      if (state.selectedSectionId === "attacks") {
        if (state.attackTaskSig !== "empty" && !shouldPauseSectionRefresh()) {
          state.attackTaskSig = "empty";
          renderSection();
        } else {
          state.attackTaskSig = "empty";
        }
      } else if (!shouldPauseSectionRefresh()) {
        renderSection();
      }
      return;
    }

    if (!state.activeTaskId || !getTaskById(state.activeTaskId)) {
      state.activeTaskId = state.tasks[0].task_id;
    }

    renderTasks();
    const refreshTaskIds = new Set();
    if (state.activeTaskId) {
      refreshTaskIds.add(state.activeTaskId);
    }
    const sectionTask = getResultTaskForCurrentSection();
    if (sectionTask?.task_id) {
      refreshTaskIds.add(sectionTask.task_id);
    }
    await Promise.all(
      Array.from(refreshTaskIds).map(async (taskId) => {
        await Promise.all([
          loadTaskResult(taskId, true),
          loadTaskLogs(taskId, true),
        ]);
      }),
    );
    renderResultView();
    if (state.selectedSectionId === "attacks") {
      if (state.attackTaskSig !== attackSig && !shouldPauseSectionRefresh()) {
        state.attackTaskSig = attackSig;
        renderSection();
      } else {
        state.attackTaskSig = attackSig;
      }
    } else if (!shouldPauseSectionRefresh()) {
      renderSection();
    }
  } catch (error) {
    if (isUnauthorizedError(error)) {
      lockPanel("Session expired. Enter password again.");
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
    return task || null;
  } catch (error) {
    if (isUnauthorizedError(error)) {
      lockPanel("Session expired. Enter password again.");
      return null;
    }
    setHint(`Start failed: ${error.message}`, "error");
    return null;
  }
}

async function stopActiveTask() {
  if (!state.activeTaskId) {
    setHint("Select task first.", "error");
    return;
  }

  await stopTaskById(state.activeTaskId);
}

async function stopTaskById(taskId) {
  if (!taskId) {
    return;
  }

  try {
    await apiFetch(`/api/tasks/${taskId}/stop`, { method: "POST" });
    await loadTasks();
    setHint(`Stop signal sent to ${taskId}.`, "success");
    renderSection();
  } catch (error) {
    if (isUnauthorizedError(error)) {
      lockPanel("Session expired. Enter password again.");
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

async function initializeDashboard() {
  await loadMenu();
  await loadModules();
  await loadInterfaces();
  await loadPortalTemplates(true);
  await loadLootFiles(true);
  await loadTasks();

  if (state.pollHandle) {
    clearInterval(state.pollHandle);
  }
  state.pollHandle = setInterval(() => {
    if (!state.unlocked) {
      return;
    }
    loadTasks();
  }, 2500);
}

async function unlockFromIntro() {
  const password = (dom.introPasswordInput?.value || "").trim();
  if (!password) {
    setIntroHint("Enter password first.", "error");
    return;
  }
  if (dom.introLoginBtn) {
    dom.introLoginBtn.disabled = true;
    dom.introLoginBtn.textContent = "Unlocking...";
  }
  setIntroHint("Verifying...", "success");
  try {
    await gateLogin(password);
    if (dom.introPasswordInput) {
      dom.introPasswordInput.value = "";
    }
    showApp();
    setHint("Access granted.", "success");
    await initializeDashboard();
  } catch (error) {
    const message = String(error?.message || "").trim();
    if (message.toLowerCase().includes("invalid password")) {
      setIntroHint("Invalid pass.", "error");
    } else {
      setIntroHint(message || "Unlock failed.", "error");
    }
  } finally {
    if (dom.introLoginBtn) {
      dom.introLoginBtn.disabled = false;
      dom.introLoginBtn.textContent = "Unlock";
    }
  }
}

function installHandlers() {
  if (dom.introLoginForm) {
    dom.introLoginForm.addEventListener("submit", (event) => {
      event.preventDefault();
      unlockFromIntro();
    });
  } else if (dom.introLoginBtn) {
    dom.introLoginBtn.addEventListener("click", unlockFromIntro);
  }

  window.addEventListener("resize", () => {
    if (matrix.running) {
      resetMatrix();
    }
  });

  if (dom.settingsToggleBtn) {
    dom.settingsToggleBtn.addEventListener("click", () => {
      if (!dom.settingsMenu) {
        return;
      }
      dom.settingsMenu.hidden = !dom.settingsMenu.hidden;
    });
  }
  if (dom.openPasswordChangeBtn) {
    dom.openPasswordChangeBtn.addEventListener("click", () => {
      if (!dom.passwordChangePanel) {
        return;
      }
      dom.passwordChangePanel.hidden = !dom.passwordChangePanel.hidden;
      if (!dom.passwordChangePanel.hidden && dom.newPasswordInput) {
        dom.newPasswordInput.focus();
      }
    });
  }
  if (dom.changePasswordBtn) {
    dom.changePasswordBtn.addEventListener("click", changePanelPassword);
  }
  if (dom.turnOffBtn) {
    dom.turnOffBtn.addEventListener("click", turnOffSystem);
  }

  document.addEventListener("click", (event) => {
    const target = event.target;
    if (!(target instanceof Element)) {
      return;
    }
    if (!dom.settingsMenu || !dom.settingsToggleBtn) {
      return;
    }
    if (dom.settingsMenu.hidden) {
      return;
    }
    if (dom.settingsMenu.contains(target) || dom.settingsToggleBtn.contains(target)) {
      return;
    }
    dom.settingsMenu.hidden = true;
  });

  dom.refreshMenuBtn.addEventListener("click", async () => {
    await loadMenu();
    await loadModules();
    await loadInterfaces();
    await loadPortalTemplates(true);
    await loadLootFiles(true);
  });

  dom.refreshTasksBtn.addEventListener("click", loadTasks);
  dom.stopTaskBtn.addEventListener("click", stopActiveTask);
}

async function bootstrap() {
  installHandlers();
  await loadMeta();

  if (state.devNoCache) {
    state.token = "";
    state.panelSession = "";
    localStorage.removeItem("swissknife.webui.token");
    localStorage.removeItem("swissknife.webui.panel_session");
    showIntro();
    return;
  }

  const restored = await restorePanelSession();
  if (!restored) {
    state.panelSession = "";
    localStorage.removeItem("swissknife.webui.panel_session");
    showIntro();
    return;
  }

  showApp();
  await initializeDashboard();
}

bootstrap();
