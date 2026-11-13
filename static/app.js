/* Hunt Console — front-end logic.
   All writes go through huntFetch(), which adds the X-Hunt-Request header the
   server's CSRF gate requires. Every value rendered here can originate from a
   target or a model, so it goes through esc() before it reaches innerHTML. */

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

/* Fields the operator has edited since the page loaded.
   The boot sequence is asynchronous: a slow /api/scope response used to land
   after the operator started typing and silently overwrite it. Anything typed
   or toggled is marked here, and loaders skip those fields. Saving clears the
   mark, so the next load can refresh the saved values. */
const touched = new Set();
document.addEventListener("input", (e) => {
  if (e.target && e.target.id) touched.add(e.target.id);
}, true);
document.addEventListener("change", (e) => {
  if (e.target && e.target.id) touched.add(e.target.id);
}, true);

function setValue(id, value) {
  if (touched.has(id)) return;
  const el = document.getElementById(id);
  if (el) el.value = value;
}

function setChecked(id, value) {
  if (touched.has(id)) return;
  const el = document.getElementById(id);
  if (el) el.checked = !!value;
}

function markSaved(ids) {
  ids.forEach((id) => touched.delete(id));
}

const SEV_COLOR = {
  confirmed: "var(--red)", likely: "var(--yellow)", dig: "var(--green)",
  chain: "var(--accent)", lead: "var(--purple)"
};

function esc(value) {
  return String(value === null || value === undefined ? "" : value).replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}

/* ---------- transport ---------- */
const nativeFetch = window.fetch.bind(window);
function huntFetch(url, opts = {}) {
  const method = (opts.method || "GET").toUpperCase();
  if (method !== "GET" && method !== "HEAD") {
    opts = { ...opts, headers: { ...(opts.headers || {}), "X-Hunt-Request": "1" } };
  }
  return nativeFetch(url, opts);
}
async function jsonFetch(url, opts) {
  const res = await huntFetch(url, opts);
  let data = {};
  try { data = await res.json(); } catch (e) { data = { ok: false, error: "bad JSON from server" }; }
  return { res, data };
}

/* ---------- ui helpers ---------- */
function toast(message, kind = "") {
  const box = $("#toasts");
  if (!box) return;
  const el = document.createElement("div");
  el.className = "toast " + kind;
  el.textContent = message;
  box.appendChild(el);
  setTimeout(() => el.remove(), 4200);
}

let modalResolve = null;
function askConfirm({ title, body, confirmLabel = "Confirm", requireText = "", danger = false }) {
  const modal = $("#modal");
  $("#modal-title").textContent = title;
  $("#modal-body").textContent = body || "";
  $("#modal-input").style.display = requireText ? "block" : "none";
  $("#modal-input").value = "";
  $("#modal-input").placeholder = requireText ? `type ${requireText} to confirm` : "";
  const ok = $("#modal-ok");
  ok.textContent = confirmLabel;
  ok.className = "btn " + (danger ? "danger" : "primary");
  $("#modal-hint").textContent = requireText ? `Type ${requireText} exactly.` : "";
  modal.hidden = false;
  $("#modal-input").focus();
  return new Promise(resolve => {
    modalResolve = { resolve, requireText };
  });
}
function closeModal(value) {
  $("#modal").hidden = true;
  if (modalResolve) { modalResolve.resolve(value); modalResolve = null; }
}
$("#modal-cancel").addEventListener("click", () => closeModal(false));
$("#modal-ok").addEventListener("click", () => {
  const need = modalResolve && modalResolve.requireText;
  if (need && $("#modal-input").value.trim() !== need) {
    $("#modal-hint").textContent = `Text does not match "${need}".`;
    return;
  }
  closeModal(true);
});
$("#modal").addEventListener("keydown", (e) => {
  if (e.key === "Escape") closeModal(false);
  if (e.key === "Enter") $("#modal-ok").click();
});

function age(sec) {
  if (sec === null || sec === undefined) return "—";
  if (sec < 60) return Math.round(sec) + "s ago";
  if (sec < 3600) return Math.round(sec / 60) + "m ago";
  return Math.round(sec / 3600) + "h ago";
}
function bytes(n) {
  if (!n) return "0 B";
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
  return (n / 1024 / 1024).toFixed(1) + " MB";
}

/* ---------- application state ---------- */
const S = {
  methods: {}, methodsList: [], selected: new Set(), autoMode: true,
  lastPlan: null, findings: [], agents: [], logs: [], stopLatched: false,
  authConfirmed: false, authRequired: false, authLocked: false,
  strictScope: false, strictScopeLocked: false,
  scopeConfigured: false, logSelected: null, demo: false
};

/* ---------- tabs ---------- */
$$(".tab-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    $$(".tab-btn").forEach(b => b.classList.remove("active"));
    $$(".tab").forEach(t => t.classList.remove("active"));
    btn.classList.add("active");
    const id = "tab-" + btn.dataset.tab;
    const tab = document.getElementById(id);
    if (tab) tab.classList.add("active");
    if (btn.dataset.tab === "runs") loadRuns();
    if (btn.dataset.tab === "tools") loadTools();
    if (btn.dataset.tab === "playbooks") loadPlaybooks();
    if (btn.dataset.tab === "activity") { refreshActivity(); loadLogs(); }
    if (btn.dataset.tab === "setup-ai") loadAgents();
    window.scrollTo({ top: 0, behavior: "smooth" });
  });
});

/* ---------- live state ---------- */
async function refresh() {
  try {
    const { data } = await jsonFetch("/api/state");
    if (!data || data.updated === undefined) return;

    S.stopLatched = !!(data.stop && data.stop.requested);
    S.authConfirmed = !!(data.authorization && data.authorization.confirmed);
    S.authRequired = !!data.auth_required;
    S.strictScope = !!data.strict_scope;
    S.scopeConfigured = !!data.scope_configured;
    S.demo = !!data.demo_mode;
    updateTopState(data);

    $("#updated").textContent =
      "updated " + new Date(data.updated).toLocaleTimeString() +
      (data.run ? " · " + data.run.run_id : " · no run yet") +
      (data.run && data.run.demo ? " · DEMO" : "");

    const demoBanner = $("#demo-banner");
    if (demoBanner) demoBanner.style.display = (data.run && data.run.demo) ? "block" : "none";

    $("#b-confirmed").textContent = data.counts.confirmed + " confirmed";
    $("#b-likely").textContent = data.counts.likely + " likely";
    $("#b-dig").textContent = data.counts.dig + " DIG";
    $("#b-chain").textContent = data.counts.chain + " chains";
    $("#b-lead").textContent = data.counts.lead + " leads";

    S.agents = data.agents || [];
    renderAgents();
    S.findings = data.findings || [];
    renderFindings();
  } catch (e) {
    console.error("refresh failed", e);
  }
}

function updateTopState(data) {
  const scope = $("#chip-scope");
  const auth = $("#chip-auth");
  const stop = $("#chip-stop");
  const mode = $("#chip-mode");
  if (scope) {
    if (S.strictScope) {
      scope.textContent = S.scopeConfigured ? "scope strict" : "scope strict · empty";
      scope.className = "chip " + (S.scopeConfigured ? "ok" : "bad");
    } else {
      scope.textContent = "scope auto-add";
      scope.className = "chip";
    }
  }
  if (auth) {
    if (S.authConfirmed) {
      auth.textContent = "authorization on file";
      auth.className = "chip ok";
    } else if (S.authRequired) {
      auth.textContent = "authorization required";
      auth.className = "chip warn";
    } else {
      auth.textContent = "authorization optional";
      auth.className = "chip";
    }
  }
  if (stop) {
    stop.textContent = S.stopLatched ? "STOP latched" : "stop ready";
    stop.className = "chip " + (S.stopLatched ? "bad" : "ok");
  }
  if (mode) {
    mode.textContent = S.demo ? "demo mode" : "real checks";
    mode.className = "chip " + (S.demo ? "warn" : "");
  }
  const btn = $("#stop-btn");
  if (btn) {
    btn.textContent = S.stopLatched ? "Clear stop" : "Stop hunt";
    btn.className = "btn " + (S.stopLatched ? "" : "danger");
  }
}

function renderAgents() {
  const grid = $("#agent-grid");
  if (!grid) return;
  if (!S.agents.length) {
    grid.innerHTML = '<div class="empty">No agents reporting yet. Start a hunt, or run <code>python dispatch.py</code> in a terminal.</div>';
    return;
  }
  grid.innerHTML = S.agents.map(a => `
    <article class="agent">
      <div class="agent-top">
        <span class="dot ${esc(a.live_status)}"></span>
        <span class="name">${esc(a.name)}</span>
        ${a.role === "lead" ? '<span class="role-tag">LEAD</span>' : ""}
        <span class="model">${esc(a.model || "")}</span>
      </div>
      <div class="status-line ${esc(a.live_status)}">${esc(statusLabel(a))}</div>
      <div class="task-desc">${esc(a.task_desc || "idle")}</div>
      <div class="card-foot">report ${age(a.age_seconds)} · findings ${esc(a.findings_count || 0)} · ${esc(a.task_id || "—")}</div>
      ${(a.tools && a.tools.length)
        ? `<div class="card-foot">tools: ${a.tools.map(t => esc((t.bin || t.id) + (t.known === false ? " (unknown)" : t.installed ? "" : " (missing)"))).join(", ")}</div>`
        : ""}
      ${a.note ? `<div class="card-foot">${esc(a.note)}</div>` : ""}
    </article>`).join("");
}

function statusLabel(a) {
  if (a.live_status === "blocked") return "BLOCKED · " + (a.note || "outside scope");
  if (a.live_status === "live") return "LIVE · working now";
  if (a.live_status === "ontask") return "ON TASK · silent " + Math.round(a.age_seconds || 0) + "s";
  if (a.live_status === "yellow") return "ON TASK · heartbeat pending";
  return "IDLE · no recent pulse";
}

/* ---------- findings ---------- */
function renderFindings() {
  const body = $("#findings-body");
  if (!body) return;
  const q = ($("#f-search") ? $("#f-search").value : "").toLowerCase().trim();
  const sev = ($("#f-sev") ? $("#f-sev").value : "all");
  const rows = S.findings.filter(f => {
    if (sev !== "all" && f.severity !== sev) return false;
    if (!q) return true;
    return [f.title, f.host, f.url, f.agent, f.evidence, f.category]
      .join(" ").toLowerCase().includes(q);
  });
  $("#findings-count").textContent = rows.length + " shown · " + S.findings.length + " total";
  $("#findings-empty").style.display = rows.length ? "none" : "block";

  body.innerHTML = rows.map(f => `
    <tr>
      <td class="mono">${esc(new Date(f.ts).toLocaleTimeString())}</td>
      <td>${esc(f.agent)}</td>
      <td><span class="sev" style="color:${SEV_COLOR[f.severity] || "#ccc"}">${esc(f.severity)}</span></td>
      <td>
        <div class="f-title">${esc(f.title)}${f.demo ? '<span class="demo-tag">DEMO</span>' : ""}
          ${f.dup_count > 1 ? `<span class="dupe">seen ${esc(f.dup_count)}×</span>` : ""}</div>
        ${f.evidence ? `<div class="f-evidence">${esc(f.evidence)}</div>` : ""}
        ${f.command ? `<div class="f-url">${esc(f.command)}</div>` : ""}
      </td>
      <td>
        <div>${esc(f.host || "—")}</div>
        ${f.url ? `<div class="f-url">${esc(f.url)}</div>` : ""}
        ${f.param ? `<div class="f-url">param: ${esc(f.param)}</div>` : ""}
        ${f.category ? `<div class="f-url">${esc(f.category)}</div>` : ""}
      </td>
    </tr>`).join("");
}

function exportFindings() {
  if (!S.findings.length) { toast("No findings to export.", "warn"); return; }
  const lines = ["# Hunt findings", "", "| Severity | Title | Host | Evidence |", "|---|---|---|---|"];
  S.findings.forEach(f => lines.push(
    `| ${f.severity} | ${(f.title || "").replace(/\|/g, "\\|")} | ${f.host || ""} | ${(f.evidence || "").replace(/\|/g, "\\|")} |`));
  copyText(lines.join("\n"), "Findings copied as Markdown.");
}

async function copyText(text, okMessage) {
  try {
    await navigator.clipboard.writeText(text);
    toast(okMessage || "Copied.", "ok");
  } catch (e) {
    toast("Clipboard blocked by the browser.", "err");
  }
}

/* ---------- activity ---------- */
async function refreshActivity() {
  try {
    const { data } = await jsonFetch("/api/activity");
    const el = $("#activity-log");
    if (!el) return;
    el.textContent = (data.lines && data.lines.length)
      ? data.lines.join("\n") : "waiting for agents…";
    el.scrollTop = el.scrollHeight;
  } catch (e) { /* the next poll will retry */ }
}

/* ---------- runs ---------- */
async function loadRuns() {
  const sel = $("#run-select");
  if (!sel) return;
  try {
    const { data } = await jsonFetch("/api/runs");
    const runs = data.runs || [];
    const keep = sel.value;
    sel.innerHTML = runs.map(r => `
      <option value="${esc(r.run_id)}">${esc(r.run_id)} — ${esc(r.target || "?")} · ${esc(r.findings)} findings · ${esc(r.assets)} assets${r.running ? " · RUNNING" : ""}</option>`).join("");
    if (keep && runs.some(r => r.run_id === keep)) sel.value = keep;
    else if (data.current && runs.some(r => r.run_id === data.current)) sel.value = data.current;
    if (!runs.length) {
      $("#diff-added").innerHTML = '<div class="empty">No runs yet — start a hunt on the Dashboard tab.</div>';
      $("#diff-removed").innerHTML = "";
      $("#run-summary").textContent = "";
      return;
    }
    await loadDiff();
  } catch (e) { console.error("loadRuns failed", e); }
}

async function loadDiff() {
  const runId = $("#run-select").value;
  if (!runId) return;
  try {
    const { data } = await jsonFetch("/api/diff?run=" + encodeURIComponent(runId));
    if (!data.ok) {
      $("#diff-added").innerHTML = `<div class="empty">${esc(data.error || "diff unavailable")}</div>`;
      $("#diff-removed").innerHTML = "";
      return;
    }
    const added = (data.assets.added || []).map(a =>
      `<div class="added">+ ${esc(a.value)} <span class="dim">${esc(a.kind || "")}</span></div>`);
    (data.findings.added || []).forEach(f => added.push(
      `<div class="added">+ [${esc(f.severity)}] ${esc(f.title)}</div>`));
    const removed = (data.assets.removed || []).map(a => `<div class="removed">− ${esc(a.value)}</div>`);
    (data.findings.removed || []).forEach(f => removed.push(`<div class="removed">− ${esc(f.title)}</div>`));

    $("#diff-added").innerHTML = added.length ? added.join("") : '<div class="empty">Nothing new since the previous run.</div>';
    $("#diff-removed").innerHTML = removed.length ? removed.join("") : '<div class="empty">Nothing vanished.</div>';
    $("#run-summary").textContent =
      (data.is_first_run ? "first run — nothing to diff against yet" : "compared with " + data.base_run) +
      " · " + (data.assets.total || 0) + " assets · " + (data.findings.total || 0) + " unique findings";
  } catch (e) { console.error("loadDiff failed", e); }
}

/* ---------- categories ---------- */
function updateAutoChip() {
  const chip = $("#auto-chip");
  if (chip) {
    chip.classList.toggle("checked", S.autoMode);
    const cb = chip.querySelector("input");
    if (cb) cb.checked = S.autoMode;
  }
  const wrap = $("#category-chips");
  if (wrap) wrap.classList.toggle("auto-active", S.autoMode);
  const hint = $("#cat-hint");
  if (hint) {
    hint.textContent = S.autoMode
      ? "Auto mode: the target check ranks the categories and the server picks the plan. Click any chip to take control."
      : "Manual selection: only the checked categories will run.";
  }
}

function setCategories(cats) {
  S.selected = new Set(cats);
  $$(".cat-chip[data-cat]").forEach(chip => {
    const on = S.selected.has(chip.dataset.cat);
    chip.classList.toggle("checked", on);
    const cb = chip.querySelector("input");
    if (cb) cb.checked = on;
  });
}

async function loadCategories() {
  try {
    const { data } = await jsonFetch("/api/categories");
    const cats = data.categories || [];
    S.methodsList = data.methods || [];
    S.methods = {};
    S.methodsList.forEach(m => { S.methods[m.id] = m; });
    S.selected = new Set(cats);

    const wrap = $("#category-chips");
    if (!wrap) return;
    wrap.innerHTML = `
      <label class="cat-chip auto-chip checked" id="auto-chip" title="Profile the target, then let the plan decide what runs">
        <input type="checkbox" checked> auto plan
      </label>` +
      cats.map(c => {
        const m = S.methods[c] || {};
        const kind = m.automated ? "auto" : "manual";
        return `<label class="cat-chip checked" data-cat="${esc(c)}" title="${esc(m.tagline || "")}">
          <input type="checkbox" checked>
          <span class="dot-tiny ${kind}"></span>${esc(m.name || c.replace(/_/g, " "))}
        </label>`;
      }).join("");

    $("#auto-chip").addEventListener("click", (e) => {
      e.preventDefault();
      S.autoMode = true;
      setCategories(cats);
      updateAutoChip();
    });
    wrap.querySelectorAll(".cat-chip[data-cat]").forEach(chip => {
      chip.addEventListener("click", (e) => {
        e.preventDefault();
        S.autoMode = false;
        const cat = chip.dataset.cat;
        if (S.selected.has(cat)) S.selected.delete(cat); else S.selected.add(cat);
        const cb = chip.querySelector("input");
        if (cb) cb.checked = S.selected.has(cat);
        chip.classList.toggle("checked", S.selected.has(cat));
        updateAutoChip();
      });
    });
    updateAutoChip();
  } catch (e) { console.error("loadCategories failed", e); }
}

/* ---------- scope + authorization ---------- */
async function loadScope() {
  try {
    const { data } = await jsonFetch("/api/scope");
    setValue("in-scope", (data.in_scope || []).join("\n"));
    setValue("out-scope", (data.out_scope || []).join("\n"));
  } catch (e) { /* keep whatever is in the boxes */ }
  try {
    const { data } = await jsonFetch("/api/authorization");
    const a = data.authorization || {};
    setValue("auth-program", a.program || "");
    setValue("auth-url", a.program_url || "");
    setValue("auth-by", a.authorized_by || "");
    setValue("auth-ref", a.reference || "");
    setValue("auth-window", [a.window_start, a.window_end].filter(Boolean).join(" → "));
    setValue("auth-rate", a.rate_limit || "");
    setChecked("auth-confirm", a.confirmed);
    S.authConfirmed = !!a.confirmed;
    updateTopState({});
  } catch (e) { /* optional */ }
  try {
    const { data } = await jsonFetch("/api/settings");
    S.authRequired = !!data.require_auth;
    S.authLocked = !!data.locked;
    S.strictScope = !!data.strict_scope;
    S.strictScopeLocked = !!data.strict_scope_locked;
    const cb = $("#auth-required");
    if (cb) {
      setChecked("auth-required", S.authRequired);
      cb.disabled = S.authLocked;
    }
    const note = $("#auth-required-note");
    if (note) {
      note.textContent = S.authLocked
        ? "Pinned by HUNT_REQUIRE_AUTH for this installation."
        : "";
    }
    const scb = $("#scope-strict");
    if (scb) {
      setChecked("scope-strict", S.strictScope);
      scb.disabled = S.strictScopeLocked;
    }
    const snote = $("#scope-strict-note");
    if (snote) {
      snote.textContent = S.strictScopeLocked
        ? "Pinned by HUNT_STRICT_SCOPE for this installation."
        : "";
    }
    updateTopState({});
  } catch (e) { /* optional */ }
}

async function saveScope() {
  const in_scope = $("#in-scope").value.split("\n").map(s => s.trim()).filter(Boolean);
  const out_scope = $("#out-scope").value.split("\n").map(s => s.trim()).filter(Boolean);
  try {
    const { data } = await jsonFetch("/api/scope", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ in_scope, out_scope })
    });
    if (!data.ok) { toast(data.error || "scope save failed", "err"); return; }
    markSaved(["in-scope", "out-scope"]);
    S.scopeConfigured = in_scope.length > 0;
    if (data.unparsed && data.unparsed.length) {
      toast("Saved. Could not parse: " + data.unparsed.join(", "), "warn");
    } else {
      toast("Scope saved.", "ok");
    }
    updateTopState({});
  } catch (e) { toast("scope save failed: " + e, "err"); }
}

async function saveAuthSetting() {
  const on = $("#auth-required").checked;
  try {
    const { data } = await jsonFetch("/api/settings", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ require_auth: on })
    });
    if (!data.ok) {
      $("#auth-required").checked = !on;
      toast(data.error || "authorization setting was not saved", "err");
      return;
    }
    markSaved(["auth-required"]);
    S.authRequired = !!data.require_auth;
    toast(S.authRequired
      ? "Hunts now require a confirmed authorization record."
      : "Authorization is now optional. Scope is still enforced.",
      "ok");
    updateTopState({});
  } catch (e) {
    $("#auth-required").checked = !on;
    toast("authorization setting failed: " + e, "err");
  }
}

async function saveStrictScope() {
  const on = $("#scope-strict").checked;
  try {
    const { data } = await jsonFetch("/api/settings", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ strict_scope: on })
    });
    if (!data.ok) {
      $("#scope-strict").checked = !on;
      toast(data.error || "scope setting was not saved", "err");
      return;
    }
    markSaved(["scope-strict"]);
    S.strictScope = !!data.strict_scope;
    toast(S.strictScope
      ? "Strict scope: a hunt target must already be in the in-scope list."
      : "Scope is lenient: a new hunt target is added to the list automatically. Out-of-scope entries still block.",
      "ok");
    updateTopState({});
  } catch (e) {
    $("#scope-strict").checked = !on;
    toast("scope setting failed: " + e, "err");
  }
}

async function saveAuthorization() {
  const confirmed = $("#auth-confirm").checked;
  const body = {
    program: $("#auth-program").value.trim(),
    program_url: $("#auth-url").value.trim(),
    authorized_by: $("#auth-by").value.trim(),
    reference: $("#auth-ref").value.trim(),
    window_start: "", window_end: "",
    rate_limit: $("#auth-rate").value.trim(),
    notes: "",
    confirmed
  };
  const windowText = $("#auth-window").value.trim();
  if (windowText) {
    const parts = windowText.split(/→|->|to/i).map(s => s.trim());
    body.window_start = parts[0] || "";
    body.window_end = parts[1] || "";
  }
  try {
    const { data } = await jsonFetch("/api/authorization", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    if (!data.ok) { toast(data.error || "authorization save failed", "err"); return; }
    markSaved(["auth-program", "auth-url", "auth-by", "auth-ref",
               "auth-window", "auth-rate", "auth-confirm"]);
    S.authConfirmed = !!data.authorization.confirmed;
    toast(S.authConfirmed ? "Authorization recorded." : "Authorization draft saved (not confirmed).",
          S.authConfirmed ? "ok" : "warn");
    updateTopState({});
  } catch (e) { toast("authorization save failed: " + e, "err"); }
}

/* ---------- stop ---------- */
async function toggleStop() {
  if (S.stopLatched) {
    const { data } = await jsonFetch("/api/stop", { method: "DELETE" });
    if (data.ok) { S.stopLatched = false; toast("Stop cleared. The next hunt can start.", "ok"); }
    updateTopState({});
    return;
  }
  const ok = await askConfirm({
    title: "Stop the hunt?",
    body: "Every running worker checks this flag before its next request. Work already in flight is terminated; nothing new starts.",
    confirmLabel: "Stop now", danger: true
  });
  if (!ok) return;
  const { data } = await jsonFetch("/api/stop", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ reason: "operator pressed stop" })
  });
  if (data.ok) { S.stopLatched = true; toast("Emergency stop latched.", "warn"); pollHuntStatus(); }
  else toast(data.error || "stop failed", "err");
  updateTopState({});
}

/* ---------- plan ---------- */
async function runPlan() {
  const target = $("#hunt-form").target.value.trim();
  const statusEl = $("#hunt-status");
  if (!target) {
    statusEl.className = "hunt-status error";
    statusEl.textContent = "Enter a target first.";
    return;
  }
  const btn = $("#plan-btn");
  btn.disabled = true;
  statusEl.className = "hunt-status";
  statusEl.textContent = "profiling " + target + " with ordinary GETs, then ranking categories…";
  try {
    // The server accepts a not-yet-listed target only in lenient mode and only
    // when this header is present, so a cross-site image/link cannot profile.
    const { data } = await jsonFetch(
      "/api/plan?profile=1&target=" + encodeURIComponent(target),
      { headers: { "X-Hunt-Request": "1" } });
    if (!data.ok) {
      statusEl.className = "hunt-status error";
      statusEl.textContent = data.error || "plan failed";
      if (data.profile) renderProfile(data.profile);
      return;
    }
    S.lastPlan = data;
    renderPlan(data);
    statusEl.className = "hunt-status ok";
    statusEl.textContent = data.summary;
  } catch (e) {
    statusEl.className = "hunt-status error";
    statusEl.textContent = "plan request failed: " + e;
  } finally { btn.disabled = false; }
}

function renderPlan(plan) {
  const panel = $("#plan-panel");
  panel.style.display = "block";
  const max = Math.max(...plan.steps.map(s => s.score), 1);
  const items = plan.steps.map(s => `
    <div class="plan-item">
      <div class="plan-rank">${s.rank}</div>
      <div>
        <h4>${esc(s.name)} <span class="tag ${s.automated ? "auto" : "manual"}">${s.automated ? "scripted" : "manual"}</span></h4>
        <div class="plan-reason">${esc(s.reason || s.tagline)}</div>
        <div class="bar"><span style="width:${Math.round(100 * s.score / max)}%"></span></div>
      </div>
      <div class="plan-score"><b>${s.score}</b>${esc(s.confidence)}</div>
    </div>`).join("");
  $("#plan-list").innerHTML = items;
  $("#plan-actions").innerHTML = `
    <button class="btn primary small" id="plan-apply-auto">Use scripted categories</button>
    <button class="btn small" id="plan-apply-all">Use all ranked categories</button>
    <button class="btn small ghost" id="plan-open-playbook">Open playbooks</button>
    <span class="hint">${plan.manual.length} category(ies) need a human with credentials or a browser.</span>`;
  $("#plan-apply-auto").addEventListener("click", () => {
    S.autoMode = false;
    setCategories(plan.automated);
    updateAutoChip();
    toast("Selected " + plan.automated.length + " scripted categories.", "ok");
  });
  $("#plan-apply-all").addEventListener("click", () => {
    S.autoMode = false;
    setCategories(plan.steps.map(s => s.category));
    updateAutoChip();
    toast("Selected all ranked categories (manual ones will record notes).", "ok");
  });
  $("#plan-open-playbook").addEventListener("click", () => {
    const tab = document.querySelector('.tab-btn[data-tab="playbooks"]');
    if (tab) tab.click();
  });
  if (plan.profile) renderProfile(plan.profile);
}

function renderProfile(data) {
  const el = $("#profile-panel");
  if (!el) return;
  el.style.display = "block";
  if (!data || !data.ok) {
    el.innerHTML = `<div class="hint"><b style="color:var(--red)">Target check failed.</b> ${esc((data && data.error) || "no response")}</div>`;
    return;
  }
  const techs = (data.technologies || []).map(t =>
    `<span class="chip">${esc(t.name)}${t.version ? " " + esc(t.version) : ""}</span>`).join("") ||
    '<span class="hint">no clear framework fingerprint</span>';
  const cats = (data.categories || []).map(c => `
    <div class="plan-item" style="grid-template-columns:70px 1fr;">
      <span class="tag ${c.confidence === "high" ? "manual" : "auto"}">${esc(c.confidence)}</span>
      <div><b>${esc(c.category.replace(/_/g, " "))}</b>
        <div class="plan-reason">${esc(c.reason)}</div></div>
    </div>`).join("") || '<span class="hint">Nothing stood out — start with recon.</span>';
  el.innerHTML = `
    <div class="row" style="margin-bottom:10px;">
      <span class="mono">${esc(data.final_url || data.base_url || "")}</span>
      <span class="chip">HTTP ${esc(data.status)}</span>
      ${data.server ? `<span class="chip">${esc(data.server)}</span>` : ""}
    </div>
    <div style="margin-bottom:12px;">${techs}</div>
    <div class="pb-cols">
      <div><h4 class="hint">LIKELY BUG CLASSES</h4><div class="plan-list">${cats}</div></div>
      <div><h4 class="hint">SURFACE NOTES</h4><div class="hint">${esc((data.notes || []).join(" · ") || "—")}</div></div>
    </div>`;
}

/* ---------- start hunt ---------- */
async function startHunt(e) {
  e.preventDefault();
  const form = e.target;
  const target = form.target.value.trim();
  const rounds = parseInt(form.rounds.value, 10) || 3;
  const statusEl = $("#hunt-status");
  const btn = $("#hunt-submit");
  if (!target) {
    statusEl.className = "hunt-status error";
    statusEl.textContent = "Enter a target first.";
    return;
  }
  btn.disabled = true;
  statusEl.className = "hunt-status";
  statusEl.textContent = S.autoMode
    ? "profiling the target, then starting the ranked plan…"
    : "starting " + target + " with " + S.selected.size + " categories…";
  try {
    const { data } = await jsonFetch("/api/start", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, rounds, categories: S.autoMode ? null : Array.from(S.selected) })
    });
    if (data.profile) renderProfile(data.profile);
    if (!data.ok) {
      statusEl.className = "hunt-status error";
      let msg = data.error || "failed to start";
      if (data.requires_authorization) msg += " Open Scope & authorization below, or turn off blocking there.";
      const missing = (data.tools_missing || []).map(t => t.name).join(", ");
      if (missing) msg += " — missing tools: " + missing + " (Tools tab)";
      statusEl.textContent = msg;
      btn.disabled = false;
      return;
    }
    const how = data.categories_source === "plan" ? "ranked plan (scripted categories)"
      : data.categories_source === "user" ? "your selection" : "all categories";
    if (data.scope_seeded) {
      const box = $("#in-scope");
      const entries = box.value.split("\n").map(s => s.trim()).filter(Boolean);
      if (!entries.includes(data.scope_seeded)) entries.push(data.scope_seeded);
      setValue("in-scope", entries.join("\n"));
      S.scopeConfigured = true;
      updateTopState({});
    }
    statusEl.className = data.warning ? "hunt-status warning" : "hunt-status ok";
    statusEl.textContent = (data.warning ? data.warning + " — " : "") +
      "Hunt running on " + target + " (" + rounds + " rounds, " +
      data.categories.length + " categories — " + how + ").";
    pollHuntStatus();
  } catch (err) {
    statusEl.className = "hunt-status error";
    statusEl.textContent = "request failed: " + err;
    btn.disabled = false;
  }
}

async function pollHuntStatus() {
  const btn = $("#hunt-submit");
  const statusEl = $("#hunt-status");
  try {
    const { data } = await jsonFetch("/api/status");
    S.stopLatched = !!(data.stop && data.stop.requested);
    updateTopState({});
    if (data.value) {
      if (btn) btn.disabled = true;
      setTimeout(pollHuntStatus, 3000);
    } else {
      if (btn) btn.disabled = false;
      if (data.error) {
        statusEl.className = "hunt-status error";
        statusEl.textContent = "hunt failed: " + data.error;
      } else if (statusEl.textContent.indexOf("Hunt running") === 0) {
        statusEl.className = "hunt-status ok";
        statusEl.textContent = "Hunt complete.";
      }
      loadRuns();
    }
  } catch (e) { if (btn) btn.disabled = false; }
}

/* ---------- playbooks ---------- */
async function loadPlaybooks() {
  if (S.methodsList.length) { renderPlaybookList(); return; }
  try {
    const { data } = await jsonFetch("/api/methods");
    S.methodsList = data.methods || [];
    S.methods = {};
    S.methodsList.forEach(m => { S.methods[m.id] = m; });
    renderPlaybookList();
  } catch (e) { console.error("loadPlaybooks failed", e); }
}

function renderPlaybookList() {
  const list = $("#pb-list");
  if (!list) return;
  list.innerHTML = S.methodsList.map(m => `
    <button class="pb-item" data-cat="${esc(m.id)}">
      <b>${esc(m.name)}</b>
      <span>${esc(m.automated ? "scripted" : "manual")} · ${esc(m.severity_hint)}</span>
    </button>`).join("");
  list.querySelectorAll(".pb-item").forEach(btn => {
    btn.addEventListener("click", () => showPlaybook(btn.dataset.cat));
  });
  const first = S.methodsList[0];
  if (first) showPlaybook(first.id);
}

async function showPlaybook(category) {
  $$(".pb-item").forEach(b => b.classList.toggle("active", b.dataset.cat === category));
  const detail = $("#pb-detail");
  detail.innerHTML = '<div class="empty">loading playbook…</div>';
  try {
    const { data } = await jsonFetch("/api/methods?category=" + encodeURIComponent(category));
    if (!data.ok) { detail.innerHTML = `<div class="empty">${esc(data.error)}</div>`; return; }
    const p = data.playbook;
    const steps = (p.steps || []).map((s, i) => `
      <div class="pb-step">
        <div class="num">${i + 1}</div>
        <div>
          <h5>${esc(s.title)}</h5>
          <p>${esc(s.detail)}</p>
          ${(s.commands || []).map(c => `
            <div class="cmd">${esc(c)}<button type="button" data-copy="${esc(c)}">copy</button></div>`).join("")}
        </div>
      </div>`).join("");
    const refs = (p.refs || []).map(r =>
      `<li><a href="${esc(r.url)}" target="_blank" rel="noopener noreferrer">${esc(r.label)}</a></li>`).join("");
    detail.innerHTML = `
      <h2>${esc(p.name)}</h2>
      <div class="pb-tagline">${esc(p.tagline)}</div>
      <div class="pb-meta">
        <span class="tag ${data.automated ? "auto" : "manual"}">${data.automated ? "scripted checks available" : "manual testing"}</span>
        <span class="chip">${esc(p.severity_hint)}</span>
      </div>
      <div class="pb-block"><h4>Objective</h4><p>${esc(p.objective)}</p></div>
      <div class="pb-block"><h4>Why it matters</h4><p>${esc(p.why)}</p></div>
      <div class="pb-block"><h4>Step-by-step</h4>${steps}</div>
      <div class="pb-cols">
        <div class="pb-block"><h4>Evidence to capture</h4><ul>${(p.evidence || []).map(e => `<li>${esc(e)}</li>`).join("")}</ul></div>
        <div class="pb-block"><h4>Pitfalls</h4><ul>${(p.pitfalls || []).map(e => `<li>${esc(e)}</li>`).join("")}</ul></div>
      </div>
      <div class="pb-block"><h4>Recommended tools</h4><div class="row">${(p.tools || []).map(t => `<span class="chip">${esc(t)}</span>`).join("")}</div>
        <p class="hint" style="margin-top:8px;">${esc(p.manual)}</p></div>
      <div class="pb-block"><h4>References</h4><ul>${refs}</ul></div>`;
    detail.querySelectorAll("[data-copy]").forEach(btn => {
      btn.addEventListener("click", () => copyText(btn.dataset.copy, "Command copied."));
    });
  } catch (e) {
    detail.innerHTML = `<div class="empty">playbook failed to load: ${esc(e)}</div>`;
  }
}

/* ---------- tools ---------- */
function renderTools(data) {
  S.demo = !!data.demo_mode;
  const s = data.summary || {};
  $("#tool-summary").innerHTML =
    `<b>${esc(s.catalogued)}</b> tools · <b>${esc(s.stages)}</b> stages · ` +
    `<span style="color:var(--green)">${esc(s.installed)}</span>/${esc(s.selected_total)} selected installed · ` +
    `<span style="color:var(--yellow)">${esc((s.missing || []).length)}</span> missing` +
    (S.demo ? ' · <span style="color:var(--yellow)">demo mode</span>' : "");

  const q = ($("#tool-search") ? $("#tool-search").value : "").toLowerCase().trim();
  const stages = (data.stages || []).filter(stage => {
    if (!q) return true;
    return (stage.label + " " + stage.id + " " + stage.tools.map(t => t.id + " " + t.what).join(" "))
      .toLowerCase().includes(q);
  });
  const grid = $("#tool-grid");
  if (!stages.length) { grid.innerHTML = '<div class="empty">No tool matches that search.</div>'; return; }

  grid.innerHTML = stages.map(stage => {
    const sel = stage.tools.find(t => t.id === stage.selected) || stage.tools[0];
    const opts = stage.tools.map(t =>
      `<option value="${esc(t.id)}" ${t.id === stage.selected ? "selected" : ""}>${esc(t.id)} — ${t.installed ? "installed" : "need install"}${t.default ? " (default)" : ""}</option>`).join("");
    const alts = stage.tools.filter(t => t.id !== stage.selected).map(t =>
      `<button class="alt-chip" type="button" data-stage="${esc(stage.id)}" data-tool="${esc(t.id)}" title="${esc(t.what)}">${esc(t.id)}${t.installed ? " ✓" : ""}</button>`).join("");
    const ready = !!(sel && sel.installed);
    return `
      <div class="tool-stage">
        <div class="tool-stage-head">
          <h3>${esc(stage.label)}</h3>
          <span class="pill ${ready ? "ok" : "need"}">${ready ? "READY" : "NEED INSTALL"}</span>
        </div>
        <div class="blurb">${esc(stage.blurb)}</div>
        <select data-stage="${esc(stage.id)}">${opts}</select>
        ${alts ? `<div class="tool-alt">${alts}</div>` : ""}
        <div class="tool-detail">
          <div>${esc(sel ? sel.what : "")}</div>
          ${sel ? `<div style="margin-top:4px;"><a href="${esc(sel.repo)}" target="_blank" rel="noopener noreferrer">${esc(sel.repo.replace("https://github.com/", "github.com/"))}</a>${sel.version ? ` · <span class="mono">${esc(sel.version)}</span>` : ""}</div>` : ""}
          ${sel && !sel.installed ? `<div class="cmd">${esc(sel.install)}<button type="button" data-copy="${esc(sel.install)}">copy</button></div>` : ""}
        </div>
        <div class="tool-need">needed by: ${stage.needed_by.length ? stage.needed_by.map(c => `<code>${esc(c)}</code>`).join(", ") : "manual use — not required by a scripted category"}</div>
      </div>`;
  }).join("");
  grid.querySelectorAll("[data-copy]").forEach(btn => {
    btn.addEventListener("click", () => copyText(btn.dataset.copy, "Install command copied."));
  });
}

async function loadTools(force) {
  try {
    const { data } = await jsonFetch("/api/tools" + (force ? "?refresh=1" : ""));
    if (data.ok) renderTools(data);
  } catch (e) { console.error("loadTools failed", e); }
}

async function chooseTool(stage, toolId) {
  if (!stage || !toolId) return;
  try {
    const { data } = await jsonFetch("/api/tools", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ selected: { [stage]: toolId } })
    });
    if (data.ok) { renderTools(data); toast("Tool selection saved.", "ok"); }
    else toast(data.error || "selection failed", "err");
  } catch (e) { toast("selection failed: " + e, "err"); }
}

/* ---------- logs ---------- */
async function loadLogs() {
  try {
    const { data } = await jsonFetch("/api/logs");
    S.logs = data.logs || [];
    const list = $("#log-list");
    list.innerHTML = S.logs.length ? S.logs.map(l => `
      <div class="log-row">
        <span class="lname">${esc(l.name)}</span>
        <span class="lmeta">${l.lines} lines · ${bytes(l.size)}</span>
        <button class="btn small ghost" data-view="${esc(l.name)}">view</button>
        <button class="btn small danger" data-del="${esc(l.name)}">delete</button>
      </div>`).join("") : '<div class="empty">No log files yet.</div>';

    list.querySelectorAll("[data-view]").forEach(b => b.addEventListener("click", () => viewLog(b.dataset.view)));
    list.querySelectorAll("[data-del]").forEach(b => b.addEventListener("click", () => deleteLog(b.dataset.del)));

    const audit = $("#audit-log");
    if (audit) {
      const rows = (data.audit || []).slice(-12).reverse();
      audit.textContent = rows.length ? rows.map(a =>
        `${a.ts.slice(11, 19)}  ${a.action}  ${typeof a.detail === "string" ? a.detail : JSON.stringify(a.detail)}`).join("\n")
        : "no audited actions yet";
    }
  } catch (e) { console.error("loadLogs failed", e); }
}

async function viewLog(name) {
  S.logSelected = name;
  const box = $("#log-view");
  box.textContent = "loading " + name + "…";
  try {
    const { data } = await jsonFetch("/api/logs/" + encodeURIComponent(name) + "?tail=400");
    if (!data.ok) { box.textContent = data.error || "log unavailable"; return; }
    $("#log-view-title").textContent = data.name + " · last " + data.returned + " of " + data.total + " lines";
    box.textContent = data.lines.join("\n") || "(empty)";
    box.scrollTop = box.scrollHeight;
  } catch (e) { box.textContent = "log request failed: " + e; }
}

async function deleteLog(name) {
  const ok = await askConfirm({
    title: "Delete " + name + "?",
    body: "This removes the file from the data directory. The deletion itself is appended to the audit trail.",
    confirmLabel: "Delete log", danger: true
  });
  if (!ok) return;
  try {
    const { data } = await jsonFetch("/api/logs/" + encodeURIComponent(name), { method: "DELETE" });
    if (data.ok) { toast("Deleted " + name + ".", "ok"); loadLogs(); if (S.logSelected === name) $("#log-view").textContent = ""; }
    else toast(data.error || "delete failed", "err");
  } catch (e) { toast("delete failed: " + e, "err"); }
}

async function clearLogs() {
  const ok = await askConfirm({
    title: "Clear all logs?",
    body: "Every *.log file in the data directory is removed. Findings and run history are untouched.",
    confirmLabel: "Clear all logs", requireText: "CLEAR", danger: true
  });
  if (!ok) return;
  try {
    const { data } = await jsonFetch("/api/logs/clear", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ confirm: "CLEAR" })
    });
    if (data.ok) { toast("Cleared " + data.cleared + " log file(s).", "ok"); $("#log-view").textContent = ""; loadLogs(); }
    else toast(data.error || "clear failed", "err");
  } catch (e) { toast("clear failed: " + e, "err"); }
}

/* ---------- agents ---------- */
function agentRow(a) {
  a = a || { name: "", role: "worker", model: "", api_key_set: false };
  const ph = a.api_key_set ? "•••••••• (set — blank keeps it)" : "optional";
  return `<tr>
    <td><input type="text" name="name" value="${esc(a.name)}" placeholder="worker-x"></td>
    <td><select name="role">
      <option value="lead" ${a.role === "lead" ? "selected" : ""}>lead</option>
      <option value="worker" ${a.role !== "lead" ? "selected" : ""}>worker</option>
    </select></td>
    <td><input type="text" name="model" value="${esc(a.model)}" placeholder="opencode/glm-5.3-flash-free"></td>
    <td><input type="password" name="api_key" value="" placeholder="${ph}"></td>
    <td><button class="btn small danger" type="button" onclick="this.closest('tr').remove()">✕</button></td>
  </tr>`;
}

async function loadAgents() {
  try {
    const { data } = await jsonFetch("/api/agents");
    $("#agents-body").innerHTML = (data.agents || []).map(agentRow).join("");
  } catch (e) { /* keep the table */ }
}

async function saveAgents() {
  const agents = $$("#agents-body tr").map(tr => ({
    name: tr.querySelector('[name="name"]').value.trim(),
    role: tr.querySelector('[name="role"]').value,
    model: tr.querySelector('[name="model"]').value.trim(),
    api_key: tr.querySelector('[name="api_key"]').value.trim()
  })).filter(a => a.name && a.model);
  try {
    const { data } = await jsonFetch("/api/agents", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ agents })
    });
    if (data.ok) { toast("Saved " + data.count + " agents.", "ok"); loadAgents(); }
    else toast(data.error || "save failed", "err");
  } catch (e) { toast("save failed: " + e, "err"); }
}

/* ---------- wiring ---------- */
$("#hunt-form").addEventListener("submit", startHunt);
$("#plan-btn").addEventListener("click", runPlan);
$("#scope-toggle").addEventListener("click", () => $("#scope-panel").classList.toggle("open"));
$("#scope-save").addEventListener("click", saveScope);
$("#auth-save").addEventListener("click", saveAuthorization);
$("#auth-required").addEventListener("change", saveAuthSetting);
$("#scope-strict").addEventListener("change", saveStrictScope);
$("#stop-btn").addEventListener("click", toggleStop);
$("#run-select").addEventListener("change", loadDiff);
$("#run-refresh").addEventListener("click", loadRuns);
$("#tools-refresh").addEventListener("click", () => loadTools(true));
$("#tool-search").addEventListener("input", () => loadTools());
$("#tool-grid").addEventListener("change", (e) => {
  if (e.target.tagName === "SELECT") chooseTool(e.target.dataset.stage, e.target.value);
});
$("#tool-grid").addEventListener("click", (e) => {
  const chip = e.target.closest(".alt-chip");
  if (chip) chooseTool(chip.dataset.stage, chip.dataset.tool);
});
$("#f-search").addEventListener("input", renderFindings);
$("#f-sev").addEventListener("change", renderFindings);
$("#export-findings").addEventListener("click", exportFindings);
$("#log-clear").addEventListener("click", clearLogs);
$("#log-refresh").addEventListener("click", loadLogs);
$("#add-agent-btn").addEventListener("click", () => $("#agents-body").insertAdjacentHTML("beforeend", agentRow()));
$("#save-agents-btn").addEventListener("click", saveAgents);
$("#cats-all").addEventListener("click", () => {
  S.autoMode = false;
  setCategories(S.methodsList.map(m => m.id));
  updateAutoChip();
});
$("#cats-none").addEventListener("click", () => {
  S.autoMode = false;
  setCategories([]);
  updateAutoChip();
});
$("#cats-auto").addEventListener("click", () => {
  S.autoMode = true;
  setCategories(S.methodsList.map(m => m.id));
  updateAutoChip();
});

/* ---------- boot ---------- */
(async function boot() {
  await loadCategories();
  await loadScope();
  await loadAgents();
  await refresh();
  await refreshActivity();
  loadLogs();
  pollHuntStatus();
  setInterval(refresh, 3000);
  setInterval(refreshActivity, 4000);
  setInterval(() => {
    if ($("#tab-runs").classList.contains("active")) loadRuns();
  }, 10000);
})();
