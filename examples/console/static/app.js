/*
  Trust Console — the interactive page (/app).

  Everything shown after a call comes from the console's /api: the request as sent, the verifier's
  eight checks and its outcome, what the simulator answered. This file decides nothing; it lays the
  answer out, in 中文 or English.
*/
"use strict";

const CHECKS = ["credential_present", "freshness", "digest", "signature", "delegation", "chain",
                "revocation", "authority"];
const TOUR = [
  { run: "impersonation" },
  { run: null },
  { run: "enroll-today" },
  { run: "tampered" },
  { run: "list-insured" },
  { run: "after-revocation", revoke: true },
];
const LOG_SHOWN = 12;
const STATUS_EVERY_MS = 15000;
const PERSON_REF = /^EMP-[0-9]{4}$/;

const state = {
  lang: "zh", strings: {}, scenarios: [], tools: {}, today: "", status: null,
  tab: "tour", current: null, result: null, busy: null, error: null, fieldErrors: {},
  tour: 0, log: [],
};

const $ = (sel, root = document) => root.querySelector(sel);
const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (c) => (
  { "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" }[c]));

function t(key, vars = {}) {
  const table = state.strings[state.lang] || {};
  let text = table[key] ?? (state.strings.en || {})[key] ?? key;
  for (const [name, value] of Object.entries(vars)) text = text.split(`{${name}}`).join(String(value));
  return text;
}
const has = (key) => key in (state.strings[state.lang] || {});

function remember(key, value) {
  try { localStorage.setItem(key, value); } catch (_) { /* private window: not remembered */ }
}
function recall(key) {
  try { return localStorage.getItem(key); } catch (_) { return null; }
}

class ApiError extends Error {
  constructor(message, field) { super(message); this.field = field || null; }
}

async function api(path, options = {}) {
  let response;
  try {
    response = await fetch(path, { headers: { "Content-Type": "application/json" }, ...options });
  } catch (_) {
    throw new ApiError(t("error.network"));
  }
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new ApiError(body.error || `${response.status} ${response.statusText}`, body.field);
  return body;
}

// ------------------------------------------------------------------------------------ actions

async function runScenario(id) {
  const s = state.scenarios.find((item) => item.id === id);
  if (!s) return;
  state.current = id;
  if (id === "impersonation") {
    await perform(() => api("/api/call/impersonation", { method: "POST" }));
    return;
  }
  await perform(() => api("/api/call", {
    method: "POST",
    body: JSON.stringify({ tool: s.tool, arguments: s.arguments, variant: s.variant, scenario: s.id }),
  }));
}

// What the page can tell before anything is sent: the same rules the server applies, in words.
function checkFields(tool, args) {
  const errors = {};
  for (const [field, value] of Object.entries(args)) {
    if (field === "person_ref" && !PERSON_REF.test(value)) errors[field] = t("error.person_ref");
    if (field.endsWith("_date") && !/^\d{4}-\d{2}-\d{2}$/.test(value)) errors[field] = t("error.date");
    if (field === "salary_grade" && !(Number.isInteger(value) && value >= 1 && value <= 60)) {
      errors[field] = t("error.salary_grade");
    }
  }
  return errors;
}

async function sendBuilt() {
  const form = $("#build-form");
  const tool = form.tool.value;
  const args = {};
  for (const field of state.tools[tool] || []) {
    const input = form.elements[field];
    args[field] = field === "salary_grade" ? (input.value === "" ? NaN : Number(input.value)) : input.value;
  }
  state.fieldErrors = checkFields(tool, args);
  if (Object.keys(state.fieldErrors).length) { state.result = null; state.error = null; render(); focusFirstError(); return; }
  state.current = null;
  await perform(() => api("/api/call", {
    method: "POST", body: JSON.stringify({ tool, arguments: args, variant: form.variant.value }),
  }));
}

function focusFirstError() {
  const field = Object.keys(state.fieldErrors)[0];
  if (field) { const el = $(`#f-${field}`); if (el) el.focus(); }
}

async function perform(call) {
  document.body.classList.remove("revealed");
  state.busy = "sending"; state.error = null; state.result = null; state.fieldErrors = {};
  render();
  showResult();
  try {
    state.result = await call();
  } catch (err) {
    if (err.field && state.tab === "build") {
      state.fieldErrors = { [err.field]: has(`error.${err.field}`) ? t(`error.${err.field}`) : err.message };
    } else {
      state.error = err.message;
    }
  }
  state.busy = null;
  await Promise.all([refreshLog(), refreshStatus()]);
  render();
  if (state.result) revealChecks();
  if (Object.keys(state.fieldErrors).length) focusFirstError();
}

async function revoke() {
  state.busy = "revoking"; state.error = null; render();
  let ok = true;
  try {
    state.status = await api("/api/revoke", { method: "POST" });
    if (state.status.confirmed === false) state.error = t("revoke.unconfirmed");
  } catch (err) { state.error = err.message; ok = false; }
  state.busy = null; render();
  return ok;
}

async function reissue() {
  state.busy = "reissuing"; state.error = null; render();
  try { state.status = await api("/api/reissue", { method: "POST" }); } catch (err) { state.error = err.message; }
  state.busy = null; render();
}

async function refreshLog() {
  try { state.log = (await api("/api/log")).entries; } catch (_) { /* keep the last one */ }
}

async function refreshStatus() {
  try { state.status = await api("/api/status"); } catch (_) { /* keep the last one */ }
}

async function runTourStep() {
  const step = TOUR[state.tour];
  if (step.revoke && state.status && state.status.credential !== "revoked") {
    if (!(await revoke())) return; // a refused or failed revocation stops the step; its reason shows
  }
  if (step.run) await runScenario(step.run);
}

// Bring the result into view when it is not: narrow screens stack it under the controls.
function showResult() {
  const box = $("#outcome");
  const rect = box.getBoundingClientRect();
  if (rect.top < 0 || rect.bottom > window.innerHeight) box.scrollIntoView({ block: "center", behavior: "smooth" });
}

// ------------------------------------------------------------------------------------- render

function render() {
  document.documentElement.lang = state.lang === "zh" ? "zh-Hant" : "en";
  document.title = t("app.title");
  for (const node of document.querySelectorAll("[data-t]")) node.textContent = t(node.dataset.t);
  for (const button of document.querySelectorAll("#lang button")) {
    button.setAttribute("aria-pressed", String(button.dataset.lang === state.lang));
  }
  for (const tab of document.querySelectorAll(".tab")) {
    tab.setAttribute("aria-selected", String(tab.dataset.tab === state.tab));
  }
  for (const name of ["tour", "scenarios", "build"]) $(`#panel-${name}`).hidden = state.tab !== name;
  renderStatus();
  renderTour();
  renderScenarios();
  renderBuild();
  renderWho();
  renderResult();
  renderLog();
}

function renderStatus() {
  const s = state.status;
  if (!s) { $("#status").innerHTML = ""; return; }
  const colon = t("punct.colon");
  const gateway = s.target === "gateway" && s.gatewayReachable === false
    ? `<span class="down">${esc(t("status.gateway.down"))}</span>` : `<span>${esc(t(`status.target.${s.target}`))}</span>`;
  $("#status").innerHTML =
    `<span>${esc(t("status.credential"))}${colon}<b class="${esc(s.credential)}">${esc(t(`status.${s.credential}`))}</b></span>${gateway}`;
}

function busyLine() {
  if (state.busy === "revoking") return `<p class="busy">${esc(t("revoke.busy"))}</p>`;
  if (state.busy === "reissuing") return `<p class="busy">${esc(t("reissue.busy"))}</p>`;
  return "";
}

function revocationControls() {
  if (state.status && state.status.public) return `<p class="hint">${esc(t("public.locked"))}</p>`;
  const revoked = state.status && state.status.credential === "revoked";
  return `<div class="revocation-actions">
      <button type="button" class="secondary danger" id="revoke" ${revoked || state.busy ? "disabled" : ""}>${esc(t("revoke.button"))}</button>
      <button type="button" class="secondary" id="reissue" ${!revoked || state.busy ? "disabled" : ""}>${esc(t("reissue.button"))}</button>
    </div>${busyLine()}${revoked && !state.busy ? `<p class="hint">${esc(t("revoke.done"))}</p>` : ""}`;
}

function renderTour() {
  const n = state.tour + 1;
  const step = TOUR[state.tour];
  const last = state.tour === TOUR.length - 1;
  const dots = TOUR.map((_, i) => `<span class="${i <= state.tour ? "on" : ""}"></span>`).join("");
  $("#panel-tour").innerHTML = `<div class="tour">
      <div class="count">${esc(t("tour.step", { n, total: TOUR.length }))}</div>
      <h3>${esc(t(`tour.${n}.title`))}</h3>
      <p>${esc(t(`tour.${n}.text`))}</p>
      <div class="controls">
        <button type="button" class="secondary" id="tour-back" ${state.tour === 0 ? "disabled" : ""}>${esc(t("tour.back"))}</button>
        ${step.run || step.revoke ? `<button type="button" class="primary" id="tour-run" ${state.busy ? "disabled" : ""}>${esc(t("tour.run"))}</button>` : ""}
        ${last ? `<button type="button" class="secondary" id="tour-restart">${esc(t("tour.restart"))}</button>`
               : `<button type="button" class="secondary" id="tour-next">${esc(t("tour.next"))}</button>`}
      </div>
      ${step.revoke ? revocationControls() : busyLine()}
      ${state.error && state.tab === "tour" ? `<p class="error">${esc(state.error)}</p>` : ""}
      <div class="dots">${dots}</div>
    </div>`;
}

function expectation(s) {
  if (s.expect.status === "refused") {
    return t("scenarios.expect.refused", { n: CHECKS.indexOf(s.expect.check) + 1 });
  }
  return t(`scenarios.expect.${s.expect.status}`);
}

function renderScenarios() {
  const groups = [];
  for (const s of state.scenarios) {
    let group = groups.find((g) => g.name === s.group);
    if (!group) { group = { name: s.group, items: [] }; groups.push(group); }
    group.items.push(s);
  }
  const revoked = state.status && state.status.credential === "revoked";
  $("#panel-scenarios").innerHTML = `<p class="hint">${esc(t("scenarios.intro"))}</p>` +
    groups.map((g) => `<div class="group"><h3>${esc(t(`group.${g.name}`))}</h3>
      ${g.name === "revocation" ? revocationControls() : ""}
      ${g.items.map((s) => {
        const waiting = s.needs === "revoked" && !revoked;
        return `<button type="button" class="scenario" data-id="${esc(s.id)}"
          aria-current="${state.current === s.id}" ${state.busy || waiting ? "disabled" : ""}>
          <div class="name">${esc(t(`scenario.${s.id}.title`))}</div>
          <div class="what">${esc(t(`scenario.${s.id}.what`))}</div>
          <div class="expect">${esc(waiting ? t("scenarios.needs.revoked") : expectation(s))}</div>
        </button>`;
      }).join("")}
    </div>`).join("");
}

function renderBuild() {
  const panel = $("#panel-build");
  const form = $("#build-form", panel);
  const chosen = form ? form.tool.value : "enroll_employee";
  const values = {};
  if (form) for (const el of form.elements) if (el.name) values[el.name] = el.value;
  const defaults = { person_ref: "EMP-0201", start_date: state.today, end_date: state.today, salary_grade: "3" };
  const fields = (state.tools[chosen] || []).map((field) => {
    const value = values[field] ?? defaults[field] ?? "";
    const type = field.endsWith("_date") ? "date" : field === "salary_grade" ? "number" : "text";
    const extra = type === "number" ? 'min="1" max="60" step="1"' : "";
    const error = state.fieldErrors[field];
    const id = esc(`f-${field}`);
    return `<div class="field${error ? " invalid" : ""}"><label for="${id}">${esc(t(`field.${field}`))}</label>
      <input id="${id}" name="${esc(field)}" type="${type}" value="${esc(value)}" ${extra}
        ${error ? `aria-invalid="true" aria-describedby="${id}-error"` : ""}>
      ${error ? `<span class="field-error" id="${id}-error">${esc(error)}</span>` : ""}
      ${field.endsWith("_date") ? `<span class="note">${esc(t("build.today", { today: state.today }))}</span>` : ""}
      ${field === "person_ref" ? `<span class="note">${esc(t("build.person"))}</span>` : ""}</div>`;
  }).join("");
  const toolOptions = Object.keys(state.tools).map((tool) =>
    `<option value="${esc(tool)}" ${tool === chosen ? "selected" : ""}>${esc(t(`tool.${tool}`))}</option>`).join("");
  const variant = values.variant || "none";
  const variantOptions = ["none", "strip", "replay", "tamper", "wrong_key"].map((v) =>
    `<option value="${v}" ${v === variant ? "selected" : ""}>${esc(t(`variant.${v}`))}</option>`).join("");
  panel.innerHTML = `<p class="hint">${esc(t("build.intro"))}</p>
    <form id="build-form" novalidate>
      <div class="field"><label for="f-tool">${esc(t("build.tool"))}</label>
        <select id="f-tool" name="tool">${toolOptions}</select></div>
      ${fields}
      <div class="field"><label for="f-variant">${esc(t("build.attack"))}</label>
        <select id="f-variant" name="variant">${variantOptions}</select></div>
      <button type="submit" class="primary" id="build-send" ${state.busy ? "disabled" : ""}>${esc(t("build.send"))}</button>
    </form>`;
}

function renderWho() {
  const s = state.status;
  if (!s) { $("#who").innerHTML = ""; return; }
  const id = s.identity;
  $("#who").innerHTML = `<h2>${esc(t("who.title"))}</h2>
    <dl>
      <dt>${esc(t("who.entity"))}</dt><dd>${esc(t("who.names.entity"))}</dd>
      <dt>${esc(t("who.lei"))}</dt><dd class="mono nowrap">${esc(id.lei)}</dd>
      ${id.ubn ? `<dt>${esc(t("who.ubn"))}</dt><dd class="mono nowrap">${esc(id.ubn)}</dd>` : ""}
      <dt>${esc(t("who.person"))}</dt><dd>${esc(t("who.names.person"))}</dd>
      <dt>${esc(t("who.role"))}</dt><dd class="mono">${esc(id.role)}</dd>
      <dt>${esc(t("who.agent"))}</dt><dd class="mono">${esc(id.agent)}</dd>
    </dl>
    <p class="note">${esc(t("who.note"))}</p>`;
}

function highlightJson(value, namespace, changedField) {
  const text = JSON.stringify(value, null, 2);
  return esc(text).replace(/(&quot;(?:[^&]|&(?!quot;))*?&quot;)(\s*:)?|\b(-?\d+(?:\.\d+)?)\b/g,
    (match, str, colon, num) => {
      if (str && colon) {
        const key = str.slice(6, -6);
        const ours = namespace && key.startsWith(`${namespace}/`);
        const changed = changedField && key === changedField;
        return `<span class="${ours ? "x" : "k"}${changed ? " changed" : ""}">${str}</span>${colon}`;
      }
      if (str) return `<span class="s">${str}</span>`;
      return `<span class="n">${num}</span>`;
    });
}

// The system's own error, in the visitor's language where the page knows it.
function systemError(text) {
  const notEnrolled = /^(EMP-\d{4}) is not enrolled by employer (\S+)/.exec(text || "");
  if (notEnrolled) return t("system.not_enrolled", { person: notEnrolled[1], ubn: notEnrolled[2] });
  return text;
}

function outcomeText(r) {
  const o = r.outcome;
  if (o.status === "self-asserted") {
    const m = r.measured || {};
    return m.live ? t("result.impersonation", m) : t("result.impersonation.none");
  }
  if (o.status === "unavailable") return t("outcome.unavailable.plain");
  if (o.status === "allowed") {
    if (!r.server) return t("outcome.allowed.policy");
    return r.server.ok ? t("outcome.allowed.plain") : t("outcome.allowed.refusedBySystem");
  }
  if (o.check) return has(`layer.${o.layer}`) ? t(`layer.${o.layer}`) : t("layer.unknown");
  return t("outcome.refused.noReport");
}

function renderResult() {
  const r = state.result;
  const namespace = state.status ? state.status.namespace : null;
  $("#tampered").hidden = !(r && r.tampered);
  if (r && r.tampered) $("#tampered").textContent = t("result.tampered", r.tampered);

  if (state.busy === "sending") {
    $("#request").innerHTML = `<span class="placeholder">${esc(t("result.sending"))}</span>`;
  } else if (r) {
    $("#request").innerHTML = highlightJson(r.request, namespace, r.tampered ? r.tampered.field : null);
  } else {
    $("#request").innerHTML = `<span class="placeholder">${esc(t("result.empty"))}</span>`;
  }

  const checks = r ? r.checks : CHECKS.map((id) => ({ id, status: "pending", ms: null, detail: null }));
  $("#checks").innerHTML = checks.map((c, i) => `<li data-check="${esc(c.id)}" data-state="${esc(c.status)}">
      <span class="mark">${c.status === "pass" ? "✓" : c.status === "fail" ? "✗" : "–"}</span>
      <span class="label">${i + 1}. ${esc(t(`check.${c.id}`))}</span>
      <span class="ms">${c.ms != null ? `${esc(c.ms)} ms` : esc(t(`check.state.${c.status}`))}</span>
      <span class="source">${esc(t(`check.${c.id}.source`))}</span>
      <span class="why">${esc(t(`check.${c.id}.why`))}</span>
    </li>`).join("");

  const out = $("#outcome");
  const colon = t("punct.colon");
  if (state.error && state.tab !== "tour") {
    out.dataset.status = "error";
    out.innerHTML = `<div class="plain">${esc(t("result.error"))}${colon}${esc(state.error)}</div>`;
  } else if (state.busy === "sending") {
    out.dataset.status = "sending";
    out.innerHTML = `<div class="word">${esc(t("result.sending"))}</div>`;
  } else if (r) {
    const o = r.outcome;
    // Verified, then refused by the system on a business rule: neither "allowed" nor a refusal.
    const business = o.status === "allowed" && r.server && !r.server.ok;
    out.dataset.status = business ? "business" : o.status;
    const at = o.check ? `<div class="at">${esc(t("outcome.at", { n: CHECKS.indexOf(o.check) + 1, check: t(`check.${o.check}`) }))}</div>` : "";
    let raw = "";
    if (o.detail && o.status !== "self-asserted") {
      const label = o.check ? t("result.verifier") : o.status === "unavailable" ? t("result.connection") : t("result.gateway");
      raw = `<div class="raw"><b>${esc(label)}${colon}</b>${o.layer ? `${esc(o.layer)} — ` : ""}${esc(o.detail)}</div>`;
    }
    const without = r.group === "attack" || (state.current && (state.scenarios.find((s) => s.id === state.current) || {}).group === "attack")
      ? `<div class="without">${esc(t("result.without"))}</div>` : "";
    out.innerHTML = `<div class="word">${esc(business ? t("outcome.business") : t(`outcome.${o.status}`))}</div>${at}<div class="plain">${esc(outcomeText(r))}</div>${raw}${o.status === "refused" ? without : ""}`;
  } else {
    out.dataset.status = "empty";
    out.innerHTML = `<div class="plain placeholder">${esc(t("result.empty"))}</div>`;
  }

  const server = $("#server");
  if (!r || r.target === "impersonation") { server.innerHTML = ""; return; }
  let heading = t("result.server");
  let body = "";
  if (r.outcome.status === "unavailable") { heading = t("result.server.unreachable"); }
  else if (r.outcome.status !== "allowed") { heading = t("result.server.notReceived"); body = `<p>${esc(t("result.server.blocked"))}</p>`; }
  else if (!r.server) { heading = t("result.server.notSent"); body = `<p>${esc(t("result.server.policy"))}</p>`; }
  else if (!r.server.ok) body = `<p>${esc(t("result.server.error"))} <b>${esc(systemError(r.server.text))}</b></p>`;
  else body = serverBody(r.server.body || {});
  server.innerHTML = `<h3>${esc(heading)}</h3>${body}`;
}

function filer(record) {
  const f = record && (record.withdrawnBy || record.adjustedBy || record.filedBy);
  return f ? `LEI ${esc(f.lei)} · ${esc(f.role)}<br><span class="aid">${esc(f.agentAid)}</span>` : "—";
}

// What the simulator answered, in words; the filer is the identity the gateway verified.
function serverBody(b) {
  const rec = b.record || {};
  if (b.action === "enrol" || b.action === "withdraw" || b.action === "adjust") {
    const key = { enrol: "result.server.enrol", withdraw: "result.server.withdraw", adjust: "result.server.adjust" }[b.action];
    const line = t(key, { person: rec.personRef, date: rec.endDate || rec.startDate, grade: rec.salaryGrade });
    return `<p>${esc(line)}${b.note ? ` ${esc(t("result.server.replaced"))}` : ""}</p>
      <dl><dt>${esc(t("result.server.filedBy"))}</dt><dd>${filer(rec)}</dd></dl>`;
  }
  if (Array.isArray(b.insured)) {
    const rows = b.insured.map((x) => `<tr><td class="nowrap">${esc(x.personRef)}</td><td class="nowrap">${esc(t(`record.${x.status}`))}</td><td>${filer(x)}</td></tr>`).join("");
    const count = b.insured.length;
    return `<p>${esc(t(count === 1 ? "result.server.list.one" : "result.server.list", { count }))}</p>
      <table class="records"><thead><tr><th>${esc(t("result.server.person"))}</th><th>${esc(t("result.server.status"))}</th><th>${esc(t("result.server.filedBy"))}</th></tr></thead>
      <tbody>${rows}</tbody></table>`;
  }
  return `<pre class="json">${esc(JSON.stringify(b, null, 2))}</pre>`;
}

function renderLog() {
  const rows = state.log.slice(0, LOG_SHOWN).map((e) => {
    const what = e.scenario ? t(`scenario.${e.scenario}.title`) : `${t(`tool.${e.tool}`)}${e.variant !== "none" ? ` · ${t(`variant.${e.variant}`)}` : ""}`;
    const why = e.layer && has(`layer.short.${e.layer}`) ? t(`layer.short.${e.layer}`) : e.layer;
    const result = `${e.systemRefused ? t("outcome.business") : t(`outcome.${e.status}`)}${e.check ? ` · ${CHECKS.indexOf(e.check) + 1}. ${why}` : why ? ` · ${why}` : ""}`;
    return `<tr><td class="mono">${esc(e.time)}</td><td>${esc(what)}</td><td class="${esc(e.systemRefused ? "business" : e.status)}">${esc(result)}</td>
      <td class="mono">${e.lei ? `${esc(e.lei)} · ${esc(e.role)}` : esc(t("log.unverified"))}</td></tr>`;
  }).join("");
  const more = state.log.length > LOG_SHOWN
    ? `<tr><td colspan="4" class="more">${esc(t("log.more", { n: LOG_SHOWN }))}</td></tr>` : "";
  $("#log tbody").innerHTML = (rows + more) || `<tr><td colspan="4">${esc(t("log.empty"))}</td></tr>`;
}

// Show the checks in the order they ran. The result is already final; this only lets the eye follow.
function revealChecks() {
  const items = [...document.querySelectorAll("#checks li")];
  items.forEach((li) => { li.style.visibility = "hidden"; });
  items.forEach((li, i) => setTimeout(() => { li.style.visibility = "visible"; }, 70 * (i + 1)));
  setTimeout(() => document.body.classList.add("revealed"), 70 * (items.length + 1));
}

// ------------------------------------------------------------------------------------- events

document.addEventListener("click", (event) => {
  const target = event.target.closest("button");
  if (!target || target.disabled) return;
  if (target.dataset.lang) {
    state.lang = target.dataset.lang; remember("vlei-app-lang", state.lang); render();
  } else if (target.dataset.tab) {
    state.tab = target.dataset.tab; state.error = null; remember("vlei-app-tab", state.tab); render();
  } else if (target.classList.contains("scenario")) {
    runScenario(target.dataset.id);
  } else if (target.id === "revoke") {
    revoke();
  } else if (target.id === "reissue") {
    reissue();
  } else if (target.id === "tour-run") {
    runTourStep();
  } else if (target.id === "tour-next") {
    state.tour = Math.min(TOUR.length - 1, state.tour + 1); state.error = null; render();
  } else if (target.id === "tour-back") {
    state.tour = Math.max(0, state.tour - 1); state.error = null; render();
  } else if (target.id === "tour-restart") {
    state.tour = 0; state.error = null; state.result = null; render();
  }
});

document.addEventListener("change", (event) => {
  if (event.target.name === "tool") { state.fieldErrors = {}; renderBuild(); }
});

document.addEventListener("submit", (event) => {
  if (event.target.id === "build-form") { event.preventDefault(); sendBuilt(); }
});

async function start() {
  const params = new URLSearchParams(location.search);
  const lang = params.get("lang") || recall("vlei-app-lang");
  if (lang === "zh" || lang === "en") state.lang = lang;
  const tab = params.get("tab") || recall("vlei-app-tab");
  if (["tour", "scenarios", "build"].includes(tab)) state.tab = tab;
  state.strings = await (await fetch("/app/i18n.json")).json();
  const listing = await api("/api/scenarios");
  state.scenarios = listing.scenarios; state.tools = listing.tools; state.today = listing.today;
  state.status = await api("/api/status");
  await refreshLog();
  render();
  // Another visitor, or the presenter, may revoke or re-issue: the header follows.
  setInterval(async () => { if (!state.busy) { await refreshStatus(); renderStatus(); renderScenarios(); } }, STATUS_EVERY_MS);
}

start().catch((err) => {
  document.body.insertAdjacentHTML("afterbegin", `<p class="error">${esc(err.message)}</p>`);
});
