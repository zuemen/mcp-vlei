/*
  MCP × vLEI — the story (/story).

  One scenario, chosen at the top, followed by three views:
    1 issuer   the legal entity's role credential and the chain that authorizes the AI agent
    2 gateway  the scenario's real tools/call: the eight checks as they ran, and the gateway's reads
    3 outcome  what the user's AI assistant says, and what the labour-insurance system shows

  ▶ Play walks the three views for the chosen scenario. Every call is real (/api/call through the
  gateway); the checks are vlei-authz's report; the log is read from its decision log
  (/api/evidence); revoking and re-issuing act on the real credential. Results are kept per
  scenario, so switching back shows what that scenario did.
*/
"use strict";

const ORDER = ["enroll-today", "list-insured", "salary-by-filer", "enroll-15-days", "no-credential",
               "tampered", "replayed", "wrong-key", "after-revocation"];
const CHECKS = ["credential_present", "freshness", "digest", "signature", "delegation", "chain",
                "revocation", "authority"];
const FIELDS = ["credential", "credentialSaid", "delegatedAid", "signature"];
const HOP_MS = 480, CHECK_MS = 280, LINE_MS = 110, DWELL_MS = 2200;

const state = { lang: "zh", strings: {}, view: "issuer", status: null, scenarios: {}, selected: "enroll-today",
                results: {}, busy: false, message: "", runId: 0,
                mode: "live", seen: new Set(), firstLoad: true, impAt: 0, liveData: null, replay: null,
                agent: { available: true, busy: false, runs: [] },
                since: Number(recall("vlei-story-since")) || 0 };

const $ = (sel, root = document) => root.querySelector(sel);
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => (
  { "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" }[c]));
function t(key, vars = {}) {
  const table = state.strings[state.lang] || {};
  let text = table[key] ?? (state.strings.en || {})[key] ?? key;
  for (const [name, value] of Object.entries(vars)) text = text.split(`{${name}}`).join(String(value));
  return text;
}
const short = (v) => { const s = String(v || ""); return s.length > 16 ? `${s.slice(0, 6)}…${s.slice(-4)}` : s; };
const idh = (v) => `<span class="id" title="${esc(v)}">${esc(short(v))}</span>`;
function remember(k, v) { try { localStorage.setItem(k, v); } catch (_) { /* not kept */ } }
function recall(k) { try { return localStorage.getItem(k); } catch (_) { return null; } }

async function api(path, options = {}) {
  const response = await fetch(path, { headers: { "Content-Type": "application/json" }, cache: "no-store", ...options });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || `HTTP ${response.status}`);
  return body;
}

const identity = () => (state.status && state.status.identity) || {};
const revoked = () => !!state.status && state.status.credential === "revoked";
const layerName = (layer) => (layer && state.strings[state.lang] && state.strings[state.lang][`layer.short.${layer}`])
  ? `${t(`layer.short.${layer}`)}（${layer}）` : (layer || "refused");

/* ---------------------------------------------------------------------------------------- */
/* the scenario bar and the steps                                                            */

function renderHeader() {
  const s = state.status;
  if (!s) return;
  const cred = `${t("status.credential")}${t("punct.colon")}${t(revoked() ? "status.revoked" : "status.issued")}`;
  const gw = s.gatewayReachable ? t("status.target.gateway") : t("status.gateway.down");
  $("#status").innerHTML = `<span class="${revoked() ? "down" : ""}">${esc(t("st.status", { cred, gw }))}</span>`;
}

function renderPick() {
  $("#chips").innerHTML = ORDER.filter((id) => state.scenarios[id]).map((id) => {
    const s = state.scenarios[id];
    return `<button type="button" class="chip" role="radio" data-pick="${id}" data-group="${esc(s.group)}"
      aria-checked="${String(id === state.selected)}" ${state.busy ? "disabled" : ""}>${esc(t(`scenario.${id}.title`))}${
      state.results[id] ? ` <span class="ran">${esc(t("st.ran"))}</span>` : ""}</button>`;
  }).join("");
  $("#what").textContent = t(`scenario.${state.selected}.what`);
  $("#play").disabled = state.busy;
}

function renderStepper() {
  for (const b of document.querySelectorAll("#stepper button")) {
    if (b.dataset.view === state.view) b.setAttribute("aria-current", "step"); else b.removeAttribute("aria-current");
  }
}

function show(view) {
  state.view = view;
  for (const name of ["issuer", "gateway", "outcome"]) $(`#view-${name}`).hidden = name !== view;
  renderStepper();
  const url = new URL(location.href); url.searchParams.set("view", view); url.searchParams.set("scenario", state.selected);
  history.replaceState(null, "", url);
  if (view === "issuer") renderIssuer();
  if (view === "gateway" && !state.busy) renderGatewayFromResult();
  if (view === "outcome") renderOutcome();
}

/* ---------------------------------------------------------------------------------------- */
/* 1 issuer                                                                                  */

function renderIssuer() {
  const id = identity();
  const rows = [
    ["st.iss.entity", t("who.names.entity")], ["st.iss.lei", id.lei], ["st.iss.ubn", id.ubn],
    ["st.iss.country", "TW"], ["st.iss.person", t("who.names.person")], ["st.iss.role", id.role],
    ["st.iss.agent", id.agent, true],
  ];
  $("#fields").innerHTML = rows.map(([k, v, wide]) => `<div class="${wide ? "wide" : ""}"><dt>${esc(t(k))}</dt>
      <dd class="${wide ? "id" : ""}">${esc(v || "—")}</dd></div>`).join("");

  const card = $("#vcard");
  card.dataset.state = revoked() ? "revoked" : "issued";
  card.dataset.stamp = state.lang === "zh" ? "已撤銷" : "REVOKED";
  $("#card-name").textContent = t("who.names.entity");
  $("#card-lei").textContent = id.lei || "";
  $("#card-grid").innerHTML = [["UBN", id.ubn], ["COUNTRY", "TW"], ["ROLE", id.role]]
    .map(([k, v]) => `<div><span>${k}</span><b>${esc(v || "—")}</b></div>`).join("");
  $("#card-status").textContent = revoked() ? t("st.iss.revokedState") : t("st.card.verifiable");

  const chain = [
    ["st.chain.root", t("st.chain.root.sub")], ["st.chain.qvi", t("st.chain.qvi.sub")],
    ["st.chain.le", t("who.names.entity")], ["st.chain.ecr", `${t("who.names.person")} · ${t("st.chain.ecr.sub")}`],
    ["st.chain.agent", `${t("st.chain.agent.sub")} · ${short(id.agent)}`],
  ];
  $("#chain").innerHTML = chain.map(([k, sub], i) => `<li class="${i === chain.length - 1 ? "agent" : ""}">
      <span class="cw"><b>${esc(t(k))}</b><span>${esc(sub)}</span></span></li>`).join("");

  const callout = $("#iss-callout");
  const note = state.selected === "after-revocation" && !revoked() ? t("st.needRevoke")
    : revoked() && state.selected !== "after-revocation" ? t("st.revokedNote") : "";
  callout.hidden = !note; callout.textContent = note;

  const busy = state.busy ? "disabled" : "";
  $("#iss-actions").innerHTML = revoked()
    ? `<button class="btn primary" data-act="reissue" ${busy}>${esc(t("st.iss.reissue"))}</button>`
    : `<button class="btn danger" data-act="revoke" ${busy}>${esc(t("st.iss.revoke"))}</button>`;
  $("#iss-msg").textContent = state.message;
}

async function revoke() {
  state.busy = true; state.message = t("st.iss.revoking"); renderAll();
  try { await api("/api/revoke", { method: "POST", body: "{}" }); state.status = await api("/api/status"); state.message = t("st.iss.revokedState"); }
  catch (err) { state.message = t("st.error", { message: err.message }); }
  state.busy = false; renderAll();
}

async function reissue() {
  state.busy = true; state.message = t("st.iss.reissuing"); renderAll();
  $("#vcard").classList.add("minting");
  try { await api("/api/reissue", { method: "POST", body: "{}" }); state.status = await api("/api/status"); state.message = t("st.iss.active"); }
  catch (err) { state.message = t("st.error", { message: err.message }); }
  $("#vcard").classList.remove("minting");
  state.busy = false; renderAll();
}

/* ---------------------------------------------------------------------------------------- */
/* 2 gateway                                                                                 */

const NODES = [["agent", "AI"], ["mcp", "{ }"], ["gateway", "GW"], ["authz", "8"], ["system", "勞"]];

function nodeHtml(key, glyph) {
  return `<div class="node" data-node="${key}"><span class="glyph">${esc(glyph)}</span>
      <span><b>${esc(t(`st.node.${key}`))}</b><span class="nsub">${esc(t(`st.node.${key}.sub`))}</span></span></div>`;
}

function renderFlow() {
  $("#flow").innerHTML = NODES.map(([key, glyph], i) => {
    const link = i ? '<div class="link"></div>' : "";
    if (key !== "authz") return link + nodeHtml(key, glyph);
    return `${link}<div class="pair">${nodeHtml(key, glyph)}<span class="wire"></span>${nodeHtml("witness", "W")}</div>`;
  }).join("") + '<span class="packet" id="packet"></span>';
}

function movePacket(key, refused = false) {
  const node = $(`[data-node="${key}"]`), packet = $("#packet");
  if (!node || !packet) return;
  const box = node.getBoundingClientRect(), flow = $("#flow").getBoundingClientRect();
  packet.style.top = `${box.top - flow.top + box.height / 2 - 7}px`;
  packet.classList.add("on");
  packet.classList.toggle("refused", refused);
}

function lit(key, cls) {
  const node = $(`[data-node="${key}"]`);
  if (node) { node.classList.remove("lit", "stop", "dark"); if (cls) node.classList.add(cls); }
}

function renderSteps(states = {}, ms = {}) {
  $("#steps").innerHTML = CHECKS.map((name, i) => {
    const s = states[name] || "wait";
    const label = s === "pass" ? t("st.state.pass") : s === "fail" ? t("st.state.fail") : s === "skip" ? t("st.state.skip") : "";
    return `<li data-s="${s}"><span class="n">${s === "pass" ? "✓" : s === "fail" ? "✗" : String(i + 1).padStart(2, "0")}</span>
      <span>${esc(t(`check.${name}`))}${label ? ` · ${esc(label)}` : ""}</span>
      <span class="ms">${ms[name] != null && s !== "skip" ? `${Number(ms[name]).toFixed(1)} ms` : ""}</span></li>`;
  }).join("");
}

function describeCall(record) {
  const sub = $('[data-node="mcp"] .nsub');
  if (!sub || !record) return;
  const present = FIELDS.filter((f) => (record.metaKeys || []).some((k) => k.endsWith(`/${f}`)));
  sub.textContent = present.length ? t("st.node.mcp.carried", { fields: present.join(" · ") }) : t("st.node.mcp.bare");
  sub.classList.toggle("bad", !present.length);
}

function finalNodes(r) {
  for (const key of ["agent", "mcp", "gateway", "authz"]) lit(key, "lit");
  if (r.witnessRead) lit("witness", "lit");
  if (r.allowed) { lit("system", "lit"); movePacket("system"); }
  else { lit("authz", "stop"); lit("system", "dark"); movePacket("authz", true); }
  describeCall(r.evidence);
}

/* The chosen scenario's last run, drawn without replaying it — or an invitation to run it. */
function renderGatewayFromResult() {
  renderFlow();
  const r = state.results[state.selected];
  if (!r) {
    renderSteps();
    $("#term").innerHTML = `<span class="idle">${esc(t("st.notRun"))}</span>`;
    $("#gw-actions").innerHTML = `<button class="btn" data-act="runStep">${esc(t("st.runStep"))}</button>`;
    return;
  }
  renderSteps(r.states, r.ms);
  $("#term").innerHTML = r.logHtml;
  finalNodes(r);
  $("#gw-actions").innerHTML = `<button class="btn" data-act="runStep">${esc(t("st.runStep"))}</button>
    <button class="btn primary next" data-go="outcome">${esc(t("st.gw.next"))}</button>`;
}

function line(html, cls = "") {
  const term = $("#term");
  const stamp = new Date().toLocaleTimeString(state.lang === "zh" ? "zh-TW" : "en-GB", { hour12: false });
  term.insertAdjacentHTML("beforeend", `<span class="line ${cls}"><span class="t">[${stamp}]</span> ${html}</span>`);
  term.scrollTop = term.scrollHeight;
}

async function runGateway(id) {
  const scenario = state.scenarios[id];
  const run = ++state.runId;
  renderFlow(); renderSteps(); $("#term").innerHTML = ""; $("#gw-actions").innerHTML = "";
  const started = Date.now();
  const call = api("/api/call", { method: "POST", body: JSON.stringify({
    scenario: id, tool: scenario.tool, arguments: scenario.arguments, variant: scenario.variant }) })
    .then((r) => ({ ok: true, r }), (e) => ({ ok: false, e }));

  for (const key of ["agent", "mcp", "gateway", "authz"]) { movePacket(key); lit(key, "lit"); await sleep(HOP_MS); }
  const answer = await call;
  if (run !== state.runId) return;
  if (!answer.ok) { line(`<span class="bad">${esc(t("st.error", { message: answer.e.message }))}</span>`); return; }
  const result = answer.r;

  const states = {}, ms = {};
  const byId = Object.fromEntries((result.checks || []).map((c) => [c.id, c]));
  let failed = false, witnessRead = false;
  for (const name of CHECKS) {
    const c = byId[name] || {};
    if (failed || !["pass", "fail"].includes(c.status)) { states[name] = "skip"; continue; }
    states[name] = "run"; renderSteps(states, ms);
    if (["signature", "delegation", "chain", "revocation"].includes(name)) { lit("witness", "lit"); witnessRead = true; }
    await sleep(CHECK_MS);
    states[name] = c.status; ms[name] = c.ms;
    if (c.status === "fail") failed = true;
    renderSteps(states, ms);
  }
  renderSteps(states, ms);
  const allowed = result.outcome && result.outcome.status === "allowed";
  if (allowed) { movePacket("system"); await sleep(HOP_MS); lit("system", "lit"); }
  else { movePacket("authz", true); lit("authz", "stop"); lit("system", "dark"); }

  const evidence = await findEvidence(result.tool, started);
  describeCall(evidence);
  await streamLog(result, evidence);
  state.results[id] = { result, evidence, states, ms, allowed, witnessRead, logHtml: $("#term").innerHTML,
                        arguments: scenario.arguments };
  $("#gw-actions").innerHTML = `<button class="btn" data-act="runStep">${esc(t("st.runStep"))}</button>
    <button class="btn primary next" data-go="outcome">${esc(t("st.gw.next"))}</button>`;
}

async function findEvidence(tool, started) {
  for (let i = 0; i < 6; i += 1) {
    try {
      const data = await api("/api/evidence?limit=5");
      const rec = (data.records || []).find((r) => r.tool === tool && Date.parse(r.at) >= started - 3000);
      if (rec) return rec;
    } catch (_) { /* the log is optional to the story */ }
    await sleep(250);
  }
  return null;
}

function kelRole(aid, result, record) {
  const v = result.verified || {}, c = result.caller || {};
  if (aid && (aid === v.delegateAid || aid === c.agent)) return t("ev.role.agent");
  if (aid && (aid === v.holderAid || aid === c.holder)) return t("ev.role.holder");
  const read = (record.witnessReads || []).find((r) => r.aid === aid);
  const cred = (record.schemas || []).find((s) => (read?.anchors || []).some(([i, sn]) => i === s.said && sn === "0"));
  return cred ? t("ev.role.issuer", { type: cred.type || "credential" }) : t("ev.role.other");
}

async function streamLog(result, record) {
  const say = async (html) => { line(html); await sleep(LINE_MS); };
  const c = result.caller || {};
  await say(`<span class="k">MCP </span>${t("st.log.call", { tool: esc(result.tool), agent: idh(c.agent) })}`);
  if (record) {
    const present = FIELDS.filter((f) => (record.metaKeys || []).some((k) => k.endsWith(`/${f}`)));
    await say(`<span class="k">GATE</span> ${present.length ? esc(t("st.log.fields", { fields: present.join(" · ") }))
      : `<span class="bad">${esc(t("st.log.nofields"))}</span>`}`);
  }
  for (const [i, ch] of (result.checks || []).entries()) {
    if (ch.status !== "pass" && ch.status !== "fail") continue;
    const word = ch.status === "pass" ? `<span class="good">${esc(t("st.state.pass"))}</span>` : `<span class="bad">${esc(t("st.state.fail"))}</span>`;
    await say(`<span class="k">AUTH</span> ${t("st.log.check", { n: i + 1, name: esc(t(`check.${ch.id}`)), result: word, ms: Number(ch.ms || 0).toFixed(1) })}`);
  }
  if (record) {
    const groups = new Map();
    for (const read of record.witnessReads || []) {
      if (read.typ !== "kel") continue;
      const g = groups.get(read.aid) || { aid: read.aid, w: new Set(), e: 0, anchors: [] };
      g.w.add(read.witness); g.e = Math.max(g.e, read.events || 0); g.anchors.push(...(read.anchors || []));
      groups.set(read.aid, g);
    }
    for (const g of groups.values()) {
      await say(`<span class="k">WITN</span> ${t("st.log.kel", { role: esc(kelRole(g.aid, result, record)), aid: idh(g.aid), w: g.w.size, e: g.e })}`);
    }
    const anchors = [...groups.values()].flatMap((g) => g.anchors);
    for (const s of record.schemas || []) {
      const isRevoked = anchors.some(([i, sn]) => i === s.said && sn === "1");
      const isIssued = anchors.some(([i, sn]) => i === s.said && sn === "0");
      if (isRevoked || isIssued) {
        await say(`<span class="k">TEL </span>${t("st.log.anchor", { type: esc(s.type || "?"), said: idh(s.said),
          state: isRevoked ? `<span class="bad">${esc(t("st.log.revokedRec"))}</span>` : `<span class="good">${esc(t("st.log.issued"))}</span>` })}`);
      }
      await say(`<span class="k">SCHM</span> ${t("st.log.schema", { type: esc(s.type || "?"), said: idh(s.schema),
        verdict: s.official ? `<span class="good">${esc(t("st.log.official"))}</span>` : `<span class="bad">${esc(t("st.log.unofficial"))}</span>` })}`);
    }
  }
  const v = result.verified || {};
  if (result.outcome && result.outcome.status === "allowed") {
    await say(`<span class="good">${esc(t("st.log.allow", { lei: v.lei || c.lei, role: v.role || c.role }))}</span>`);
    const rec = result.server && result.server.body && result.server.body.record;
    if (rec) await say(`<span class="good">${esc(t("st.log.filed", { person: rec.personRef, date: rec.startDate, grade: rec.salaryGrade }))}</span>`);
    else if (result.server && result.server.text) await say(esc(t("st.log.system", { text: result.server.text })));
  } else {
    const layer = (result.outcome && (result.outcome.layer || result.outcome.check)) || "refused";
    await say(`<span class="bad">${esc(t("st.log.deny", { layer }))}</span>`);
  }
}

/* ---------------------------------------------------------------------------------------- */
/* 3 outcome                                                                                 */

/* Which of four things happened: allowed; identity not established; revoked; verified but not
   authorized. The two sides show the same one. */
function kind(r) {
  if (r.allowed) return "allowed";
  const layer = (r.result.outcome && r.result.outcome.layer) || "";
  if (layer === "revoked") return "revoked";
  if (layer === "role_mismatch" || layer === "scope_exceeded") return "notAuthorized";
  return "unknown";
}

function askText(tool, args) {
  if (tool === "enroll_employee") return t("st.ask.enroll", { person: args.person_ref, date: args.start_date, grade: args.salary_grade });
  if (tool === "adjust_insured_salary") return t("st.ask.adjust", { person: args.person_ref, grade: args.salary_grade });
  if (tool === "withdraw_employee") return t("st.ask.withdraw", { person: args.person_ref, date: args.end_date });
  return t("st.ask.list");
}

function renderOutcome() {
  const chrome = (title) => `<div class="chrome"><i></i><i></i><i></i><b>${esc(title)}</b></div>`;
  const r = state.results[state.selected];
  const sys = $("#dev-system");
  if (!r) {
    $("#dev-chat").innerHTML = chrome(t("st.out.chat")) + `<p class="empty">${esc(t("st.notRun"))}</p>`;
    sys.className = "device system";
    sys.innerHTML = chrome(t("st.out.sys")) + `<p class="empty">${esc(t("st.notRun"))}</p>`;
    return;
  }
  const result = r.result, args = r.arguments || {};
  const k = kind(r);
  const layer = (result.outcome && (result.outcome.layer || result.outcome.check)) || "refused";
  const body = (result.server && result.server.body) || {};
  const rec = body.record;
  const insured = Array.isArray(body.insured) ? body.insured : null;
  let reply;
  if (k === "allowed") {
    reply = rec ? t("st.out.ai.ok", { person: rec.personRef, date: rec.startDate, grade: rec.salaryGrade })
      : insured ? t("st.ai.list", { n: insured.length }) : t("st.ai.done");
  } else if (k === "revoked") reply = t("st.ai.revoked");
  else if (k === "notAuthorized") reply = t("st.ai.notAuthorized", { layer: layerName(layer) });
  else reply = t("st.out.ai.no", { layer: layerName(layer) });
  $("#dev-chat").innerHTML = chrome(t("st.out.chat")) + `<div class="body">
      <div class="bubble user">${esc(askText(result.tool, args))}</div>
      <div class="bubble ai ${k === "allowed" ? "ok" : "no"}">${esc(reply)}<span class="tool">tools/call ${esc(result.tool)} → ${
        k === "allowed" ? "allowed" : `refused · ${esc(layer)}`}</span></div></div>`;

  const v = result.verified || {}, c = result.caller || {};
  const filer = `<div class="wide"><span>${esc(t("st.out.filer"))}</span><b class="big">${esc(t("who.names.entity"))}</b></div>
        <div><span>LEI</span><b class="id">${esc(v.lei || c.lei)}</b></div>
        <div><span>${esc(t("st.iss.ubn"))}</span><b class="id">${esc(c.ubn || "")}</b></div>
        <div><span>${esc(t("st.iss.person"))}</span><b>${esc(t("who.names.person"))}</b></div>
        <div><span>${esc(t("st.out.via"))}</span><b>${t("st.out.via.agent", { agent: idh(v.delegateAid || c.agent) })}</b></div>`;
  sys.className = `device system ${k === "allowed" ? "ok" : "no"}`;
  if (k === "allowed") {
    const detail = rec ? `<div><span>${esc(t("st.out.employee"))}</span><b class="id">${esc(rec.personRef)}</b></div>
        <div><span>${esc(t("st.out.from"))}</span><b class="id">${esc(rec.startDate)}</b></div>
        <div><span>${esc(t("st.out.grade"))}</span><b class="id">${esc(rec.salaryGrade)}</b></div>` : "";
    const rows = insured ? `<div class="wide"><span>${esc(t("st.out.count"))}</span><div class="rows">${insured.slice(0, 6).map((x) =>
        `<div><span class="id">${esc(x.personRef)}</span><span class="id">${esc(x.startDate)}</span><span>${esc(x.status || "")}</span></div>`).join("")}</div></div>` : "";
    sys.innerHTML = chrome(t("st.out.sys")) + `<div class="body"><span class="verdict ok">✓ ${esc(t("st.out.verified"))}</span>
      <div class="record">${filer}${detail}${rows}</div></div>`;
  } else if (k === "notAuthorized" || k === "revoked") {
    sys.innerHTML = chrome(t("st.out.sys")) + `<div class="body"><span class="verdict no">✗ ${esc(t(k === "revoked" ? "st.out.revoked" : "st.out.notAuthorized"))}</span>
      <div class="record">${filer}<div class="wide"><span>${esc(t("st.out.whyNot", { layer: "" }))}</span><b>${esc(layerName(layer))}</b></div></div></div>`;
  } else {
    sys.innerHTML = chrome(t("st.out.sys")) + `<div class="body"><span class="verdict no">✗ ${esc(t("st.out.unverified"))}</span>
      <div class="unknown"><div class="q">?</div><b>${esc(t("st.out.unknown"))}</b>
        <p>${esc(t("st.out.nothing", { layer: layerName(layer) }))}</p></div></div>`;
  }
}

/* ---------------------------------------------------------------------------------------- */
/* the real Claude: the same request, before and after                                       */

function when(at) {
  const date = new Date(at);
  if (Number.isNaN(date.getTime())) return esc(at || "");
  return date.toLocaleTimeString(state.lang === "zh" ? "zh-TW" : "en-GB", { hour12: false });
}
const ACTION_TOOL = { enrol: "enroll_employee", withdraw: "withdraw_employee", adjust: "adjust_insured_salary" };
const isScript = (declared) => String(declared || "").startsWith("trust-console");

/* Who sent it, by the name the client gave itself: a label, never evidence. */
function sourceOf(declared, via) {
  const n = String(declared || "").toLowerCase();
  if (n.startsWith("anthropic/toolbox")) return t("st.src.claudeai");
  if (n.startsWith("claude-ai") || n.includes("claude desktop")) return t("st.src.desktop");
  if (n.startsWith("claude-code") || n.includes("claude code")) return t("st.src.code");
  if (isScript(declared)) return t("st.src.script");
  return declared || t(via === "public" ? "st.src.public" : "st.src.local");
}

function fresh(key) {
  const isNew = !state.firstLoad && !state.seen.has(key);
  state.seen.add(key);
  return isNew ? "fresh" : "";
}

function renderBefore(data) {
  const feed = $("#before-feed");
  if (!data || !data.reachable) { feed.innerHTML = `<li class="empty">${esc(t("st.before.down"))}</li>`; return; }
  const filings = (data.filings || []).filter((f) => Date.parse(f.at) >= state.since).slice().reverse();
  if (!filings.length) { feed.innerHTML = `<li class="empty">${esc(t("st.before.empty"))}</li>`; return; }
  feed.innerHTML = filings.map((f) => {
    const impostor = f.personRef === data.impostor;
    const declared = (f.filedBy || {}).declaredClient || "?";
    const tool = ACTION_TOOL[f.action] || "enroll_employee";
    return `<li class="entry ${fresh(`b|${f.at}|${f.personRef}`)} ${impostor ? "impostor" : ""}">
      <div class="row1"><span class="time">${when(f.at)}</span><b>${esc(t(`st.tool.${tool}`))} ${esc(f.personRef)}</b>
        <span>${esc(f.startDate || "")}${f.salaryGrade ? ` · ${esc(t("st.out.grade"))} ${esc(f.salaryGrade)}` : ""}</span>
        ${impostor ? `<span class="tag">${esc(t("st.before.impostor"))}</span>` : ""}</div>
      <div class="declared">${esc(t("st.who.declared", { name: declared }))}</div>
      <div class="knows">${esc(t("st.before.knows"))}</div></li>`;
  }).join("");
}

function renderAfter(records) {
  const feed = $("#after-feed");
  const only = $("#only-claude").checked;
  const id = identity();
  const rows = records.filter((r) => r.tool && Date.parse(r.at) >= state.since && (!only || !isScript(r.declaredClient)));
  if (!rows.length) { feed.innerHTML = `<li class="empty">${esc(t("st.after.empty"))}</li>`; return; }
  feed.innerHTML = rows.map((r) => {
    const allowed = r.decision === "allow";
    const rid = (r.report || {}).identity || {};
    const lei = r.lei || rid.lei;
    const ours = lei && lei === id.lei;
    const impostor = !allowed && state.impAt && Math.abs(Date.parse(r.at) - state.impAt) < 8000 && r.layer === "missing_credential";
    const verdict = allowed
      ? `<div class="ok">✓ ${esc(t("st.after.verified", { entity: ours ? t("who.names.entity") : lei, lei, role: r.role || rid.role,
          person: ours ? t("who.names.person") : "—", agent: short(r.delegateAid || rid.delegateAid) }))}</div>`
      : `<div class="no">✗ ${esc(t("st.after.refused", { layer: layerName(r.layer || "refused") }))}</div>`;
    return `<li class="entry ${fresh(`a|${r.at}|${r.tool}`)} ${impostor ? "impostor" : ""}">
      <div class="row1"><span class="time">${when(r.at)}</span><b>${esc(t(`st.tool.${r.tool}`))}</b>
        <span class="src">${r.declaredClient ? `${esc(sourceOf(r.declaredClient, r.via))} · ` : ""}${esc(t(r.via === "public" ? "st.src.public" : "st.src.local"))}</span>
        ${impostor ? `<span class="tag">${esc(t("st.before.impostor"))}</span>` : ""}</div>
      ${r.declaredClient ? `<div class="declared">${esc(t("st.who.declared", { name: r.declaredClient }))}</div>` : ""}
      ${verdict}</li>`;
  }).join("");
}

async function refreshLive() {
  const [before, evidence] = await Promise.all([
    api("/api/before/ledger").catch(() => ({ reachable: false, filings: [] })),
    api("/api/evidence?limit=30").catch(() => ({ records: [] })),
  ]);
  state.liveData = { before, records: evidence.records || [] };
  renderBefore(before);
  renderAfter(state.liveData.records);
  await refreshAgent();
  state.firstLoad = false;
}

/* ---------------------------------------------------------------------------------------- */
/* a real Claude agent: Claude Code on this machine, given one connection (examples/console/agent.py) */

/* Claude's words, with its `code` and **bold**; everything else as text. */
function claudeText(text) {
  return esc(text).replace(/`([^`]+)`/g, "<code>$1</code>").replace(/\*\*([^*]+)\*\*/g, "<b>$1</b>")
    .replace(/\n{2,}/g, "</p><p>").replace(/\n/g, "<br>");
}

function argsText(args) {
  return Object.entries(args || {}).map(([k, v]) => `${k}: ${typeof v === "string" ? v : JSON.stringify(v)}`).join(", ");
}

/* What the system recorded as the filer: the before half has only a self-given name. */
function filedBy(result) {
  let body;
  try { body = JSON.parse(result); } catch (_) { return ""; }
  const by = body && body.record && body.record.filedBy;
  if (!by) return "";
  if (by.lei) {
    const id = identity();
    const entity = by.lei === id.lei ? t("who.names.entity") : `LEI ${by.lei}`;
    return `<div class="filed">${esc(t("st.agent.filed.verified", { entity, lei: by.lei, role: by.role || "—" }))}</div>`;
  }
  return `<div class="filed unverified">${esc(t("st.agent.filed.declared", { name: by.declaredClient || "?" }))}</div>`;
}

function renderChat(side, run) {
  const box = $(`#chat-${side}`);
  if (!box) return;
  const hint = !state.agent.available ? "st.agent.unavailable" : !run ? "st.agent.idle" : null;
  if (hint) { box.innerHTML = `<p class="ag-hint">${esc(t(hint))}</p>`; box.dataset.html = ""; box.dataset.run = ""; return; }
  const parts = [`<div class="ag-turn you"><span class="ag-who">${esc(t("st.agent.you"))}</span><p>${esc(run.prompt)}</p></div>`];
  for (const e of run.events || []) {
    if (e.kind === "call") {
      const res = e.status === "running" ? `<div class="ag-working">${esc(t("st.agent.waiting"))}</div>`
        : e.status === "done" ? `<div class="res">✓ ${esc(t("st.agent.ok"))}</div>${filedBy(e.result)}`
        : `<div class="res">✗ ${esc(String(e.result || "").split("\n")[0])}</div>`;
      parts.push(`<div class="ag-turn call ${esc(e.status)}"><span class="ag-who">${esc(t("st.agent.calls", { server: e.server }))}</span>
        <code>${esc(e.tool)}(${esc(argsText(e.arguments))})</code>${res}</div>`);
    } else if (e.kind === "say") {
      parts.push(`<div class="ag-turn claude"><span class="ag-who">${esc(t("st.agent.says"))}</span><p>${claudeText(e.text)}</p></div>`);
    }
  }
  if (run.status === "running" && !(run.events || []).some((e) => e.kind === "call" && e.status === "running")) {
    parts.push(`<div class="ag-working">${esc(t(run.events && run.events.length ? "st.agent.thinking" : "st.agent.starting", { server: run.server }))}</div>`);
  }
  if (run.status === "error") parts.push(`<div class="ag-err">${esc(t("st.agent.error", { message: run.error || "?" }))}</div>`);
  if (run.status === "done") {
    parts.push(`<div class="ag-meta">${esc(t("st.agent.meta", { model: run.model || "Claude", secs: Math.round((run.durationMs || 0) / 1000) }))}</div>`);
  }
  // Re-rendered on every poll: only when something changed, and only what is new fades in —
  // otherwise the whole conversation flickers while Claude works.
  const html = parts.join("");
  if (box.dataset.html === html) return;
  const seen = box.dataset.run === run.id ? Number(box.dataset.count || 0) : 0;
  box.dataset.html = html; box.dataset.run = run.id;
  box.innerHTML = html;
  const turns = box.querySelectorAll(".ag-turn");
  turns.forEach((el, i) => { if (i >= seen) el.classList.add("new"); });
  box.dataset.count = String(turns.length);
}

function renderAgent() {
  const runs = (state.agent.runs || []).filter((r) => Date.parse(r.at) >= state.since);
  for (const side of ["before", "after"]) renderChat(side, runs.filter((r) => r.side === side).pop());
  for (const b of document.querySelectorAll(".btn.ask")) b.disabled = !state.agent.available || state.agent.busy;
}

async function refreshAgent() {
  try { state.agent = await api("/api/agent/runs"); } catch (_) { state.agent = { available: false, runs: [] }; }
  renderAgent();
}

async function ask(side, what) {
  for (const b of document.querySelectorAll(".btn.ask")) b.disabled = true;
  try {
    const r = await api("/api/agent/run", { method: "POST", body: JSON.stringify({ side, ask: what, lang: state.lang }) });
    state.agent.runs = [...(state.agent.runs || []), r.run]; state.agent.busy = true;
  } catch (err) { $("#imp-msg").textContent = t("st.error", { message: err.message }); }
  renderAgent();
}

async function impersonate() {
  const button = $("#impersonate");
  button.disabled = true; $("#imp-msg").textContent = "…";
  try {
    const r = await api("/api/before/impersonate", { method: "POST", body: "{}" });
    state.impAt = Date.now();
    $("#imp-msg").textContent = t("st.imp.done", { name: r.claimed,
      before: r.before.filed ? t("st.imp.filed") : (r.before.error || "?"),
      after: r.after.allowed ? "allowed" : t("st.imp.refused", { layer: layerName(r.after.layer) }) });
    await refreshLive();
  } catch (err) { $("#imp-msg").textContent = t("st.error", { message: err.message }); }
  button.disabled = false;
}

/* ---------------------------------------------------------------------------------------- */
/* the replay scene: one call Bob's agent signed, delivered twice (/api/story/replay)          */

/* One delivery as a line. Its words and its colour both follow the status the verifier returned:
   accepted is the only green, refused the only red, anything else neither. */
function deliveryLine(which, d) {
  if (d.status === "allowed") return { cls: "ok", text: `✓ ${t(`st.replay.${which}.allowed`)}` };
  if (d.status === "refused") {
    return { cls: "no", text: `✗ ${t(`st.replay.${which}.refused`, { layer: d.layer || d.check || "—" })}`,
             message: d.message };
  }
  return { cls: "na", text: t(`st.replay.${which}.unavailable`, { detail: d.message || "" }) };
}

function renderReplay() {
  const out = $("#replay-out"), r = state.replay;
  if (!out) return;
  out.dataset.run = (r && r.runId) || "";   // what the recorder waits on: a new run, not the last one
  if (!r) { out.innerHTML = ""; return; }
  if (r.pending) { out.innerHTML = `<li class="replay-note">${esc(t("st.replay.running"))}</li>`; return; }
  if (r.error) { out.innerHTML = `<li class="entry"><div class="na">${esc(t("st.error", { message: r.error }))}</div></li>`; return; }
  const lines = [["original", r.original], ["copy", r.copy]].map(([which, d]) => {
    const l = deliveryLine(which, d);
    const said = l.message ? `<div class="declared">${esc(l.message)}</div>` : "";
    const system = d.systemRefused ? `<div class="declared">${esc(t("st.replay.system", { text: d.systemRefused }))}</div>` : "";
    return `<li class="entry" data-delivery="${which}" data-status="${esc(d.status)}"><div class="${l.cls}">${esc(l.text)}</div>${said}${system}</li>`;
  });
  const digest = (d) => String(d.sha256 || "").slice(0, 16);
  const same = r.identicalBytes ? t("st.replay.identical", { digest: digest(r.original) })
    : t("st.replay.different", { first: digest(r.original), second: digest(r.copy) });
  const where = r.target === "gateway" ? t("st.replay.where.gateway", { url: r.url }) : t("st.replay.where.policy");
  out.innerHTML = lines.join("") + `<li class="replay-note">${esc(same)} ${esc(where)}</li>`;
}

async function replay() {
  const button = $("#replay");
  button.disabled = true;
  state.replay = { pending: true }; renderReplay();
  try { state.replay = await api("/api/story/replay", { method: "POST", body: "{}" }); }
  catch (err) { state.replay = { error: err.message, runId: `error-${Date.now()}` }; }
  renderReplay();
  button.disabled = false;
  await refreshLive();
}

function setMode(mode) {
  state.mode = mode;
  for (const b of document.querySelectorAll(".modes button")) b.setAttribute("aria-selected", String(b.dataset.mode === mode));
  $("#live").hidden = mode !== "live";
  $("#demo-mode").hidden = mode !== "demo";
  const url = new URL(location.href); url.searchParams.set("mode", mode); history.replaceState(null, "", url);
  if (mode === "live") refreshLive();
  else show(state.view);
}

/* ---------------------------------------------------------------------------------------- */
/* play: the three views in order, for the chosen scenario                                   */

async function play() {
  if (state.busy) return;
  const id = state.selected;
  if (id === "after-revocation" && !revoked()) { show("issuer"); state.message = t("st.needRevoke"); renderIssuer(); return; }
  state.busy = true; state.message = ""; renderPick();
  try {
    show("issuer"); await sleep(DWELL_MS);
    show("gateway"); await runGateway(id);
    await sleep(DWELL_MS);
    show("outcome");
  } finally {
    state.busy = false; renderPick(); renderIssuer();
  }
}

async function runStep() {
  if (state.busy) return;
  state.busy = true; renderPick();
  try { await runGateway(state.selected); } finally { state.busy = false; renderPick(); }
}

/* ---------------------------------------------------------------------------------------- */

function renderStatic() {
  document.documentElement.lang = state.lang === "zh" ? "zh-Hant" : "en";
  for (const el of document.querySelectorAll("[data-t]")) el.textContent = t(el.dataset.t);
  for (const b of document.querySelectorAll("#lang button")) b.setAttribute("aria-pressed", String(b.dataset.lang === state.lang));
}

function renderAll() { renderStatic(); renderHeader(); renderPick(); renderStepper(); if (state.view === "issuer") renderIssuer(); if (state.view === "outcome") renderOutcome(); }

document.addEventListener("click", (event) => {
  const lang = event.target.closest("#lang button");
  if (lang) { state.lang = lang.dataset.lang; remember("vlei-app-lang", state.lang); renderAll();
    if (state.view === "gateway" && !state.busy) renderGatewayFromResult();
    if (state.liveData) { renderBefore(state.liveData.before); renderAfter(state.liveData.records); renderAgent(); }
    renderReplay();
    return; }
  const pick = event.target.closest("[data-pick]");
  if (pick && !state.busy) { state.selected = pick.dataset.pick; state.message = ""; renderPick(); show(state.view); return; }
  if (event.target.closest("#play")) { play(); return; }
  const mode = event.target.closest(".modes button");
  if (mode) { setMode(mode.dataset.mode); return; }
  if (event.target.closest("#impersonate")) { impersonate(); return; }
  if (event.target.closest("#replay")) { replay(); return; }
  const askBtn = event.target.closest(".btn.ask");
  if (askBtn) { ask(askBtn.dataset.side, askBtn.dataset.ask); return; }
  if (event.target.closest("#fresh-start")) {   // a recording starts from an empty board
    state.since = Date.now(); remember("vlei-story-since", String(state.since)); refreshLive(); return; }
  if (event.target.closest("#show-all")) { state.since = 0; remember("vlei-story-since", "0"); refreshLive(); return; }
  const step = event.target.closest("#stepper button");
  if (step && !state.busy) { show(step.dataset.view); return; }
  const go = event.target.closest("[data-go]");
  if (go && !state.busy) { show(go.dataset.go); return; }
  const act = event.target.closest("[data-act]");
  if (act) { ({ revoke, reissue, runStep })[act.dataset.act](); }
});

async function start() {
  const params = new URLSearchParams(location.search);
  const lang = params.get("lang") || recall("vlei-app-lang");
  if (lang === "zh" || lang === "en") state.lang = lang;
  state.strings = await (await fetch("/app/i18n.json")).json();
  const [listing, status] = await Promise.all([api("/api/scenarios"), api("/api/status")]);
  state.scenarios = Object.fromEntries(listing.scenarios.map((s) => [s.id, s]));
  state.status = status;
  const chosen = params.get("scenario");
  if (chosen && state.scenarios[chosen]) state.selected = chosen;
  renderAll();
  const view = params.get("view");
  show(["issuer", "gateway", "outcome"].includes(view) ? view : "issuer");
  setMode(params.get("mode") === "demo" ? "demo" : "live");
  document.addEventListener("change", (event) => {
    if (event.target.id === "only-claude" && state.liveData) renderAfter(state.liveData.records);
  });
  setInterval(() => { if (state.mode === "live" && !document.hidden) refreshLive(); }, 2000);
  setInterval(() => { if (state.mode === "live" && state.agent.busy && !document.hidden) refreshAgent(); }, 700);
  setInterval(async () => {   // revoked or re-issued elsewhere (/app, a script): follow it
    if (state.busy) return;
    try { const s = await api("/api/status"); const changed = !state.status || s.credential !== state.status.credential;
      state.status = s; renderHeader(); if (changed && state.view === "issuer") renderIssuer(); } catch (_) { /* later */ }
  }, 15000);
}

start().catch((err) => {
  document.body.insertAdjacentHTML("afterbegin", `<p class="banner">${esc(err.message)}</p>`);
});
