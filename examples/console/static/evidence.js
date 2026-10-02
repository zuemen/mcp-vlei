/*
  Gateway evidence (/evidence): every tools/call the gateway decided, newest first, read from
  vlei-authz's own decision log through /api/evidence (allow-listed field by field on the server).

  For the selected call, five steps:
    1 what arrived      — which vLEI keys the call carried, and the argument names (never values)
    2 the eight checks  — as vlei-authz ran them, with their detail and time
    3 the witness reads — whose key event log, from which witness; revocation from the anchors
    4 the schemas       — each presented credential's schema against GLEIF's published SAIDs
    5 the outcome       — forwarded with the verified identity, or refused at the gateway

  Refreshes every 2 s and follows the newest call until one is chosen from the list.
*/
"use strict";

const REFRESH_MS = 2000;
const CHECKS = ["credential_present", "freshness", "digest", "signature", "delegation", "chain",
                "revocation", "authority"];
const FIELDS = ["credential", "credentialSaid", "delegatedAid", "signature"];

const state = { lang: "zh", strings: {}, records: [], official: [], fictional: "",
                selected: null, pinned: false, error: null };

const $ = (sel, root = document) => root.querySelector(sel);
const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (c) => (
  { "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" }[c]));

function t(key, vars = {}) {
  const table = state.strings[state.lang] || {};
  let text = table[key] ?? (state.strings.en || {})[key] ?? key;
  for (const [name, value] of Object.entries(vars)) text = text.split(`{${name}}`).join(String(value));
  return text;
}
function remember(key, value) { try { localStorage.setItem(key, value); } catch (_) { /* not kept */ } }
function recall(key) { try { return localStorage.getItem(key); } catch (_) { return null; } }

/* An identifier, shortened for reading; the whole value on hover. */
function id(value) {
  if (!value) return "";
  const text = String(value);
  const shown = text.length > 16 ? `${text.slice(0, 8)}…${text.slice(-4)}` : text;
  return `<span class="id" title="${esc(text)}">${esc(shown)}</span>`;
}
const keyOf = (record) => `${record.at}|${record.tool}|${record.decision}`;
function when(at) {
  const date = new Date(at);
  if (Number.isNaN(date.getTime())) return esc(at || "");
  return date.toLocaleTimeString(state.lang === "zh" ? "zh-TW" : "en-GB", { hour12: false });
}
const viaText = (record) => t(record.via === "public" ? "ev.via.public"
  : record.via === "local" ? "ev.via.local" : "ev.via.unknown");
const layerText = (layer) => layer ? `${t(`layer.short.${layer}`)} · ${layer}` : "";

/* ---------------------------------------------------------------------------------------- */

function stepArrived(record) {
  const present = FIELDS.filter((name) => (record.metaKeys || []).some((k) => k.endsWith(`/${name}`)));
  const chips = FIELDS.map((name) => {
    const yes = present.includes(name);
    return `<span class="chip ${yes ? "yes" : "no"}">${esc(t(`ev.field.${name}`))} · ${esc(t(yes ? "ev.present" : "ev.absent"))}</span>`;
  }).join("");
  const args = (record.argumentNames || []).length
    ? (record.argumentNames || []).map(esc).join(" · ") : esc(t("ev.s1.noargs"));
  return `<section class="step"><h3>${esc(t("ev.s1"))}</h3>
    <p class="hint">${esc(t("ev.s1.fields"))}</p><div class="chips">${chips}</div>
    ${present.length ? "" : `<p class="note">${esc(t("ev.s1.none"))}</p>`}
    <p class="hint">${esc(t("ev.s1.args"))}</p><p class="args">${args}</p></section>`;
}

function stepChecks(record) {
  const report = record.report;
  if (!report || !(report.checks || []).length) {
    return `<section class="step"><h3>${esc(t("ev.s2"))}</h3><p class="hint">${esc(t("ev.s2.none"))}</p></section>`;
  }
  const byName = Object.fromEntries(report.checks.map((c) => [c.name, c]));
  const rows = CHECKS.map((name, index) => {
    const check = byName[name] || {};
    const status = check.passed === true ? "pass" : check.passed === false ? "fail"
      : check.skipped ? "skipped" : "pending";
    const mark = { pass: "✓", fail: "✗", skipped: "–", pending: "·" }[status];
    const ms = typeof check.durationMs === "number" ? `${check.durationMs.toFixed(1)} ms` : "";
    return `<li data-state="${status}"><span class="mark">${mark}</span>
      <span class="name">${index + 1}. ${esc(t(`check.${name}`))}${check.layer ? ` — ${esc(check.layer)}` : ""}</span>
      <span class="ms">${esc(ms)}</span>
      ${check.detail ? `<span class="detail">${esc(check.detail)}</span>` : ""}</li>`;
  }).join("");
  const total = typeof report.totalMs === "number" ? `<p class="hint">${esc(t("ev.total", { ms: report.totalMs.toFixed(1) }))}</p>` : "";
  return `<section class="step"><h3>${esc(t("ev.s2"))}</h3><ol class="checks">${rows}</ol>${total}</section>`;
}

function kelReads(record) { return (record.witnessReads || []).filter((r) => r.typ === "kel"); }

function roleOf(aid, record) {
  const identity = (record.report || {}).identity || {};
  if (!aid) return t("ev.role.other");
  if (aid === record.delegateAid || aid === identity.delegateAid) return t("ev.role.agent");
  if (aid === record.holderAid || aid === identity.holderAid) return t("ev.role.holder");
  const read = kelReads(record).find((r) => r.aid === aid);
  const issued = (record.schemas || []).find((s) => (read?.anchors || []).some(([i, sn]) => i === s.said && sn === "0"));
  if (issued) return t("ev.role.issuer", { type: issued.type || "credential" });
  return t("ev.role.other");
}

/* How many distinct witnesses answered, and how many reads that took (a log read for the chain and
   again for revocation is two reads from each witness). */
function witnessText(witnesses) {
  const distinct = new Set(witnesses).size;
  return witnesses.length > distinct
    ? t("ev.witnesses.reads", { n: distinct, reads: witnesses.length })
    : t("ev.witnesses", { n: distinct });
}

function stepWitness(record) {
  const reads = record.witnessReads || [];
  if (!reads.length) {
    return `<section class="step"><h3>${esc(t("ev.s3"))}</h3><p class="hint">${esc(t("ev.s3.none"))}</p></section>`;
  }
  // One row per log: the same key event log is read from every witness (a quorum), so the row
  // says how many witnesses answered rather than repeating itself.
  const groups = new Map();
  for (const read of reads) {
    const key = `${read.typ}|${read.aid || read.said}`;
    const group = groups.get(key) || { ...read, witnesses: [], ms: 0, events: read.events };
    group.witnesses.push(read.witness);
    group.ms = Math.max(group.ms, read.ms || 0);
    group.events = Math.max(group.events ?? 0, read.events ?? 0);
    groups.set(key, group);
  }
  const rows = [...groups.values()].map((read) => `<tr>
      <td>${esc(String(read.typ || "").toUpperCase())} ${id(read.aid || read.said)}</td>
      <td>${esc(read.typ === "kel" ? roleOf(read.aid, record) : (read.state || ""))}</td>
      <td class="muted">${esc(witnessText(read.witnesses))}</td>
      <td class="muted">${read.events != null ? esc(t(read.events === 1 ? "ev.kel.event" : "ev.kel.events", { n: read.events })) : ""}</td>
      <td class="muted">${esc(`${read.ms} ms`)}</td></tr>`).join("");
  const records = (record.schemas || []).map((cred) => {
    const revoked = kelReads(record).find((r) => (r.anchors || []).some(([i, sn]) => i === cred.said && sn === "1"));
    const issued = kelReads(record).find((r) => (r.anchors || []).some(([i, sn]) => i === cred.said && sn === "0"));
    const where = revoked || issued;
    const verdict = revoked ? `<span class="bad">${esc(t("ev.rec.revoked"))}</span>`
      : issued ? `<span class="ok">${esc(t("ev.rec.issued"))}</span>`
      : `<span class="muted">${esc(t("ev.rec.unread"))}</span>`;
    return `<tr><td>${esc(cred.type || "?")} ${id(cred.said)}</td><td>${verdict}</td>
      <td class="muted">${where ? t("ev.rec.where", { issuer: id(where.aid) }) : ""}</td></tr>`;
  }).join("");
  return `<section class="step"><h3>${esc(t("ev.s3"))}</h3><p class="hint">${esc(t("ev.s3.hint"))}</p>
    <table class="reads"><tbody>${rows}</tbody></table>
    ${records ? `<p class="hint" style="margin-top:12px">${esc(t("ev.s3.records"))}</p>
    <table class="records"><tbody>${records}</tbody></table>` : ""}</section>`;
}

function stepSchemas(record) {
  const schemas = record.schemas || [];
  if (!schemas.length) {
    return `<section class="step"><h3>${esc(t("ev.s4"))}</h3><p class="hint">${esc(t("ev.s4.none"))}</p></section>`;
  }
  const rows = schemas.map((s) => `<tr><td>${esc(s.type || "?")}</td><td>${id(s.schema)}</td>
      <td>${s.official ? `<span class="ok">✓ ${esc(t("ev.s4.match", { type: s.type }))}</span>`
                        : `<span class="bad">✗ ${esc(t("ev.s4.nomatch"))}</span>`}</td></tr>`).join("");
  const forged = record.layer === "unknown_root" && schemas.every((s) => s.official)
    ? `<p class="note">${esc(t("ev.s4.forged"))}</p>` : "";
  const source = state.official[0]?.source || "";
  return `<section class="step"><h3>${esc(t("ev.s4"))}</h3><table class="schemas"><tbody>${rows}</tbody></table>
    ${forged}<p class="hint"><a href="${esc(source)}" target="_blank" rel="noopener">${esc(t("ev.s4.source"))}</a></p></section>`;
}

function stepOutcome(record) {
  const identity = (record.report || {}).identity || {};
  let body;
  if (record.decision === "allow") {
    body = esc(t("ev.out.allow", { lei: record.lei || identity.lei || "—", role: record.role || identity.role || "—" }));
  } else {
    body = esc(t(record.wire === "grpc" ? "ev.out.deny.grpc" : "ev.out.deny.http"));
    body += `<div class="reason">${esc(t("ev.out.reason"))}: ${esc(record.layer || "refused")}: ${esc(record.message || "")}</div>`;
  }
  return `<section class="step"><h3>${esc(t("ev.s5"))}</h3><div class="outcome-box">${body}</div></section>`;
}

/* ---------------------------------------------------------------------------------------- */

function render() {
  document.documentElement.lang = state.lang === "zh" ? "zh-Hant" : "en";
  for (const el of document.querySelectorAll("[data-t]")) el.textContent = t(el.dataset.t);
  for (const button of document.querySelectorAll("#lang button")) {
    button.setAttribute("aria-pressed", String(button.dataset.lang === state.lang));
  }
  $("#fictional").textContent = state.fictional || "";

  const live = $("#live");
  live.innerHTML = state.pinned
    ? `<span class="live pinned"><span class="dot"></span>${esc(t("ev.pinned"))} <button type="button" id="latest">${esc(t("ev.latest"))}</button></span>`
    : `<span class="live"><span class="dot"></span>${esc(t("ev.live"))}</span>`;

  const main = $("#ev");
  if (state.error) {
    main.innerHTML = `<p class="error">${esc(t("ev.error", { message: state.error }))}</p>`;
  } else if (!state.records.length) {
    main.innerHTML = `<p class="empty">${esc(t("ev.empty"))}</p>`;
  } else {
    const record = state.records.find((r) => keyOf(r) === state.selected) || state.records[0];
    const verdict = record.decision === "allow" ? t("ev.result.allow")
      : `${t("ev.result.deny")}${record.layer ? ` · ${layerText(record.layer)}` : ""}`;
    main.innerHTML = `<div class="head" data-decision="${esc(record.decision)}">
        <span class="when">${when(record.at)}</span><span class="tool">${esc(record.tool || "—")}</span>
        <span class="verdict">${esc(verdict)}</span><span class="via">${esc(viaText(record))}</span></div>
      ${stepArrived(record)}${stepChecks(record)}${stepWitness(record)}${stepSchemas(record)}${stepOutcome(record)}`;
  }

  $("#list").innerHTML = state.records.map((record) => `<tr data-key="${esc(keyOf(record))}"
      aria-selected="${String(keyOf(record) === state.selected)}">
      <td>${when(record.at)}</td><td>${esc(viaText(record))}</td><td>${esc(record.tool || "—")}</td>
      <td class="${record.decision === "allow" ? "allow" : "deny"}">${esc(record.decision === "allow"
        ? t("ev.result.allow") : `${t("ev.result.deny")}${record.layer ? ` · ${record.layer}` : ""}`)}</td></tr>`).join("");
}

async function refresh() {
  try {
    const response = await fetch("/api/evidence?limit=20", { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    state.records = data.records || [];
    state.official = data.officialSchemas || [];
    state.fictional = data.fictional || "";
    state.error = null;
    if (!state.pinned || !state.records.some((r) => keyOf(r) === state.selected)) {
      state.pinned = false;
      state.selected = state.records.length ? keyOf(state.records[0]) : null;
    }
  } catch (err) {
    state.error = err.message;
  }
  render();
}

document.addEventListener("click", (event) => {
  const lang = event.target.closest("#lang button");
  if (lang) { state.lang = lang.dataset.lang; remember("vlei-app-lang", state.lang); render(); return; }
  if (event.target.closest("#latest")) { state.pinned = false; refresh(); return; }
  const row = event.target.closest("#list tr[data-key]");
  if (row) { state.selected = row.dataset.key; state.pinned = true; render(); window.scrollTo({ top: 0, behavior: "smooth" }); }
});

async function start() {
  const params = new URLSearchParams(location.search);
  const lang = params.get("lang") || recall("vlei-app-lang");
  if (lang === "zh" || lang === "en") state.lang = lang;
  state.strings = await (await fetch("/app/i18n.json")).json();
  await refresh();
  setInterval(refresh, REFRESH_MS);
}

start().catch((err) => {
  document.body.insertAdjacentHTML("afterbegin", `<p class="error">${esc(err.message)}</p>`);
});
