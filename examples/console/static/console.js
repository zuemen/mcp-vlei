/*
  Trust Console — front end.

  The backend sends whole states; this file renders them. The only thing it decides for itself is
  the pace at which the verification column lights up, because that is a property of the recording
  rather than of the verification: the checks have already run by the time a state arrives.
*/

const CHECK_STEP_MS = 280;          // readable, without wasting the clock
const MARK = { pass: "✓", fail: "✗", pending: "–", skipped: "–", running: "–" };

const $ = (id) => document.getElementById(id);

/* The console is one 1280×720 stage, scaled to fill the window: at 1920×1080 it is drawn 1.5×,
   natively, so a recording at that size is as sharp as the screen. */
const STAGE = { width: 1280, height: 720 };
function fitStage() {
  document.documentElement.style.zoom = Math.min(innerWidth / STAGE.width, innerHeight / STAGE.height);
}
addEventListener("resize", fitStage);
fitStage();
const params = new URLSearchParams(location.search);
if (params.get("chrome") === "off") document.body.classList.add("no-chrome");
/* ?lang=en: the page is English already but for one term, the employer's 統一編號 — named here as
   the story's English names it ("who.ubn" in i18n.json), for a take with no Chinese on screen. */
const ENGLISH = params.get("lang") === "en";
const term = (text) => (ENGLISH ? String(text).replace(/統一編號/g, "Unified Business No.") : text);

let revealTimers = [];
let lastSceneKey = null;
let sceneMode = "measured";

/* ------------------------------------------------------------------ cards */

function renderCard(card) {
  if (!card) return "";
  const status = ["valid", "revoked", "refused", "invalid", "simulated"].includes(card.status)
    ? card.status : "unverified";
  const text = { valid: "valid", revoked: "revoked", refused: "refused", invalid: "invalid",
                 simulated: "simulated", unverified: "not presented" }[status];
  return `<div class="card ${status}">
      <div class="kind"><span>${card.role}</span><span>${card.type}</span></div>
      <div class="lei">${card.lei}</div>
      <div class="label">${term(card.label)}</div>
      <div class="status">${text}</div>
      <div class="stamp">${card.revokedAt || ""}</div>
      ${card.note ? `<div class="note">${card.note}</div>` : ""}
    </div>`;
}

/* ---------------------------------------------------------------- request */

/* Syntax colouring, with the extension's four keys picked out. Escaping first: the JSON comes from
   credentials, and a console that renders them as markup would be a poor advertisement for a
   project about trust. */
// The extension's namespace, from the state: its keys are the ones picked out in red.
let vleiPrefix = null;

function highlight(json) {
  const escaped = json
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

  return escaped.replace(
    /("(\\u[\da-fA-F]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(\.\d*)?([eE][+-]?\d+)?)/g,
    (match) => {
      if (/^"/.test(match)) {
        if (/:$/.test(match)) {
          return vleiPrefix && match.includes(vleiPrefix)
            ? `<span class="vlei">${match}</span>`
            : `<span class="k">${match}</span>`;
        }
        return `<span class="s">${match}</span>`;
      }
      return `<span class="n">${match}</span>`;
    }
  );
}

/* ----------------------------------------------------------- verification */

function checkRow(check, index, status) {
  const mark = MARK[status] || "–";
  const right = status === "pass" && check.ms != null ? `${check.ms.toFixed(1)} ms` : "";
  const why = status === "fail" && check.detail
    ? `<div class="why">${check.detail}</div>` : "";
  return `<li class="check ${status}">
      <span class="mark">${mark}</span>
      <span><span class="num">${index + 1}</span>${check.label}</span>
      <span class="ms">${right}</span>
      ${why}
    </li>`;
}

/* Light the rows in sequence. The checks are already decided; this paces the reveal so a viewer
   can follow which layer stopped the call, which is the whole reason the column exists. */
function revealChecks(checks) {
  revealTimers.forEach(clearTimeout);
  revealTimers = [];

  const draw = (upTo) => {
    $("checks").innerHTML = checks.map((check, i) => {
      if (i < upTo) return checkRow(check, i, check.status);
      if (i === upTo && check.status !== "skipped") return checkRow(check, i, "running");
      return checkRow(check, i, "pending");
    }).join("");
  };

  draw(0);
  checks.forEach((check, i) => {
    revealTimers.push(setTimeout(() => {
      // A failure ends the sequence: everything after it is skipped, not still to come.
      if (check.status === "fail") {
        $("checks").innerHTML = checks.map((c, j) =>
          checkRow(c, j, j <= i ? c.status : "skipped")).join("");
        revealTimers.forEach(clearTimeout);
        revealTimers = [];
        showOutcome();
        return;
      }
      draw(i + 1);
      if (i === checks.length - 1) showOutcome();
    }, CHECK_STEP_MS * (i + 1)));
  });
}

let pendingOutcome = null;
function showOutcome() {
  if (!pendingOutcome) return;
  const { status, layer, note, headline } = pendingOutcome;
  const text = headline ? esc(headline)
    : status === "allowed" ? "ALLOWED"
    : status === "refused" ? `REFUSED <span class="layer">· ${layer}</span>`
    : status === "unavailable" ? "NOT RUNNING"
    : "GRANTED ON SELF-ASSERTION";
  $("outcome").className = `outcome ${status}`;
  $("outcome").innerHTML = `${text}${note ? `<span class="note">${note}</span>` : ""}`;
}

/* ------------------------------------------------------------------ state */

/* Scene 0, observed mode: the observatory's record of the real connector beside the replay. Every
   value was written by a client, so every value is escaped and set as text. */
function esc(value) {
  return String(value)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function observedValue(value) {
  if (value === null || value === undefined) return '<span class="obs-none">not sent</span>';
  const text = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  return `<code>${esc(text)}</code>`;
}

function renderObserved(observed) {
  if (!observed.available) {
    return `<div class="obs-empty">${esc(observed.reason)}</div>`
      + `<div class="obs-source">source · ${esc(observed.source || "")}</div>`;
  }
  const rows = observed.rows.map((row) => `
    <div class="obs-label">${esc(row.label)}</div>
    <div class="obs-cell">${observedValue(row.real)}</div>
    <div class="obs-cell">${observedValue(row.replay)}</div>
    <div class="obs-verdict ${esc(row.verdict)}">${row.verdict === "same" ? "same" : "differs"}</div>`);
  return `<div class="obs-grid">
      <div></div>
      <div class="obs-head">Real Claude connector</div>
      <div class="obs-head">My script · replay</div>
      <div></div>
      ${rows.join("")}
    </div>
    <div class="obs-source">read from ${esc(observed.source)} · real ${esc(observed.realAt)}`
    + ` · replay ${esc(observed.replayAt)}</div>`;
}

function render(state) {
  vleiPrefix = state.namespace ? `${state.namespace}/` : null;
  $("scene-n").textContent = state.scene;
  if (state.sceneCount) $("scene-total").textContent = state.sceneCount;
  $("banner").hidden = !state.banner;
  $("banner").textContent = state.banner || "";
  $("scene-title").textContent = state.sceneTitle || "";

  $("card-employer").innerHTML = renderCard(state.identities?.employer);
  $("card-agent").innerHTML = renderCard(state.identities?.agent);
  $("card-server").innerHTML = renderCard(state.identities?.server);

  const revoked = state.identities?.agent?.status === "revoked";
  $("revoke").disabled = revoked;
  $("revoke").textContent = revoked ? "ECR revoked" : "Revoke the ECR credential";

  const evidence = state.evidence || {};
  const provenance = evidence.credentials
    ? `credentials <b>${evidence.credentials}</b> · signed with <b>${evidence.signing}</b>`
      + ` · revocation read from <b>${evidence.revocation}</b>`
    : "";
  const diff = state.verification?.outcome?.agentDiff;
  // A set-up problem shown before the take, not discovered during it.
  const warning = state.readiness
    ? `<div style="color:var(--fail);margin-bottom:8px">⚠ ${state.readiness}</div>` : "";
  const fictional = state.fictional ? `<div class="fictional">${state.fictional}</div>` : "";
  $("evidence").innerHTML = warning + fictional + provenance
    + (diff ? `<div class="diff">${diff.replace(/</g, "&lt;")}</div>` : "");

  const request = state.request || {};
  $("req-name").textContent = request.name || "";
  const observed = state.scene === 0 && state.sceneMode === "observed" ? state.observed : null;
  sceneMode = state.sceneMode || "measured";
  $("req-json").hidden = Boolean(observed);
  $("observed").hidden = !observed;
  $("req-json").innerHTML = observed ? "" : highlight(request.json || "");
  $("observed").innerHTML = observed ? renderObserved(observed) : "";
  $("self-asserted").hidden = request.mode !== "plain";

  $("log-entries").innerHTML = (state.log || []).slice(0, 3)
    .map((e) => `<span class="entry"><span class="ts">${e.ts}</span>${e.text}</span>`)
    .join("");

  pendingOutcome = state.verification?.outcome || null;

  /* Re-render without replaying: a state that arrives for the same run (a reconnect, a log line)
     should not restart the reveal someone is watching. A new run of the same scene — its key pressed
     again — carries a new signed request, and is replayed from the first check. */
  const sceneKey = `${state.scene}|${state.sceneMode}|${state.identities?.agent?.status}`
    + `|${state.request?.json || ""}`;
  const checks = state.verification?.checks || [];
  if (sceneKey !== lastSceneKey) {
    lastSceneKey = sceneKey;
    if (state.scene === 0) {
      // Stop a reveal still running from the scene before: its timers would otherwise redraw
      // that scene's passing rows over this scene's empty column.
      revealTimers.forEach(clearTimeout);
      revealTimers = [];
      $("checks").innerHTML = checks.map((c, i) => checkRow(c, i, "skipped")).join("");
      showOutcome();
    } else {
      $("outcome").className = "outcome";
      $("outcome").innerHTML = "";
      revealChecks(checks);
    }
  }
}

/* ------------------------------------------------------------ connection */

function connect() {
  const source = new EventSource("/events");

  source.onopen = () => {
    $("dot").classList.remove("down");
    $("live-text").textContent = "live";
  };
  source.onmessage = (event) => render(JSON.parse(event.data));
  source.onerror = () => {
    $("dot").classList.add("down");
    $("live-text").textContent = "reconnecting";
    source.close();
    setTimeout(connect, 1500);
  };
}

/* --------------------------------------------------------------- controls */

document.addEventListener("keydown", (event) => {
  if (event.key >= "0" && event.key <= "9") {
    fetch(`/scene/${event.key}`, { method: "POST" });
  } else if (event.code === "Space") {
    event.preventDefault();
    lastSceneKey = null;                       // replay the current scene
    fetch("/state").then((r) => r.json()).then(render);
  } else if (event.key === "o" || event.key === "O") {
    // Scene 0 only: switch between the in-process measurement and the observatory's records.
    const next = sceneMode === "observed" ? "measured" : "observed";
    fetch(`/scene/0/mode/${next}`, { method: "POST" });
  } else if (event.key === "r" || event.key === "R") {
    fetch("/reset", { method: "POST" });
  } else if (event.key === "i" || event.key === "I") {
    // After the revocation scene: issue the holder a fresh ECR for the next take.
    fetch("/reissue", { method: "POST" });
  }
});

$("revoke").addEventListener("click", async () => {
  const button = $("revoke");
  button.disabled = true;
  button.textContent = "revoking…";
  await fetch("/revoke", { method: "POST" });
});

connect();
