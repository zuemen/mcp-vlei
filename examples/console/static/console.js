/*
  Trust Console — front end. Design: docs/DEMO-CONSOLE.md

  The backend sends whole states; this file renders them. The only thing it decides for itself is
  the pace at which the verification column lights up, because that is a property of the recording
  rather than of the verification: the checks have already run by the time a state arrives.
*/

const CHECK_STEP_MS = 280;          // readable, without wasting the clock
const NUMERALS = ["①", "②", "③", "④", "⑤", "⑥", "⑦", "⑧"];
const MARK = { pass: "✓", fail: "✗", pending: "–", skipped: "–", running: "–" };

const $ = (id) => document.getElementById(id);
const params = new URLSearchParams(location.search);
if (params.get("chrome") === "off") document.body.classList.add("no-chrome");

let revealTimers = [];
let lastSceneKey = null;

/* ------------------------------------------------------------------ cards */

function renderCard(card) {
  if (!card) return "";
  const status = ["valid", "revoked", "refused", "invalid"].includes(card.status)
    ? card.status : "unverified";
  const text = { valid: "valid", revoked: "revoked", refused: "refused", invalid: "invalid",
                 unverified: "not presented" }[status];
  return `<div class="card ${status}">
      <div class="kind"><span>${card.role}</span><span>${card.type}</span></div>
      <div class="lei">${card.lei}</div>
      <div class="label">${card.label}</div>
      <div class="status">● ${text}</div>
      ${card.revokedAt ? `<div class="stamp">${card.revokedAt}</div>` : ""}
      ${card.note ? `<div class="note">${card.note}</div>` : ""}
    </div>`;
}

/* ---------------------------------------------------------------- request */

/* Syntax colouring, with the extension's four keys picked out. Escaping first: the JSON comes from
   credentials, and a console that renders them as markup would be a poor advertisement for a
   project about trust. */
function highlight(json) {
  const escaped = json
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

  return escaped.replace(
    /("(\\u[\da-fA-F]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(\.\d*)?([eE][+-]?\d+)?)/g,
    (match) => {
      if (/^"/.test(match)) {
        if (/:$/.test(match)) {
          return match.includes("org.gleif.vlei/")
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
      <span>${NUMERALS[index]} ${check.label}</span>
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
  const { status, layer, note } = pendingOutcome;
  const text = status === "allowed" ? "ALLOWED"
    : status === "refused" ? `REFUSED <span class="layer">· ${layer}</span>`
    : status === "unavailable" ? "NOT RUNNING"
    : "GRANTED ON SELF-ASSERTION";
  $("outcome").className = `outcome ${status}`;
  $("outcome").innerHTML = `${text}${note ? `<span class="note">${note}</span>` : ""}`;
}

/* ------------------------------------------------------------------ state */

function render(state) {
  $("scene-n").textContent = state.scene;
  $("scene-title").textContent = state.sceneTitle ? `· ${state.sceneTitle}` : "";

  $("card-server").innerHTML = renderCard(state.identities?.server);
  $("card-agent").innerHTML = renderCard(state.identities?.agent);

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
  $("evidence").innerHTML = warning + provenance
    + (diff ? `<div class="diff">${diff.replace(/</g, "&lt;")}</div>` : "");

  const request = state.request || {};
  $("req-name").textContent = request.name || "";
  $("req-json").innerHTML = highlight(request.json || "");
  $("self-asserted").hidden = request.mode !== "plain";

  $("log-entries").innerHTML = (state.log || [])
    .map((e) => `<span class="entry"><span class="ts">${e.ts}</span>${e.text}</span>`)
    .join("");

  pendingOutcome = state.verification?.outcome || null;

  /* Re-render without replaying: a state that arrives for the same scene (a reconnect, a log line)
     should not restart the reveal someone is watching. */
  const sceneKey = `${state.scene}|${state.identities?.agent?.status}`;
  const checks = state.verification?.checks || [];
  if (sceneKey !== lastSceneKey) {
    lastSceneKey = sceneKey;
    if (state.scene === 0) {
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
  if (event.key >= "0" && event.key <= "5") {
    fetch(`/scene/${event.key}`, { method: "POST" });
  } else if (event.code === "Space") {
    event.preventDefault();
    lastSceneKey = null;                       // replay the current scene
    fetch("/state").then((r) => r.json()).then(render);
  } else if (event.key === "r" || event.key === "R") {
    fetch("/reset", { method: "POST" });
  } else if (event.key === "i" || event.key === "I") {
    // After scene 3: issue the holder a fresh ECR, so scenes 4 and 5 have one to present.
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
