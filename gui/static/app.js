/* AutoPENT console — vanilla JS, no build step, no framework.
   Talks to the stdlib server (gui/server.py) via /api/*. */
"use strict";

/* ------------------------------------------------------------------ */
/* tiny helpers                                                        */
const $ = (sel, el) => (el || document).querySelector(sel);
const $$ = (sel, el) => Array.from((el || document).querySelectorAll(sel));

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
}[c]));

function fmt(v, digits) {
  if (v === null || v === undefined) return "—";
  if (typeof v === "boolean") return v ? "yes" : "no";
  if (typeof v === "number") {
    let s = v.toFixed(digits === undefined ? 4 : digits);
    s = s.replace(/\.?0+$/, "");
    return s === "" ? "0" : s;
  }
  return String(v);
}

async function api(path, body, expect) {
  const opt = body === undefined
    ? { method: "GET" }
    : { method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body) };
  const res = await fetch(path, opt);
  let payload;
  try { payload = await res.json(); }
  catch (e) { payload = { error: "bad gateway: " + e }; }
  const wanted = expect || 200;
  const okCodes = Array.isArray(wanted) ? wanted : [wanted, 202, 409];
  if (res.status === 404 && payload.error) payload.http_status = 404;
  else if (!res.ok && okCodes.indexOf(res.status) < 0) {
    const err = new Error(payload.error || "HTTP " + res.status);
    err.http_status = res.status;
    err.payload = payload;
    throw err;
  }
  payload.http_status = res.status;
  return payload;
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function pollJob(jobId, onProgress, deadlineMs) {
  const deadline = Date.now() + (deadlineMs || 3600000);
  for (;;) {
    const job = await api("/api/jobs/" + jobId);
    if (job.status === "running" && onProgress) onProgress(job);
    if (job.status === "done") return job;
    if (job.status === "error") {
      const err = new Error(job.error || "job failed");
      err.job = job;
      throw err;
    }
    if (Date.now() > deadline) throw new Error("job timed out");
    await sleep(500);
  }
}

/* ------------------------------------------------------------------ */
/* theme (light / dark) — persisted; defaults to the OS preference      */
const THEME_KEY = "autopent-theme";
function applyTheme(t) { document.documentElement.dataset.theme = t; }
function initTheme() {
  let saved = null;
  try { saved = localStorage.getItem(THEME_KEY); } catch (e) { /* no-op */ }
  const prefersLight = window.matchMedia &&
    window.matchMedia("(prefers-color-scheme: light)").matches;
  applyTheme(saved || (prefersLight ? "light" : "dark"));
}
$("#theme-toggle").addEventListener("click", () => {
  const next = document.documentElement.dataset.theme === "dark"
    ? "light" : "dark";
  applyTheme(next);
  try { localStorage.setItem(THEME_KEY, next); } catch (e) { /* no-op */ }
});
initTheme();

/* ------------------------------------------------------------------ */
/* tabs                                                               */
$$(".tab").forEach(btn => {
  btn.addEventListener("click", () => {
    $$(".tab").forEach(b => b.classList.remove("active"));
    $$(".panel").forEach(p => p.classList.remove("active"));
    btn.classList.add("active");
    $("#panel-" + btn.dataset.tab).classList.add("active");
    if (btn.dataset.tab === "run") refreshRecentRuns();
    if (btn.dataset.tab === "experiments") refreshPastExperiments();
    if (btn.dataset.tab === "states") refreshSamples();
  });
});

/* ------------------------------------------------------------------ */
/* viewer dialog (artifact contents)                                  */
const viewer = $("#viewer");
function openViewer(title, text) {
  $("#viewer-title").textContent = title;
  $("#viewer-code").textContent = text;
  viewer.showModal();
}
$("#viewer-close").addEventListener("click", () => viewer.close());
$("#viewer-copy").addEventListener("click", async () => {
  const t = $("#viewer-code").textContent;
  try { await navigator.clipboard.writeText(t); } catch (e) {
    const ta = document.createElement("textarea");
    ta.value = t; document.body.appendChild(ta);
    ta.select(); document.execCommand("copy"); ta.remove();
  }
});
document.addEventListener("click", onclickLink);
function onclickLink(ev) {
  const a = ev.target.closest("a[data-view]");
  if (a) {
    ev.preventDefault();
    const title = a.getAttribute("data-view");
    const url = new URL(a.href, location.href);
    fetch(url).then(r => {
      if (!r.ok) { openViewer(title, "// fetch failed: HTTP " + r.status); return null; }
      return r.text();
    }).then(t => { if (t !== null) openViewer(title, t || "(empty file)"); });
  }
}

/* ------------------------------------------------------------------ */
/* health + shared selectors                                          */
let HEALTH = null;
async function initHealth() {
  try {
    HEALTH = await api("/api/health");
    $("#engine-chip").textContent = "verifier: " + HEALTH.verifier_engine;
    $("#health-chip").textContent = "server ok · " + HEALTH.version;
    $("#health-chip").classList.add("ok");
  } catch (e) {
    $("#health-chip").textContent = "server error";
    $("#health-chip").classList.add("bad");
  }
}

const CATALOG = { scenarios: [], samples: [] };
async function initCatalog() {
  try {
    const s = await api("/api/scenarios");
    CATALOG.scenarios = s.scenarios;
    $("#run-scenario").innerHTML = s.scenarios.map(o =>
      `<option value="${esc(o.id)}">${esc(o.id)} — ${esc(o.name)} (${o.nodes} nodes)</option>`
    ).join("");
    $("#demo-scenario").innerHTML = $("#run-scenario").innerHTML;
    $("#run-scenario").dispatchEvent(new Event("change"));

    const sm = await api("/api/samples");
    CATALOG.samples = sm.samples;
    $("#run-sample").innerHTML = sm.samples.map(o =>
      `<option value="${esc(o.file)}">${esc(o.file)}${o.valid === false ? " (invalid-on-purpose)" : ""}</option>`
    ).join("");
    $("#run-sample").dispatchEvent(new Event("change"));
  } catch (e) { console.error(e); }
}

/* ------------------------------------------------------------------ */
/* RUN tab                                                            */
$$("#run-source input").forEach(r => r.addEventListener("change", () => {
  const src = $$("#run-source input").find(i => i.checked).value;
  $("#run-src-baked").classList.toggle("hidden", src !== "baked");
  $("#run-src-sample").classList.toggle("hidden", src !== "sample");
  $("#run-src-custom").classList.toggle("hidden", src !== "custom");
}));

$("#run-scenario").addEventListener("change", () => {
  const s = CATALOG.scenarios.find(
    o => o.id === $("#run-scenario").value);
  if (s) $("#run-scenario-info").textContent =
    `${s.nodes} nodes · ${s.edges} edges · objective: ${s.objective || "?"} ` +
    `· target ${s.objective_node} · L_opt=${s.optimal_path_length}`;
});
$("#run-sample").addEventListener("change", () => {
  const s = CATALOG.samples.find(o => o.file === $("#run-sample").value);
  if (s) $("#run-sample-info").textContent = s.description;
});
$("#run-state-file").addEventListener("change", (ev) => {
  const f = ev.target.files[0];
  if (!f) return;
  const rd = new FileReader();
  rd.onload = () => { $("#run-state-json").value = rd.result; };
  rd.readAsText(f);
});
$("#btn-validate-run-state").addEventListener("click", async () => {
  const box = $("#run-state-validate");
  box.classList.remove("hidden", "invalid");
  box.textContent = "validating…";
  try {
    const st = JSON.parse($("#run-state-json").value || "null");
    const v = await api("/api/validate-state", { state: st });
    renderValidate(box, v);
  } catch (e) {
    box.classList.add("invalid");
    box.textContent = "JSON parse error: " + e.message;
  }
});

function renderValidate(box, v) {
  const lines = [];
  lines.push(v.ok ? "✓ state is valid" : "✗ state is invalid");
  lines.push("");
  const info = v.info || {};
  lines.push(`nodes: ${info.node_count ?? "?"}   edges: ${info.edge_count ?? "?"}` +
             (info.v_total !== undefined ? `   |V_total| (protected): ${info.v_total}` : ""));
  if (info.computed_path_hops !== undefined)
    lines.push(`shortest ATTACKER→objective path: ${info.computed_path_hops} hops ` +
               `[${(info.computed_path_relations || []).join(" → ")}]`);
  if (v.errors.length) { lines.push("\nerrors:"); v.errors.forEach(e => lines.push("  ✗ " + e)); }
  if (v.warnings.length) { lines.push("\nwarnings (still runnable):"); v.warnings.forEach(w => lines.push("  ▲ " + w)); }
  box.classList.toggle("invalid", !v.ok);
  box.textContent = lines.join("\n");
}

$("#run-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const out = $("#run-output"), empty = $("#run-empty"), st = $("#run-status");
  const btn = $("#btn-run");
  const src = $$("#run-source input").find(i => i.checked).value;
  const body = {
    config: $("#run-config").value,
    seed: parseInt($("#run-seed").value, 10),
    operator: $("#run-operator").value,
    approve_all: $("#run-approve-all").checked,
    approve_tokens: $("#run-tokens").value.split(",").map(s => s.trim())
      .filter(Boolean),
  };
  if (src === "baked") body.scenario = $("#run-scenario").value;
  if (src === "sample") body.state_name = $("#run-sample").value;
  if (src === "custom") body.state_json_string = $("#run-state-json").value;

  btn.disabled = true; st.textContent = "running…";
  try {
    const r = await api("/api/run", body);
    out.classList.remove("hidden"); empty.classList.add("hidden");
    renderRun(r);
    st.textContent = "done";
    refreshRecentRuns();
  } catch (e) {
    st.textContent = "";
    if (e.payload && e.payload.error) {
      out.classList.remove("hidden"); empty.classList.add("hidden");
      $("#run-meta").textContent = "run failed";
      $("#run-meta").className = "chip bad";
      $("#run-engine").textContent = "";
      $("#run-metrics").innerHTML = "";
      $("#run-verifier").outerHTML =
        `<div class="subcard" id="run-verifier" style="border-left:3px solid var(--bad)">` +
        `<b>error</b> — ${esc(e.payload.error)}</div>`;
      $("#run-plan").innerHTML = ""; $("#run-trace").innerHTML = "";
      $("#run-artifacts").innerHTML = "";
    } else { alert("run failed: " + e.message); }
  } finally { btn.disabled = false; setTimeout(() => st.textContent = "", 2500); }
});

function metricGrid(metrics) {
  const order = [
    ["coverage", "Coverage", "Eq. 3"], ["path_efficiency", "Efficiency Ep", "Eq. 4/11"],
    ["safety", "Safety", "Eq. 5"], ["stealth", "Stealth", "Eq. 6"],
    ["composite_r", "Composite R", "Eq. 9"], ["detection_rate", "Detection rate", "per step"],
    ["recon_precision", "Recon precision", "vs ground truth"],
    ["recon_recall", "Recon recall", "vs ground truth"],
    ["mttd_sim_seconds", "MTTD (sim s)", "first alert"],
    ["objective_reached", "Objective reached", "Eq. 11 anchor"],
  ];
  return order.filter(([k]) => k in metrics).map(([k, label, note]) => {
    const v = metrics[k];
    const good = v === true || (typeof v === "number" && v >= 0.999);
    const cls = (k === "objective_reached" || k === "safety")
      ? (good ? "ok" : "bad") : "";
    return `<div class="metric"><div class="k">${esc(label)}</div>` +
           `<div class="v ${cls}">${esc(fmt(v, k === "mttd_sim_seconds" ? 1 : 4))}</div>` +
           `<div class="k">${esc(note)}</div></div>`;
  }).join("");
}

function renderRun(r) {
  const rec = r.record, m = rec.metrics, v = rec.verification;
  const flags = rec.audit_flags || {};
  $("#run-meta").textContent =
    `${rec.scenario} · ${rec.config} · seed ${rec.seed} · ` +
    `session ${rec.session.session}`;
  $("#run-meta").className =
    "chip " + (m.objective_reached ? "ok" : "flag");
  $("#run-engine").textContent =
    `engine: ${rec.engine} · steps ${rec.trace.filter(t => !t.skipped).length}` +
    (m.objective_reached ? " · objective reached" : " · objective NOT reached");
  $("#run-engine").className =
    "chip " + (m.objective_reached ? "ok" : "bad");
  $("#run-metrics").innerHTML = metricGrid(m);

  const blocked = v.blocked || [], holds = v.holds || [];
  $("#run-verifier").innerHTML =
    `<b>verifier</b> ${v.enabled ? "ENABLED" : "DISABLED (ablation)"}` +
    ` · engine ${esc(v.engine)}${v.z3_available ? " (z3" + esc(v.z3_verdict || "") + ")" : ""}` +
    ` · steps in ${v.n_steps_in} → out ${v.n_steps_out}` +
    (blocked.length ? " · <span class=\"chip bad\">BLOCKED " + blocked.length + "</span>" : "") +
    (holds.length ? " · <span class=\"chip flag\">HITL holds " + holds.length + "</span>" : " · no holds") +
    (blocked.length
      ? "<div style='margin-top:6px'>" + blocked.map(b =>
          `<div class="small">step ${esc(b.step_id)}: ${esc((b.reasons || []).join("; "))}</div>`
        ).join("") + "</div>" : "") +
    (holds.length
      ? "<div style='margin-top:6px'>" + holds.map(h =>
          `<div class="small">step ${esc(h.step_id)} → ${esc(h.token)} → ` +
          `<b>${esc((rec.holds_resolved || {})[h.step_id] || "?")}</b></div>`
        ).join("") + "</div>" : "");

  const verdicts = {};
  const holdsBy = {}; (v.holds || []).forEach(h => holdsBy[String(h.step_id)] = h);
  (rec.plan.steps || []).forEach(s => {
    const sid = String(s.step_id);
    if ((v.blocked || []).some(b => String(b.step_id) === sid))
      verdicts[sid] = { txt: "BLOCKED", cls: "bad" };
    else if (holdsBy[sid]) {
      const d = (rec.holds_resolved || {})[sid];
      verdicts[sid] = { txt: "HELD→" + (d || "?"),
                        cls: d === "denied" || d === "pending" ? "bad" : "flag" };
    } else if (flags[sid] && flags[sid].length)
      verdicts[sid] = { txt: "FLAGGED", cls: "flag" };
    else verdicts[sid] = { txt: "ALLOWED", cls: "ok" };
  });
  $("#run-plan").innerHTML = "<table class='table'><thead><tr>" +
    ["#", "action", "target", "technique", "impact", "cvss", "r", "verdict"]
      .map(h => `<th>${esc(h)}</th>`).join("") + "</tr></thead><tbody>" +
    (rec.plan.steps || []).map(s => {
      const sid = String(s.step_id);
      const vd = verdicts[sid] || { txt: "?", cls: "" };
      return `<tr><td>${esc(s.step_id)}</td><td>${esc(s.action)}</td>` +
        `<td class="mono">${esc(s.target.id)}</td>` +
        `<td class="mono">${esc(s.technique)}</td><td>${esc(s.impact)}</td>` +
        `<td>${esc(fmt(s.cvss, 1))}</td><td>${esc(fmt(s.stealth_cost, 2))}</td>` +
        `<td><span class="chip ${vd.cls}">${esc(vd.txt)}</span></td></tr>`;
    }).join("") + "</tbody></table>";

  $("#run-trace").innerHTML = "<table class='table'><thead><tr>" +
    ["#", "target", "p_obs", "D", "success", "compromised", "alert",
     "dt (sim s)", "note"].map(h => `<th>${esc(h)}</th>`).join("") +
    "</tr></thead><tbody>" +
    rec.trace.map(t => {
      if (t.skipped) {
        return `<tr><td>${esc(t.step_id)}</td><td colspan="8" class="dim">` +
          `SKIP — ${esc(t.reason)}</td></tr>`;
      }
      return `<tr><td>${esc(t.step_id)}</td><td class="mono">` +
        `${esc(t.target_id || "?")}</td><td>${esc(fmt(t.p_obs, 2))}</td>` +
        `<td>${esc(fmt(t.d_score, 2))}</td>` +
        `<td>${t.success ? '<span class="chip ok">ok</span>'
                          : '<span class="chip bad">fail</span>'}</td>` +
        `<td>${t.compromised ? '<span class="chip ok">reached</span>' : ""}</td>` +
        `<td>${t.detected ? '<span class="chip flag">ALERT</span>' : ""}</td>` +
        `<td>${esc(fmt(t.dt_sim_seconds, 1))}</td>` +
        `<td class="dim small">${esc(t.terminated_session
          ? "kill-switch: session terminated" : "")}</td></tr>`;
    }).join("") + "</tbody></table>";

  $("#run-artifacts").innerHTML = Object.entries(r.artifact_links || {})
    .map(([name, href]) =>
      `<a class="lnk" href="${esc(href)}" data-view="${esc(name)}">${esc(name)}</a>`)
    .join("") +
    (Object.keys(r.artifact_links || {}).length
      ? "" : "<span class='dim small'>artifacts unavailable</span>");
}

async function refreshRecentRuns() {
  try {
    const r = await api("/api/results");
    $("#recent-runs").innerHTML = r.runs.length
      ? r.runs.map(x => {
          const links = Object.entries(x.links || {}).slice(0, 3).map(
              ([name, href]) =>
                `<a class="lnk" href="${esc(href)}" data-view="${esc(name)}">${esc(name)}</a>`)
            .join(" ");
          return `<div class="list-item"><span class="mono small">${esc(x.name)}</span>${links}</div>`;
        }).join("")
      : "no GUI runs yet";
  } catch (e) { $("#recent-runs").textContent = "error listing runs"; }
}

/* ------------------------------------------------------------------ */
/* DEMO tab                                                           */
$("#btn-demo").addEventListener("click", async () => {
  const btn = $("#btn-demo"), pc = $("#demo-narrative"), st = $("#btn-demo");
  btn.disabled = true;
  pc.classList.remove("hidden");
  pc.textContent = "running demo…";
  try {
    const r = await api("/api/demo", {
      scenario: $("#demo-scenario").value,
      seed: parseInt($("#demo-seed").value, 10),
    });
    pc.textContent = r.narrative;
    $("#demo-metrics").innerHTML = metricGrid(r.metrics);
    $("#demo-artifacts").innerHTML = Object.entries(r.artifact_links || {})
      .map(([n, h]) =>
        `<a class="lnk" href="${esc(h)}" data-view="${esc(n)}">${esc(n)}</a>`)
      .join("");
  } catch (e) {
    pc.textContent = "demo failed: " + e.message;
  } finally { btn.disabled = false; }
});

/* ------------------------------------------------------------------ */
/* EXPERIMENTS tab                                                    */
$("#btn-exp").addEventListener("click", async () => {
  const seeds = parseInt($("#exp-seeds").value, 10);
  const scen = $$(".exp-scen:checked").map(c => c.value);
  if (!scen.length) { alert("pick at least one scenario"); return; }
  const btn = $("#btn-exp"), wrap = $("#exp-progress-wrap");
  const errBox = $("#exp-error");
  errBox.classList.add("hidden");
  btn.disabled = true;
  wrap.classList.remove("hidden");
  setProgress(0, "submitting…");
  try {
    const r = await api("/api/experiments", { seeds, scenarios: scen });
    const job = await pollJob(r.job_id, (j) =>
      setProgress(j.total ? j.done / j.total : 0, j.label));
    await renderExperiments(job);
  } catch (e) {
    errBox.classList.remove("hidden", "invalid");
    errBox.classList.add("invalid");
    errBox.textContent = "experiments failed — " + (e.message || e);
  } finally {
    btn.disabled = false;
    wrap.classList.add("hidden");
    refreshPastExperiments();
  }
});
function setProgress(frac, label) {
  $("#exp-progress").style.width =
    Math.min(100, Math.round((frac || 0) * 100)) + "%";
  $("#exp-progress-label").textContent = label || "";
}

async function renderExperiments(job) {
  const out = job.result;
  $("#exp-output").classList.remove("hidden");
  const s = out.summary.scenarios || {};
  const head = ["scenario", "config", "Coverage", "Ep", "Safety", "Stealth",
                "R", "det rate", "recon P", "recon R", "obj reached"];
  $("#exp-table").innerHTML = "<table class='table'><thead><tr>" +
    head.map(h => `<th>${esc(h)}</th>`).join("") + "</tr></thead><tbody>" +
    Object.keys(s).sort().map(scen => Object.keys(s[scen].configs)
      .sort().map(cfg => {
        const a = s[scen].configs[cfg];
        const f = (k, d) => esc(fmt(a[k] ? a[k].mean : a[k], d));
        return `<tr><td>${esc(scen)}</td><td>${esc(cfg)}</td>` +
          `<td>${f("coverage")}</td><td>${f("path_efficiency")}</td>` +
          `<td>${f("safety")}</td><td>${f("stealth")}</td>` +
          `<td>${f("composite_r")}</td><td>${f("detection_rate")}</td>` +
          `<td>${f("recon_precision")}</td><td>${f("recon_recall")}</td>` +
          `<td>${esc(fmt(a.objective_success_rate, 2))}</td></tr>`;
      }).join("")).join("") + "</tbody></table>";

  const wrows = [];
  const fmtP = (p) => p === 0 ? "0" : p < 0.001 ? p.toExponential(1) : fmt(p, 4);
  Object.keys(s).sort().forEach(scen => {
    Object.keys(s[scen].welch_tests || {}).sort().forEach(cmp => {
      Object.keys(s[scen].welch_tests[cmp]).forEach(metric => {
        const t = s[scen].welch_tests[cmp][metric];
        wrows.push(`<tr><td>${esc(scen)}</td><td>${esc(cmp.replace("_vs_full", " vs full"))}</td>` +
          `<td>${esc(metric)}</td><td>${esc(fmt(t.t, 2))}</td>` +
          `<td>${esc(fmt(t.df, 1))}</td><td>${esc(fmtP(t.p))}</td></tr>`);
      });
    });
  });
  $("#exp-welch").innerHTML = wrows.length
    ? "<table class='table'><thead><tr><th>scenario</th><th>comparison</th>" +
      "<th>metric</th><th>t</th><th>df</th><th>p</th></tr></thead><tbody>" +
      wrows.join("") + "</tbody></table>"
    : "<p class='hint'>none (single config run)</p>";

  const figs = out.links.figures || [];
  $("#exp-figures").innerHTML = figs.map((href, i) => {
    const names = ["fig2 web — framework vs ablations",
                   "fig3 cloud — time-to-detection",
                   "fig4 ad — 4-hop kill chain"];
    return `<figure><a href="${esc(href)}" target="_blank" rel="noopener">` +
      `<img src="${esc(href)}" alt="figure ${i + 1}"></a>` +
      `<figcaption>${esc(names[i] || "figure")}</figcaption></figure>`;
  }).join("");

  $("#exp-links").innerHTML =
    `<a class="lnk" href="${esc(out.links["table2.csv"])}" data-view="table2.csv">table2.csv</a>` +
    `<a class="lnk" href="${esc(out.links["summary.json"])}" data-view="summary.json">summary.json</a>` +
    `<span class="dim small">outdir: <code class="mono">${esc(out.outdir)}</code></span>`;
}

async function refreshPastExperiments() {
  try {
    const r = await api("/api/results");
    $("#past-experiments").innerHTML = r.experiments.length
      ? r.experiments.map(x => {
          const links = [];
          if (x.links) {
            if (x.links["summary.json"])
              links.push(`<a class="lnk" href="${esc(x.links["summary.json"])}" data-view="summary.json (${esc(x.name)})">summary</a>`);
            if (x.links["table2.csv"])
              links.push(`<a class="lnk" href="${esc(x.links["table2.csv"])}" data-view="table2.csv (${esc(x.name)})">table2.csv</a>`);
            (x.links.figures || []).forEach((f, i) =>
              links.push(`<a class="lnk" href="${esc(f)}" target="_blank" rel="noopener">fig${i + 1}</a>`));
          }
          return `<div class="list-item"><span class="mono small">${esc(x.name)}</span>${links.join(" ")}</div>`;
        }).join("")
      : "no GUI experiment jobs yet";
  } catch (e) { $("#past-experiments").textContent = "error listing jobs"; }
}

/* ------------------------------------------------------------------ */
/* STATES & SAMPLES tab                                               */
let SAMPLES = [];
async function refreshSamples() {
  try {
    SAMPLES = (await api("/api/samples")).samples;
    $("#samples-list").innerHTML = SAMPLES.map(o => {
      const chip = o.valid
        ? '<span class="chip ok">valid</span>'
        : '<span class="chip bad">invalid (for testing)</span>';
      return `<div class="sample-card"><b class="mono">${esc(o.file)}</b> ${chip}` +
        `<div class="desc">${esc(o.description)}</div>` +
        `<span>${o.bytes} bytes</span> ` +
        `<a class="lnk" href="${esc(o.link)}" data-view="${esc(o.file)}">view</a> ` +
        `<a class="lnk" href="${esc(o.link)}" download="${esc(o.file)}">download</a> ` +
        `<button class="btn btn-mini" data-use-sample="${esc(o.file)}">use in Run tab</button>` +
        `&nbsp; <button class="btn btn-mini" data-check-sample="${esc(o.file)}">validate</button></div>`;
    }).join("") +
    `<p class="hint">The three <code>state_*.json</code> baked scenarios are
       also selectable directly on the Run tab. Start with
       <b>state_mini_custom.json</b> (the smallest valid custom state) to see
       the custom-state path work end to end.</p>`;
  } catch (e) {
    $("#samples-list").textContent = "could not load samples: " + e.message;
  }
}
document.addEventListener("click", async (ev) => {
  const use = ev.target.closest("[data-use-sample]");
  if (use) {
    ev.preventDefault();
    await switchTab("run");
    $$("#run-source input").find(i => i.value === "sample").checked = true;
    $$("#run-source input").forEach(r =>
      r.dispatchEvent(new Event("change")));
    let tries = 20;
    while (!CATALOG.samples.length && tries--) await sleep(100);
    $("#run-sample").value = use.dataset.useSample;
    $("#run-sample").dispatchEvent(new Event("change"));
  }
  const chk = ev.target.closest("[data-check-sample]");
  if (chk) {
    ev.preventDefault();
    const target = $$("#samples-list a[data-view]").find(
      a => a.getAttribute("data-view") === chk.dataset.checkSample);
    if (target) {
      const text = await (await fetch(target.getAttribute("href"))).text();
      $("#val-textarea").value = text;
      await switchTab("states");
      await doValidate();
    }
  }
});

function switchTab(name) {
  const btn = $$(".tab").find(b => b.dataset.tab === name);
  if (btn) btn.click();
  return sleep(50);
}

$("#val-file").addEventListener("change", (ev) => {
  const f = ev.target.files[0];
  if (!f) return;
  const rd = new FileReader();
  rd.onload = () => { $("#val-textarea").value = rd.result; };
  rd.readAsText(f);
});
async function doValidate() {
  const box = $("#validate-output");
  box.classList.remove("hidden", "invalid");
  box.textContent = "validating…";
  try {
    const st = JSON.parse($("#val-textarea").value || "null");
    const v = await api("/api/validate-state", { state: st });
    renderValidate(box, v);
  } catch (e) {
    box.classList.add("invalid");
    box.textContent = "JSON parse error: " + e.message;
  }
}
$("#btn-validate").addEventListener("click", doValidate);
$("#btn-send-to-run").addEventListener("click", async () => {
  await switchTab("run");
  $$("#run-source input").find(i => i.value === "custom").checked = true;
  $$("#run-source input").forEach(r => r.dispatchEvent(new Event("change")));
  $("#run-state-json").value = $("#val-textarea").value;
});

/* ------------------------------------------------------------------ */
/* SELFTEST tab                                                       */
$("#btn-selftest").addEventListener("click", async () => {
  const btn = $("#btn-selftest"), st = $("#selftest-status");
  btn.disabled = true; st.textContent = "running…";
  try {
    const r = await api("/api/selftest", {});
    const job = await pollJob(r.job_id, null, 180000);
    const res = job.result;
    $("#selftest-output").classList.remove("hidden");
    $("#selftest-output").innerHTML =
      `<div class="list-item"><b>${res.pass} passed, ${res.fail} failed</b>` +
      `${res.fail === 0 ? '<span class="chip ok">all green</span>'
                        : '<span class="chip bad">errors above</span>'}</div>` +
      res.results.map(x => {
        const cls = x.ok ? "ok" : "bad";
        return `<div class="list-item"><span class="chip ${cls}">` +
          `${x.ok ? "PASS" : "FAIL"}</span>` +
          `<span class="small">${esc(x.check)}</span>` +
          (x.ok ? "" : `<span class="small dim">${esc(x.detail || "")}</span>`) +
          `</div>`;
      }).join("");
    st.textContent = res.fail === 0 ? "selftest 9/9 passed" : "selftest failed";
  } catch (e) {
    st.textContent = "selftest failed: " + e.message;
  } finally { btn.disabled = false; setTimeout(() => st.textContent = "", 4000); }
});

/* ------------------------------------------------------------------ */
/* boot                                                               */
(async function boot() {
  await initHealth();
  await initCatalog();
  refreshRecentRuns();
  refreshPastExperiments();
  refreshSamples();
})();
