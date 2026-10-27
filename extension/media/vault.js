// Vault webview. Renders state pushed by the extension; every action is a message back to it.
(function () {
  const vscode = acquireVsCodeApi();
  const $ = (s) => document.querySelector(s);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
  const send = (type, extra = {}) => vscode.postMessage({ type, ...extra });

  let state = vscode.getState() || { tab: "vault", filter: "all" };
  let data = { findings: [], security_score: null, a11y_score: null, busy: {} };

  const LOCK_OPEN = '<svg class="lock" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="10" width="16" height="11" rx="2"/><path class="shackle" d="M8 10V7a4 4 0 0 1 7.5-2"/></svg>';
  const LOCK_SHUT = '<svg class="lock" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="4" y="10" width="16" height="11" rx="2"/><path class="shackle" d="M8 10V7a4 4 0 0 1 8 0v3"/><path d="M9 15.5l2 2 4-4"/></svg>';

  // ---------- tabs ----------
  function showTab(tab) {
    state.tab = tab;
    vscode.setState(state);
    document.querySelectorAll(".tabs button").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.tab === tab)));
    document.querySelectorAll("section[data-tab]").forEach((s) => (s.hidden = s.dataset.tab !== tab));
    if (tab === "traces" || tab === "cost") send("traces", { hours: Number($("#hours")?.value || 24) });
    if (tab === "audit") send("audit");
  }
  document.querySelectorAll(".tabs button").forEach((b) => b.addEventListener("click", () => showTab(b.dataset.tab)));

  // ---------- vault ----------
  const scoreColor = (n) => (n >= 90 ? "var(--vc-teal)" : n >= 60 ? "var(--vc-amber)" : "var(--vc-red)");

  function findingHtml(f) {
    const loc = f.start_line ? `${f.path}:${f.start_line}` : f.path;
    const tag = f.wcag ? `WCAG ${f.wcag}` : f.cwe || f.owasp;
    return `<div class="find">
      <span class="sev ${esc(f.severity)}">${esc(f.severity === "critical" ? "crit" : f.severity)}</span>
      <span class="t" data-open="${esc(f.id)}" title="${esc(f.message)}">${esc(f.title)}<span class="cat">${esc(f.category)}</span></span>
      <small>${esc(loc)}${tag ? " · " + esc(tag) : ""}</small>
      <span class="acts">${f.fixable ? `<button data-fix="${esc(f.id)}">🔒 Fix</button>` : ""}<button class="quiet" data-ignore="${esc(f.id)}">Accept risk</button></span>
    </div>`;
  }

  function renderVault() {
    const el = $("#vault");
    const all = data.findings || [];
    const sec = data.security_score;
    if (sec === null) {
      el.innerHTML = `<div class="head"><span>WORKSPACE</span>${LOCK_OPEN}</div>
        <p class="muted">No scan yet. VibeCheck checks your code for security holes, leaked keys, risky AI features and WCAG accessibility issues. Everything runs on this machine.</p>
        <div class="row"><button class="btn" data-act="scan" ${data.busy.scan ? "disabled" : ""}>${data.busy.scan ? "Scanning…" : "Scan workspace"}</button></div>
        ${data.error ? `<p class="err">${esc(data.error)}</p>` : ""}`;
      return;
    }
    const open = all.filter((f) => f.category !== "a11y" || data.showA11y !== false);
    const filtered = state.filter === "all" ? open : open.filter((f) => (state.filter === "security" ? f.category !== "a11y" : f.category === state.filter));
    const crit = all.filter((f) => f.severity === "critical").length;
    const clean = all.length === 0;
    const filters = ["all", "security", "ai", "a11y"]
      .map((k) => `<button data-filter="${k}" aria-pressed="${state.filter === k}">${{ all: "All", security: "Security", ai: "AI", a11y: "Accessibility" }[k]} ${k === "all" ? open.length : open.filter((f) => (k === "security" ? f.category !== "a11y" : f.category === k)).length}</button>`)
      .join("");
    el.innerHTML = `
      <div class="head"><span>WORKSPACE</span><span style="color:${scoreColor(Math.min(sec, data.a11y_score))}">${clean ? LOCK_SHUT : LOCK_OPEN}</span></div>
      ${clean ? `<div class="secure">${LOCK_SHUT}<div class="score" style="justify-content:center"><b style="color:var(--vc-teal)">100</b></div><p>WORKSPACE SECURED · 0 CODE LEFT THIS MACHINE</p></div>` : `
      <div class="score"><b style="color:${scoreColor(sec)}">${sec}</b><small>/ 100 security score</small></div>
      <div class="meter"><i style="width:${sec}%;background:${scoreColor(sec)}"></i></div>
      <div class="subscores"><div><strong>${crit}</strong>critical</div><div><strong style="color:${scoreColor(data.a11y_score)}">${data.a11y_score}</strong>accessibility</div></div>`}
      <div class="row"><button class="btn" data-act="scan" ${data.busy.scan ? "disabled" : ""}>${data.busy.scan ? "Scanning…" : "Scan workspace"}</button>
        <span class="live">● local${data.seconds ? " · " + data.seconds + "s" : ""}</span></div>
      ${data.error ? `<p class="err">${esc(data.error)}</p>` : ""}
      ${(data.errors || []).map((e) => `<p class="err">${esc(e)}</p>`).join("")}
      ${clean ? "" : `<div class="filters">${filters}</div>${filtered.map(findingHtml).join("") || '<p class="muted">Nothing in this group.</p>'}`}`;
  }

  // ---------- scan a link ----------
  function renderLink() {
    const r = data.link;
    let out = `<p class="muted">Paste a GitHub repo or a website. Repos are cloned to a temporary folder and never run. Websites get passive checks plus a WCAG accessibility check.</p>
      <input type="text" id="link" placeholder="https://github.com/owner/repo or https://yoursite.com" value="${esc(state.link || "")}" aria-label="Link to scan">
      <div class="row"><button class="btn" data-act="scanLink" ${data.busy.link ? "disabled" : ""}>${data.busy.link ? "Scanning…" : "Scan link"}</button>
      <button class="btn ghost" data-act="a11y" ${data.busy.link ? "disabled" : ""}>WCAG check only</button></div>`;
    if (data.linkError) out += `<p class="err">${esc(data.linkError)}</p>`;
    if (r) {
      const m = r.meta || {};
      const bits = [r.kind === "repo" ? "GitHub repo" : "Website", ...(m.stack || []), m.files ? `${m.files} files` : "", m.scripts ? `${m.scripts} scripts` : "", m.source_maps ? `${m.source_maps} source files exposed` : ""].filter(Boolean);
      out += `<div class="meta">Detected: ${esc(bits.join(" · "))}</div>`;
      if (r.security_score !== undefined) out += `<div class="subscores"><div><strong style="color:${scoreColor(r.security_score)}">${r.security_score}</strong>security</div><div><strong style="color:${scoreColor(r.a11y_score)}">${r.a11y_score}</strong>accessibility</div></div>`;
      else if (r.a11y_score !== undefined) out += `<div class="subscores"><div><strong style="color:${scoreColor(r.a11y_score)}">${r.a11y_score}</strong>accessibility</div><div><strong>${r.findings.length}</strong>WCAG issues</div></div>`;
      if (m.ai_endpoints && m.ai_endpoints.length) out += `<div class="meta">AI endpoints seen in bundles: ${esc(m.ai_endpoints.join(", "))}</div>`;
      (r.notes || []).forEach((n) => (out += `<div class="note">${esc(n)}</div>`));
      (r.errors || []).forEach((e) => (out += `<p class="err">${esc(e)}</p>`));
      out += r.findings.map(findingHtml).join("") || `<p class="muted">No issues found.</p>`;
    }
    $("#linkview").innerHTML = out;
    const input = $("#link");
    input.addEventListener("input", () => { state.link = input.value; vscode.setState(state); });
    input.addEventListener("keydown", (e) => { if (e.key === "Enter") send("scanLink", { link: input.value }); });
  }

  // ---------- traces + cost ----------
  const ms = (n) => (n >= 1000 ? (n / 1000).toFixed(2) + "s" : n + "ms");
  const usd = (n) => (n == null ? "–" : n === 0 ? "$0" : n < 0.01 ? "$" + n.toFixed(4) : "$" + n.toFixed(2));

  function tracingOff(t) {
    return `<p class="muted">${esc(t?.reason || "Loading…")}</p>
      <div class="row"><button class="btn" data-act="startTracing">Start AI tracing</button><button class="btn ghost" data-act="traceApp">Trace my app</button></div>
      <p class="muted">Tracing runs a local MLflow server on 127.0.0.1. "Trace my app" adds a dev-only file so your app's AI calls show up here with latency, errors, tokens, model, provider and cost.</p>`;
  }

  function hoursPicker() {
    const h = state.hours || 24;
    return `<label class="meta">Period <select id="hours">${[1, 24, 168, 720].map((v) => `<option value="${v}" ${v === h ? "selected" : ""}>${{ 1: "last hour", 24: "last 24h", 168: "last 7 days", 720: "last 30 days" }[v]}</option>`).join("")}</select></label>`;
  }

  function renderTraces() {
    const t = data.traces;
    if (!t || !t.available) { $("#traceview").innerHTML = tracingOff(t); return; }
    const s = t.summary;
    const rows = t.rows.slice(0, 60).map((r) => `<div class="trace">
        <div class="top"><b title="${esc(r.input_preview)}">${esc(r.endpoint)}</b><span>${new Date(r.time).toLocaleTimeString()}</span></div>
        <div>${esc(r.model)} · ${esc(r.provider)}</div>
        <div class="muted">${ms(r.latency_ms)} · ${r.input_tokens}/${r.output_tokens} tok · ${usd(r.cost_usd)}</div>
        <div>${r.status === "ERROR" ? '<span class="tag err">ERROR</span>' : ""}${r.flags.map((f) => `<span class="tag">${esc(f.replace(/_/g, " "))}</span>`).join("")}</div>
      </div>`).join("");
    $("#traceview").innerHTML = `${hoursPicker()}
      <div class="kpis">
        <div><strong>${s.requests}</strong>requests</div>
        <div><strong style="color:${s.error_rate > 5 ? "var(--vc-red)" : s.error_rate > 0 ? "var(--vc-amber)" : "var(--vc-teal)"}">${s.error_rate}%</strong>errors</div>
        <div><strong>${ms(s.p50_ms)} / ${ms(s.p95_ms)}</strong>p50 / p95</div>
        <div><strong>${s.tokens_per_trace.toLocaleString()}</strong>tokens / trace</div>
      </div>
      ${s.flagged ? `<div class="alert">⚠ ${s.flagged} trace(s) flagged by the security guard</div>` : ""}
      ${rows || '<p class="muted">No traces in this period. Run your app with tracing on.</p>'}
      <div class="row"><button class="btn ghost" data-act="openMlflow">Open in MLflow</button></div>`;
    $("#hours").addEventListener("change", (e) => { state.hours = Number(e.target.value); vscode.setState(state); send("traces", { hours: state.hours }); });
  }

  function barChart(obj) {
    const entries = Object.entries(obj).slice(0, 6);
    if (!entries.length) return '<p class="muted">No priced calls yet.</p>';
    const max = Math.max(...entries.map(([, v]) => v)) || 1;
    const W = 260, label = 96, bar = W - label - 60;
    const rows = entries.map(([k, v], i) => {
      const y = i * 24 + 4;
      const w = Math.max(1.5, (v / max) * bar);
      return `<text x="0" y="${y + 12}" font-size="10">${esc(k.length > 15 ? k.slice(0, 14) + "…" : k)}</text>
        <rect x="${label}" y="${y}" width="${w.toFixed(1)}" height="14" rx="2" fill="var(--vc-teal)"></rect>
        <text x="${(label + w + 4).toFixed(1)}" y="${y + 11}" font-size="10" style="fill:var(--vc-fg)">${usd(v)}</text>`;
    }).join("");
    return `<svg viewBox="0 0 ${W} ${entries.length * 24 + 6}" width="100%" role="img" aria-label="Cost breakdown">${rows}</svg>`;
  }

  function lineChart(obj, fmt) {
    const entries = Object.entries(obj);
    if (entries.length < 2) return `<p class="muted">${entries.length ? "Need at least two days of data." : "No data yet."}</p>`;
    const W = 260, H = 110, L = 40, B = 18, T = 8;
    const vals = entries.map(([, v]) => v);
    const max = Math.max(...vals) || 1;
    const x = (i) => L + (i * (W - L - 6)) / (entries.length - 1);
    const y = (v) => T + (H - T - B) * (1 - v / max);
    const pts = vals.map((v, i) => `${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(" ");
    const last = vals.length - 1;
    return `<svg viewBox="0 0 ${W} ${H}" width="100%" role="img" aria-label="Trend over time">
      <line x1="${L}" y1="${y(max)}" x2="${W - 6}" y2="${y(max)}" stroke="var(--vc-line)"></line>
      <line x1="${L}" y1="${y(0)}" x2="${W - 6}" y2="${y(0)}" stroke="var(--vc-line)"></line>
      <text x="${L - 4}" y="${y(max) + 3}" font-size="9" text-anchor="end">${fmt(max)}</text>
      <text x="${L - 4}" y="${y(0) + 3}" font-size="9" text-anchor="end">${fmt(0)}</text>
      <polygon points="${x(0)},${y(0)} ${pts} ${x(last)},${y(0)}" fill="var(--vc-teal)" opacity=".14"></polygon>
      <polyline points="${pts}" fill="none" stroke="var(--vc-teal)" stroke-width="2"></polyline>
      <circle cx="${x(last)}" cy="${y(vals[last])}" r="3.5" fill="var(--vc-teal)"></circle>
      <text x="${L}" y="${H - 4}" font-size="9">${esc(entries[0][0].slice(5))}</text>
      <text x="${W - 6}" y="${H - 4}" font-size="9" text-anchor="end">${esc(entries[last][0].slice(5))}</text>
    </svg>`;
  }

  function renderCost() {
    const t = data.traces;
    if (!t || !t.available) { $("#costview").innerHTML = tracingOff(t); return; }
    const c = t.cost;
    const budget = data.budget || 0;
    $("#costview").innerHTML = `${hoursPicker()}
      <div class="kpis">
        <div><strong>${usd(c.total_usd)}</strong>total</div>
        <div><strong>${usd(c.avg_per_trace_usd)}</strong>per trace</div>
        <div><strong style="color:${budget && c.projected_month_usd > budget ? "var(--vc-amber)" : "var(--vc-fg)"}">${usd(c.projected_month_usd)}</strong>projected / month</div>
        <div><strong>${c.priced_traces}</strong>priced calls</div>
      </div>
      ${budget && c.projected_month_usd > budget ? `<div class="alert">⚠ On track for ${usd(c.projected_month_usd)} this month, over your ${usd(budget)} budget.</div>` : ""}
      ${c.unpriced_traces ? `<p class="meta">${c.unpriced_traces} call(s) have no price for their model. Add it to ~/.vibecheck/prices.json.</p>` : ""}
      <div class="chart"><h4>Cost by model</h4>${barChart(c.by_model)}</div>
      <div class="chart"><h4>Cost by provider</h4>${barChart(c.by_provider)}</div>
      <div class="chart"><h4>Cost by endpoint</h4>${barChart(c.by_endpoint)}</div>
      <div class="chart"><h4>Cost per day</h4>${lineChart(c.by_day, usd)}</div>
      <div class="chart"><h4>Tokens per day</h4>${lineChart(c.tokens_by_day, (n) => (n >= 1000 ? (n / 1000).toFixed(0) + "k" : String(n)))}</div>`;
    $("#hours").addEventListener("change", (e) => { state.hours = Number(e.target.value); vscode.setState(state); send("traces", { hours: state.hours }); });
  }

  // ---------- audit ----------
  function renderAudit() {
    const a = data.audit;
    if (!a) { $("#auditview").innerHTML = '<p class="muted">Loading…</p>'; return; }
    const c = a.chain;
    const entries = a.entries.map((e) => `<div class="entry"><span class="node"></span><div>
        <p>${esc(e.action.replace(".", ": "))}</p>
        <small>${new Date(e.ts * 1000).toLocaleString()} · ${esc(e.actor)} · ${esc(JSON.stringify(e.detail).slice(0, 140))}</small><br>
        <small>${esc(e.hash.slice(0, 12))}…</small></div></div>`).join("");
    $("#auditview").innerHTML = `
      <div class="${c.ok ? "chain-ok" : "chain-bad"}">${c.ok ? `✓ Chain verified · ${c.entries} entries` : `✗ Chain broken at entry ${c.broken_at}. History was edited.`}</div>
      <div class="row"><button class="btn ghost" data-act="verify">Verify again</button>
        <button class="btn" data-act="export" data-format="html">Export report</button>
        <button class="btn ghost" data-act="export" data-format="json">JSON</button>
        <button class="btn ghost" data-act="export" data-format="csv">CSV</button></div>
      ${entries || '<p class="muted">Nothing logged yet.</p>'}`;
  }

  function renderAll() {
    renderVault();
    renderLink();
    renderTraces();
    renderCost();
    renderAudit();
  }

  // ---------- events ----------
  document.body.addEventListener("click", (e) => {
    const t = e.target.closest("button, [data-open]");
    if (!t) return;
    if (t.dataset.filter) { state.filter = t.dataset.filter; vscode.setState(state); renderVault(); return; }
    if (t.dataset.fix) return send("fix", { id: t.dataset.fix });
    if (t.dataset.ignore) return send("ignore", { id: t.dataset.ignore });
    if (t.dataset.open) return send("open", { id: t.dataset.open });
    const act = t.dataset.act;
    if (act === "scanLink") return send("scanLink", { link: $("#link").value });
    if (act === "a11y") return send("a11y", { url: $("#link").value });
    if (act === "export") return send("export", { format: t.dataset.format });
    if (act) send(act);
  });

  window.addEventListener("message", (e) => {
    const m = e.data;
    if (m.type === "state") {
      Object.assign(data, m.data);
      renderAll();
    }
  });

  showTab(state.tab || "vault");
  renderAll();
  send("ready");
})();
