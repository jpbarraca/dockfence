/* dockfence WebUI — vanilla JS, no external deps */
let toastTimer = null;
function toast(msg, isError) {
  const t = document.getElementById("toast");
  if (!t) return;
  t.textContent = msg;
  t.classList.toggle("error", !!isError);
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, isError ? 6000 : 3000);
}
async function jfetch(url, opts) {
  const r = await fetch(url, opts);
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || (r.status + " " + r.statusText));
  return data;
}
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const fwSpan = (fw) => `<span class="fw-${fw}">${esc(fw)}</span>`;
const ts = (t) => new Date(t * 1000).toLocaleTimeString();

/* ---- containers page ---- */
async function refreshContainers() {
  let rows;
  try { rows = await jfetch("/api/containers"); }
  catch (e) { return; }
  const tb = document.querySelector("#containers tbody");
  if (!tb) return;
  tb.innerHTML = rows.map((c) => `
    <tr>
      <td><a href="/containers/${c.id}"><b>${esc(c.name)}</b></a>${c.self ? ' <span class="badge">this is dockfence</span>' : ""}<br><span class="muted small">${esc(c.image)}</span></td>
      <td>${c.policy ? `<span class="badge">${esc(c.policy)}</span>` : '<span class="muted">—</span>'}</td>
      <td>${fwSpan(c.fw)}${c.unfilterable_reason ? `<br><span class="muted small">${esc(c.unfilterable_reason)}</span>` : ""}</td>
      <td>${c.networks.map((n) => `${esc(n.name)}: ${esc(n.v4 || n.v6 || "—")} <span class="muted">(gw ${esc(n.gateway4 || n.gateway6 || "—")})</span>`).join("<br>")}</td>
      <td>${c.ports.map((p) => `${esc(p.host)} → ${esc(p.container)}`).join("<br>") || '<span class="muted">—</span>'}</td>
      <td>${(c.blocked_in || c.blocked_out) ? `<a href="/containers/${c.id}" title="${c.blocked_24h} blocked in 24h">${c.blocked_in ?? 0} in / ${c.blocked_out ?? 0} out</a>` : "0"}</td>
      <td>${c.rules_total}</td>
    </tr>`).join("");
}
function initContainersPage() {
  refreshContainers();
  loadTopology();
  setInterval(refreshContainers, 5000);
  setInterval(loadTopology, 5000);
}

/* ---- frontpage topology: membership graph —
   containers ↔ every network they belong to ↔ dockfence (in every network) ↔ internet ---- */
const TOPO_W = 990;
const TOPO_ROWS = {
  inet: { y: 16, h: 30 },
  main: { y: 96, h: 44 },
  net: { y: 190, h: 26 },
  cont: { y: 256, h: 26 },
};

function fitLabel(label, w) {
  const max = Math.max(3, Math.floor((w - 14) / 8));
  return label.length > max ? label.slice(0, max - 1) + "…" : label;
}

function topoBox(cx, r, w, label, cls, sub, tip, rx) {
  const mid = r.y + r.h / 2;
  return `<g class="tnode ${cls || ""}">` +
    (tip ? `<title>${esc(tip)}</title>` : "") +
    `<rect x="${cx - w / 2}" y="${r.y}" width="${w}" height="${r.h}" rx="${rx == null ? 7 : rx}"/>` +
    `<text x="${cx}" y="${sub ? mid - 2 : mid + 4}">${esc(label)}</text>` +
    (sub ? `<text class="sub" x="${cx}" y="${mid + 12}">${esc(sub)}</text>` : "") +
    "</g>";
}

function renderTopology(containers, edges, health) {
  const svg = document.getElementById("topo");
  if (!svg) return;
  const note = document.getElementById("topo-note");
  const W = TOPO_W, R = TOPO_ROWS, mainX = W / 2;
  const H = R.cont.y + R.cont.h + 30;
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  const byId = new Map();
  const nets = new Map();                     // name -> network node
  for (const c of containers) {
    if (c.self) continue;                     // dockfence IS the main fw node
    byId.set(c.id, c);
    const list = c.networks && c.networks.length ? c.networks : [{ name: "(default)" }];
    c._nets = new Set();
    c._net0 = null;
    for (const n of list) {
      if (!nets.has(n.name)) nets.set(n.name, { name: n.name, members: [], gw: n.gateway4 || n.gateway6 || "" });
      const g = nets.get(n.name);
      if (!g.gw) g.gw = n.gateway4 || n.gateway6 || "";
      if (!g.members.includes(c)) g.members.push(c);
      c._nets.add(n.name);
      if (!c._net0) c._net0 = g;
    }
  }
  const parts = [];
  parts.push("<defs>" + ["acc", "err", "ok"].map((k) =>
    `<marker id="arw-${k}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto"><path d="M0 0L10 5L0 10z" fill="var(--${k})"/></marker>`
  ).join("") + "</defs>");

  // layout: containers ordered so that networks' member groups sit together,
  // networks evenly spaced in barycenter order — two refinement passes
  let order = [];
  for (const g of [...nets.values()].sort((a, b) => b.members.length - a.members.length || a.name.localeCompare(b.name))) {
    for (const c of g.members) if (!order.includes(c)) order.push(c);
  }
  const meanRank = (c, rank) => [...c._nets].reduce((s, n) => s + rank.get(n), 0) / c._nets.size;
  for (let pass = 0; pass < 2; pass++) {
    const idx = new Map(order.map((c, i) => [c, i]));
    for (const g of nets.values()) g.bary = g.members.reduce((a, c) => a + idx.get(c), 0) / g.members.length;
    const byBary = [...nets.values()].sort((a, b) => a.bary - b.bary || a.name.localeCompare(b.name));
    byBary.forEach((g, i) => { g.slot = i; });
    const rank = new Map(byBary.map((g, i) => [g.name, i]));
    order.sort((a, b) => meanRank(a, rank) - meanRank(b, rank) || idx.get(a) - idx.get(b));
  }
  const slot = W / Math.max(1, order.length);
  order.forEach((c, j) => { c._x = slot * (j + 0.5); });
  const nNets = Math.max(1, nets.size);
  for (const g of nets.values()) {
    g.cx = ((g.slot + 1) * W) / (nNets + 1);
    g.netW = Math.min(g.name.length * 9 + 30, Math.max(44, W / (nNets + 1) - 12)); // +30: room for "◇ " prefix
  }
  const midY = (r) => r.y + r.h / 2;

  // structural links (gray), drawn first: dockfence sits in every network,
  // each container links to every network it belongs to
  const line = (x1, y1, x2, y2) => parts.push(`<line class="tstruct" x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}"/>`);
  line(mainX, R.inet.y + R.inet.h, mainX, R.main.y);
  for (const g of nets.values()) {
    line(mainX, R.main.y + R.main.h, g.cx, R.net.y);
    for (const c of g.members) line(g.cx, R.net.y + R.net.h, c._x, R.cont.y);
  }

  // live edges: one polyline per edge, routed through the nodes on the real path
  const color = (kind, e) => (kind === "internal" ? "ok" : e.dir === "out" ? "acc" : "err");
  const liveEdge = (pts, kind, e, tip) => {
    const k = color(kind, e);
    const w = (1.5 + Math.min(4, Math.log2((e.count || 1) + 1))).toFixed(1);
    const d = pts.map((p, i) => (i ? "L" : "M") + p[0].toFixed(1) + " " + p[1].toFixed(1)).join(" ");
    parts.push(`<g><title>${esc(tip)}</title><path d="${d}" fill="none" stroke="var(--${k})" stroke-width="${w}" opacity="${e.established ? 0.85 : 0.5}"${e.established ? "" : ' stroke-dasharray="5 4"'} marker-end="url(#arw-${k})"/></g>`);
  };
  const netPt = (g, dx) => [g.cx + (dx || 0), midY(R.net)];
  const mainPt = (dx) => [mainX + (dx || 0), midY(R.main)];

  // external: container → its network → dockfence → internet
  const ext = edges.external || [];
  const perNet = new Map(), seq = new Map();
  for (const e of ext) {
    const c = byId.get(e.cid);
    const g = c && ((e.net && nets.get(e.net)) || c._net0);
    if (g) perNet.set(g.name, (perNet.get(g.name) || 0) + 1);
  }
  const inetX = (i) => mainX + (ext.length > 1 ? (i - (ext.length - 1) / 2) * Math.min(18, 96 / ext.length) : 0);
  ext.forEach((e, i) => {
    const c = byId.get(e.cid);
    if (!c) return;
    const g = (e.net && nets.get(e.net)) || c._net0;
    let offA = 0;
    if (g) {
      const n = perNet.get(g.name), j = seq.get(g.name) || 0;
      seq.set(g.name, j + 1);
      const clamp = g.netW / 2 - 8;
      offA = n > 1 ? Math.max(-clamp, Math.min(clamp, (j - (n - 1) / 2) * 14)) : 0;
    }
    const xe = inetX(i);
    const pts = [
      [c._x, R.cont.y],
      ...(g ? [netPt(g, offA)] : []),
      mainPt(g ? (xe - mainX) * 0.4 : 0),
      [xe, R.inet.y + R.inet.h],
    ];
    const tip = `${c.name} ${e.dir === "out" ? "→ internet" : "← internet"}${e.net ? " via " + e.net : ""} · ${e.proto} · ${e.count} session(s), ${e.established} established`;
    liveEdge(e.dir === "out" ? pts : pts.slice().reverse(), "external", e, tip);
  });

  // internal: via the network the flow was delivered on; through the main fw
  // only when the endpoints do not share that network (L3 routing)
  for (const e of edges.internal || []) {
    const s = byId.get(e.src), d = byId.get(e.dst);
    if (!s || !d) continue;
    const g = e.net && nets.get(e.net);
    let pts;
    if (g && s._nets.has(e.net)) {
      pts = [[s._x, R.cont.y], netPt(g), [d._x, R.cont.y]];                    // shared L2
    } else if (g) {
      const src = s._net0 ? [netPt(s._net0)] : [];
      pts = [[s._x, R.cont.y], ...src, mainPt(0), netPt(g), [d._x, R.cont.y]]; // L3 via main fw
    } else {
      pts = [[s._x, R.cont.y], mainPt(0), [d._x, R.cont.y]];
    }
    liveEdge(pts, "internal", e, `${s.name} ↔ ${d.name} · ${e.proto} · ${e.count} session(s), ${e.established} established`);
  }

  // nodes on top of all lines
  parts.push(topoBox(mainX, R.inet, 120, "\u2601\uFE0E internet", "inet-node", "", "outside network", R.inet.h / 2));
  parts.push(topoBox(mainX, R.main, 180, "dockfence", "fw-node", `mode: ${(health && health.mode) || "?"}`,
    "nftables firewall — attached to every network, routes between them and to the internet"));
  for (const g of nets.values()) {
    parts.push(topoBox(g.cx, R.net, g.netW, "\u25C7 " + fitLabel(g.name, g.netW - 16), "net-node", "",
      `docker network · ${g.members.length} container(s) · gateway ${esc(g.gw || "—")}`, R.net.h / 2));
  }
  for (const c of byId.values()) {
    const w = Math.max(40, Math.min(150, c.name.length * 8 + 16, slot - 6));
    const label = fitLabel(c.name, w);
    parts.push(`<a href="/containers/${c.id}"><g class="tnode fws-${esc(c.fw)}"><title>${esc(c.image || c.name)} · fw: ${esc(c.fw)}${c.policy ? " · policy: " + esc(c.policy) : ""}${c._nets.size ? " · nets: " + esc([...c._nets].join(", ")) : ""}</title><rect x="${c._x - w / 2}" y="${R.cont.y}" width="${w}" height="${R.cont.h}" rx="7"/><text x="${c._x}" y="${R.cont.y + 17}">${esc(label)}</text></g></a>`);
  }
  parts.push(`<text class="legend" x="12" y="${H - 8}"><tspan fill="var(--acc)">—</tspan> out <tspan fill="var(--err)">—</tspan> in <tspan fill="var(--ok)">—</tspan> container↔container · dashed = no established session · thickness = sessions · \u25C7 network · \u2601\uFE0E outside · box = container</text>`);
  svg.innerHTML = parts.join("");
  if (note) {
    note.textContent = !edges.available
      ? `· conntrack unavailable: ${edges.error || "unknown"}`
      : `live now: ${(edges.internal || []).length} internal, ${(edges.external || []).length} external edge(s)`;
  }
}

async function loadTopology() {
  try {
    const [containers, edges, health] = await Promise.all([
      jfetch("/api/containers"), jfetch("/api/edges"), jfetch("/api/health"),
    ]);
    renderTopology(containers, edges, health);
  } catch (e) { /* transient */ }
}

/* ---- header toggles: logging / dns capture (both default off) ---- */
function initToggles() {
  const wire = (el, key, label) => {
    if (!el) return;
    el.onclick = async () => {
      el.disabled = true;
      try {
        const cur = await jfetch("/api/settings");
        const next = !cur[key];
        await jfetch("/api/settings", { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ [key]: next }) });
        toast(`${label} ${next ? "enabled" : "disabled"}`);
        setTimeout(() => location.reload(), 300);
      } catch (e) {
        toast(e.message, true);
        el.disabled = false;
      }
    };
  };
  wire(document.getElementById("toggle-logging"), "logging", "logging");
  wire(document.getElementById("toggle-dns"), "dns_log", "dns answer capture");
}

/* ---- dns page: learned name<->ip mappings + recent answers ---- */
async function loadDns() {
  const tb = document.querySelector("#dns-names tbody");
  if (!tb) return;
  try {
    const q = document.getElementById("dns-q").value.trim();
    const rows = await jfetch("/api/dns" + (q ? "?q=" + encodeURIComponent(q) : ""));
    tb.innerHTML = rows.map((r) => `
      <tr>
        <td>${esc(r.name)}</td><td><code>${esc(r.ip)}</code></td>
        <td class="muted">${esc(r.resolver)}</td><td>${r.hits}</td>
        <td class="muted">${ts(r.last_seen)}</td>
      </tr>`).join("")
      || '<tr><td colspan="5" class="muted">nothing learned yet — enable dns capture in the header and let containers resolve names</td></tr>';
  } catch (e) { /* transient */ }
}
async function loadDnsRecent() {
  const tb = document.querySelector("#dns-recent tbody");
  if (!tb) return;
  try {
    const rows = await jfetch("/api/dns/recent");
    tb.innerHTML = rows.map((r) => `
      <tr><td class="muted">${ts(r.ts)}</td><td>${esc(r.name)}</td>
      <td><code>${esc(r.ip)}</code></td><td class="muted">${esc(r.resolver)}</td></tr>`).join("")
      || '<tr><td colspan="4" class="muted">no answers captured yet</td></tr>';
  } catch (e) { /* transient */ }
}
function initDnsPage() {
  loadDns();
  loadDnsRecent();
  const q = document.getElementById("dns-q");
  let t;
  q.oninput = () => { clearTimeout(t); t = setTimeout(loadDns, 250); };
  document.getElementById("dns-clear").onclick = async () => {
    if (!confirm("Forget all learned DNS names and recent answers?")) return;
    try {
      await jfetch("/api/dns", { method: "DELETE" });
      toast("dns mappings cleared");
    } catch (e) {
      toast(e.message, true);
      return;
    }
    loadDns();
    loadDnsRecent();
  };
  setInterval(loadDnsRecent, 10000);
}

/* ---- container detail ---- */
function fmtBytes(n) {
  if (!n) return "0";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0, v = n;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return (i === 0 ? v : v.toFixed(1)) + " " + units[i];
}

async function loadCounters(cid) {
  try {
    const data = await jfetch(`/api/containers/${cid}/counters`);
    for (const row of data.counters || []) {
      const el = document.getElementById(`ctr-${row.rule_id}`);
      if (el) el.textContent = `${row.packets} / ${fmtBytes(row.bytes)}`;
    }
  } catch (e) { /* transient */ }
}

function remoteCell(r) {
  if (r.dns) {
    const ips = [...((r.dns_ips || {})["4"] || []), ...((r.dns_ips || {})["6"] || [])];
    const tip = ips.length ? esc(ips.join(", ")) : "no IPs observed yet";
    return `<code title="${tip}">dns:${esc(r.dns)}</code> <span class="muted">(${ips.length})</span>`;
  }
  return r.cidr ? "<code>" + esc(r.cidr) + "</code>" : '<span class="muted">any</span>';
}

async function loadRules(cid) {
  const rules = await jfetch(`/api/containers/${cid}/rules`);
  const tb = document.querySelector("#rules tbody");
  tb.innerHTML = rules.length ? rules.map((r) => `
    <tr>
      <td>${r.position}</td>
      <td>${esc(r.direction)}</td><td>${esc(r.proto)}</td>
      <td>${r.port ? esc(r.port_end && r.port_end !== r.port ? r.port + "-" + r.port_end : r.port) : "—"}</td>
      <td>${remoteCell(r)}</td>
      <td class="${r.action === "accept" ? "fw-active" : "fw-error"}">${esc(r.action)}</td>
      <td><input type="checkbox" ${r.enabled ? "checked" : ""} onchange="toggleRule(${r.id}, this.checked)"></td>
      <td>${esc(r.comment)}</td>
      <td class="muted" id="ctr-${r.id}">—</td>
      <td><button class="danger" onclick="delRule(${r.id})">del</button></td>
    </tr>`).join("") : '<tr><td colspan="10" class="muted">no rules — everything blocked by default</td></tr>';
  // dns rules need the capture to learn IPs — warn once when it is off
  const warn = document.getElementById("dns-warn");
  if (warn) {
    if (!rules.some((r) => r.dns)) {
      warn.hidden = true;
    } else {
      try {
        const s = await jfetch("/api/settings");
        warn.hidden = !!s.dns_log;
        warn.textContent = "⚠ dns capture is off — dns rules cannot learn new IPs (toggle dns in the header)";
      } catch (e) { warn.hidden = true; }
    }
  }
  loadCounters(cid);
}
async function toggleRule(id, enabled) {
  await jfetch(`/api/rules/${id}`, { method: "PATCH", headers: {"Content-Type": "application/json"}, body: JSON.stringify({ enabled }) });
}
async function delRule(id) {
  await jfetch(`/api/rules/${id}`, { method: "DELETE" });
  location.reload();
}
async function loadPresets(cid) {
  const box = document.getElementById("presets");
  if (!box) return;
  try {
    const ps = await jfetch("/api/presets");
    box.innerHTML = ps.map((p) =>
      `<button class="link" data-preset="${esc(p.name)}" title="${esc(p.description)}">${esc(p.label)}</button>`
    ).join(" · ");
    box.querySelectorAll("[data-preset]").forEach((b) => {
      b.onclick = async () => {
        try {
          const res = await jfetch(`/api/containers/${cid}/presets/${b.dataset.preset}`, { method: "POST" });
          toast(`preset applied: ${res.added.length} rule(s) added, ${res.skipped} already present`);
        } catch (e) {
          toast(e.message, true);
          return;
        }
        loadRules(cid);
      };
    });
  } catch (e) {
    box.textContent = "(presets unavailable)";
  }
}
function initContainerPage(cid) {
  loadRules(cid);
  loadLogs(cid);
  loadPresets(cid);
  loadSessions(cid);
  setInterval(() => loadSessions(cid), 5000);
  setInterval(() => loadCounters(cid), 5000);
  document.getElementById("f-apply").onclick = () => loadLogs(cid);
  // flush helper: drop the container's conntrack entries so rule changes
  // apply to established flows immediately (server needs the conntrack tool)
  document.getElementById("flush-btn").onclick = async () => {
    try {
      const res = await jfetch(`/api/containers/${cid}/flush`, { method: "POST" });
      if (res.available) {
        toast(`flushed: ${res.deleted} conntrack entr${res.deleted === 1 ? "y" : "ies"} deleted` +
              (res.errors && res.errors.length ? `, ${res.errors.length} command error(s)` : ""));
      } else {
        toast(res.error || "conntrack flush unavailable", true);
      }
      loadSessions(cid);
    } catch (e) {
      toast(String((e && e.message) || e), true);
    }
  };
  // allow-from-log dialog: submit creates an accept rule (server validates)
  const allowForm = document.getElementById("allow-form");
  allowForm.onsubmit = async (ev) => {
    ev.preventDefault();
    const f = ev.target;
    // remote side matches by cidr OR dns name, never both (server rejects both set)
    const byDns = f.querySelector("input[name=matchby]:checked").value === "dns";
    const body = {
      direction: f.direction.value, proto: f.proto.value, action: "accept",
      comment: f.comment.value,
      cidr: byDns ? "" : f.cidr.value.trim(),
      dns: byDns ? f.dns.value.trim() : "",
    };
    if (f.port.value) body.port = +f.port.value;
    if (f.port.value && f.port_end.value) body.port_end = +f.port_end.value;
    try {
      const res = await jfetch(`/api/containers/${cid}/rules`, { method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body) });
      document.getElementById("allow-dlg").close();
      const dport = res.port ? " dport " + res.port + (res.port_end && res.port_end !== res.port ? "-" + res.port_end : "") : "";
      toast(`allowed: ${res.direction} ${res.proto}${dport}${res.cidr ? " to " + res.cidr : res.dns ? " to dns:" + res.dns : ""}`);
    } catch (e) {
      toast(e.message, true);  // e.g. "proto 'tcp' requires a destination port"
      return;
    }
    loadRules(cid);
  };
  document.getElementById("allow-cancel").onclick = () => document.getElementById("allow-dlg").close();
  const allowProto = allowForm.querySelector("select[name=proto]");
  allowProto.onchange = () => {
    const noPorts = allowProto.value === "icmp";
    allowForm.querySelectorAll("[name=port], [name=port_end]").forEach((i) => { i.disabled = noPorts; });
  };
  // match-by radios: cidr and dns inputs are mutually exclusive (server rejects both)
  allowForm.querySelectorAll("input[name=matchby]").forEach((r) => { r.onchange = syncAllowMatchInputs; });
  // port fields only make sense for tcp/udp/any-with-port; icmp has no ports
  const protoSel = document.querySelector("#add-rule select[name=proto]");
  const syncPortFields = () => {
    const noPorts = protoSel.value === "icmp";
    document.querySelectorAll("#add-rule [name=port], #add-rule [name=port_end]").forEach((i) => {
      i.disabled = noPorts;
      i.title = noPorts ? "icmp has no destination ports" : "";
    });
  };
  protoSel.onchange = syncPortFields;
  syncPortFields();
  document.getElementById("add-rule").onsubmit = async (ev) => {
    ev.preventDefault();
    const f = ev.target;
    const body = {
      direction: f.direction.value, proto: f.proto.value, action: f.action.value,
      comment: f.comment.value, cidr: f.cidr.value, dns: f.dns.value,
    };
    if (f.port.value) body.port = +f.port.value;
    if (f.port_end.value) body.port_end = +f.port_end.value;
    try {
      await jfetch(`/api/containers/${cid}/rules`, { method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body) });
      f.reset();
      syncPortFields();
    } catch (e) {
      toast(e.message, true);  // e.g. "proto 'tcp' requires a destination port"
      return;
    }
    loadRules(cid);
  };
  document.querySelectorAll(".preset").forEach((b) => {
    b.onclick = async () => {
      const p = JSON.parse(b.dataset.p);
      const f = document.getElementById("add-rule");
      if (p.direction === "in") { // ingress preset: allow published ports incl. gateway cidr
        p.proto = "tcp";
        const ports = [...document.querySelectorAll("td code")].map(() => null); // ports listed above
        const hostPorts = window.__publishedPorts || [];
        p.port = hostPorts[0] || null;
      }
      try {
        const res = await jfetch(`/api/containers/${cid}/rules`, { method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(p) });
        toast(`rule added (${res.action} ${res.proto}${res.port ? " " + res.port : ""})`);
      } catch (e) {
        toast(e.message, true);
        return;
      }
      loadRules(cid);
    };
  });
  let es = null;
  const live = document.getElementById("f-live");
  live.onchange = () => {
    if (es) { es.close(); es = null; }
    if (live.checked) es = tailLogs(cid);
  };
  if (live.checked) es = tailLogs(cid);
}
function tailLogs(cid) {
  const es = new EventSource(`/api/logs/stream?container=${cid}`);
  es.onmessage = (ev) => {
    const r = JSON.parse(ev.data);
    prependLog(r);
  };
  return es;
}
async function loadLogs(cid) {
  const dir = document.getElementById("f-dir").value;
  const proto = document.getElementById("f-proto").value;
  const port = document.getElementById("f-port").value;
  const q = new URLSearchParams({limit: "100"});
  if (dir) q.set("direction", dir);
  if (proto) q.set("proto", proto);
  if (port) q.set("port", port);
  const rows = await jfetch(`/api/containers/${cid}/logs?` + q);
  document.querySelector("#logs tbody").innerHTML =
    rows.map(logRow).join("") || '<tr><td colspan="8" class="muted">no blocked attempts recorded</td></tr>';
}
function ipCell(ip, name) {
  return name ? `<code>${esc(ip)}</code><br><span class="muted small">≈ ${esc(name)}</span>`
              : `<code>${esc(ip)}</code>`;
}
/* per-row index so the allow button can reference the exact log entry */
const logIndex = new Map();
let logSeq = 0;

function logRow(r) {
  const i = logSeq++;
  logIndex.set(i, r);
  if (logIndex.size > 600) {  // bound memory on long live tails
    logIndex.delete(logIndex.keys().next().value);
  }
  return `<tr>
    <td class="muted">${ts(r.ts)}</td><td>${esc(r.dir)}</td>
    <td>${ipCell(r.src, r.src_name)}</td><td>${ipCell(r.dst, r.dst_name)}</td>
    <td>${esc(r.proto)}</td><td>${r.sport ?? "—"}</td><td>${r.dport ?? "—"}</td>
    <td><button class="link" onclick="allowFromLog(${i})" title="create an allow rule from this attempt">allow</button></td></tr>`;
}

/* allow-form match-by radios: the cidr and dns inputs are mutually exclusive
   (the server rejects a rule matching the remote side both ways) */
function syncAllowMatchInputs() {
  const f = document.getElementById("allow-form");
  if (!f) return;
  const checked = f.querySelector("input[name=matchby]:checked");
  const byDns = checked && checked.value === "dns";
  f.querySelector("[name=cidr]").disabled = byDns;
  f.querySelector("[name=dns]").disabled = !byDns;
}

/* allow-from-log: prefill the dialog with the exact flow — or widen it */
function allowFromLog(i) {
  const r = logIndex.get(i);
  if (!r) return;
  const dlg = document.getElementById("allow-dlg");
  if (!dlg) return;
  const f = document.getElementById("allow-form");
  const remote = r.dir === "in" ? r.src : r.dst;
  const remoteName = r.dir === "in" ? r.src_name : r.dst_name;
  f.direction.value = r.dir === "in" ? "in" : "out";
  f.proto.value = ["tcp", "udp", "icmp", "any"].includes(r.proto) ? r.proto : "any";
  f.port.value = r.dport ?? "";
  f.port_end.value = "";
  f.cidr.value = remote ? remote + (remote.includes(":") ? "/128" : "/32") : "";
  f.dns.value = remoteName || "";
  f.comment.value = remoteName ? `allowed from log (≈ ${remoteName})` : "allowed from log";
  // match the remote side by IP (cidr) or by the DNS name the capture attached to it —
  // a made-up name would match nothing, so the dns option needs an observed name
  const dnsOpt = document.getElementById("allow-dns-opt");
  dnsOpt.querySelector("input[name=matchby]").disabled = !remoteName;
  dnsOpt.title = remoteName ? "" : "no DNS name observed for this IP";
  dnsOpt.style.opacity = remoteName ? "" : ".55";
  f.matchby.value = "ip";  // default to the exact IP; pick dns to follow name changes
  syncAllowMatchInputs();
  document.getElementById("allow-desc").innerHTML =
    `<b>${esc(r.dir)}</b> ${esc(r.proto)} ${esc(remote)}${r.dport ? ":" + r.dport : ""}` +
    (remoteName ? ` <span class="muted">(≈ ${esc(remoteName)})</span>` : "") +
    (remoteName
      ? " — prefilled; allow by IP (cidr) or by DNS name, or widen to allow more."
      : " — prefilled; widen the cidr/port to allow more.");
  dlg.showModal();
}

function endpointCell(ip, port, name) {
  if (!ip) return '<span class="muted">—</span>';
  return `${ipCell(ip, name)}${port ? `<span class="muted small">:${port}</span>` : ""}`;
}

async function loadSessions(cid) {
  const tb = document.querySelector("#sessions tbody");
  if (!tb) return;
  try {
    const data = await jfetch(`/api/containers/${cid}/sessions`);
    if (!data.available) {
      tb.innerHTML = `<tr><td colspan="6" class="muted">conntrack not available: ${esc(data.error || "unknown error")}</td></tr>`;
      return;
    }
    tb.innerHTML = data.sessions.map((s) => `
      <tr>
        <td>${s.dir === "out" ? "→ out" : "← in"}</td>
        <td>${esc(s.proto)}</td>
        <td>${s.state ? `<span class="badge">${esc(s.state)}</span>` : '<span class="muted">—</span>'}${s.assured ? ' <span class="muted small">✓</span>' : ""}</td>
        <td>${endpointCell(s.src, s.sport, s.src_name)}</td>
        <td>${endpointCell(s.dst, s.dport, s.dst_name)}</td>
        <td class="muted">${s.timeout}s</td>
      </tr>`).join("")
      || '<tr><td colspan="6" class="muted">no active sessions right now</td></tr>';
  } catch (e) { /* transient */ }
}
function prependLog(r) {
  const tb = document.querySelector("#logs tbody");
  tb.insertAdjacentHTML("afterbegin", logRow(r));
  while (tb.children.length > 200) tb.lastChild.remove();
}

document.addEventListener("DOMContentLoaded", () => {
  initToggles();
  // stash published ports for the ingress preset
  const ul = document.querySelectorAll("ul code");
  if (ul.length) {
    window.__publishedPorts = [...ul].map((c) => parseInt(c.textContent.split(":").pop(), 10)).filter((n) => !isNaN(n) && n > 0);
  }
});
