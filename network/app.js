/* Kavach Network watch — synthetic demo, local agent reader and pcap importer.
 * No payloads are read. The agent exposes metadata-only flow summaries. */

(function () {
  "use strict";

  const LOCAL_HOST = "macbook-01";
  const LOCAL_IP = "192.168.1.24";

  const DEMO_REMOTES = [
    { ip: "10.20.4.15", name: "sap-s4-prod", vendor: "SAP", app: "SAP S/4HANA", port: 443, protocol: "TLS", risk: "low", weight: 18 },
    { ip: "10.20.4.10", name: "sap-web-disp", vendor: "SAP", app: "SAP Web Dispatcher", port: 443, protocol: "TLS", risk: "low", weight: 11 },
    { ip: "52.96.14.18", name: "outlook.office365.com", vendor: "Microsoft", app: "Microsoft 365", port: 443, protocol: "TLS", risk: "low", weight: 16 },
    { ip: "142.250.1.1", name: "dns.google", vendor: "Google", app: "DNS over TLS", port: 853, protocol: "TLS", risk: "low", weight: 7 },
    { ip: "192.168.1.1", name: "gateway", vendor: "Local", app: "DNS", port: 53, protocol: "UDP", risk: "low", weight: 9 },
    { ip: "10.30.7.22", name: "mqtt-broker", vendor: "Industrial", app: "MQTT", port: 1883, protocol: "TCP", risk: "medium", weight: 7 },
    { ip: "10.30.7.40", name: "plc-line-2", vendor: "Siemens", app: "Modbus/TCP", port: 502, protocol: "TCP", risk: "high", weight: 5 },
    { ip: "10.30.7.50", name: "historian", vendor: "Industrial", app: "IEC 60870-5-104", port: 102, protocol: "TCP", risk: "medium", weight: 4 },
    { ip: "140.82.112.3", name: "github.com", vendor: "GitHub", app: "GitHub", port: 443, protocol: "TLS", risk: "low", weight: 7 },
    { ip: "203.0.113.77", name: "unknown-203.0.113.77", vendor: "Unknown", app: "HTTPS", port: 443, protocol: "TLS", risk: "high", weight: 3 },
    { ip: "10.20.4.30", name: "fileserver", vendor: "Windows", app: "SMB", port: 445, protocol: "TCP", risk: "medium", weight: 5 },
    { ip: "10.20.4.12", name: "jump-host", vendor: "Linux", app: "SSH", port: 22, protocol: "TCP", risk: "medium", weight: 2 },
    { ip: "203.0.113.88", name: "unknown-203.0.113.88", vendor: "Unknown", app: "HTTP", port: 80, protocol: "TCP", risk: "high", weight: 1 },
  ];

  const state = {
    mode: "demo",
    paused: false,
    data: null,
    startedAt: Date.now(),
    timer: null,
    liveTimer: null,
    series: [],
    hosts: new Map(),
    protocols: new Map(),
    apps: new Map(),
    flows: [],
    alerts: [],
    packets: 0,
    drops: 0,
    lastAlertAt: new Map(),
    filter: { direction: "all", protocol: "all", app: "all", host: "" },
    importing: false,
  };

  const $ = (id) => document.getElementById(id);
  const palette = {
    warn: css("--warn", "#e8a33d"),
    info: css("--info", "#7fb0ff"),
    good: css("--good", "#4fd1c5"),
    bad: css("--bad", "#f97066"),
    muted: css("--muted", "#8fa9b7"),
    line: css("--line", "rgba(234,242,246,.14)"),
  };

  function css(name, fallback) {
    const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    return value || fallback;
  }

  function fmtBytes(bytes) {
    const n = Number(bytes) || 0;
    if (n < 1000) return `${Math.round(n)} B`;
    if (n < 1000 * 1000) return `${(n / 1000).toFixed(n < 10000 ? 1 : 0)} KB`;
    if (n < 1000 * 1000 * 1000) return `${(n / 1e6).toFixed(n < 1e7 ? 1 : 0)} MB`;
    return `${(n / 1e9).toFixed(1)} GB`;
  }

  function fmtTime(ts) {
    const value = Number(ts);
    if (!value) return "—";
    const d = new Date(value * 1000);
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  }

  function fmtStamp(ts) {
    const value = Number(ts);
    if (!value) return "—";
    const d = new Date(value * 1000);
    const now = new Date();
    if (d.toDateString() === now.toDateString()) return fmtTime(value);
    const options = { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", second: "2-digit" };
    if (d.getFullYear() !== now.getFullYear()) options.year = "numeric";
    return d.toLocaleString([], options);
  }

  function fmtSpan(start, end) {
    const first = Number(start);
    const last = Number(end);
    if (!first || !last) return "no timestamps";
    const a = new Date(first * 1000);
    const b = new Date(last * 1000);
    if (a.toDateString() === b.toDateString()) {
      return `${a.toLocaleDateString([], { day: "2-digit", month: "short" })}, ${fmtTime(first)} – ${fmtTime(last)}`;
    }
    return `${fmtStamp(first)} – ${fmtStamp(last)}`;
  }

  function shortName(value) {
    const text = String(value || "");
    return text.length > 38 ? `${text.slice(0, 18)}…${text.slice(-16)}` : text;
  }

  function riskRank(risk) {
    return risk === "high" ? 3 : risk === "medium" ? 2 : 1;
  }

  function riskLabel(risk) {
    const safe = risk === "high" || risk === "medium" || risk === "low" ? risk : "info";
    return `<span class="nw-risk ${safe}">${safe}</span>`;
  }

  function pickRemote() {
    const total = DEMO_REMOTES.reduce((sum, r) => sum + r.weight, 0);
    let n = Math.random() * total;
    for (const remote of DEMO_REMOTES) {
      n -= remote.weight;
      if (n <= 0) return remote;
    }
    return DEMO_REMOTES[0];
  }

  function addAlert(severity, title, detail, key) {
    const now = Date.now();
    const last = state.lastAlertAt.get(key) || 0;
    if (now - last < 45000) return;
    state.lastAlertAt.set(key, now);
    state.alerts.unshift({ severity, title, detail, time: now / 1000 });
    state.alerts = state.alerts.slice(0, 8);
  }

  function recordFlow(flow) {
    state.flows.unshift(flow);
    state.flows = state.flows.slice(0, 180);

    const remoteIp = flow.direction === "inbound" ? flow.srcIp : flow.dstIp;
    const remoteName = flow.direction === "inbound" ? flow.src : flow.dst;
    const remoteVendor = flow.vendor || "Unknown";
    if (remoteIp && remoteIp !== LOCAL_IP) {
      const host = state.hosts.get(remoteIp) || {
        ip: remoteIp,
        name: remoteName,
        vendor: remoteVendor,
        bytesIn: 0,
        bytesOut: 0,
        apps: new Set(),
        lastSeen: flow.ts,
        risk: flow.risk || "low",
      };
      if (flow.direction === "inbound") host.bytesIn += flow.bytes;
      else host.bytesOut += flow.bytes;
      host.apps.add(flow.app);
      host.lastSeen = Math.max(host.lastSeen, flow.ts);
      if (riskRank(flow.risk) > riskRank(host.risk)) host.risk = flow.risk;
      state.hosts.set(remoteIp, host);
    }

    state.protocols.set(flow.protocol, (state.protocols.get(flow.protocol) || 0) + flow.bytes);
    const app = state.apps.get(flow.app) || { bytes: 0, flows: 0 };
    app.bytes += flow.bytes;
    app.flows += 1;
    state.apps.set(flow.app, app);
  }

  function demoFlow(remoteOverride) {
    const remote = remoteOverride || pickRemote();
    const direction = remote.app === "Modbus/TCP" || remote.app === "IEC 60870-5-104"
      ? (Math.random() < 0.55 ? "outbound" : "inbound")
      : (Math.random() < 0.68 ? "outbound" : "inbound");
    const big = Math.random() < 0.08;
    const bytes = big ? 90000 + Math.floor(Math.random() * 900000) : 500 + Math.floor(Math.random() * 60000);
    const local = { name: LOCAL_HOST, ip: LOCAL_IP };
    const host = direction === "outbound" ? local : { name: remote.name, ip: remote.ip };
    const dst = direction === "outbound" ? { name: remote.name, ip: remote.ip } : local;
    let verdict = remote.risk === "high" ? "review" : remote.risk === "medium" ? "watch" : "normal";
    if (remote.protocol === "TCP" && remote.port === 80) verdict = "cleartext";
    if (remote.app === "Modbus/TCP" || remote.app === "IEC 60870-5-104") verdict = "OT boundary";

    return {
      ts: Date.now() / 1000,
      host: host.name,
      src: host.name,
      srcIp: host.ip,
      dst: dst.name,
      dstIp: dst.ip,
      vendor: remote.vendor,
      app: remote.app,
      protocol: remote.protocol,
      port: remote.port,
      direction,
      bytes,
      risk: remote.risk,
      verdict,
    };
  }

  function addDemoSample() {
    const remote = pickRemote();
    const flow = demoFlow(remote);
    recordFlow(flow);
    state.packets += 15 + Math.floor(Math.random() * 80);
    if (Math.random() < 0.01) state.drops += 1;

    if (remote.app === "HTTP") addAlert("critical", "Cleartext HTTP", `${remote.name} received an unencrypted request on port 80.`, `http:${remote.ip}`);
    if (remote.app === "Modbus/TCP") addAlert("high", "Modbus/TCP crossing the IT/OT boundary", `${LOCAL_HOST} opened a session to ${remote.name} (${remote.ip}:502).`, "modbus");
    if (remote.app === "IEC 60870-5-104") addAlert("high", "IEC 60870-5-104 session", `${LOCAL_HOST} reached the historian ${remote.name} on port 102.`, "iec104");
    if (remote.app === "MQTT") addAlert("info", "MQTT broker session", `${LOCAL_HOST} is publishing to ${remote.name} on port 1883.`, "mqtt");
    if (remote.vendor === "Unknown" && remote.app === "HTTPS") addAlert("high", "Unknown host contacted", `${remote.name} received outbound TLS from ${LOCAL_HOST}.`, `unknown:${remote.ip}`);
    if (remote.app === "SMB") addAlert("medium", "SMB file share", `${LOCAL_HOST} accessed ${remote.name} on port 445.`, "smb");

    const now = Date.now() / 1000;
    state.series.push({
      t: now,
      in: flow.direction === "inbound" ? flow.bytes : Math.floor(Math.random() * 24000),
      out: flow.direction === "outbound" ? flow.bytes : Math.floor(Math.random() * 18000),
    });
    if (state.series.length > 60) state.series.shift();
  }

  function buildDemoSnapshot() {
    const series = state.series.map((p) => ({ in: p.in, out: p.out }));
    return {
      mode: "demo",
      interface: "demo0",
      status: "capturing",
      updatedAt: Date.now() / 1000,
      stats: {
        packets: state.packets,
        flows: state.flows.length,
        drops: state.drops,
        hosts: state.hosts.size,
      },
      series,
      protocols: [...state.protocols.entries()].map(([name, bytes]) => ({ name, bytes })),
      apps: [...state.apps.entries()].map(([name, v]) => ({ name, bytes: v.bytes, flows: v.flows })),
      hosts: [...state.hosts.values()].map((h) => ({
        ip: h.ip, name: h.name, vendor: h.vendor, bytesIn: h.bytesIn, bytesOut: h.bytesOut,
        apps: [...h.apps], lastSeen: h.lastSeen, risk: h.risk,
      })),
      flows: state.flows.slice(0, 70),
      alerts: state.alerts.slice(0, 8),
    };
  }

  function aggregateLive(json) {
    // The agent already sends the dashboard shape. Normalise the optional fields.
    const flows = (json.flows || []).map((f) => ({
      ts: f.ts || f.lastSeen || Date.now() / 1000,
      firstSeen: f.firstSeen || f.ts || Date.now() / 1000,
      lastSeen: f.lastSeen || f.ts || Date.now() / 1000,
      host: f.host || f.src || "local",
      src: f.src || f.host || "local",
      srcIp: f.srcIp || f.src_ip || "",
      dst: f.dst || f.destination || "remote",
      dstIp: f.dstIp || f.dst_ip || "",
      vendor: f.vendor || "Unknown",
      app: f.app || "Other",
      protocol: f.protocol || "TCP",
      port: f.port || f.dport || 0,
      direction: f.direction || "outbound",
      bytes: f.bytes || 0,
      packets: f.packets || 1,
      risk: f.risk || "low",
      verdict: f.verdict || "normal",
    }));
    return {
      mode: "live",
      interface: json.interface || "en0",
      status: json.status || "capturing",
      error: json.error || "",
      updatedAt: json.updatedAt || Date.now() / 1000,
      captureHost: json.captureHost || "",
      stats: json.stats || { packets: 0, flows: flows.length, drops: 0, hosts: (json.hosts || []).length },
      series: json.series || [],
      protocols: json.protocols || [],
      apps: json.apps || [],
      hosts: json.hosts || [],
      flows,
      alerts: json.alerts || [],
    };
  }

  function setSource(mode, label, detail) {
    const pill = $("source-pill");
    const sourceLabel = $("source-label");
    const interfacePill = $("interface-pill");
    if (!pill || !sourceLabel || !interfacePill) return;
    pill.className = `nw-pill ${mode}`;
    sourceLabel.textContent = label;
    interfacePill.textContent = `Source · ${shortName(detail || "demo0")}`;
    interfacePill.title = detail || "";
  }

  function render(data) {
    state.data = data;
    const isFile = data.mode === "file";
    if (isFile) {
      state.mode = "file";
      setSource("file", "Imported capture", data.interface);
    } else if (data.mode === "live" && data.status === "error") {
      state.mode = "live";
      setSource("error", "Agent error", data.interface);
    } else if (data.mode === "live") {
      state.mode = "live";
      setSource("live", "Live agent", data.interface);
    } else {
      state.mode = "demo";
      setSource("demo", "Demo traffic", data.interface || "demo0");
    }
    const errorEl = $("source-error");
    if (errorEl) {
      if (data.error) {
        errorEl.textContent = data.error;
        errorEl.style.display = "block";
      } else {
        errorEl.textContent = "";
        errorEl.style.display = "none";
      }
    }

    const series = data.series || [];
    const hasTransitSeries = series.some((p) => (p.transit || 0) > 0);
    const hasTransitTotal = hasTransitSeries || Number(data.stats?.transit || 0) > 0;
    const updated = $("updated-pill");
    if (isFile) {
      updated.textContent = data.meta?.hasTimestamps ? `Capture · ${fmtStamp(data.updatedAt)}` : "Capture · no timestamps";
    } else {
      updated.textContent = `Updated · ${fmtTime(data.updatedAt)}`;
    }
    $("source-mode").textContent = isFile
      ? "Imported capture"
      : data.mode === "live"
        ? (data.status === "error" ? "Live agent · error" : "Live agent")
        : "Demo";
    $("source-interface").textContent = data.interface || "demo0";
    $("source-interface").title = data.interface || "";
    $("source-local").textContent = data.meta?.localIp || data.captureHost || "—";
    $("source-packets").textContent = Number(data.stats?.packets || 0).toLocaleString();
    $("source-flows").textContent = Number(data.stats?.flows || data.flows.length || 0).toLocaleString();
    const transitRow = $("source-transit-row");
    if (transitRow) {
      transitRow.hidden = !hasTransitTotal;
      $("source-transit").textContent = fmtBytes(data.stats?.transit || 0);
    }
    $("privacy-pill").textContent = isFile ? "Headers only · no upload" : "No payloads captured";
    $("source-drops").textContent = isFile ? "n/a" : Number(data.stats?.drops || 0).toLocaleString();
    $("source-updated").textContent = data.meta?.hasTimestamps === false ? "No timestamps" : fmtStamp(data.updatedAt);

    const inTotal = series.reduce((s, p) => s + (p.in || 0), 0);
    const outTotal = series.reduce((s, p) => s + (p.out || 0), 0);
    $("kpi-in").textContent = fmtBytes(inTotal);
    $("kpi-out").textContent = fmtBytes(outTotal);
    $("kpi-hosts").textContent = (data.hosts || []).length;
    $("kpi-flows").textContent = Number(data.stats?.flows ?? (data.flows || []).length).toLocaleString();
    $("kpi-flows-note").textContent = isFile || data.mode === "live" ? "unique conversations" : "sampled from capture";
    $("kpi-alerts").textContent = (data.alerts || []).length;

    const pause = $("pause-button");
    if (pause) {
      pause.disabled = isFile;
      pause.textContent = isFile ? "Static capture" : (state.paused ? "Resume view" : "Pause view");
    }
    $("chart-title").textContent = isFile ? "Throughput · last 60 seconds of capture" : "Throughput · last 60 seconds";
    $("chart-range").textContent = isFile && data.meta?.hasTimestamps
      ? fmtSpan(data.meta.start, data.meta.end)
      : "inbound / outbound";
    $("legend-transit").hidden = !hasTransitSeries;
    $("hosts-note").textContent = isFile
      ? "All endpoints · bytes across the imported capture"
      : "Remote hosts · bytes over the selected window";
    $("flow-note").textContent = isFile
      ? "Parsed locally · nothing uploaded · metadata only"
      : "Metadata only · no payload or credential capture";

    drawChart(series);
    renderProtocols(data.protocols || []);
    renderApps(data.apps || []);
    renderAlerts(data.alerts || []);
    renderHosts(data.hosts || []);
    populateFilters(data);
    renderFlows(data.flows || []);
  }

  function drawChart(series) {
    const canvas = $("traffic-chart");
    if (!canvas) return;
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    const width = Math.max(300, rect.width);
    const height = Math.max(160, rect.height);
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    const ctx = canvas.getContext("2d");
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, width, height);

    const pad = { top: 14, right: 8, bottom: 16, left: 8 };
    const w = width - pad.left - pad.right;
    const h = height - pad.top - pad.bottom;
    const values = series.map((p) => Math.max(p.in || 0, p.out || 0, p.transit || 0));
    const max = Math.max(1, ...values) * 1.15;

    ctx.strokeStyle = palette.line;
    ctx.lineWidth = 1;
    for (let i = 0; i < 4; i += 1) {
      const y = pad.top + (h / 3) * i;
      ctx.beginPath();
      ctx.moveTo(pad.left, y);
      ctx.lineTo(pad.left + w, y);
      ctx.stroke();
    }

    function line(key, color, fill) {
      if (!series.length) return;
      const step = series.length > 1 ? w / (series.length - 1) : w;
      ctx.beginPath();
      series.forEach((p, i) => {
        const x = pad.left + step * i;
        const y = pad.top + h - ((p[key] || 0) / max) * h;
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
      ctx.strokeStyle = color;
      ctx.lineWidth = 1.6;
      ctx.stroke();
      if (fill) {
        ctx.lineTo(pad.left + w, pad.top + h);
        ctx.lineTo(pad.left, pad.top + h);
        ctx.closePath();
        ctx.fillStyle = fill;
        ctx.fill();
      }
    }

    line("in", palette.warn, "rgba(232,163,61,.10)");
    line("out", palette.info, "rgba(127,176,255,.08)");
    if (series.some((p) => (p.transit || 0) > 0)) line("transit", palette.good, "rgba(79,209,197,.06)");
  }

  function renderProtocols(protocols) {
    const el = $("protocol-mix");
    if (!el) return;
    const total = protocols.reduce((s, p) => s + (p.bytes || 0), 0) || 1;
    const sorted = protocols.slice().sort((a, b) => b.bytes - a.bytes);
    const top = sorted.slice(0, 5);
    const other = sorted.slice(5).reduce((s, p) => s + p.bytes, 0);
    const rows = other > 0 ? [...top, { name: "Other", bytes: other }] : top;
    if (!rows.length) {
      el.innerHTML = '<p class="nw-empty">Waiting for traffic…</p>';
      return;
    }
    el.innerHTML = rows.map((p, i) => {
      const pct = Math.max(1, Math.round((p.bytes / total) * 100));
      const color = [palette.warn, palette.info, palette.good, "#b58cff", "#ff8fa3", palette.muted][i % 6];
      return `<div class="nw-mix-row"><strong>${escapeHtml(p.name)}</strong><span class="nw-mix-track"><span class="nw-mix-fill" style="width:${pct}%;background:${color}"></span></span><span class="pct">${pct}%</span></div>`;
    }).join("");
  }

  function renderApps(apps) {
    const el = $("top-apps");
    if (!el) return;
    const top = apps.slice().sort((a, b) => b.bytes - a.bytes).slice(0, 7);
    if (!top.length) {
      el.innerHTML = '<p class="nw-empty">Waiting for application flows…</p>';
      return;
    }
    el.innerHTML = top.map((a) => `<div class="nw-app-row"><b>${escapeHtml(a.name)}</b><span>${fmtBytes(a.bytes)} · ${a.flows || 0} flows</span></div>`).join("");
  }

  function renderAlerts(alerts) {
    const el = $("alerts");
    if (!el) return;
    if (!alerts.length) {
      el.innerHTML = state.data?.mode === "file"
        ? '<p class="nw-empty">No rule-based alerts in this capture.</p>'
        : '<p class="nw-empty">No open alerts. Keep watching.</p>';
      return;
    }
    el.innerHTML = alerts.slice(0, 6).map((a) => `<div class="nw-alert ${escapeHtml(a.severity || "info")}"><span class="bar"></span><div><p>${escapeHtml(a.title || "Alert")}</p><span>${escapeHtml(a.detail || "")} · ${fmtTime(a.time)}</span></div></div>`).join("");
  }

  function renderHosts(hosts) {
    const body = $("hosts-body");
    if (!body) return;
    const sorted = hosts.slice().sort((a, b) => (b.bytesIn + b.bytesOut) - (a.bytesIn + a.bytesOut)).slice(0, 12);
    if (!sorted.length) {
      body.innerHTML = '<tr><td colspan="7" class="nw-empty">Waiting for hosts…</td></tr>';
      return;
    }
    body.innerHTML = sorted.map((h) => `<tr>
      <td><strong>${escapeHtml(h.name || h.ip)}</strong></td>
      <td>${escapeHtml(h.ip || "")}</td>
      <td>${escapeHtml((h.apps || []).join(", ") || "—")}</td>
      <td class="num">${fmtBytes(h.bytesIn || 0)}</td>
      <td class="num">${fmtBytes(h.bytesOut || 0)}</td>
      <td>${fmtTime(h.lastSeen)}</td>
      <td>${riskLabel(h.risk || "low")}</td>
    </tr>`).join("");
  }

  function populateFilters(data) {
    const protocolSelect = $("filter-protocol");
    const appSelect = $("filter-app");
    if (!protocolSelect || !appSelect) return;
    const protocols = [...new Set((data.flows || []).map((f) => f.protocol).filter(Boolean))].sort();
    const apps = [...new Set((data.flows || []).map((f) => f.app).filter(Boolean))].sort();
    const currentProtocol = state.filter.protocol;
    const currentApp = state.filter.app;
    protocolSelect.innerHTML = '<option value="all">All</option>' + protocols.map((p) => `<option value="${escapeHtml(p)}">${escapeHtml(p)}</option>`).join("");
    appSelect.innerHTML = '<option value="all">All</option>' + apps.map((a) => `<option value="${escapeHtml(a)}">${escapeHtml(a)}</option>`).join("");
    protocolSelect.value = protocols.includes(currentProtocol) ? currentProtocol : "all";
    appSelect.value = apps.includes(currentApp) ? currentApp : "all";
  }

  function renderFlows(flows) {
    const body = $("flows-body");
    if (!body) return;
    const f = state.filter;
    const rows = flows.filter((flow) => {
      if (f.direction !== "all" && flow.direction !== f.direction) return false;
      if (f.protocol !== "all" && flow.protocol !== f.protocol) return false;
      if (f.app !== "all" && flow.app !== f.app) return false;
      if (f.host) {
        const needle = f.host.toLowerCase();
        if (!`${flow.host} ${flow.dst} ${flow.srcIp} ${flow.dstIp}`.toLowerCase().includes(needle)) return false;
      }
      return true;
    }).slice(0, 35);

    if (!rows.length) {
      body.innerHTML = '<tr><td colspan="10" class="nw-empty">No flows match the filters.</td></tr>';
      return;
    }
    body.innerHTML = rows.map((flow) => `<tr>
      <td title="First seen ${fmtTime(flow.firstSeen || flow.ts)}">${fmtTime(flow.ts)}</td>
      <td><strong>${escapeHtml(flow.host)}</strong></td>
      <td>${escapeHtml(flow.dst)}</td>
      <td>${escapeHtml(flow.app)}</td>
      <td>${escapeHtml(flow.protocol)}</td>
      <td class="num">${flow.port || "—"}</td>
      <td>${escapeHtml(flow.direction)}</td>
      <td class="num">${Number(flow.packets || 1).toLocaleString()}</td>
      <td class="num">${fmtBytes(flow.bytes)}</td>
      <td>${verdictLabel(flow.verdict)}</td>
    </tr>`).join("");
  }

  function verdictLabel(verdict) {
    if (verdict === "cleartext") return '<span class="nw-risk high">cleartext</span>';
    if (verdict === "OT boundary") return '<span class="nw-risk medium">OT boundary</span>';
    if (verdict === "review") return '<span class="nw-risk high">review</span>';
    if (verdict === "watch") return '<span class="nw-risk medium">watch</span>';
    if (verdict === "transit") return '<span class="nw-risk info">transit</span>';
    return '<span class="nw-risk low">normal</span>';
  }

  function escapeHtml(value) {
    return String(value == null ? "" : value).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  function stopTimers() {
    if (state.timer) { clearInterval(state.timer); state.timer = null; }
    if (state.liveTimer) { clearInterval(state.liveTimer); state.liveTimer = null; }
  }

  function startDemo() {
    stopTimers();
    state.mode = "demo";
    state.paused = false;
    const pause = $("pause-button");
    if (pause) { pause.disabled = false; pause.textContent = "Pause view"; }
    for (let i = 0; i < 36; i += 1) addDemoSample();
    render(buildDemoSnapshot());
    state.timer = setInterval(() => {
      if (state.paused) return;
      addDemoSample();
      render(buildDemoSnapshot());
    }, 1000);
  }

  async function tryLive() {
    try {
      const response = await fetch("/api/snapshot", { cache: "no-store", headers: { Accept: "application/json" } });
      if (!response.ok) throw new Error("no agent");
      const json = await response.json();
      if (!json || json.mode !== "live") throw new Error("not live");
      if (state.mode === "file" || state.importing) return;
      stopTimers();
      const data = aggregateLive(json);
      render(data);
      if (!state.liveTimer) {
        state.liveTimer = setInterval(async () => {
          if (state.paused || state.mode === "file") return;
          try {
            const next = await fetch("/api/snapshot", { cache: "no-store" }).then((r) => r.json());
            render(aggregateLive(next));
          } catch {
            setSource("error", "Agent disconnected", state.data?.interface || "en0");
            const errorEl = $("source-error");
            if (errorEl) {
              errorEl.textContent = "The local agent stopped responding. Showing the last snapshot while reconnecting.";
              errorEl.style.display = "block";
            }
            $("source-mode").textContent = "Live agent · disconnected";
          }
        }, 2000);
      }
    } catch {
      if (state.mode === "file" || state.importing) return;
      if (state.mode !== "demo") setSource("demo", "Demo traffic", "demo0");
      if (!state.timer) startDemo();
    }
  }

  function analyzeFile(file) {
    const status = $("pcap-status");
    const input = $("pcap-file");
    const reset = $("reset-source");
    if (!file) return;
    const name = String(file.name || "capture");
    if (!window.KavachPcap) {
      if (status) {
        status.textContent = "The local parser did not load. Reload the page and try again.";
        status.className = "nw-import-status error";
      }
      return;
    }
    if (!/\.(pcapng|pcap|cap)$/i.test(name)) {
      if (status) {
        status.textContent = "Choose a .pcap or .pcapng file from tcpdump, Wireshark or a SPAN/TAP.";
        status.className = "nw-import-status error";
      }
      return;
    }
    if (file.size > 200 * 1024 * 1024) {
      if (status) {
        status.textContent = "That file is larger than 200 MB. Split it with editcap or capture a shorter window.";
        status.className = "nw-import-status error";
      }
      return;
    }

    stopTimers();
    state.importing = true;
    state.paused = false;
    const pause = $("pause-button");
    if (pause) pause.textContent = "Pause view";
    setSource("loading", "Reading capture", name);
    if (status) {
      status.textContent = `Reading ${name} (${fmtBytes(file.size)}) on this device…`;
      status.className = "nw-import-status working";
    }

    window.setTimeout(async () => {
      try {
        const buffer = await file.arrayBuffer();
        const data = window.KavachPcap.analyze(buffer, name);
        state.filter = { direction: "all", protocol: "all", app: "all", host: "" };
        const direction = $("filter-direction");
        const protocol = $("filter-protocol");
        const app = $("filter-app");
        const host = $("filter-host");
        if (direction) direction.value = "all";
        if (protocol) protocol.value = "all";
        if (app) app.value = "all";
        if (host) host.value = "";
        render(data);
        if (reset) reset.hidden = false;
        if (status) {
          const span = data.meta?.hasTimestamps
            ? fmtSpan(data.meta.start, data.meta.end)
            : "timestamps not recorded";
          const truncated = data.meta?.truncated ? " Read stopped at the safety limit." : "";
          status.textContent = `Parsed ${Number(data.stats.packets).toLocaleString()} packets · ${Number(data.stats.flows).toLocaleString()} flows · ${data.stats.hosts} hosts · ${span}.${truncated} Nothing was uploaded.`;
          status.className = "nw-import-status success";
        }
        document.getElementById("overview")?.scrollIntoView({ behavior: "smooth", block: "start" });
      } catch (error) {
        startDemo();
        if (status) {
          status.textContent = `${name} could not be read: ${error?.message || "unknown format"}. Nothing was uploaded.`;
          status.className = "nw-import-status error";
        }
        if (reset) reset.hidden = true;
      } finally {
        state.importing = false;
        if (input) input.value = "";
      }
    }, 40);
  }

  function resetSource() {
    const reset = $("reset-source");
    const status = $("pcap-status");
    if (reset) reset.hidden = true;
    if (status) {
      status.textContent = "No file selected. Nothing leaves this device.";
      status.className = "nw-import-status";
    }
    state.filter = { direction: "all", protocol: "all", app: "all", host: "" };
    startDemo();
    tryLive();
  }

  function wireImport() {
    const zone = $("drop-zone");
    const choose = $("pcap-choose");
    const sample = $("pcap-sample");
    const input = $("pcap-file");
    const reset = $("reset-source");
    if (choose && input) choose.addEventListener("click", () => input.click());
    if (input) input.addEventListener("change", () => analyzeFile(input.files?.[0]));
    if (reset) reset.addEventListener("click", resetSource);
    if (sample) sample.addEventListener("click", async () => {
      const status = $("pcap-status");
      if (status) {
        status.textContent = "Loading the synthetic sample…";
        status.className = "nw-import-status working";
      }
      try {
        const response = await fetch("/network/samples/kavach-sample.pcap", { cache: "no-store" });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const blob = await response.blob();
        analyzeFile(new File([blob], "kavach-sample.pcap", { type: "application/vnd.tcpdump.pcap" }));
      } catch (error) {
        if (status) {
          status.textContent = `The sample could not be loaded: ${error?.message || "network error"}.`;
          status.className = "nw-import-status error";
        }
      }
    });
    if (!zone) return;
    ["dragenter", "dragover"].forEach((type) => zone.addEventListener(type, (event) => {
      event.preventDefault();
      zone.classList.add("dragging");
    }));
    zone.addEventListener("dragleave", (event) => {
      if (!zone.contains(event.relatedTarget)) zone.classList.remove("dragging");
    });
    zone.addEventListener("drop", (event) => {
      event.preventDefault();
      zone.classList.remove("dragging");
      analyzeFile(event.dataTransfer?.files?.[0]);
    });
  }

  function init() {
    const pause = $("pause-button");
    if (pause) {
      pause.addEventListener("click", () => {
        state.paused = !state.paused;
        pause.textContent = state.paused ? "Resume view" : "Pause view";
      });
    }
    const direction = $("filter-direction");
    if (direction) direction.addEventListener("change", () => { state.filter.direction = direction.value; renderFlows(state.data?.flows || []); });
    const protocol = $("filter-protocol");
    if (protocol) protocol.addEventListener("change", () => { state.filter.protocol = protocol.value; renderFlows(state.data?.flows || []); });
    const app = $("filter-app");
    if (app) app.addEventListener("change", () => { state.filter.app = app.value; renderFlows(state.data?.flows || []); });
    const host = $("filter-host");
    if (host) host.addEventListener("input", () => { state.filter.host = host.value.trim(); renderFlows(state.data?.flows || []); });
    window.addEventListener("resize", () => { if (state.data) drawChart(state.data.series || []); });

    wireImport();
    tryLive();
  }

  init();
})();
