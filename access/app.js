/* Kavach Access watch — synthetic demo + local CSV/JSON access-log analysis.
 * Nothing is uploaded. Timestamps are interpreted in the browser's timezone. */

(function () {
  "use strict";

  const OFF_START = 8;
  const OFF_END = 19;
  const SAF_WINDOW = 30 * 60;
  const TRAVEL_KM = 300;
  const TRAVEL_SPEED = 1200;
  const TRAVEL_MAX_HOURS = 6;

  const state = {
    mode: "demo",
    events: [],
    meta: null,
    data: null,
    importing: false,
    filter: { search: "", result: "all", country: "all", app: "all", risk: "all" },
  };

  const $ = (id) => document.getElementById(id);
  const palette = {
    good: css("--good", "#4fd1c5"),
    bad: css("--bad", "#f97066"),
    warn: css("--warn", "#e8a33d"),
    info: css("--info", "#7fb0ff"),
    muted: css("--muted", "#8fa9b7"),
    line: css("--line", "rgba(234,242,246,.14)"),
  };

  function css(name, fallback) {
    const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    return value || fallback;
  }

  function fmtTime(ts) {
    const value = Number(ts);
    if (!value) return "—";
    return new Date(value * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
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

  function fmtDateClock(ts) {
    const value = Number(ts);
    if (!value) return "—";
    const d = new Date(value * 1000);
    const now = new Date();
    const options = { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", second: "2-digit" };
    if (d.getFullYear() !== now.getFullYear()) options.year = "numeric";
    return d.toLocaleString([], options);
  }

  function fmtSpan(start, end) {
    const first = Number(start);
    const last = Number(end);
    if (!first || !last) return "no window";
    return `${fmtDateClock(first)} – ${fmtDateClock(last)}`;
  }

  function fmtNumber(value) {
    return Number(value || 0).toLocaleString();
  }

  function escapeHtml(value) {
    return String(value == null ? "" : value).replace(/[&<>"']/g, (c) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    }[c]));
  }

  function riskRank(risk) {
    return risk === "high" ? 3 : risk === "medium" ? 2 : 1;
  }

  function riskLabel(risk) {
    const safe = risk === "high" || risk === "medium" || risk === "low" ? risk : "info";
    return `<span class="nw-risk ${safe}">${safe}</span>`;
  }

  function resultLabel(result) {
    const safe = result === "success" ? "success" : "failure";
    return `<span class="aw-result ${safe}">${escapeHtml(result || "unknown")}</span>`;
  }

  let regionNames = null;
  try {
    regionNames = new Intl.DisplayNames(["en"], { type: "region" });
  } catch {
    regionNames = null;
  }

  function countryName(value) {
    const text = String(value == null ? "" : value).trim();
    if (!text) return "Unknown";
    if (/^[a-z]{2}$/i.test(text) && regionNames) {
      const name = regionNames.of(text.toUpperCase());
      if (name && name !== text.toUpperCase()) return name;
    }
    return text;
  }

  function str(value) {
    if (value == null) return "";
    return String(value).trim();
  }

  function parseTs(value) {
    if (value == null || value === "") return null;
    if (typeof value === "number") {
      if (!Number.isFinite(value)) return null;
      return value > 1e12 ? value / 1000 : value;
    }
    const text = String(value).trim();
    if (/^\d+(\.\d+)?$/.test(text)) {
      const n = Number(text);
      if (!Number.isFinite(n)) return null;
      return n > 1e12 ? n / 1000 : n;
    }
    let candidate = text;
    if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}/.test(candidate)) candidate = candidate.replace(" ", "T");
    let date = new Date(candidate);
    if (Number.isNaN(date.getTime())) date = new Date(text);
    if (Number.isNaN(date.getTime())) return null;
    return date.getTime() / 1000;
  }

  function haversine(lat1, lon1, lat2, lon2) {
    const toRad = (value) => (value * Math.PI) / 180;
    const dLat = toRad(lat2 - lat1);
    const dLon = toRad(lon2 - lon1);
    const a = Math.sin(dLat / 2) ** 2
      + Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
    return 6371 * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  }

  const ALIASES = {
    ts: ["timestamp", "time", "ts", "datetime", "date", "event_time", "createddatetime", "timecreated", "eventtime"],
    user: ["user", "username", "account", "actor", "upn", "userprincipalname", "subject", "target_user", "user_name"],
    source_ip: ["source_ip", "sourceip", "src_ip", "client_ip", "clientip", "ipaddress", "ip_address", "ip", "remote_ip"],
    country: ["country", "country_code", "countrycode", "geo", "location", "location_countryorregion", "countryorregion"],
    city: ["city", "location_city"],
    lat: ["lat", "latitude", "location_geocoordinates_latitude"],
    lon: ["lon", "lng", "longitude", "location_geocoordinates_longitude"],
    asn: ["asn", "as_org", "asn_org"],
    target_host: ["target_host", "targethost", "host", "computer", "destination", "dst_host", "resource_displayname", "resource"],
    target_ip: ["target_ip", "targetip", "dst_ip", "dest_ip", "destination_ip"],
    application: ["application", "app", "service", "appdisplayname", "workload"],
    auth_method: ["auth_method", "auth", "authentication", "method", "auth_type", "authenticationmethod", "authenticationprotocol"],
    result: ["result", "status", "outcome", "success", "event_result", "status_errorcode"],
    reason: ["reason", "failure_reason", "error", "status_reason", "message", "status_failure_reason", "status_failurereason", "failurereason"],
    mfa: ["mfa", "mfa_status", "mfa_result", "authentication_requirement", "authenticationrequirement"],
    privilege: ["privilege", "privileges", "role", "is_admin", "admin"],
  };

  function normKey(value) {
    return String(value == null ? "" : value)
      .replace(/^\uFEFF/, "")
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "_")
      .replace(/^_+|_+$/g, "");
  }

  function flattenObject(value, prefix, out, depth) {
    const target = out || {};
    if (!value || typeof value !== "object" || depth > 3) return target;
    for (const [key, child] of Object.entries(value)) {
      const next = prefix ? `${prefix}_${key}` : key;
      if (Array.isArray(child)) continue;
      if (child && typeof child === "object") flattenObject(child, next, target, (depth || 0) + 1);
      else if (child != null) target[next] = child;
    }
    return target;
  }

  function normalizeObject(value) {
    const out = {};
    for (const [key, child] of Object.entries(flattenObject(value, "", {}, 0))) {
      out[normKey(key)] = child;
    }
    return out;
  }

  function getField(raw, keys) {
    for (const key of keys) {
      if (raw[key] != null && raw[key] !== "") return raw[key];
    }
    return "";
  }

  function parseCsv(text) {
    const rows = [];
    let row = [];
    let field = "";
    let quoted = false;
    for (let i = 0; i < text.length; i += 1) {
      const char = text[i];
      if (quoted) {
        if (char === '"') {
          if (text[i + 1] === '"') { field += '"'; i += 1; } else quoted = false;
        } else {
          field += char;
        }
      } else if (char === '"') {
        quoted = true;
      } else if (char === ",") {
        row.push(field);
        field = "";
      } else if (char === "\n") {
        row.push(field);
        rows.push(row);
        row = [];
        field = "";
      } else if (char !== "\r") {
        field += char;
      }
    }
    if (field.length || row.length) {
      row.push(field);
      rows.push(row);
    }
    return rows.filter((cells) => cells.some((cell) => String(cell).trim() !== ""));
  }

  function normalizeResult(value, reason, mfa) {
    const raw = str(value).toLowerCase();
    const text = `${raw} ${str(reason)} ${str(mfa)}`.toLowerCase();
    if (["true", "yes", "success", "succeeded", "allowed", "allow", "ok", "granted", "accepted", "0"].includes(raw)) return "success";
    if (["false", "no", "failure", "failed", "deny", "denied", "blocked", "block", "1"].includes(raw)) return "failure";
    if (/fail|denied|deny|blocked|block|invalid|locked|error|reject|expired|unauthorized|forbidden/.test(text)) return "failure";
    if (/success|succeeded|allowed|granted|accepted|approved/.test(text)) return "success";
    return "unknown";
  }

  function normalizeRecord(raw, index) {
    const resultRaw = getField(raw, ALIASES.result);
    const reason = str(getField(raw, ALIASES.reason));
    const mfa = str(getField(raw, ALIASES.mfa));
    const ts = parseTs(getField(raw, ALIASES.ts));
    const user = str(getField(raw, ALIASES.user));
    const hasResult = str(resultRaw) !== "" || reason !== "" || mfa !== "";
    if (ts == null || !user || !hasResult) return null;

    let result = normalizeResult(resultRaw, reason, mfa);
    if (raw.status_errorcode !== undefined && String(resultRaw) === String(raw.status_errorcode)) {
      const code = str(raw.status_errorcode);
      result = code === "0" ? "success" : "failure";
    }

    const latRaw = getField(raw, ALIASES.lat);
    const lonRaw = getField(raw, ALIASES.lon);
    const lat = latRaw === "" ? null : Number(latRaw);
    const lon = lonRaw === "" ? null : Number(lonRaw);
    const latitude = Number.isFinite(lat) && lat >= -90 && lat <= 90 ? lat : null;
    const longitude = Number.isFinite(lon) && lon >= -180 && lon <= 180 ? lon : null;
    let asn = str(getField(raw, ALIASES.asn));
    if (/^\d+$/.test(asn)) asn = `AS${asn}`;

    return {
      id: index,
      ts,
      user,
      source_ip: str(getField(raw, ALIASES.source_ip)) || "—",
      country: countryName(getField(raw, ALIASES.country)),
      city: str(getField(raw, ALIASES.city)),
      lat: latitude,
      lon: longitude,
      asn,
      target_host: str(getField(raw, ALIASES.target_host)),
      target_ip: str(getField(raw, ALIASES.target_ip)),
      application: str(getField(raw, ALIASES.application)) || str(getField(raw, ALIASES.target_host)) || "Unknown",
      auth_method: str(getField(raw, ALIASES.auth_method)) || "Unknown",
      result,
      reason,
      mfa,
      privilege: str(getField(raw, ALIASES.privilege)),
    };
  }

  function normalizeRows(rows) {
    const events = [];
    let skipped = 0;
    const limit = Math.min(rows.length, 100000);
    for (let i = 0; i < limit; i += 1) {
      const event = normalizeRecord(rows[i], i);
      if (event) events.push(event);
      else skipped += 1;
    }
    return { events, skipped };
  }

  function parseAccessText(text, fileName) {
    const clean = text.replace(/^\uFEFF/, "");
    const trimmed = clean.trim();
    if (/\.json$/i.test(fileName) || trimmed.startsWith("[") || trimmed.startsWith("{")) {
      let parsed;
      try {
        parsed = JSON.parse(trimmed);
      } catch {
        const lines = trimmed.split(/\r?\n/).filter((line) => line.trim());
        parsed = lines.map((line) => JSON.parse(line));
      }
      const rows = Array.isArray(parsed)
        ? parsed
        : (parsed.events || parsed.value || parsed.records || []);
      if (!Array.isArray(rows)) throw new Error("JSON must be an array, or an object with an events or value array.");
      return normalizeRows(rows.map((row) => normalizeObject(row)));
    }

    const rows = parseCsv(clean);
    if (rows.length < 2) throw new Error("The CSV needs a header row and at least one event.");
    const headers = rows[0].map(normKey);
    const objects = rows.slice(1).map((cells) => {
      const row = {};
      headers.forEach((header, i) => {
        if (header) row[header] = cells[i] == null ? "" : String(cells[i]).trim();
      });
      return row;
    });
    return normalizeRows(objects);
  }

  function isPrivileged(event) {
    return /admin|root|privileged|domain admin|superuser|break.?glass/.test(
      `${event.privilege} ${event.user}`.toLowerCase(),
    );
  }

  function isMfaDenied(event) {
    return /mfa|multi.?factor|2fa|authenticator/.test(`${event.mfa} ${event.reason}`.toLowerCase())
      && /den|fail|reject|timeout|block/.test(`${event.mfa} ${event.reason}`.toLowerCase());
  }

  function isLegacy(event) {
    return /legacy|basic|imap|pop|smtp|ntlm/.test(`${event.auth_method}`.toLowerCase());
  }

  function riskFor(event) {
    let level = 1;
    if (event.mfaDenied || event.newCountry || event.offHours || event.legacy) level = 2;
    if (event.privileged && event.result === "success" && (event.offHours || event.newCountry)) level = 3;
    if (event.criticalAsset) level = 3;
    if (event.impossible || event.successAfterFailure || event.spray) level = 3;
    return ["low", "medium", "high"][level - 1];
  }

  function verdictFor(event) {
    if (event.criticalAsset) return "critical asset";
    if (event.impossible) return "impossible travel";
    if (event.spray) return "password spray";
    if (event.successAfterFailure) return "success after failure";
    if (event.newCountry) return "new country";
    if (event.offHours && event.privileged) return "off-hours privileged";
    if (event.offHours) return "off-hours";
    if (event.mfaDenied) return "MFA denied";
    if (event.legacy) return "legacy auth";
    if (event.result === "failure") return "failed sign-in";
    return "normal";
  }

  function buildAlerts(events) {
    const alerts = new Map();
    const add = (key, severity, title, detail, time) => {
      alerts.set(key, { severity, title, detail, time });
    };
    for (const event of events) {
      if (event.criticalAsset && event.result === "success"
        && (event.offHours || event.newCountry || event.impossible || event.privileged || event.legacy)) {
        add(
          `critical:${event.user}:${event.criticalAsset.value}`,
          "critical",
          "Critical asset access",
          `${event.user} reached ${event.criticalAsset.label || event.criticalAsset.value} from ${event.country}.`,
          event.ts,
        );
      }
      if (event.impossible) {
        add(
          `travel:${event.user}`,
          "high",
          "Impossible travel",
          `${event.user}: ${event.travelKm.toLocaleString()} km in ${event.travelMinutes} minutes.`,
          event.ts,
        );
      }
      if (event.spray) {
        add(
          `spray:${event.source_ip}`,
          "high",
          "Password spray",
          `${event.source_ip} failed against ${event.sprayUsers || "multiple"} accounts.`,
          event.ts,
        );
      }
      if (event.successAfterFailure) {
        add(
          `saf:${event.user}`,
          "high",
          "Success after failure",
          `${event.user} signed in ${event.failureMinutes} minutes after a failed attempt.`,
          event.ts,
        );
      }
      if (event.privileged && event.offHours && event.result === "success") {
        add(
          `offpriv:${event.user}`,
          "high",
          "Privileged off-hours access",
          `${event.user} used ${event.application} at ${fmtTime(event.ts)}.`,
          event.ts,
        );
      }
      if (event.newCountry && event.result === "success") {
        add(
          `geo:${event.user}:${event.country}`,
          "medium",
          "New country sign-in",
          `${event.user} signed in from ${event.country} for the first time.`,
          event.ts,
        );
      }
      if (event.mfaDenied) {
        add(
          `mfa:${event.user}`,
          "medium",
          "MFA denied",
          `${event.user} had an MFA challenge denied from ${event.country}.`,
          event.ts,
        );
      }
      if (event.legacy && event.result === "success") {
        add(
          `legacy:${event.user}`,
          "medium",
          "Legacy authentication",
          `${event.user} signed in with ${event.auth_method}.`,
          event.ts,
        );
      }
    }
    return [...alerts.values()].sort((a, b) => b.time - a.time).slice(0, 8);
  }

  function buildSeries(events, now) {
    const maxTs = events.reduce((max, event) => Math.max(max, event.ts), 0);
    const end = Math.ceil(Math.max(now || 0, maxTs) / 3600) * 3600;
    const start = end - (24 * 3600);
    const series = Array.from({ length: 24 }, (_, i) => ({
      label: new Date((start + i * 3600) * 1000).getHours(),
      success: 0,
      failure: 0,
    }));
    for (const event of events) {
      if (event.ts < start || event.ts >= end) continue;
      const index = Math.floor((event.ts - start) / 3600);
      const bucket = series[index];
      if (!bucket) continue;
      if (event.result === "success") bucket.success += 1;
      else if (event.result === "failure") bucket.failure += 1;
    }
    return { series, start, end };
  }

  function derive(rawEvents, meta) {
    const events = rawEvents.slice().sort((a, b) => a.ts - b.ts);
    const assets = window.KavachAssets ? window.KavachAssets.list() : [];
    const userState = new Map();
    const lastFailure = new Map();
    const sprayBuckets = new Map();

    for (const event of events) {
      event.newCountry = false;
      event.impossible = false;
      event.successAfterFailure = false;
      event.spray = false;
      event.sprayUsers = 0;
      event.criticalAsset = null;
      event.travelKm = 0;
      event.travelMinutes = 0;
      event.failureMinutes = 0;
      event.offHours = false;
      event.privileged = isPrivileged(event);
      event.mfaDenied = isMfaDenied(event);
      event.legacy = isLegacy(event);

      const date = new Date(event.ts * 1000);
      const hour = date.getHours();
      const day = date.getDay();
      event.offHours = hour < OFF_START || hour >= OFF_END || day === 0 || day === 6;

      event.criticalAsset = assets.length
        ? window.KavachAssets.matchesAny([event.target_ip, event.target_host, event.application])
        : null;

      const user = userState.get(event.user) || { countries: new Set(), last: null };
      if (event.result === "success") {
        if (event.country && event.country !== "Unknown") {
          if (user.countries.size > 0 && !user.countries.has(event.country)) event.newCountry = true;
          user.countries.add(event.country);
        }
        if (event.lat != null && event.lon != null) {
          if (user.last && user.last.lat != null) {
            const seconds = event.ts - user.last.ts;
            const km = haversine(user.last.lat, user.last.lon, event.lat, event.lon);
            if (seconds > 0 && seconds <= TRAVEL_MAX_HOURS * 3600 && km >= TRAVEL_KM && (km / (seconds / 3600)) > TRAVEL_SPEED) {
              event.impossible = true;
              event.travelKm = Math.round(km);
              event.travelMinutes = Math.max(1, Math.round(seconds / 60));
            }
          }
          user.last = { ts: event.ts, lat: event.lat, lon: event.lon };
        }
      }
      userState.set(event.user, user);

      if (event.result === "success") {
        const failure = lastFailure.get(event.user);
        if (failure && event.ts >= failure && event.ts - failure <= SAF_WINDOW) {
          event.successAfterFailure = true;
          event.failureMinutes = Math.max(1, Math.round((event.ts - failure) / 60));
        }
      }
      if (event.result === "failure") {
        lastFailure.set(event.user, event.ts);
        const bucketStart = Math.floor(event.ts / 600) * 600;
        const bucketKey = `${event.source_ip}|${bucketStart}`;
        const bucket = sprayBuckets.get(bucketKey) || { users: new Set(), events: [] };
        bucket.users.add(event.user);
        bucket.events.push(event);
        sprayBuckets.set(bucketKey, bucket);
      }
    }

    for (const bucket of sprayBuckets.values()) {
      if (bucket.users.size < 5) continue;
      for (const event of bucket.events) {
        event.spray = true;
        event.sprayUsers = bucket.users.size;
      }
    }

    for (const event of events) {
      event.risk = riskFor(event);
      event.verdict = verdictFor(event);
    }

    const stats = {
      total: events.length,
      successes: events.filter((event) => event.result === "success").length,
      failures: events.filter((event) => event.result === "failure").length,
      targeted: new Set(events.filter((event) => event.result === "failure").map((event) => event.user)).size,
      successAfterFailure: events.filter((event) => event.successAfterFailure).length,
      impossible: events.filter((event) => event.impossible).length,
      offHours: events.filter((event) => event.offHours && event.result === "success").length,
      critical: events.filter((event) => event.criticalAsset).length,
      mfaDenied: events.filter((event) => event.mfaDenied).length,
      legacy: events.filter((event) => event.legacy).length,
      privileged: new Set(events.filter((event) => event.privileged).map((event) => event.user)).size,
      highRisk: events.filter((event) => event.risk === "high").length,
    };
    const latestEvent = events.reduce((max, event) => Math.max(max, event.ts), 0);
    const updatedAt = meta.updatedAt || latestEvent || Date.now() / 1000;
    const timeline = buildSeries(events, updatedAt);
    const hourHeat = Array.from({ length: 24 }, () => ({ total: 0, failures: 0 }));
    for (const event of events) {
      const hour = new Date(event.ts * 1000).getHours();
      hourHeat[hour].total += 1;
      if (event.result === "failure") hourHeat[hour].failures += 1;
    }

    return {
      mode: meta.mode,
      source: meta.source,
      fileName: meta.fileName || "",
      updatedAt,
      dataStart: events.length ? events[0].ts : 0,
      dataEnd: events.length ? events[events.length - 1].ts : 0,
      events,
      stats,
      alerts: buildAlerts(events),
      series: timeline.series,
      seriesStart: timeline.start,
      seriesEnd: timeline.end,
      hourHeat,
    };
  }

  function setSource(mode, label) {
    const pill = $("source-pill");
    if (pill) pill.className = `nw-pill ${mode}`;
    if ($("source-label")) $("source-label").textContent = label;
  }

  function render(data) {
    state.data = data;
    state.mode = data.mode;
    setSource(data.mode === "file" ? "file" : "demo", data.mode === "file" ? "Imported logs" : "Synthetic logs");
    if ($("updated-pill")) {
      $("updated-pill").textContent = data.mode === "file"
        ? `Data through · ${fmtStamp(data.updatedAt)}`
        : `Updated · ${fmtTime(data.updatedAt)}`;
    }
    if ($("access-window")) {
      $("access-window").textContent = data.mode === "file"
        ? fmtSpan(data.dataStart, data.dataEnd)
        : "Last 24 hours";
    }
    if ($("privacy-pill")) {
      $("privacy-pill").textContent = data.mode === "file"
        ? "Imported locally · no upload"
        : "Local analysis · no raw credentials";
    }

    $("kpi-failed").textContent = fmtNumber(data.stats.failures);
    $("kpi-targets").textContent = fmtNumber(data.stats.targeted);
    $("kpi-saf").textContent = fmtNumber(data.stats.successAfterFailure);
    $("kpi-travel").textContent = fmtNumber(data.stats.impossible);
    $("kpi-offhours").textContent = fmtNumber(data.stats.offHours);
    $("kpi-critical").textContent = fmtNumber(data.stats.critical);

    $("chart-title").textContent = data.mode === "file" ? "Sign-ins · last 24 hours of data" : "Sign-ins · last 24 hours";
    $("chart-range").textContent = fmtSpan(data.seriesStart, data.seriesEnd);
    drawChart(data.series);
    renderAlerts(data.alerts);
    renderTopUsers(data.events);
    renderGeo(data.events);
    renderTargets(data.events);
    renderHeat(data.hourHeat);
    renderPosture(data);
    renderAssetHits(data.events);
    populateFilters(data);
    renderEvents();
  }

  function drawChart(series) {
    const canvas = $("access-chart");
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

    const pad = { top: 14, right: 8, bottom: 24, left: 8 };
    const w = width - pad.left - pad.right;
    const h = height - pad.top - pad.bottom;
    const max = Math.max(1, ...series.map((point) => Math.max(point.success || 0, point.failure || 0))) * 1.15;

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
      series.forEach((point, i) => {
        const x = pad.left + step * i;
        const y = pad.top + h - ((point[key] || 0) / max) * h;
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

    line("success", palette.good, "rgba(79,209,197,.07)");
    line("failure", palette.bad, "rgba(249,112,102,.06)");

    ctx.fillStyle = palette.muted;
    ctx.font = "9px ui-monospace, SFMono-Regular, Menlo, monospace";
    ctx.textAlign = "center";
    ctx.textBaseline = "top";
    [0, 6, 12, 18, 23].forEach((index) => {
      const point = series[index];
      if (!point) return;
      const x = pad.left + (series.length > 1 ? (w / (series.length - 1)) * index : w / 2);
      ctx.textAlign = index === 0 ? "left" : index === 23 ? "right" : "center";
      ctx.fillText(`${String(point.label).padStart(2, "0")}:00`, x, height - 13);
    });
  }

  function renderAlerts(alerts) {
    const el = $("access-alerts");
    if (!el) return;
    if (!alerts.length) {
      el.innerHTML = '<p class="nw-empty">No rule-based alerts in this view.</p>';
      return;
    }
    el.innerHTML = alerts.slice(0, 6).map((alert) => `<div class="nw-alert ${escapeHtml(alert.severity || "info")}">
      <span class="bar"></span>
      <div><p>${escapeHtml(alert.title || "Alert")}</p><span>${escapeHtml(alert.detail || "")} · ${fmtTime(alert.time)}</span></div>
    </div>`).join("");
  }

  function renderTopUsers(events) {
    const el = $("top-users");
    if (!el) return;
    const users = new Map();
    for (const event of events) {
      const item = users.get(event.user) || { user: event.user, failures: 0, total: 0, countries: new Set(), last: 0 };
      item.total += 1;
      if (event.result === "failure") item.failures += 1;
      item.countries.add(event.country);
      item.last = Math.max(item.last, event.ts);
      users.set(event.user, item);
    }
    const rows = [...users.values()].filter((item) => item.failures > 0).sort((a, b) => b.failures - a.failures).slice(0, 7);
    if (!rows.length) {
      el.innerHTML = '<p class="nw-empty">No failed sign-ins in this view.</p>';
      return;
    }
    el.innerHTML = rows.map((item) => `<button class="aw-row" type="button" data-user="${escapeHtml(item.user)}">
      <span class="aw-row-main"><b>${escapeHtml(item.user)}</b><small>${item.failures} failures · ${item.countries.size} countries · last ${fmtTime(item.last)}</small></span>
      <span class="aw-row-value">${item.failures}</span>
    </button>`).join("");
  }

  function renderGeo(events) {
    const el = $("top-geo");
    if (!el) return;
    const countries = new Map();
    for (const event of events) {
      const item = countries.get(event.country) || { country: event.country, total: 0, failures: 0 };
      item.total += 1;
      if (event.result === "failure") item.failures += 1;
      countries.set(event.country, item);
    }
    const rows = [...countries.values()].sort((a, b) => b.total - a.total).slice(0, 7);
    if (!rows.length) {
      el.innerHTML = '<p class="nw-empty">No geography data in this view.</p>';
      return;
    }
    el.innerHTML = rows.map((item) => `<button class="aw-row" type="button" data-country="${escapeHtml(item.country)}">
      <span class="aw-row-main"><b>${escapeHtml(item.country)}</b><small>${item.total} events · ${item.failures} failures</small></span>
      <span class="aw-row-value">${item.total}</span>
    </button>`).join("");
  }

  function renderTargets(events) {
    const el = $("top-targets");
    if (!el) return;
    const targets = new Map();
    for (const event of events) {
      const key = event.application || event.target_host || "Unknown";
      const item = targets.get(key) || { app: key, host: event.target_host, total: 0, failures: 0, critical: 0 };
      item.total += 1;
      if (event.result === "failure") item.failures += 1;
      if (event.criticalAsset) item.critical += 1;
      if (!item.host && event.target_host) item.host = event.target_host;
      targets.set(key, item);
    }
    const rows = [...targets.values()].sort((a, b) => b.total - a.total).slice(0, 7);
    if (!rows.length) {
      el.innerHTML = '<p class="nw-empty">No application data in this view.</p>';
      return;
    }
    el.innerHTML = rows.map((item) => `<button class="aw-row" type="button" data-app="${escapeHtml(item.app)}">
      <span class="aw-row-main"><b>${escapeHtml(item.app)}</b><small>${escapeHtml(item.host || "—")} · ${item.total} events · ${item.failures} failures${item.critical ? " · critical" : ""}</small></span>
      <span class="aw-row-value">${item.total}</span>
    </button>`).join("");
  }

  function renderHeat(hours) {
    const el = $("hour-heat");
    if (!el) return;
    const max = Math.max(1, ...hours.map((hour) => hour.total));
    el.innerHTML = hours.map((hour, index) => {
      const alpha = hour.total ? (0.1 + (hour.total / max) * 0.55).toFixed(2) : "0.03";
      return `<div class="aw-heat-cell ${hour.failures ? "has-failure" : ""}" style="background:rgba(127,176,255,${alpha})" title="${String(index).padStart(2, "0")}:00 · ${hour.total} sign-ins · ${hour.failures} failures"></div>`;
    }).join("");
  }

  function renderPosture(data) {
    const total = data.stats.successes + data.stats.failures;
    const rate = total ? Math.round((data.stats.successes / total) * 100) : 0;
    $("posture-success-rate").textContent = `${rate}%`;
    $("posture-mfa").textContent = fmtNumber(data.stats.mfaDenied);
    $("posture-legacy").textContent = fmtNumber(data.stats.legacy);
    $("posture-privileged").textContent = fmtNumber(data.stats.privileged);
  }

  function renderAssetHits(events) {
    const el = $("asset-hits");
    const count = $("asset-hit-count");
    if (!el) return;
    const hits = events.filter((event) => event.criticalAsset).sort((a, b) => b.ts - a.ts);
    if (count) count.textContent = fmtNumber(hits.length);
    if (!hits.length) {
      el.innerHTML = '<p class="nw-empty">No access events touch a critical asset yet.</p>';
      return;
    }
    const seen = new Set();
    const rows = [];
    for (const event of hits) {
      const key = `${event.user}|${event.criticalAsset.value}|${event.target_host}|${event.result}`;
      if (seen.has(key)) continue;
      seen.add(key);
      rows.push(event);
      if (rows.length >= 6) break;
    }
    el.innerHTML = rows.map((event) => `<div class="nw-asset-hit">
      <div>
        <b>${escapeHtml(event.criticalAsset.label || event.criticalAsset.value)}</b>
        <span>${escapeHtml(event.user)} → ${escapeHtml(event.target_host || event.target_ip)} · ${escapeHtml(event.result)} · ${fmtTime(event.ts)}</span>
      </div>
      <em>${escapeHtml(event.country)}</em>
    </div>`).join("");
  }

  function populateFilters(data) {
    const countrySelect = $("filter-country");
    const appSelect = $("filter-app");
    if (!countrySelect || !appSelect) return;
    const countries = [...new Set(data.events.map((event) => event.country).filter(Boolean))].sort();
    const apps = [...new Set(data.events.map((event) => event.application).filter(Boolean))].sort();
    countrySelect.innerHTML = '<option value="all">All</option>' + countries.map((value) => `<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`).join("");
    appSelect.innerHTML = '<option value="all">All</option>' + apps.map((value) => `<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`).join("");
    if (!countries.includes(state.filter.country)) state.filter.country = "all";
    if (!apps.includes(state.filter.app)) state.filter.app = "all";
    countrySelect.value = state.filter.country;
    appSelect.value = state.filter.app;
  }

  function renderEvents() {
    const body = $("events-body");
    if (!body || !state.data) return;
    const filter = state.filter;
    const search = filter.search.toLowerCase();
    const filtered = state.data.events.slice().sort((a, b) => b.ts - a.ts).filter((event) => {
      if (filter.result !== "all" && event.result !== filter.result) return false;
      if (filter.country !== "all" && event.country !== filter.country) return false;
      if (filter.app !== "all" && event.application !== filter.app) return false;
      if (filter.risk !== "all" && event.risk !== filter.risk) return false;
      if (search) {
        const text = `${event.user} ${event.source_ip} ${event.country} ${event.target_host} ${event.target_ip} ${event.application}`.toLowerCase();
        if (!text.includes(search)) return false;
      }
      return true;
    });
    const rows = filtered.slice(0, 60);
    if ($("events-note")) {
      $("events-note").textContent = `${rows.length} of ${filtered.length} events · ${state.data.events.length} loaded · ${state.data.mode === "file" ? "parsed locally" : "synthetic demo"}`;
    }
    if (!rows.length) {
      body.innerHTML = '<tr><td colspan="9" class="nw-empty">No events match the filters.</td></tr>';
      return;
    }
    body.innerHTML = rows.map((event) => `<tr class="${event.criticalAsset ? "critical" : ""}" title="${escapeHtml(event.reason || event.verdict)}">
      <td>${fmtStamp(event.ts)}</td>
      <td><strong>${escapeHtml(event.user)}</strong>${event.privileged ? ' <span class="nw-risk high">privileged</span>' : ""}</td>
      <td>${escapeHtml(event.source_ip)}<br><small>${escapeHtml(event.city || "—")}</small></td>
      <td>${escapeHtml(event.country)}<br><small>${escapeHtml(event.asn || "—")}</small></td>
      <td>${escapeHtml(event.target_host || "—")}<br><small>${escapeHtml(event.target_ip || "—")}</small></td>
      <td>${escapeHtml(event.application)}</td>
      <td>${escapeHtml(event.auth_method)}</td>
      <td>${resultLabel(event.result)}${event.reason ? `<br><small>${escapeHtml(event.reason)}</small>` : ""}</td>
      <td>${riskLabel(event.risk)}<small class="aw-verdict">${escapeHtml(event.verdict)}</small></td>
    </tr>`).join("");
  }

  function lastAt(hour, minute) {
    const date = new Date();
    date.setHours(hour, minute, 0, 0);
    if (date.getTime() > Date.now()) date.setDate(date.getDate() - 1);
    return date.getTime() / 1000;
  }

  function buildDemoEvents() {
    const geo = {
      India: { lat: 12.97, lon: 77.59 },
      Singapore: { lat: 1.35, lon: 103.82 },
      UAE: { lat: 25.20, lon: 55.27 },
      UK: { lat: 51.51, lon: -0.13 },
      US: { lat: 40.71, lon: -74.01 },
      Germany: { lat: 50.11, lon: 8.68 },
      Netherlands: { lat: 52.37, lon: 4.90 },
    };
    const events = [];
    let id = 1;
    const add = (ts, user, fields) => {
      const point = geo[fields.country] || { lat: null, lon: null };
      events.push({
        id: id++,
        ts,
        user,
        source_ip: fields.ip || "—",
        country: fields.country || "Unknown",
        city: fields.city || "",
        lat: fields.lat != null ? fields.lat : point.lat,
        lon: fields.lon != null ? fields.lon : point.lon,
        asn: fields.asn || "",
        target_host: fields.target || "",
        target_ip: fields.targetIp || "",
        application: fields.app || "Unknown",
        auth_method: fields.auth || "Password, MFA",
        result: fields.result || "success",
        reason: fields.reason || "",
        mfa: fields.mfa || "satisfied",
        privilege: fields.privilege || "user",
      });
    };

    const normalUsers = [
      { user: "anita.rao", country: "India", city: "Bengaluru", ip: "49.207.18.24", asn: "AS24560", app: "Microsoft 365", target: "outlook.office365.com", targetIp: "52.96.14.18", privilege: "user" },
      { user: "rohit.mehta", country: "India", city: "Mumbai", ip: "49.207.22.81", asn: "AS24560", app: "SAP S/4HANA", target: "sap-s4-prod", targetIp: "10.20.4.15", privilege: "user" },
      { user: "meera.iyer", country: "India", city: "Bengaluru", ip: "10.20.4.50", asn: "AS64512", app: "HR portal", target: "hr-portal", targetIp: "10.20.4.60", privilege: "user" },
      { user: "santosh.k", country: "Singapore", city: "Singapore", ip: "203.0.113.20", asn: "AS64500", app: "SAP S/4HANA", target: "sap-s4-prod", targetIp: "10.20.4.15", privilege: "admin" },
      { user: "arjun.s", country: "India", city: "Bengaluru", ip: "10.20.4.71", asn: "AS64512", app: "Microsoft 365", target: "outlook.office365.com", targetIp: "52.96.14.18", privilege: "user" },
      { user: "priya.n", country: "India", city: "Bengaluru", ip: "10.20.4.62", asn: "AS64512", app: "SAP S/4HANA", target: "sap-s4-prod", targetIp: "10.20.4.15", privilege: "user" },
      { user: "vendor.john", country: "Netherlands", city: "Amsterdam", ip: "203.0.113.55", asn: "AS64510", app: "Engineering console", target: "plc-line-2", targetIp: "10.30.7.40", privilege: "vendor" },
      { user: "svc.backup", country: "India", city: "Bengaluru", ip: "10.20.4.90", asn: "AS64512", app: "Microsoft 365", target: "outlook.office365.com", targetIp: "52.96.14.18", privilege: "service" },
    ];

    const businessHours = [
      [9, 10], [11, 5], [14, 15], [16, 20], [18, 5],
    ];
    normalUsers.forEach((user, index) => {
      const slots = user.user === "arjun.s" ? businessHours.slice(0, 2) : businessHours;
      slots.forEach(([hour, minute], slotIndex) => {
        add(lastAt(hour, minute) + index * 20 + slotIndex, user.user, {
          ...user,
          result: "success",
          reason: "",
        });
      });
    });

    add(lastAt(16, 20), "rohit.mehta", {
      country: "India", city: "Mumbai", ip: "49.207.22.81", asn: "AS24560",
      app: "SAP S/4HANA", target: "sap-s4-prod", targetIp: "10.20.4.15",
      result: "failure", reason: "Invalid password", auth: "Password", mfa: "not prompted",
    });
    add(lastAt(16, 22), "rohit.mehta", {
      country: "India", city: "Mumbai", ip: "49.207.22.81", asn: "AS24560",
      app: "SAP S/4HANA", target: "sap-s4-prod", targetIp: "10.20.4.15",
      result: "failure", reason: "Invalid password", auth: "Password", mfa: "not prompted",
    });
    add(lastAt(16, 25), "rohit.mehta", {
      country: "India", city: "Mumbai", ip: "49.207.22.81", asn: "AS24560",
      app: "SAP S/4HANA", target: "sap-s4-prod", targetIp: "10.20.4.15",
      result: "success", reason: "", auth: "Password, MFA", mfa: "satisfied",
    });

    add(lastAt(17, 0), "meera.iyer", {
      country: "India", city: "Bengaluru", ip: "10.20.4.50", asn: "AS64512",
      app: "HR portal", target: "hr-portal", targetIp: "10.20.4.60",
      result: "failure", reason: "MFA denied", auth: "Password, MFA", mfa: "denied",
    });
    add(lastAt(17, 3), "meera.iyer", {
      country: "India", city: "Bengaluru", ip: "10.20.4.50", asn: "AS64512",
      app: "HR portal", target: "hr-portal", targetIp: "10.20.4.60",
      result: "failure", reason: "MFA denied", auth: "Password, MFA", mfa: "denied",
    });
    add(lastAt(17, 8), "meera.iyer", {
      country: "India", city: "Bengaluru", ip: "10.20.4.50", asn: "AS64512",
      app: "HR portal", target: "hr-portal", targetIp: "10.20.4.60",
      result: "success", reason: "", auth: "Password, MFA", mfa: "satisfied",
    });

    add(lastAt(11, 15), "svc.backup", {
      country: "India", city: "Bengaluru", ip: "10.20.4.90", asn: "AS64512",
      app: "Microsoft 365", target: "outlook.office365.com", targetIp: "52.96.14.18",
      result: "success", reason: "Service account", auth: "IMAP Legacy", mfa: "not supported", privilege: "service",
    });

    add(lastAt(18, 0), "arjun.s", {
      country: "UK", city: "London", ip: "198.51.100.23", asn: "AS64520",
      app: "Microsoft 365", target: "outlook.office365.com", targetIp: "52.96.14.18",
      result: "success", reason: "New country", auth: "Password, MFA", mfa: "satisfied",
    });
    add(lastAt(10, 0), "arjun.s", {
      country: "India", city: "Bengaluru", ip: "10.20.4.71", asn: "AS64512",
      app: "OT historian", target: "historian", targetIp: "10.30.7.50",
      result: "success", reason: "Maintenance window", auth: "Password, MFA", mfa: "satisfied",
    });

    const sprayUsers = ["anita.rao", "rohit.mehta", "meera.iyer", "arjun.s", "priya.n", "svc.backup"];
    sprayUsers.forEach((user, index) => {
      add(lastAt(2, 5) + index * 45, user, {
        country: "Netherlands", city: "Amsterdam", ip: "203.0.113.77", asn: "AS64510",
        app: "Microsoft 365", target: "outlook.office365.com", targetIp: "52.96.14.18",
        result: "failure", reason: "Invalid password", auth: "Password", mfa: "not prompted",
      });
    });

    add(lastAt(2, 20), "priya.n", {
      country: "India", city: "Bengaluru", ip: "10.20.4.62", asn: "AS64512",
      app: "SAP S/4HANA", target: "sap-s4-prod", targetIp: "10.20.4.15",
      result: "success", reason: "", auth: "Password, MFA", mfa: "satisfied",
    });
    add(lastAt(2, 45), "priya.n", {
      country: "US", city: "New York", ip: "198.51.100.44", asn: "AS64530",
      app: "SAP S/4HANA", target: "sap-s4-prod", targetIp: "10.20.4.15",
      result: "success", reason: "Impossible travel", auth: "Password, MFA", mfa: "satisfied",
    });

    add(lastAt(3, 10), "santosh.k", {
      country: "Singapore", city: "Singapore", ip: "203.0.113.20", asn: "AS64500",
      app: "SAP S/4HANA", target: "sap-s4-prod", targetIp: "10.20.4.15",
      result: "success", reason: "Privileged sign-in", auth: "Password, MFA", mfa: "satisfied", privilege: "admin",
    });
    add(lastAt(3, 35), "vendor.john", {
      country: "Netherlands", city: "Amsterdam", ip: "203.0.113.55", asn: "AS64510",
      app: "Engineering console", target: "plc-line-2", targetIp: "10.30.7.40",
      result: "success", reason: "Vendor remote session", auth: "Password", mfa: "satisfied", privilege: "vendor",
    });

    return events;
  }

  function rebuild() {
    const data = derive(state.events, state.meta || { mode: "demo", source: "Synthetic access logs" });
    render(data);
  }

  function loadDemo() {
    state.events = buildDemoEvents();
    state.meta = { mode: "demo", source: "Synthetic access logs", updatedAt: Date.now() / 1000 };
    rebuild();
  }

  async function analyzeFile(file) {
    const status = $("access-status");
    const input = $("access-file");
    const reset = $("reset-source");
    if (!file) return;
    const name = String(file.name || "access-export");
    if (!/\.(csv|json)$/i.test(name)) {
      if (status) {
        status.textContent = "Choose a .csv or .json export from your identity, VPN, SAP or SIEM tooling.";
        status.className = "nw-import-status error";
      }
      return;
    }
    if (file.size > 50 * 1024 * 1024) {
      if (status) {
        status.textContent = "That export is larger than 50 MB. Split it by date range or user group and try again.";
        status.className = "nw-import-status error";
      }
      return;
    }

    state.importing = true;
    setSource("loading", "Reading access logs");
    if (status) {
      status.textContent = `Reading ${name} on this device…`;
      status.className = "nw-import-status working";
    }

    window.setTimeout(async () => {
      try {
        const text = await file.text();
        const parsed = parseAccessText(text, name);
        if (!parsed.events.length) {
          throw new Error("No usable rows. Check timestamp, user and result columns.");
        }
        state.events = parsed.events;
        state.meta = { mode: "file", source: name, fileName: name };
        rebuild();
        if (reset) reset.hidden = false;
        if (status) {
          const windowText = fmtSpan(state.data.dataStart, state.data.dataEnd);
          const skipped = parsed.skipped ? ` · ${fmtNumber(parsed.skipped)} rows skipped` : "";
          status.textContent = `Parsed ${fmtNumber(parsed.events.length)} events${skipped} · ${windowText}. Nothing was uploaded.`;
          status.className = "nw-import-status success";
        }
        document.getElementById("overview")?.scrollIntoView({ behavior: "smooth", block: "start" });
      } catch (error) {
        if (status) {
          status.textContent = `${name} could not be read: ${error?.message || "unknown format"}. Nothing was uploaded.`;
          status.className = "nw-import-status error";
        }
        if (reset) reset.hidden = state.mode !== "file";
      } finally {
        state.importing = false;
        if (input) input.value = "";
      }
    }, 40);
  }

  function resetSource() {
    const reset = $("reset-source");
    const status = $("access-status");
    if (reset) reset.hidden = true;
    if (status) {
      status.textContent = "No file selected. Nothing leaves this device.";
      status.className = "nw-import-status";
    }
    state.filter = { search: "", result: "all", country: "all", app: "all", risk: "all" };
    const search = $("filter-search");
    const result = $("filter-result");
    const country = $("filter-country");
    const app = $("filter-app");
    const risk = $("filter-risk");
    if (search) search.value = "";
    if (result) result.value = "all";
    if (country) country.value = "all";
    if (app) app.value = "all";
    if (risk) risk.value = "all";
    loadDemo();
  }

  function wireImport() {
    const zone = $("drop-zone");
    const choose = $("access-choose");
    const sample = $("access-sample");
    const input = $("access-file");
    const reset = $("reset-source");
    if (choose && input) choose.addEventListener("click", () => input.click());
    if (input) input.addEventListener("change", () => analyzeFile(input.files?.[0]));
    if (reset) reset.addEventListener("click", resetSource);
    if (sample) {
      sample.addEventListener("click", async () => {
        const status = $("access-status");
        if (status) {
          status.textContent = "Loading the synthetic access sample…";
          status.className = "nw-import-status working";
        }
        try {
          const response = await fetch("/access/samples/kavach-access-sample.csv", { cache: "no-store" });
          if (!response.ok) throw new Error(`HTTP ${response.status}`);
          const text = await response.text();
          analyzeFile(new File([text], "kavach-access-sample.csv", { type: "text/csv" }));
        } catch (error) {
          if (status) {
            status.textContent = `The sample could not be loaded: ${error?.message || "network error"}.`;
            status.className = "nw-import-status error";
          }
        }
      });
    }
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

  function wireFilters() {
    const search = $("filter-search");
    const result = $("filter-result");
    const country = $("filter-country");
    const app = $("filter-app");
    const risk = $("filter-risk");
    const clear = $("clear-filters");
    if (search) search.addEventListener("input", () => { state.filter.search = search.value.trim(); renderEvents(); });
    if (result) result.addEventListener("change", () => { state.filter.result = result.value; renderEvents(); });
    if (country) country.addEventListener("change", () => { state.filter.country = country.value; renderEvents(); });
    if (app) app.addEventListener("change", () => { state.filter.app = app.value; renderEvents(); });
    if (risk) risk.addEventListener("change", () => { state.filter.risk = risk.value; renderEvents(); });
    if (clear) {
      clear.addEventListener("click", () => {
        state.filter = { search: "", result: "all", country: "all", app: "all", risk: "all" };
        if (search) search.value = "";
        if (result) result.value = "all";
        if (country) country.value = "all";
        if (app) app.value = "all";
        if (risk) risk.value = "all";
        renderEvents();
      });
    }

    const users = $("top-users");
    if (users) {
      users.addEventListener("click", (event) => {
        const button = event.target.closest("[data-user]");
        if (!button) return;
        state.filter.search = button.dataset.user || "";
        if (search) search.value = state.filter.search;
        renderEvents();
        document.getElementById("events")?.scrollIntoView({ behavior: "smooth", block: "start" });
      });
    }
    const geo = $("top-geo");
    if (geo) {
      geo.addEventListener("click", (event) => {
        const button = event.target.closest("[data-country]");
        if (!button) return;
        state.filter.country = button.dataset.country || "all";
        if (country) country.value = state.filter.country;
        renderEvents();
        document.getElementById("events")?.scrollIntoView({ behavior: "smooth", block: "start" });
      });
    }
    const targets = $("top-targets");
    if (targets) {
      targets.addEventListener("click", (event) => {
        const button = event.target.closest("[data-app]");
        if (!button) return;
        state.filter.app = button.dataset.app || "all";
        if (app) app.value = state.filter.app;
        renderEvents();
        document.getElementById("events")?.scrollIntoView({ behavior: "smooth", block: "start" });
      });
    }
  }

  function init() {
    wireImport();
    wireFilters();
    if (window.KavachAssets) {
      window.KavachAssets.bindUI({
        onChange: () => {
          if (state.events.length) rebuild();
        },
      });
    }
    loadDemo();
    window.addEventListener("resize", () => {
      if (state.data) drawChart(state.data.series);
    });
  }

  init();
})();
