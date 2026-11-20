/* Kavach critical-asset watchlist.
 * Shared by Network watch and Access watch. Stored in this browser only. */

(function () {
  "use strict";

  const KEY = "kavach.criticalAssets.v1";
  const DEFAULTS = [
    { value: "10.20.4.15", label: "SAP S/4HANA production" },
    { value: "10.30.7.40", label: "PLC line 2" },
    { value: "10.30.7.50", label: "OT historian" },
  ];
  const VALUE_RE = /^[a-zA-Z0-9:._\-\/\[\]*]+$/;

  let assets = load();

  function clean(value) {
    return String(value == null ? "" : value).trim();
  }

  function validValue(value) {
    const text = clean(value);
    if (!text || text.length > 255) return false;
    return VALUE_RE.test(text);
  }

  function load() {
    try {
      const raw = localStorage.getItem(KEY);
      if (raw) {
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed)) {
          return parsed
            .map((row) => ({ value: clean(row && row.value), label: clean(row && row.label) }))
            .filter((row) => validValue(row.value));
        }
      }
    } catch {
      // Private mode or corrupt storage: fall back to the example list.
    }
    return DEFAULTS.map((row) => ({ ...row }));
  }

  function persist() {
    try {
      localStorage.setItem(KEY, JSON.stringify(assets));
    } catch {
      // The watchlist still works for this page view.
    }
  }

  function list() {
    return assets.map((row) => ({ ...row }));
  }

  function add(value, label) {
    const next = clean(value);
    if (!validValue(next)) {
      return { ok: false, error: "Use an IP address, CIDR range or hostname without spaces." };
    }
    if (assets.some((row) => row.value.toLowerCase() === next.toLowerCase())) {
      return { ok: false, error: "That asset is already on the watchlist." };
    }
    assets.push({ value: next, label: clean(label) || next });
    persist();
    return { ok: true };
  }

  function remove(value) {
    const needle = clean(value).toLowerCase();
    const before = assets.length;
    assets = assets.filter((row) => row.value.toLowerCase() !== needle);
    if (assets.length !== before) persist();
  }

  function reset() {
    assets = DEFAULTS.map((row) => ({ ...row }));
    persist();
  }

  function ipv4ToInt(value) {
    const parts = value.split(".");
    if (parts.length !== 4) return null;
    let out = 0;
    for (const part of parts) {
      if (!/^\d{1,3}$/.test(part)) return null;
      const n = Number(part);
      if (n < 0 || n > 255) return null;
      out = (out * 256) + n;
    }
    return out >>> 0;
  }

  function ipv6ToBigInt(value) {
    let text = value.toLowerCase();
    if (text.includes("%")) return null;
    const halves = text.split("::");
    if (halves.length > 2) return null;
    const left = halves[0] ? halves[0].split(":") : [];
    const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
    if (halves.length === 1) {
      if (left.length !== 8) return null;
    } else if (left.length + right.length > 8) {
      return null;
    }
    const groups = [...left, ...Array(8 - left.length - right.length).fill("0"), ...right];
    if (groups.length !== 8) return null;
    let out = 0n;
    for (const group of groups) {
      if (!/^[0-9a-f]{1,4}$/.test(group)) return null;
      out = (out << 16n) + BigInt(parseInt(group, 16));
    }
    return out;
  }

  function isIpv4(value) {
    return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(value) && ipv4ToInt(value) !== null;
  }

  function isIpv6(value) {
    return value.includes(":") && ipv6ToBigInt(value) !== null;
  }

  function matchesCidr(value, cidr) {
    const [network, prefixText] = cidr.split("/");
    const prefix = Number(prefixText);
    if (!Number.isInteger(prefix)) return false;
    if (isIpv4(value) && isIpv4(network)) {
      if (prefix < 0 || prefix > 32) return false;
      if (prefix === 0) return true;
      const mask = prefix === 32 ? 0xffffffff : (0xffffffff << (32 - prefix)) >>> 0;
      return (ipv4ToInt(value) & mask) === (ipv4ToInt(network) & mask);
    }
    if (isIpv6(value) && isIpv6(network)) {
      if (prefix < 0 || prefix > 128) return false;
      if (prefix === 0) return true;
      const mask = ((1n << 128n) - 1n) ^ ((1n << BigInt(128 - prefix)) - 1n);
      return (ipv6ToBigInt(value) & mask) === (ipv6ToBigInt(network) & mask);
    }
    return false;
  }

  function matches(value, assetValue) {
    const needle = clean(value).replace(/\.$/, "").toLowerCase();
    const pattern = clean(assetValue).replace(/\.$/, "").toLowerCase();
    if (!needle || !pattern) return false;
    if (pattern.includes("/")) return matchesCidr(needle, pattern);
    if (pattern.startsWith("*.")) {
      return needle.endsWith(pattern.slice(1)) && needle.length > pattern.length - 1;
    }
    return needle === pattern;
  }

  function matchesAny(values, assetList) {
    const source = Array.isArray(assetList) ? assetList : assets;
    for (const asset of source) {
      for (const value of values) {
        if (matches(value, asset.value)) return asset;
      }
    }
    return null;
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

  function renderList(error) {
    const listEl = document.getElementById("asset-list");
    const countEl = document.getElementById("asset-count");
    const errorEl = document.getElementById("asset-error");
    if (countEl) countEl.textContent = `${assets.length} watched`;
    if (errorEl) errorEl.textContent = error || "";
    if (!listEl) return;
    if (!assets.length) {
      listEl.innerHTML = '<p class="nw-empty">No critical assets yet. Add an IP, CIDR range or hostname.</p>';
      return;
    }
    listEl.innerHTML = assets.map((asset) => `<div class="nw-asset-row">
      <div><b>${escapeHtml(asset.label || asset.value)}</b><span>${escapeHtml(asset.value)}</span></div>
      <button type="button" data-asset-remove="${escapeHtml(asset.value)}" aria-label="Remove ${escapeHtml(asset.label || asset.value)}">Remove</button>
    </div>`).join("");
  }

  function bindUI(options) {
    const opts = options || {};
    const form = document.getElementById("asset-form");
    const value = document.getElementById("asset-value");
    const label = document.getElementById("asset-label");
    const listEl = document.getElementById("asset-list");

    renderList();
    if (form && value) {
      form.addEventListener("submit", (event) => {
        event.preventDefault();
        const result = add(value.value, label ? label.value : "");
        if (!result.ok) {
          renderList(result.error);
          return;
        }
        value.value = "";
        if (label) label.value = "";
        renderList();
        if (typeof opts.onChange === "function") opts.onChange();
      });
    }
    if (listEl) {
      listEl.addEventListener("click", (event) => {
        const button = event.target.closest("[data-asset-remove]");
        if (!button) return;
        remove(button.dataset.assetRemove);
        renderList();
        if (typeof opts.onChange === "function") opts.onChange();
      });
    }
    const resetButton = document.getElementById("asset-reset");
    if (resetButton) {
      resetButton.addEventListener("click", () => {
        reset();
        renderList();
        if (typeof opts.onChange === "function") opts.onChange();
      });
    }
    return { list, matchesAny, render: renderList };
  }

  window.KavachAssets = {
    list,
    add,
    remove,
    reset,
    matches,
    matchesAny,
    bindUI,
  };
})();
