/* Kavach pcap reader — classic pcap + basic pcapng, metadata only.
 * Parses Ethernet, raw IP, Linux SLL and 802.11/radiotap captures in the
 * browser. The file never leaves the device. */

(function () {
  "use strict";

  const APP_PORTS = {
    443: "HTTPS/TLS", 80: "HTTP", 53: "DNS", 853: "DNS over TLS", 22: "SSH",
    21: "FTP", 23: "Telnet", 445: "SMB", 139: "NetBIOS", 3389: "RDP", 502: "Modbus/TCP", 102: "IEC 60870-5-104",
    1883: "MQTT", 8883: "MQTT/TLS", 47808: "BACnet", 161: "SNMP", 123: "NTP",
    3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL", 25: "SMTP", 587: "SMTP",
    993: "IMAPS", 3478: "STUN/TURN", 1900: "SSDP", 5353: "mDNS", 67: "DHCP",
    68: "DHCP", 500: "IPsec", 4500: "IPsec", 1194: "OpenVPN", 51820: "WireGuard",
    8080: "HTTP", 8443: "HTTPS/TLS", 623: "IPMI", 20000: "DNP3", 44818: "EtherNet/IP",
  };
  const OT_PORTS = new Set([102, 502, 1883, 8883, 20000, 44818, 47808]);
  const CLEAR_PORTS = new Set([21, 23, 80, 8080]);
  const KNOWN_PORTS = new Set([
    ...Object.keys(APP_PORTS).map(Number),
    ...OT_PORTS,
    ...CLEAR_PORTS,
  ]);
  const PRIVATE_RE = /^(10\.|127\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|fc|fd|fe80:|::1$)/;

  const u8 = (v, o) => v.getUint8(o);
  const u16 = (v, o, le) => v.getUint16(o, le);
  const u32 = (v, o, le) => v.getUint32(o, le);

  function ipv4(v, o) { return `${u8(v, o)}.${u8(v, o + 1)}.${u8(v, o + 2)}.${u8(v, o + 3)}`; }
  function ipv6(v, o) {
    const parts = [];
    for (let i = 0; i < 16; i += 2) parts.push(u16(v, o + i, false).toString(16));
    return parts.join(":");
  }
  function isPrivate(ip) { return PRIVATE_RE.test(ip || ""); }
  function isMulticast(ip) { return /^(22[4-9]\.|23[0-9]\.|24[0-9]\.|25[0-5]\.|ff)/i.test(ip || ""); }
  function knownPort(port) { return KNOWN_PORTS.has(Number(port)); }

  function classify(port, proto) {
    const app = APP_PORTS[port] || (proto === "ICMP" || proto === "ICMPv6" ? proto : "Other");
    if (proto === "ICMP" || proto === "ICMPv6") return { app, protocol: proto };
    if (port === 443 || port === 8443) return { app, protocol: "TLS" };
    if (port === 80 || port === 8080) return { app, protocol: "HTTP" };
    if (port === 53 || port === 853) return { app, protocol: "DNS" };
    if (OT_PORTS.has(port)) return { app, protocol: app };
    if (proto === "UDP") return { app, protocol: "UDP" };
    if (proto === "TCP") return { app, protocol: "TCP" };
    return { app, protocol: proto };
  }

  function readClassic(view, meta) {
    const magic = u32(view, 0, false);
    const little = magic === 0xd4c3b2a1 || magic === 0x4d3cb2a1;
    const nano = magic === 0xa1b23c4d || magic === 0x4d3cb2a1;
    const linkType = u32(view, 20, little);
    const packets = [];
    let offset = 24;
    let truncated = false;
    while (offset + 16 <= view.byteLength) {
      if (packets.length >= 250000) { truncated = true; break; }
      const tsSec = u32(view, offset, little);
      const tsFrac = u32(view, offset + 4, little);
      const incl = u32(view, offset + 8, little);
      const orig = u32(view, offset + 12, little);
      const start = offset + 16;
      if (incl <= 0 || start + incl > view.byteLength) { truncated = true; break; }
      const ts = tsSec + tsFrac / (nano ? 1e9 : 1e6);
      readFrame(view, start, incl, linkType, ts, orig, packets);
      offset = start + incl;
    }
    meta.format = "pcap";
    meta.linkType = linkType;
    meta.truncated = truncated;
    return packets;
  }

  function readPcapng(view, meta) {
    const packets = [];
    let offset = 0;
    let little = true;
    let interfaces = [];
    let truncated = false;
    while (offset + 12 <= view.byteLength) {
      if (packets.length >= 250000) { truncated = true; break; }
      const typeBE = u32(view, offset, false);
      if (typeBE === 0x0a0d0d0a) {
        const bom = u32(view, offset + 8, false);
        little = bom === 0x4d3c2b1a;
      }
      const type = u32(view, offset, little);
      const total = u32(view, offset + 4, little);
      if (total < 12 || offset + total > view.byteLength) { truncated = true; break; }
      if (type === 0x00000001) {
        const linkType = u16(view, offset + 8, little);
        let resolution = 1e6;
        let opt = offset + 16;
        const end = offset + total - 4;
        while (opt + 4 <= end) {
          const code = u16(view, opt, little);
          const len = u16(view, opt + 2, little);
          if (code === 0) break;
          if (code === 9 && len >= 1) {
            const value = u8(view, opt + 4);
            resolution = value & 0x80 ? Math.pow(2, value & 0x7f) : Math.pow(10, value);
          }
          opt += 4 + len + ((4 - (len % 4)) % 4);
        }
        interfaces.push({ linkType, resolution });
      } else if (type === 0x00000006) {
        const iface = u32(view, offset + 8, little);
        const high = u32(view, offset + 12, little);
        const low = u32(view, offset + 16, little);
        const capLen = u32(view, offset + 20, little);
        const origLen = u32(view, offset + 24, little);
        const start = offset + 28;
        const info = interfaces[iface] || interfaces[0] || { linkType: 1, resolution: 1e6 };
        if (start + capLen <= offset + total) {
          const ts = ((high * 4294967296) + low) / info.resolution;
          readFrame(view, start, capLen, info.linkType, ts, origLen, packets);
        }
      } else if (type === 0x00000003) {
        const origLen = u32(view, offset + 8, little);
        const start = offset + 12;
        const info = interfaces[0] || { linkType: 1 };
        const captured = Math.max(0, total - 16);
        if (captured > 0) {
          readFrame(view, start, Math.min(origLen, captured), info.linkType, 0, origLen, packets);
        }
      }
      offset += total;
    }
    meta.format = "pcapng";
    meta.linkType = interfaces[0]?.linkType || 1;
    meta.truncated = truncated;
    return packets;
  }

  function readFrame(view, start, incl, linkType, ts, orig, out) {
    let ipStart = -1;
    let end = start + incl;
    if (linkType === 1) {
      if (incl < 14) return;
      let etherType = u16(view, start + 12, false);
      let offset = 14;
      while (etherType === 0x8100 || etherType === 0x88a8) {
        if (start + offset + 4 > end) return;
        etherType = u16(view, start + offset + 2, false);
        offset += 4;
      }
      if (etherType === 0x0800 || etherType === 0x86dd) ipStart = start + offset;
    } else if (linkType === 12 || linkType === 101 || linkType === 228 || linkType === 229) {
      ipStart = start;
    } else if (linkType === 113) {
      if (incl < 16) return;
      const proto = u16(view, start + 14, false);
      if (proto === 0x0800 || proto === 0x86dd) ipStart = start + 16;
    } else if (linkType === 276) {
      if (incl < 20) return;
      const proto = u16(view, start, false);
      if (proto === 0x0800 || proto === 0x86dd) ipStart = start + 20;
    } else if (linkType === 0) {
      if (incl < 4) return;
      const family = u32(view, start, false);
      if (family === 2 || family === 0x02000000 || family === 24 || family === 0x18000000 || family === 28 || family === 30) ipStart = start + 4;
    } else if (linkType === 105 || linkType === 127) {
      readWifi(view, start, end, linkType, ts, orig || incl, out);
      return;
    }
    if (ipStart < 0 || ipStart >= end) return;
    readIp(view, ipStart, end, ts, orig || incl, out);
  }

  function readWifi(view, start, end, linkType, ts, size, out) {
    let offset = start;
    if (linkType === 127) {
      if (start + 8 > end) return;
      const headerLength = u16(view, start + 2, true);
      if (headerLength < 8) return;
      offset = start + headerLength;
    }
    if (offset + 24 > end) return;
    const frameControl = u16(view, offset, true);
    const type = (frameControl >> 2) & 3;
    const subtype = (frameControl >> 4) & 0x0f;
    if (type !== 2) return;
    const flags = frameControl >> 8;
    const toDs = !!(flags & 0x01);
    const fromDs = !!(flags & 0x02);
    let headerLength = 24;
    if (toDs && fromDs) headerLength += 6;
    if (subtype & 0x08) headerLength += 2;
    if (flags & 0x80) headerLength += 4;
    const llc = offset + headerLength;
    if (llc + 8 > end) return;
    if (u8(view, llc) !== 0xaa || u8(view, llc + 1) !== 0xaa || u8(view, llc + 2) !== 0x03) return;
    const etherType = u16(view, llc + 6, false);
    if (etherType !== 0x0800 && etherType !== 0x86dd) return;
    readIp(view, llc + 8, end, ts, size, out);
  }

  function readIp(view, start, end, ts, size, out) {
    if (start >= end) return;
    const version = u8(view, start) >> 4;
    if (version === 4) {
      const ihl = (u8(view, start) & 0x0f) * 4;
      if (ihl < 20 || start + ihl > end) return;
      const total = u16(view, start + 2, false);
      const protoNum = u8(view, start + 9);
      const src = ipv4(view, start + 12);
      const dst = ipv4(view, start + 16);
      const payload = start + ihl;
      const proto = protoNum === 6 ? "TCP" : protoNum === 17 ? "UDP" : protoNum === 1 ? "ICMP" : `IP/${protoNum}`;
      const fragmentOffset = u16(view, start + 6, false) & 0x1fff;
      const ports = fragmentOffset ? [0, 0] : readPorts(view, payload, end, protoNum);
      out.push({ ts, src, dst, sport: ports[0], dport: ports[1], proto, size: total || size || end - start });
    } else if (version === 6) {
      if (start + 40 > end) return;
      let next = u8(view, start + 6);
      const total = u16(view, start + 4, false) + 40;
      const src = ipv6(view, start + 8);
      const dst = ipv6(view, start + 24);
      let payload = start + 40;
      let guard = 0;
      let fragmentOffset = 0;
      while ((next === 0 || next === 43 || next === 44 || next === 60) && payload + 8 <= end && guard < 8) {
        const hdr = u8(view, payload);
        if (next === 44) {
          fragmentOffset = u16(view, payload + 2, false) >> 3;
          next = hdr;
          payload += 8;
        } else {
          next = hdr;
          payload += (u8(view, payload + 1) + 1) * 8;
        }
        guard += 1;
      }
      const proto = next === 6 ? "TCP" : next === 17 ? "UDP" : next === 58 ? "ICMPv6" : `IP/${next}`;
      const ports = fragmentOffset ? [0, 0] : readPorts(view, payload, end, next);
      out.push({ ts, src, dst, sport: ports[0], dport: ports[1], proto, size: total || size || end - start });
    }
  }

  function readPorts(view, start, end, proto) {
    if (proto === 6 && start + 4 <= end) return [u16(view, start, false), u16(view, start + 2, false)];
    if (proto === 17 && start + 4 <= end) return [u16(view, start, false), u16(view, start + 2, false)];
    return [0, 0];
  }

  function analyze(buffer, fileName) {
    const view = new DataView(buffer);
    if (view.byteLength < 24) throw new Error("The file is too small to be a capture.");
    const meta = { fileName };
    let packets;
    const magic = u32(view, 0, false);
    if (magic === 0xa1b2c3d4 || magic === 0xa1b23c4d || magic === 0xd4c3b2a1 || magic === 0x4d3cb2a1) {
      packets = readClassic(view, meta);
    } else if (magic === 0x0a0d0d0a) {
      packets = readPcapng(view, meta);
    } else {
      throw new Error("Unrecognised capture format. Use a .pcap or .pcapng file.");
    }
    if (!packets.length) throw new Error("No IP packets found. The capture may use an unsupported link type or be empty.");
    return buildSnapshot(packets, meta);
  }

  function buildSnapshot(packets, meta) {
    const ipCounts = new Map();
    for (const p of packets) {
      if (isPrivate(p.src) && !isMulticast(p.src)) ipCounts.set(p.src, (ipCounts.get(p.src) || 0) + 1);
      if (isPrivate(p.dst) && !isMulticast(p.dst)) ipCounts.set(p.dst, (ipCounts.get(p.dst) || 0) + 1);
    }
    const local = [...ipCounts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] || packets[0].src;
    const flowMap = new Map();
    const hosts = new Map();
    const protocols = new Map();
    const apps = new Map();
    const alerts = [];
    const alertKeys = new Set();
    const pushAlert = (key, severity, title, detail, time) => {
      if (alertKeys.has(key) || alerts.length >= 200) return;
      alertKeys.add(key);
      alerts.push({ severity, title, detail, time });
    };
    const seen = new Set();
    const buckets = new Map();
    let bytesIn = 0;
    let bytesOut = 0;
    let bytesTransit = 0;
    let maxTs = 0;
    let minTs = Infinity;
    for (const packet of packets) {
      if (packet.ts) {
        if (packet.ts > maxTs) maxTs = packet.ts;
        if (packet.ts < minTs) minTs = packet.ts;
      }
    }
    if (!Number.isFinite(minTs)) minTs = 0;
    const startTs = Math.max(minTs, maxTs - 59);

    for (const p of packets) {
      const direction = p.src === local ? "outbound" : p.dst === local ? "inbound" : "transit";
      const remoteIp = direction === "inbound" ? p.src : p.dst;
      const port = direction === "inbound"
        ? p.sport
        : direction === "outbound"
          ? p.dport
          : (knownPort(p.dport) || !knownPort(p.sport) ? p.dport : p.sport);
      const c = classify(port, p.proto);
      let risk = "low";
      let verdict = "normal";
      if (CLEAR_PORTS.has(port)) { risk = "high"; verdict = "cleartext"; }
      else if (OT_PORTS.has(port)) { risk = "medium"; verdict = "OT boundary"; }
      else if (!isPrivate(remoteIp)) { risk = "medium"; verdict = "watch"; }
      if (direction === "transit" && verdict === "normal") {
        risk = "low";
        verdict = "transit";
      }

      const key = `${p.src}|${p.sport}|${p.dst}|${p.dport}|${p.proto}`;
      let flow = flowMap.get(key);
      const newFlow = !flow;
      if (!flow) {
        flow = {
          ts: p.ts,
          firstSeen: p.ts,
          lastSeen: p.ts,
          host: p.src,
          src: p.src,
          srcIp: p.src,
          dst: p.dst,
          dstIp: p.dst,
          vendor: isPrivate(remoteIp) ? "LAN" : "Unknown",
          app: c.app,
          protocol: c.protocol,
          port,
          direction,
          bytes: 0,
          packets: 0,
          risk,
          verdict,
        };
        flowMap.set(key, flow);
      }
      flow.bytes += p.size;
      flow.packets += 1;
      flow.firstSeen = Math.min(flow.firstSeen, p.ts);
      flow.lastSeen = Math.max(flow.lastSeen, p.ts);
      flow.ts = flow.lastSeen;
      if (risk === "high" || (risk === "medium" && flow.risk === "low")) {
        flow.risk = risk;
        flow.verdict = verdict;
      }
      if (direction === "inbound") bytesIn += p.size;
      else if (direction === "outbound") bytesOut += p.size;
      else bytesTransit += p.size;

      const endpoints = direction === "transit"
        ? [[p.src, 0, p.size], [p.dst, p.size, 0]]
        : [[remoteIp, direction === "inbound" ? p.size : 0, direction === "outbound" ? p.size : 0]];
      for (const [ip, addIn, addOut] of endpoints) {
        if (ip === local) continue;
        const item = hosts.get(ip) || { ip, name: ip, vendor: isPrivate(ip) ? "LAN" : "Unknown", bytesIn: 0, bytesOut: 0, apps: new Set(), lastSeen: p.ts, risk: "low" };
        item.bytesIn += addIn;
        item.bytesOut += addOut;
        item.apps.add(c.app);
        item.lastSeen = Math.max(item.lastSeen, p.ts);
        if (risk === "high" || (risk === "medium" && item.risk === "low")) item.risk = risk;
        hosts.set(ip, item);
        if (!seen.has(ip)) {
          seen.add(ip);
          if (!isPrivate(ip)) {
            pushAlert(`new:${ip}`, "info", "New public host", `${ip} appears in the capture.`, p.ts);
          }
        }
      }

      const alertKey = `flow:${[p.src, p.dst].sort().join("|")}:${port}`;
      if (CLEAR_PORTS.has(port)) {
        pushAlert(alertKey, "critical", "Cleartext protocol", `${p.src} → ${p.dst} on port ${port} (${c.app}).`, p.ts);
      }
      if (OT_PORTS.has(port)) {
        pushAlert(alertKey, "high", `OT protocol observed · ${c.app}`, `${p.src} → ${p.dst} on port ${port}.`, p.ts);
      }
      protocols.set(c.protocol, (protocols.get(c.protocol) || 0) + p.size);
      const app = apps.get(c.app) || { bytes: 0, flows: 0 };
      app.bytes += p.size;
      if (newFlow) app.flows += 1;
      apps.set(c.app, app);

      if (p.ts >= startTs) {
        const sec = Math.floor(p.ts);
        const bucket = buckets.get(sec) || [0, 0, 0];
        if (direction === "inbound") bucket[0] += p.size;
        else if (direction === "outbound") bucket[1] += p.size;
        else bucket[2] += p.size;
        buckets.set(sec, bucket);
      }
    }

    const series = [];
    const end = Math.ceil(maxTs);
    for (let i = end - 59; i <= end; i += 1) {
      const b = buckets.get(i) || [0, 0, 0];
      series.push({ in: b[0], out: b[1], transit: b[2] });
    }

    const flows = [...flowMap.values()].sort((a, b) => b.lastSeen - a.lastSeen);
    const hostRows = [...hosts.values()].sort((a, b) => (b.bytesIn + b.bytesOut) - (a.bytesIn + a.bytesOut));
    return {
      mode: "file",
      interface: meta.fileName,
      status: "analyzed",
      updatedAt: maxTs,
      stats: { packets: packets.length, flows: flowMap.size, drops: 0, hosts: hostRows.length, bytesIn, bytesOut, transit: bytesTransit },
      series,
      protocols: [...protocols.entries()].map(([name, bytes]) => ({ name, bytes })),
      apps: [...apps.entries()].map(([name, v]) => ({ name, bytes: v.bytes, flows: v.flows })),
      hosts: hostRows.map((h) => ({ ...h, apps: [...h.apps] })),
      flows: flows.slice(0, 200),
      alerts: alerts.slice(0, 8),
      meta: { ...meta, localIp: local, duration: maxTs - minTs, start: minTs, end: maxTs, hasTimestamps: maxTs > 0, alertsTruncated: alerts.length > 8 },
    };
  }

  window.KavachPcap = { analyze };
})();
