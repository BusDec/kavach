(() => {
  "use strict";

  const CONTROLS = [
    { key: "mfa", label: "MFA" },
    { key: "edr", label: "EDR" },
    { key: "patching", label: "Patching" },
    { key: "backup", label: "Backup" },
    { key: "logging", label: "Logging" },
    { key: "segmentation", label: "Segmentation" },
    { key: "encryption", label: "Encryption" },
    { key: "least_privilege", label: "Least privilege" },
  ];

  const CONTROL_GUIDANCE = {
    mfa: "Require phishing-resistant MFA for interactive access and review how service accounts authenticate.",
    edr: "Deploy endpoint detection and response and confirm the agent is healthy on the asset.",
    patching: "Apply the approved patch baseline and record the oldest outstanding critical update.",
    backup: "Add an immutable, tested backup with a documented restore test.",
    logging: "Forward authentication, configuration and administrative events to the SIEM.",
    segmentation: "Place the asset in a restricted zone with deny-by-default flows.",
    encryption: "Enable encryption in transit and at rest; rotate certificates and keys.",
    least_privilege: "Remove standing administrative rights and review role assignments.",
  };

  const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const CRITICALITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
  const CATEGORY_LABELS = {
    application: "Application",
    device: "Device",
    resource: "Resource",
    identity: "Identity",
  };

  const daysAgo = (days) => new Date(Date.now() - days * 86400000).toISOString();
  const minutesAgo = (minutes) => new Date(Date.now() - minutes * 60000).toISOString();

  const SAMPLE = {
    schema: "kavach.protection.v1",
    generated_at: new Date().toISOString(),
    organization: "Meridian Energy",
    notes: [
      "Synthetic register for the Kavach protection demo.",
      "Controls marked null are unverified, not assumed to be protected.",
      "Read-only: no active scanning, exploitation or response actions.",
    ],
    assets: [
      {
        id: "sap-prod", name: "SAP S/4HANA Production", category: "application",
        type: "SAP ERP", criticality: "critical", owner: "Enterprise Applications",
        site: "HQ Pune", environment: "production", exposure: "internal",
        controls: { mfa: true, edr: false, patching: true, backup: true, logging: true, segmentation: true, encryption: true, least_privilege: false },
        evidence: "SAP security review; RFC gateway excluded from this record",
        last_verified: daysAgo(3), notes: "Crown-jewel ERP for finance and maintenance.",
      },
      {
        id: "hana-prod", name: "SAP HANA Production", category: "resource",
        type: "Database", criticality: "critical", owner: "Database Team",
        site: "Data Centre Mumbai", environment: "production", exposure: "internal",
        controls: { mfa: false, edr: false, patching: true, backup: true, logging: true, segmentation: true, encryption: true, least_privilege: false },
        evidence: "Database hardening review", last_verified: daysAgo(7),
        notes: "Holds finance and maintenance data for the SAP estate.",
      },
      {
        id: "plc-line2", name: "PLC Line 2", category: "device",
        type: "Siemens S7-1500", criticality: "critical", owner: "OT Engineering",
        site: "Plant Auraiya", environment: "production", exposure: "air-gapped",
        controls: { mfa: false, edr: false, patching: false, backup: false, logging: true, segmentation: true, encryption: false, least_privilege: true },
        evidence: "OT asset walk-down", last_verified: daysAgo(21),
        notes: "Vendor-supported controller; changes need a maintenance window.",
      },
      {
        id: "ot-historian", name: "OT Historian", category: "application",
        type: "AVEVA PI", criticality: "critical", owner: "OT Engineering",
        site: "Plant Auraiya", environment: "production", exposure: "internal",
        controls: { mfa: false, edr: true, patching: false, backup: true, logging: true, segmentation: true, encryption: false, least_privilege: false },
        evidence: "OT logging review", last_verified: daysAgo(12),
        notes: "Process history for the plant; shared with engineering.",
      },
      {
        id: "grid-scada", name: "Grid SCADA", category: "application",
        type: "SCADA", criticality: "critical", owner: "Grid Operations",
        site: "Data Centre Mumbai", environment: "production", exposure: "partner",
        controls: { mfa: true, edr: false, patching: false, backup: true, logging: true, segmentation: true, encryption: false, least_privilege: false },
        evidence: "Grid operations control review", last_verified: daysAgo(9),
        notes: "Partner-supported dispatch and telemetry platform.",
      },
      {
        id: "m365", name: "Microsoft 365 Tenant", category: "application",
        type: "Cloud productivity", criticality: "high", owner: "IT Operations",
        site: "HQ Pune", environment: "production", exposure: "internet",
        controls: { mfa: true, edr: true, patching: true, backup: true, logging: true, segmentation: false, encryption: true, least_privilege: true },
        evidence: "Conditional access and tenant review", last_verified: daysAgo(2),
        notes: "Email, collaboration and identity plane for the enterprise.",
      },
      {
        id: "vpn-gw", name: "Remote Access VPN", category: "resource",
        type: "Network gateway", criticality: "critical", owner: "Network Team",
        site: "Data Centre Mumbai", environment: "production", exposure: "internet",
        controls: { mfa: true, edr: false, patching: true, backup: true, logging: true, segmentation: true, encryption: true, least_privilege: false },
        evidence: "Remote-access path review", last_verified: daysAgo(5),
        notes: "Primary remote path into IT and OT support networks.",
      },
      {
        id: "finance-share", name: "Finance File Share", category: "resource",
        type: "SMB share", criticality: "high", owner: "Finance Systems",
        site: "HQ Pune", environment: "production", exposure: "internal",
        controls: { mfa: true, edr: false, patching: true, backup: true, logging: false, segmentation: true, encryption: true, least_privilege: false },
        evidence: "File-share permission review", last_verified: daysAgo(16),
        notes: "Contains close, payroll and vendor files.",
      },
      {
        id: "aws-prod", name: "AWS Production Account", category: "application",
        type: "Cloud account", criticality: "critical", owner: "Cloud Platform",
        site: "Remote", environment: "production", exposure: "internet",
        controls: { mfa: true, edr: false, patching: true, backup: true, logging: true, segmentation: true, encryption: true, least_privilege: true },
        evidence: "Cloud control review", last_verified: daysAgo(4),
        notes: "Hosts analytics and integration workloads.",
      },
      {
        id: "svc-backup", name: "Backup Service Account", category: "identity",
        type: "Service account", criticality: "critical", owner: "IT Operations",
        site: "HQ Pune", environment: "production", exposure: "internal",
        controls: { mfa: false, logging: true, least_privilege: false },
        evidence: "Privileged-access review", last_verified: daysAgo(23),
        notes: "Standing domain backup rights; interactive logon not expected.",
      },
      {
        id: "ws-priya", name: "Priya's Workstation", category: "device",
        type: "Laptop", criticality: "medium", owner: "priya.n",
        site: "Remote", environment: "production", exposure: "internal",
        controls: { mfa: true, edr: true, patching: false, backup: false, logging: true, segmentation: false, encryption: true, least_privilege: true },
        evidence: "Endpoint inventory", last_verified: daysAgo(1),
        notes: "Uses VPN for SAP and email access.",
      },
      {
        id: "pi-dmz", name: "PI Data Archive DMZ", category: "resource",
        type: "Historian replica", criticality: "critical", owner: "OT Engineering",
        site: "DMZ", environment: "production", exposure: "partner",
        controls: { mfa: false, edr: false, patching: false, backup: true, logging: true, segmentation: true, encryption: false, least_privilege: false },
        evidence: "DMZ boundary review", last_verified: daysAgo(18),
        notes: "Partner read access to selected process data.",
      },
    ],
    devices: [
      {
        id: "ws-priya", asset_id: "ws-priya", hostname: "WS-PRIYA",
        os: "Windows 11 Pro", os_version: "22631.4890", owner: "priya.n",
        site: "Remote", criticality: "medium", patch_status: "outdated",
        edr: true, disk_encryption: true, firewall: true, admin_rights: false,
        last_seen: minutesAgo(18),
      },
      {
        id: "app-sap01", asset_id: "sap-prod", hostname: "APP-SAP01",
        os: "Windows Server 2022", os_version: "20348.3207", owner: "Enterprise Applications",
        site: "HQ Pune", criticality: "critical", patch_status: "current",
        edr: true, disk_encryption: true, firewall: true, admin_rights: false,
        last_seen: minutesAgo(6),
      },
      {
        id: "hana-db01", asset_id: "hana-prod", hostname: "HANA-DB01",
        os: "SUSE Linux 15 SP5", os_version: "5.14.21", owner: "Database Team",
        site: "Data Centre Mumbai", criticality: "critical", patch_status: "current",
        edr: true, disk_encryption: true, firewall: true, admin_rights: false,
        last_seen: minutesAgo(11),
      },
      {
        id: "ot-historian", asset_id: "ot-historian", hostname: "OT-HISTORIAN",
        os: "Red Hat Enterprise Linux 8.9", os_version: "4.18.0-513", owner: "OT Engineering",
        site: "Plant Auraiya", criticality: "critical", patch_status: "outdated",
        edr: false, disk_encryption: false, firewall: true, admin_rights: true,
        last_seen: minutesAgo(52),
      },
      {
        id: "plc-line2", asset_id: "plc-line2", hostname: "PLC-LINE2",
        os: "Siemens S7-1500", os_version: "firmware 3.1", owner: "OT Engineering",
        site: "Plant Auraiya", criticality: "critical", patch_status: "unknown",
        edr: false, disk_encryption: false, firewall: true, admin_rights: true,
        last_seen: minutesAgo(74),
      },
      {
        id: "mbp-design", asset_id: "", hostname: "MBP-DESIGN",
        os: "macOS Sequoia", os_version: "15.2", owner: "design.lead",
        site: "HQ Pune", criticality: "medium", patch_status: "outdated",
        edr: true, disk_encryption: true, firewall: true, admin_rights: false,
        last_seen: minutesAgo(33),
      },
      {
        id: "linux-jump", asset_id: "vpn-gw", hostname: "LINUX-JUMP",
        os: "Ubuntu 24.04 LTS", os_version: "6.8.0-51", owner: "Network Team",
        site: "Data Centre Mumbai", criticality: "high", patch_status: "current",
        edr: true, disk_encryption: true, firewall: true, admin_rights: false,
        last_seen: minutesAgo(9),
      },
      {
        id: "vpn-gw01", asset_id: "vpn-gw", hostname: "VPN-GW01",
        os: "FortiOS", os_version: "7.4.5", owner: "Network Team",
        site: "Data Centre Mumbai", criticality: "critical", patch_status: "current",
        edr: false, disk_encryption: true, firewall: true, admin_rights: false,
        last_seen: minutesAgo(4),
      },
      {
        id: "grid-gw01", asset_id: "grid-scada", hostname: "GRID-GW01",
        os: "Cisco IOS XE", os_version: "17.12.4", owner: "Grid Operations",
        site: "Data Centre Mumbai", criticality: "critical", patch_status: "outdated",
        edr: false, disk_encryption: true, firewall: true, admin_rights: false,
        last_seen: minutesAgo(21),
      },
    ],
    resources: [
      {
        id: "sap-rfc", asset_id: "sap-prod", name: "SAP RFC gateway", type: "SAP service",
        internet_facing: false, auth: "Service account + SNC", encryption: "SNC",
        exposure_path: "VPN -> SAProuter -> RFC", criticality: "critical", owner: "Basis",
      },
      {
        id: "sap-gui", asset_id: "sap-prod", name: "SAP GUI / HTTPS", type: "SAP service",
        internet_facing: false, auth: "SSO + MFA", encryption: "TLS 1.3",
        exposure_path: "VPN -> reverse proxy", criticality: "critical", owner: "Basis",
      },
      {
        id: "hana-sql", asset_id: "hana-prod", name: "HANA SQL", type: "Database",
        internet_facing: false, auth: "DB auth + TLS", encryption: "TLS",
        exposure_path: "SAP application subnet", criticality: "critical", owner: "Database Team",
      },
      {
        id: "pi-web", asset_id: "pi-dmz", name: "PI Web API", type: "Web API",
        internet_facing: true, auth: "Windows auth", encryption: "TLS",
        exposure_path: "Partner VPN -> DMZ -> PI", criticality: "critical", owner: "OT Engineering",
      },
      {
        id: "plc-modbus", asset_id: "plc-line2", name: "Modbus/TCP", type: "OT protocol",
        internet_facing: false, auth: "None", encryption: "None",
        exposure_path: "Plant VLAN -> Line 2", criticality: "critical", owner: "OT Engineering",
      },
      {
        id: "historian-opcua", asset_id: "ot-historian", name: "OPC UA", type: "OT protocol",
        internet_facing: false, auth: "Certificate", encryption: "Sign & encrypt",
        exposure_path: "Plant VLAN -> historian", criticality: "critical", owner: "OT Engineering",
      },
      {
        id: "finance-smb", asset_id: "finance-share", name: "Finance SMB", type: "File share",
        internet_facing: false, auth: "AD", encryption: "SMB signing",
        exposure_path: "HQ LAN", criticality: "high", owner: "Finance Systems",
      },
      {
        id: "vpn-portal", asset_id: "vpn-gw", name: "VPN portal", type: "Remote access",
        internet_facing: true, auth: "MFA", encryption: "TLS 1.3",
        exposure_path: "Public internet", criticality: "critical", owner: "Network Team",
      },
      {
        id: "m365-exchange", asset_id: "m365", name: "Exchange Online", type: "Cloud service",
        internet_facing: true, auth: "MFA + conditional access", encryption: "TLS",
        exposure_path: "Public internet", criticality: "high", owner: "IT Operations",
      },
      {
        id: "aws-s3", asset_id: "aws-prod", name: "S3 production bucket", type: "Object storage",
        internet_facing: true, auth: "IAM + bucket policy", encryption: "SSE-KMS",
        exposure_path: "AWS API", criticality: "critical", owner: "Cloud Platform",
      },
      {
        id: "saprouter", asset_id: "vpn-gw", name: "SAProuter", type: "Network service",
        internet_facing: true, auth: "IP allowlist + password", encryption: "TLS",
        exposure_path: "Public internet -> SAProuter", criticality: "critical", owner: "Basis",
      },
    ],
    logins: [
      {
        account: "priya.n", display_name: "Priya Nair", type: "human", mfa: true,
        last_login: minutesAgo(35), stale_days: 0, failed_24h: 3,
        assets: ["ws-priya"], notes: "SAP and email user.",
      },
      {
        account: "svc-backup", display_name: "Backup service", type: "service", mfa: false,
        last_login: minutesAgo(95), stale_days: 0, failed_24h: 0,
        assets: ["svc-backup"], notes: "Standing domain backup rights; interactive logon not expected.",
      },
      {
        account: "admin.sap", display_name: "SAP Basis admin", type: "privileged", mfa: true,
        last_login: daysAgo(1), stale_days: 1, failed_24h: 1,
        assets: ["sap-prod", "hana-prod"], notes: "Emergency and change access.",
      },
      {
        account: "ot.engineer", display_name: "OT engineer", type: "human", mfa: false,
        last_login: minutesAgo(28), stale_days: 0, failed_24h: 0,
        assets: ["ot-historian", "plc-line2"], notes: "Plant engineering access; shared console in control room.",
      },
      {
        account: "contractor.ravi", display_name: "Ravi (contractor)", type: "human", mfa: true,
        last_login: daysAgo(48), stale_days: 48, failed_24h: 7,
        assets: ["finance-share"], notes: "Close-support contractor; access review due.",
      },
      {
        account: "svc-pi", display_name: "PI integration service", type: "service", mfa: false,
        last_login: minutesAgo(120), stale_days: 0, failed_24h: 0,
        assets: ["pi-dmz"], notes: "Reads process data for the DMZ replica.",
      },
      {
        account: "anita.rao", display_name: "Anita Rao", type: "human", mfa: true,
        last_login: minutesAgo(44), stale_days: 0, failed_24h: 0,
        assets: ["m365"], notes: "Finance planning user.",
      },
      {
        account: "arjun.s", display_name: "Arjun S", type: "human", mfa: true,
        last_login: daysAgo(97), stale_days: 97, failed_24h: 0,
        assets: [], notes: "No sign-in for more than 90 days.",
      },
      {
        account: "helpdesk.admin", display_name: "Helpdesk administrator", type: "privileged", mfa: true,
        last_login: minutesAgo(62), stale_days: 0, failed_24h: 12,
        assets: ["m365"], notes: "Tier-1 administration; repeated failures from one device.",
      },
      {
        account: "svc-aws", display_name: "AWS automation", type: "service", mfa: false,
        last_login: minutesAgo(15), stale_days: 0, failed_24h: 0,
        assets: ["aws-prod"], notes: "Uses long-lived access keys.",
      },
    ],
    gaps: [
      {
        id: "manual-sap-notes", asset_id: "sap-prod", category: "asset", severity: "medium",
        title: "SAP security notes not reviewed for the current month",
        recommendation: "Review the latest SAP Security Notes and record applicability and owner sign-off.",
        owner: "Basis", due: daysAgo(-14).slice(0, 10),
      },
      {
        id: "manual-plc-vendor", asset_id: "plc-line2", category: "device", severity: "high",
        title: "Vendor remote-access window is not time-bound",
        recommendation: "Move vendor access to a just-in-time window with session recording and approval.",
        owner: "OT Engineering", due: daysAgo(-7).slice(0, 10),
      },
    ],
  };

  const state = {
    raw: null,
    derived: null,
    source: "demo",
    filename: "",
    tab: "overview",
    selectedAsset: "",
  };

  const $ = (id) => document.getElementById(id);

  function esc(value) {
    return String(value == null ? "" : value).replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
  }

  function text(value) {
    return String(value == null ? "" : value).trim();
  }

  function lower(value) {
    return text(value).toLowerCase();
  }

  function slug(value) {
    return lower(value).replace(/[^a-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "") || "item";
  }

  function fmtNumber(value) {
    return Number(value || 0).toLocaleString();
  }

  function fmtDate(value) {
    const date = value ? new Date(value) : null;
    if (!date || Number.isNaN(date.getTime())) return "—";
    return date.toLocaleString([], {
      year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit",
    });
  }

  function fmtRelative(value) {
    const date = value ? new Date(value) : null;
    if (!date || Number.isNaN(date.getTime())) return "—";
    const seconds = Math.round((Date.now() - date.getTime()) / 1000);
    if (seconds < 60) return "just now";
    if (seconds < 3600) return `${Math.round(seconds / 60)} min ago`;
    if (seconds < 86400) return `${Math.round(seconds / 3600)} h ago`;
    return `${Math.round(seconds / 86400)} d ago`;
  }

  function pct(value) {
    return value == null || Number.isNaN(value) ? "—" : `${Math.round(value * 100)}%`;
  }

  function boolValue(value) {
    if (value === true || value === false) return value;
    const raw = lower(value);
    if (["true", "yes", "1", "on", "enabled"].includes(raw)) return true;
    if (["false", "no", "0", "off", "disabled"].includes(raw)) return false;
    return null;
  }

  function oneOf(value, allowed, fallback) {
    const raw = lower(value);
    return allowed.includes(raw) ? raw : fallback;
  }

  function up(severity) {
    return severity === "low" ? "medium" : severity === "medium" ? "high" : "critical";
  }

  function down(severity) {
    return severity === "critical" ? "high" : severity === "high" ? "medium" : severity === "medium" ? "low" : "low";
  }

  function riskLevel(score) {
    return score >= 75 ? "critical" : score >= 55 ? "high" : score >= 35 ? "medium" : "low";
  }

  function loginRiskLevel(score) {
    return score >= 70 ? "critical" : score >= 45 ? "high" : score >= 25 ? "medium" : "low";
  }

  function riskTag(risk) {
    const safe = ["critical", "high", "medium", "low", "info"].includes(risk) ? risk : "info";
    return `<span class="nw-risk ${safe}">${esc(safe)}</span>`;
  }

  function criticalityTag(value) {
    const safe = ["critical", "high", "medium", "low"].includes(value) ? value : "medium";
    return `<span class="nw-risk ${safe === "critical" ? "critical" : safe}">${esc(safe)}</span>`;
  }

  function triTag(value, yes, no, unknown = "unverified") {
    if (value === true) return `<span class="nw-risk low">${esc(yes)}</span>`;
    if (value === false) return `<span class="nw-risk high">${esc(no)}</span>`;
    return `<span class="nw-risk info">${esc(unknown)}</span>`;
  }

  function adminTag(value) {
    if (value === true) return '<span class="nw-risk high">standing</span>';
    if (value === false) return '<span class="nw-risk low">restricted</span>';
    return '<span class="nw-risk info">unverified</span>';
  }

  function normalizeSnapshot(raw) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
      throw new Error("Expected a JSON object.");
    }
    const root = raw.snapshot && typeof raw.snapshot === "object"
      ? raw.snapshot
      : raw.protection && typeof raw.protection === "object"
        ? raw.protection
        : raw;
    if (!Array.isArray(root.assets) || !root.assets.length) {
      throw new Error("The register needs a non-empty assets array.");
    }
    const assets = root.assets.map((row, index) => normalizeAsset(row, index));
    const ids = new Set();
    for (const asset of assets) {
      let candidate = asset.id;
      let suffix = 2;
      while (ids.has(candidate)) candidate = `${asset.id}-${suffix++}`;
      asset.id = candidate;
      ids.add(candidate);
    }
    const assetIds = new Set(assets.map((asset) => asset.id));
    const devices = Array.isArray(root.devices) ? root.devices.map((row, index) => normalizeDevice(row, index, assetIds, assets)) : [];
    const resources = Array.isArray(root.resources) ? root.resources.map((row, index) => normalizeResource(row, index, assetIds, assets)) : [];
    const logins = Array.isArray(root.logins) ? root.logins.map((row, index) => normalizeLogin(row, index)) : [];
    const gaps = Array.isArray(root.gaps) ? root.gaps.map((row, index) => normalizeGap(row, index, assetIds)).filter(Boolean) : [];

    return {
      schema: text(root.schema) || "kavach.protection.v1",
      generated_at: text(root.generated_at) || new Date().toISOString(),
      organization: text(root.organization) || "Protection register",
      assets,
      devices,
      resources,
      logins,
      gaps,
      notes: Array.isArray(root.notes) ? root.notes.map(text).filter(Boolean) : [],
    };
  }

  function normalizeAsset(row, index) {
    if (!row || typeof row !== "object") throw new Error(`Asset ${index + 1} is not an object.`);
    const name = text(row.name || row.hostname || row.id);
    if (!name) throw new Error(`Asset ${index + 1} is missing a name.`);
    const controls = {};
    const source = row.controls && typeof row.controls === "object" ? row.controls : {};
    for (const control of CONTROLS) {
      controls[control.key] = Object.prototype.hasOwnProperty.call(source, control.key)
        ? boolValue(source[control.key])
        : undefined;
    }
    return {
      id: slug(row.id || name),
      name,
      category: oneOf(row.category || row.type, ["application", "device", "resource", "identity"], "application"),
      type: text(row.type) || CATEGORY_LABELS[oneOf(row.category, ["application", "device", "resource", "identity"], "application")],
      criticality: oneOf(row.criticality || row.critical, ["critical", "high", "medium", "low"], "medium"),
      owner: text(row.owner) || "Unassigned",
      site: text(row.site || row.location) || "Unspecified",
      environment: text(row.environment || row.env) || "production",
      exposure: oneOf(row.exposure, ["internet", "partner", "internal", "air-gapped"], "internal"),
      controls,
      evidence: text(row.evidence) || "",
      last_verified: text(row.last_verified || row.lastVerified) || "",
      notes: text(row.notes) || "",
    };
  }

  function normalizeDevice(row, index, assetIds, assets) {
    if (!row || typeof row !== "object") throw new Error(`Device ${index + 1} is not an object.`);
    const hostname = text(row.hostname || row.name || row.id) || `device-${index + 1}`;
    const assetId = text(row.asset_id || row.asset);
    const linked = assets.find((asset) => asset.id === assetId);
    const patched = boolValue(row.patched);
    return {
      id: slug(row.id || hostname),
      asset_id: assetIds.has(assetId) ? assetId : "",
      hostname,
      os: text(row.os || row.os_name) || "Unknown OS",
      os_version: text(row.os_version || row.version) || "",
      owner: text(row.owner) || linked?.owner || "Unassigned",
      site: text(row.site || row.location) || linked?.site || "Unspecified",
      criticality: oneOf(row.criticality || linked?.criticality, ["critical", "high", "medium", "low"], linked?.criticality || "medium"),
      patch_status: oneOf(row.patch_status || row.patch, ["current", "outdated", "unknown"], patched === true ? "current" : patched === false ? "outdated" : "unknown"),
      edr: boolValue(row.edr),
      disk_encryption: boolValue(row.disk_encryption ?? row.encryption),
      firewall: boolValue(row.firewall),
      admin_rights: boolValue(row.admin_rights ?? row.admin),
      last_seen: text(row.last_seen || row.lastSeen) || "",
    };
  }

  function normalizeResource(row, index, assetIds, assets) {
    if (!row || typeof row !== "object") throw new Error(`Resource ${index + 1} is not an object.`);
    const name = text(row.name || row.id) || `resource-${index + 1}`;
    const assetId = text(row.asset_id || row.asset);
    const linked = assets.find((asset) => asset.id === assetId);
    return {
      id: slug(row.id || name),
      asset_id: assetIds.has(assetId) ? assetId : "",
      name,
      type: text(row.type) || "Resource",
      internet_facing: boolValue(row.internet_facing ?? row.internet),
      auth: text(row.auth || row.authentication) || "Unknown",
      encryption: text(row.encryption) || "Unknown",
      exposure_path: text(row.exposure_path || row.path) || "Not recorded",
      criticality: oneOf(row.criticality || linked?.criticality, ["critical", "high", "medium", "low"], linked?.criticality || "medium"),
      owner: text(row.owner) || linked?.owner || "Unassigned",
    };
  }

  function normalizeLogin(row, index) {
    if (!row || typeof row !== "object") throw new Error(`Login ${index + 1} is not an object.`);
    const account = text(row.account || row.user || row.id) || `account-${index + 1}`;
    return {
      id: slug(row.id || account),
      account,
      display_name: text(row.display_name || row.name) || account,
      type: oneOf(row.type, ["human", "privileged", "service"], "human"),
      mfa: boolValue(row.mfa),
      last_login: text(row.last_login || row.lastLogin) || "",
      stale_days: row.stale_days == null || row.stale_days === "" || !Number.isFinite(Number(row.stale_days)) ? null : Number(row.stale_days),
      failed_24h: row.failed_24h == null && row.failed == null ? null : (Number.isFinite(Number(row.failed_24h ?? row.failed)) ? Number(row.failed_24h ?? row.failed) : null),
      assets: Array.isArray(row.assets) ? row.assets.map(text).filter(Boolean) : [],
      notes: text(row.notes) || "",
    };
  }

  function normalizeGap(row, index, assetIds) {
    if (!row || typeof row !== "object") return null;
    const title = text(row.title || row.gap);
    if (!title) return null;
    const assetId = text(row.asset_id || row.asset);
    return {
      id: text(row.id) || `manual-${index + 1}`,
      asset_id: assetIds.has(assetId) ? assetId : "",
      asset_name: text(row.asset_name || row.assetName) || "",
      category: oneOf(row.category || "asset", ["asset", "device", "resource", "login", "manual"], "manual"),
      severity: oneOf(row.severity, ["critical", "high", "medium", "low", "info"], "medium"),
      title,
      detail: text(row.detail) || "",
      recommendation: text(row.recommendation) || "Assign an owner, verify the control and record evidence.",
      owner: text(row.owner) || "Unassigned",
      due: text(row.due) || "",
      manual: true,
    };
  }

  function controlSummary(controls) {
    let met = 0;
    let missing = 0;
    let unknown = 0;
    let notApplicable = 0;
    const unknowns = [];
    for (const control of CONTROLS) {
      const value = controls[control.key];
      if (value === true) met += 1;
      else if (value === false) {
        missing += 1;
      } else if (value === null) {
        unknown += 1;
        unknowns.push(control.label);
      } else {
        notApplicable += 1;
      }
    }
    const applicable = met + missing;
    return {
      met, missing, unknown, notApplicable, applicable, unknowns,
      coverage: applicable ? met / applicable : null,
    };
  }

  function assetRiskScore(asset, summary) {
    const criticality = { critical: 35, high: 20, medium: 15, low: 5 }[asset.criticality] || 15;
    const exposure = { internet: 25, partner: 20, internal: 10, "air-gapped": 0 }[asset.exposure] || 10;
    const penalty = Math.min(40, summary.missing * 5 + summary.unknown * 2);
    return Math.min(100, criticality + exposure + penalty);
  }

  function deviceRiskScore(device, linked) {
    const criticality = { critical: 35, high: 25, medium: 15, low: 5 }[device.criticality] || 15;
    let score = criticality;
    if (device.patch_status === "outdated") score += 22;
    if (device.patch_status === "unknown") score += 6;
    if (device.edr === false) score += 14;
    if (device.disk_encryption === false) score += 14;
    if (device.firewall === false) score += 8;
    if (device.admin_rights === true) score += 10;
    if (linked?.exposure === "internet") score += 10;
    return Math.min(100, score);
  }

  function resourceRiskScore(resource) {
    const criticality = { critical: 35, high: 25, medium: 15, low: 5 }[resource.criticality] || 15;
    let score = criticality;
    if (resource.internet_facing === true) score += 25;
    if (resource.internet_facing === null) score += 8;
    const auth = lower(resource.auth);
    if (auth.includes("none")) score += 30;
    else if (!auth.includes("mfa") && !auth.includes("certificate") && !auth.includes("iam")) score += 12;
    const encryption = lower(resource.encryption);
    if (encryption.includes("none")) score += 18;
    if (lower(resource.exposure_path).includes("public internet")) score += 8;
    return Math.min(100, score);
  }

  function loginRiskScore(login) {
    let score = login.type === "privileged" ? 30 : login.type === "service" ? 25 : 5;
    if (login.mfa === false) score += 35;
    if (login.mfa === null) score += 15;
    if ((login.type === "service" || login.type === "human") && login.mfa === false) score += 10;
    if (login.stale_days != null && login.stale_days > 90) score += 25;
    else if (login.stale_days != null && login.stale_days > 45) score += 15;
    else if (login.stale_days != null && login.stale_days > 30) score += 8;
    if (login.failed_24h != null && login.failed_24h >= 10) score += 20;
    else if (login.failed_24h != null && login.failed_24h >= 5) score += 12;
    else if (login.failed_24h != null && login.failed_24h > 0) score += 4;
    return Math.min(100, score);
  }

  function gapSeverityForAsset(asset, controlKey) {
    let severity = asset.criticality === "critical"
      ? "high"
      : asset.criticality === "high"
        ? "medium"
        : asset.criticality === "medium"
          ? "low"
          : "info";
    const networkControl = ["mfa", "backup", "logging"].includes(controlKey);
    if ((asset.exposure === "internet" || asset.exposure === "partner") && networkControl) severity = "critical";
    if (["edr", "encryption", "patching"].includes(controlKey) && asset.criticality === "critical") severity = "high";
    if (controlKey === "least_privilege") severity = down(severity);
    return severity;
  }

  function derive(snapshot) {
    const assetMap = new Map();
    const assets = snapshot.assets.map((asset) => {
      const summary = controlSummary(asset.controls);
      const score = assetRiskScore(asset, summary);
      const next = {
        ...asset,
        _summary: summary,
        _score: score,
        _risk: riskLevel(score),
        _gaps: [],
      };
      assetMap.set(next.id, next);
      return next;
    });

    const devices = snapshot.devices.map((device) => {
      const linked = assetMap.get(device.asset_id);
      const score = deviceRiskScore(device, linked);
      return { ...device, _linked: linked, _score: score, _risk: riskLevel(score) };
    });

    const resources = snapshot.resources.map((resource) => {
      const linked = assetMap.get(resource.asset_id);
      const score = resourceRiskScore(resource);
      return { ...resource, _linked: linked, _score: score, _risk: riskLevel(score) };
    });

    const logins = snapshot.logins.map((login) => {
      const score = loginRiskScore(login);
      return { ...login, _score: score, _risk: loginRiskLevel(score) };
    });

    const gaps = deriveGaps(assets, devices, resources, logins, snapshot.gaps);
    for (const gap of gaps) {
      const asset = assetMap.get(gap.asset_id);
      if (asset) asset._gaps.push(gap);
    }

    const controlCoverage = CONTROLS.map((control) => {
      let met = 0;
      let missing = 0;
      let unknown = 0;
      for (const asset of assets) {
        const value = asset.controls[control.key];
        if (value === true) met += 1;
        else if (value === false) missing += 1;
        else if (value === null) unknown += 1;
      }
      const applicable = met + missing;
      return {
        ...control,
        met, missing, unknown, applicable,
        coverage: applicable ? met / applicable : null,
      };
    });

    const kpis = {
      criticalAssets: assets.filter((asset) => asset.criticality === "critical").length,
      protectedAssets: assets.filter((asset) => asset._summary.coverage != null && asset._summary.coverage >= 0.8 && !["critical", "high"].includes(asset._risk)).length,
      openGaps: gaps.length,
      criticalGaps: gaps.filter((gap) => gap.severity === "critical").length,
      privilegedWithoutMfa: logins.filter((login) => ["privileged", "service"].includes(login.type) && login.mfa === false).length,
      internetFacing: resources.filter((resource) => resource.internet_facing === true).length,
      staleAccounts: logins.filter((login) => login.stale_days > 90).length,
      devicesMissingEdr: devices.filter((device) => device.edr === false).length,
    };

    const categories = ["application", "device", "resource", "identity"].map((category) => {
      const rows = assets.filter((asset) => asset.category === category);
      const known = rows.filter((asset) => asset._summary.coverage != null);
      return {
        category,
        count: rows.length,
        coverage: known.length ? known.reduce((sum, asset) => sum + asset._summary.coverage, 0) / known.length : null,
      };
    });

    return {
      ...snapshot,
      assets,
      devices,
      resources,
      logins,
      gaps,
      kpis,
      controlCoverage,
      categories,
      assetMap,
    };
  }

  function deriveGaps(assets, devices, resources, logins, manualGaps) {
    const gaps = [];
    const seen = new Set();
    const assetLookup = new Map(assets.map((asset) => [asset.id, asset]));
    let counter = 0;

    const add = (gap) => {
      const key = `${gap.asset_id || gap.asset_name || ""}|${lower(gap.title)}`;
      if (seen.has(key)) return;
      seen.add(key);
      counter += 1;
      const assetId = gap.asset_id || "";
      gaps.push({
        id: gap.id || `gap-${counter}`,
        asset_id: assetId,
        asset_name: gap.asset_name || assetLookup.get(assetId)?.name || "",
        category: gap.category || "asset",
        severity: gap.severity || "medium",
        title: gap.title,
        detail: gap.detail || "",
        recommendation: gap.recommendation || "Assign an owner, verify the control and record evidence.",
        owner: gap.owner || "Unassigned",
        due: gap.due || "",
        manual: Boolean(gap.manual),
      });
    };

    for (const asset of assets) {
      for (const control of CONTROLS) {
        if (asset.controls[control.key] !== false) continue;
        add({
          asset_id: asset.id,
          asset_name: asset.name,
          category: "asset",
          severity: gapSeverityForAsset(asset, control.key),
          title: `${asset.name}: ${control.label} not in place`,
          detail: `${control.label} is recorded as missing for this ${asset.criticality} ${CATEGORY_LABELS[asset.category] || "asset"}.`,
          recommendation: CONTROL_GUIDANCE[control.key],
          owner: asset.owner,
        });
      }
      if (asset._summary.unknown >= 2) {
        add({
          asset_id: asset.id,
          asset_name: asset.name,
          category: "asset",
          severity: asset.criticality === "critical" ? "medium" : "low",
          title: `${asset.name}: control evidence incomplete`,
          detail: `${asset._summary.unknown} controls are unverified: ${asset._summary.unknowns.join(", ")}.`,
          recommendation: "Attach evidence or mark the control not applicable; do not assume coverage.",
          owner: asset.owner,
        });
      }
    }

    for (const device of devices) {
      const linked = device._linked;
      const base = linked?.criticality || device.criticality;
      const severity = base === "critical" ? "high" : base === "high" ? "high" : base === "medium" ? "medium" : "low";
      const owner = device.owner || linked?.owner || "Unassigned";
      const assetId = device.asset_id || "";
      const assetName = linked?.name || device.hostname;
      if (device.patch_status === "outdated") {
        add({
          asset_id: assetId, asset_name: assetName, category: "device", severity,
          title: `${device.hostname}: patch level is outdated`,
          detail: `${device.os} ${device.os_version} is below the approved patch baseline.`,
          recommendation: "Schedule the approved updates, record the maintenance window and verify the reboot.",
          owner,
        });
      }
      if (device.edr === false) {
        add({
          asset_id: assetId, asset_name: assetName, category: "device", severity,
          title: `${device.hostname}: EDR not reported`,
          detail: "No healthy endpoint detection and response agent is recorded for this device.",
          recommendation: CONTROL_GUIDANCE.edr,
          owner,
        });
      }
      if (device.disk_encryption === false) {
        add({
          asset_id: assetId, asset_name: assetName, category: "device", severity,
          title: `${device.hostname}: disk encryption not enabled`,
          detail: "The system volume is not recorded as encrypted.",
          recommendation: "Enable full-disk encryption, escrow the recovery key and record the exception if the device cannot support it.",
          owner,
        });
      }
      if (device.firewall === false) {
        add({
          asset_id: assetId, asset_name: assetName, category: "device", severity: "medium",
          title: `${device.hostname}: host firewall not enabled`,
          detail: "The host firewall is disabled or not reported.",
          recommendation: "Enable the host firewall and restrict inbound services to approved ports.",
          owner,
        });
      }
      if (device.admin_rights === true) {
        add({
          asset_id: assetId, asset_name: assetName, category: "device", severity: "medium",
          title: `${device.hostname}: standing local admin rights`,
          detail: "The primary user or a shared account has local administrator rights.",
          recommendation: "Remove standing admin rights and use just-in-time elevation.",
          owner,
        });
      }
      const lastSeen = device.last_seen ? new Date(device.last_seen) : null;
      if (lastSeen && !Number.isNaN(lastSeen.getTime())) {
        const days = Math.floor((Date.now() - lastSeen.getTime()) / 86400000);
        if (days > 30) {
          add({
            asset_id: assetId, asset_name: assetName, category: "device", severity: "low",
            title: `${device.hostname}: not seen for ${days} days`,
            detail: "The device has not reported posture within the expected window.",
            recommendation: "Confirm whether the device is retired, offline or missing its management agent.",
            owner,
          });
        }
      }
    }

    for (const resource of resources) {
      const linked = resource._linked;
      const criticality = resource.criticality || linked?.criticality || "medium";
      const severity = criticality === "critical" ? "critical" : criticality === "high" ? "high" : "medium";
      const auth = lower(resource.auth);
      const encryption = lower(resource.encryption);
      const owner = resource.owner || linked?.owner || "Unassigned";
      if (resource.internet_facing === true && !auth.includes("mfa") && !auth.includes("certificate") && !auth.includes("iam")) {
        add({
          asset_id: resource.asset_id, asset_name: linked?.name || resource.name, category: "resource",
          severity: auth.includes("none") ? "critical" : severity,
          title: `${resource.name}: internet-facing without strong authentication`,
          detail: `Authentication is recorded as “${resource.auth}” on an internet-facing service.`,
          recommendation: "Put the service behind SSO/MFA or certificate-based access and remove direct internet exposure where possible.",
          owner,
        });
      }
      if (auth.includes("none")) {
        add({
          asset_id: resource.asset_id, asset_name: linked?.name || resource.name, category: "resource",
          severity: "critical",
          title: `${resource.name}: no authentication`,
          detail: "The service is recorded with no authentication.",
          recommendation: "Add authentication or isolate the protocol behind a compensating control; treat the service as untrusted by default.",
          owner,
        });
      }
      if (encryption.includes("none")) {
        add({
          asset_id: resource.asset_id, asset_name: linked?.name || resource.name, category: "resource",
          severity: criticality === "critical" ? "high" : "medium",
          title: `${resource.name}: encryption not in place`,
          detail: "Traffic or stored data is not recorded as encrypted.",
          recommendation: CONTROL_GUIDANCE.encryption,
          owner,
        });
      }
      if (resource.internet_facing === true && lower(resource.exposure_path).includes("direct")) {
        add({
          asset_id: resource.asset_id, asset_name: linked?.name || resource.name, category: "resource",
          severity: "high",
          title: `${resource.name}: direct exposure path`,
          detail: `The exposure path is recorded as “${resource.exposure_path}”.`,
          recommendation: "Insert an authenticated gateway, WAF or broker and remove the direct path.",
          owner,
        });
      }
    }

    const unverifiedResources = resources.filter((resource) => resource.internet_facing === null);
    const unverifiedGroups = new Map();
    for (const resource of unverifiedResources) {
      const key = resource.asset_id || resource.name;
      const current = unverifiedGroups.get(key) || {
        asset_id: resource.asset_id,
        asset_name: resource._linked?.name || resource.name,
        owner: resource.owner || resource._linked?.owner || "Unassigned",
        count: 0,
      };
      current.count += 1;
      unverifiedGroups.set(key, current);
    }
    for (const group of unverifiedGroups.values()) {
      add({
        asset_id: group.asset_id, asset_name: group.asset_name, category: "resource", severity: "low",
        title: `${group.asset_name}: ${group.count} listener${group.count === 1 ? "" : "s"} with unverified exposure`,
        detail: "Listener metadata was collected, but external exposure and upstream controls are not verified.",
        recommendation: "Verify the firewall/NAT path and record whether each listening service should be reachable from an untrusted network.",
        owner: group.owner,
      });
    }

    const assetMap = new Map(assets.map((asset) => [asset.id, asset]));
    for (const login of logins) {
      const privileged = ["privileged", "service"].includes(login.type);
      const linkedCritical = (login.assets || [])
        .map((assetId) => assetMap.get(assetId))
        .filter((asset) => asset && asset.criticality === "critical");
      if (login.type === "human" && login.mfa === false && linkedCritical.length) {
        add({
          asset_id: linkedCritical[0].id, asset_name: linkedCritical[0].name, category: "login", severity: "high",
          title: `${login.account}: no MFA for critical asset access`,
          detail: `A human account reaches ${linkedCritical.map((asset) => asset.name).join(", ")} without MFA.`,
          recommendation: "Require MFA for interactive access to critical assets and record the exception if the workflow cannot support it.",
          owner: "Identity Team",
        });
      }
      if (privileged && login.mfa === false) {
        add({
          asset_id: "", asset_name: login.account, category: "login", severity: "critical",
          title: `${login.account}: privileged account without MFA`,
          detail: `A ${login.type} account has no MFA recorded.`,
          recommendation: "Require MFA for interactive use; for service accounts, move to short-lived credentials, workload identity or a managed secret store.",
          owner: "Identity Team",
        });
      }
      if (privileged && login.mfa === null) {
        add({
          asset_id: "", asset_name: login.account, category: "login", severity: "high",
          title: `${login.account}: privileged MFA not verified`,
          detail: "The account is privileged or a service account, but MFA state is unknown.",
          recommendation: "Verify the authentication method and record evidence.",
          owner: "Identity Team",
        });
      }
      if (login.stale_days != null && login.stale_days > 90) {
        add({
          asset_id: "", asset_name: login.account, category: "login", severity: login.stale_days > 180 ? "high" : "medium",
          title: `${login.account}: stale for ${login.stale_days} days`,
          detail: "The account has not signed in for more than 90 days.",
          recommendation: "Disable or remove the account unless a documented business exception exists.",
          owner: "Identity Team",
        });
      }
      if (login.failed_24h != null && login.failed_24h >= 10) {
        add({
          asset_id: "", asset_name: login.account, category: "login", severity: "high",
          title: `${login.account}: ${login.failed_24h} failed sign-ins in 24h`,
          detail: "Repeated failures may indicate password spraying, a stale credential or a misconfigured service.",
          recommendation: "Review the source, reset the credential if needed and confirm whether the account is under attack.",
          owner: "Identity Team",
        });
      } else if (login.failed_24h != null && login.failed_24h >= 5) {
        add({
          asset_id: "", asset_name: login.account, category: "login", severity: "medium",
          title: `${login.account}: ${login.failed_24h} failed sign-ins in 24h`,
          detail: "A cluster of failures was recorded for this account.",
          recommendation: "Review the source and confirm the account owner is attempting the sign-ins.",
          owner: "Identity Team",
        });
      }
    }

    for (const manual of manualGaps || []) {
      add({ ...manual, manual: true });
    }

    gaps.sort((a, b) => {
      const severity = (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9);
      if (severity) return severity;
      return String(a.title).localeCompare(String(b.title));
    });
    return gaps;
  }

  function countBySeverity(gaps) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const gap of gaps) counts[gap.severity] = (counts[gap.severity] || 0) + 1;
    return counts;
  }

  function renderAll() {
    const app = $("protection-app");
    if (!app) return;
    app.innerHTML = `
      <div class="pt-tabs" role="tablist" aria-label="Protection views">
        ${tabButton("overview", "Overview")}
        ${tabButton("assets", "Assets")}
        ${tabButton("devices", "Devices")}
        ${tabButton("resources", "Resources")}
        ${tabButton("logins", "Logins")}
        ${tabButton("gaps", "Gaps")}
      </div>
      <div class="pt-views">
        ${overviewHtml()}
        ${assetsHtml()}
        ${devicesHtml()}
        ${resourcesHtml()}
        ${loginsHtml()}
        ${gapsHtml()}
      </div>`;
    renderTabs();
    renderTables();
    renderPills();
    if (state.selectedAsset) renderDetail();
  }

  function tabButton(id, label) {
    return `<button type="button" class="pt-tab ${state.tab === id ? "active" : ""}" data-tab="${id}" role="tab" aria-selected="${state.tab === id}">${label}</button>`;
  }

  function renderTabs() {
    document.querySelectorAll("[data-tab]").forEach((button) => {
      const active = button.dataset.tab === state.tab;
      button.classList.toggle("active", active);
      button.setAttribute("aria-selected", active ? "true" : "false");
    });
    document.querySelectorAll(".pt-view").forEach((view) => {
      view.hidden = view.id !== `pt-view-${state.tab}`;
    });
  }

  function renderPills() {
    const source = $("source-pill");
    const label = $("source-label");
    if (source && label) {
      source.className = `nw-pill ${state.source === "import" ? "file" : "demo"}`;
      label.textContent = state.source === "import" ? `Imported · ${state.filename || "register"}` : "Synthetic register";
    }
    const assetPill = $("asset-pill");
    if (assetPill) assetPill.textContent = `${fmtNumber(state.derived.kpis.criticalAssets)} critical assets`;
    const updated = $("updated-pill");
    if (updated) updated.textContent = `Updated · ${fmtRelative(state.raw.generated_at)}`;
    const reset = $("reset-source");
    if (reset) reset.hidden = state.source !== "import";
  }

  function overviewHtml() {
    const data = state.derived;
    const kpis = data.kpis;
    const topGaps = data.gaps.slice(0, 6);
    const crown = data.assets.slice().sort((a, b) => b._score - a._score).slice(0, 8);
    return `
      <section class="pt-view" id="pt-view-overview">
        <div class="nw-kpis pt-kpis">
          <div class="nw-kpi"><p>Critical assets</p><b>${fmtNumber(kpis.criticalAssets)}</b><span>crown-jewel records</span></div>
          <div class="nw-kpi"><p>Fully protected</p><b>${fmtNumber(kpis.protectedAssets)}</b><span>≥80% control coverage</span></div>
          <div class="nw-kpi"><p>Open gaps</p><b>${fmtNumber(kpis.openGaps)}</b><span>across all surfaces</span></div>
          <div class="nw-kpi"><p>Critical gaps</p><b>${fmtNumber(kpis.criticalGaps)}</b><span>fix first</span></div>
          <div class="nw-kpi"><p>Privileged without MFA</p><b>${fmtNumber(kpis.privilegedWithoutMfa)}</b><span>human and service accounts</span></div>
          <div class="nw-kpi"><p>Internet-facing</p><b>${fmtNumber(kpis.internetFacing)}</b><span>resources recorded</span></div>
          <div class="nw-kpi"><p>Stale accounts</p><b>${fmtNumber(kpis.staleAccounts)}</b><span>no sign-in for 90+ days</span></div>
          <div class="nw-kpi"><p>Devices without EDR</p><b>${fmtNumber(kpis.devicesMissingEdr)}</b><span>reported posture</span></div>
        </div>

        <div class="pt-split">
          <div class="nw-panel">
            <div class="nw-panel-head"><h2>Control coverage</h2><span>known controls · all assets</span></div>
            <div class="pt-bars">
              ${data.controlCoverage.map((control) => `
                <div class="pt-bar-row">
                  <span>${esc(control.label)}</span>
                  <div class="pt-bar"><i style="width:${control.coverage == null ? 0 : Math.round(control.coverage * 100)}%"></i></div>
                  <b>${control.coverage == null ? "—" : pct(control.coverage)}</b>
                  <small>${control.met}/${control.applicable}${control.unknown ? ` · ${control.unknown} unverified` : ""}</small>
                </div>`).join("")}
            </div>
          </div>

          <div class="nw-panel">
            <div class="nw-panel-head"><h2>Top gaps</h2><span>severity first</span></div>
            <div class="pt-gap-list">
              ${topGaps.length ? topGaps.map((gap) => `
                <button type="button" class="pt-gap-row" data-gap-asset="${esc(gap.asset_id)}">
                  <span class="pt-gap-sev">${riskTag(gap.severity)}</span>
                  <span class="pt-gap-main"><b>${esc(gap.title)}</b><small>${esc(gap.asset_name || "Identity")} · ${esc(gap.owner || "Unassigned")}</small></span>
                </button>`).join("") : '<p class="nw-empty">No gaps recorded.</p>'}
            </div>
          </div>
        </div>

        <div class="nw-panel pt-overview-table">
          <div class="nw-panel-head"><h2>Crown jewels</h2><span>highest protection risk first</span></div>
          <div class="nw-table-wrap" style="border:0">
            <table class="nw-table pt-asset-table">
              <thead><tr><th>Asset</th><th>Category</th><th>Criticality</th><th>Exposure</th><th>Coverage</th><th>Risk</th><th class="num">Gaps</th><th>Owner</th></tr></thead>
              <tbody>${crown.map((asset) => `
                <tr data-asset="${esc(asset.id)}">
                  <td><strong>${esc(asset.name)}</strong><small>${esc(asset.type)} · ${esc(asset.site)}</small></td>
                  <td>${esc(CATEGORY_LABELS[asset.category] || asset.category)}</td>
                  <td>${criticalityTag(asset.criticality)}</td>
                  <td>${esc(asset.exposure)}</td>
                  <td>${coverageCell(asset._summary)}</td>
                  <td>${riskTag(asset._risk)}</td>
                  <td class="num">${asset._gaps.length}</td>
                  <td>${esc(asset.owner)}</td>
                </tr>`).join("")}</tbody>
            </table>
          </div>
        </div>

        <div class="pt-callout">
          <b>Read-only protection posture.</b>
          <span>This register reads declared controls and metadata. It does not probe hosts, exploit services, block traffic or change the estate. Unknown controls stay unknown until evidence is attached.</span>
        </div>
      </section>`;
  }

  function assetsHtml() {
    return `
      <section class="pt-view" id="pt-view-assets" hidden>
        <div class="nw-panel">
          <div class="nw-panel-head"><h2>Critical asset register</h2><span id="pt-asset-count">—</span></div>
          <div class="nw-filters">
            <label for="pt-asset-search">Search</label>
            <input id="pt-asset-search" type="search" placeholder="Asset, owner, site or type">
            <label for="pt-asset-criticality">Criticality</label>
            <select id="pt-asset-criticality">
              <option value="all">All</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option>
            </select>
            <label for="pt-asset-category">Category</label>
            <select id="pt-asset-category">
              <option value="all">All</option><option value="application">Application</option><option value="device">Device</option><option value="resource">Resource</option><option value="identity">Identity</option>
            </select>
            <label for="pt-asset-risk">Risk</label>
            <select id="pt-asset-risk">
              <option value="all">All</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option>
            </select>
            <button class="nw-btn" type="button" data-clear="assets">Clear filters</button>
            <button class="nw-btn" type="button" data-export="assets">Export assets CSV</button>
          </div>
          <div class="nw-table-wrap" style="border:0">
            <table class="nw-table pt-asset-table">
              <thead><tr><th>Asset</th><th>Category</th><th>Criticality</th><th>Exposure</th><th>Owner</th><th>Controls</th><th>Coverage</th><th>Risk</th><th class="num">Gaps</th><th>Last verified</th></tr></thead>
              <tbody id="pt-asset-body"></tbody>
            </table>
          </div>
        </div>
        <div id="pt-detail"></div>
      </section>`;
  }

  function devicesHtml() {
    return `
      <section class="pt-view" id="pt-view-devices" hidden>
        <div class="nw-panel">
          <div class="nw-panel-head"><h2>Device protection</h2><span id="pt-device-count">—</span></div>
          <div class="nw-filters">
            <label for="pt-device-search">Search</label>
            <input id="pt-device-search" type="search" placeholder="Host, OS, owner or site">
            <label for="pt-device-patch">Patch</label>
            <select id="pt-device-patch"><option value="all">All</option><option value="current">Current</option><option value="outdated">Outdated</option><option value="unknown">Unknown</option></select>
            <label for="pt-device-edr">EDR</label>
            <select id="pt-device-edr"><option value="all">All</option><option value="true">Reported</option><option value="false">Missing</option><option value="unknown">Unverified</option></select>
            <label for="pt-device-risk">Risk</label>
            <select id="pt-device-risk"><option value="all">All</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select>
            <button class="nw-btn" type="button" data-clear="devices">Clear filters</button>
            <button class="nw-btn" type="button" data-export="devices">Export devices CSV</button>
          </div>
          <div class="nw-table-wrap" style="border:0">
            <table class="nw-table pt-device-table">
              <thead><tr><th>Host</th><th>Linked asset</th><th>OS</th><th>Patch</th><th>EDR</th><th>Encryption</th><th>Firewall</th><th>Admin rights</th><th>Risk</th><th>Last seen</th></tr></thead>
              <tbody id="pt-device-body"></tbody>
            </table>
          </div>
        </div>
      </section>`;
  }

  function resourcesHtml() {
    return `
      <section class="pt-view" id="pt-view-resources" hidden>
        <div class="nw-panel">
          <div class="nw-panel-head"><h2>Exposed resources</h2><span id="pt-resource-count">—</span></div>
          <div class="nw-filters">
            <label for="pt-resource-search">Search</label>
            <input id="pt-resource-search" type="search" placeholder="Service, type, owner or path">
            <label for="pt-resource-exposure">Exposure</label>
            <select id="pt-resource-exposure"><option value="all">All</option><option value="true">Internet-facing</option><option value="false">Internal</option><option value="unknown">Unverified</option></select>
            <label for="pt-resource-risk">Risk</label>
            <select id="pt-resource-risk"><option value="all">All</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select>
            <button class="nw-btn" type="button" data-clear="resources">Clear filters</button>
            <button class="nw-btn" type="button" data-export="resources">Export resources CSV</button>
          </div>
          <div class="nw-table-wrap" style="border:0">
            <table class="nw-table pt-resource-table">
              <thead><tr><th>Resource</th><th>Type</th><th>Linked asset</th><th>Internet-facing</th><th>Auth</th><th>Encryption</th><th>Exposure path</th><th>Risk</th></tr></thead>
              <tbody id="pt-resource-body"></tbody>
            </table>
          </div>
        </div>
      </section>`;
  }

  function loginsHtml() {
    return `
      <section class="pt-view" id="pt-view-logins" hidden>
        <div class="nw-panel">
          <div class="nw-panel-head"><h2>Login protection</h2><span id="pt-login-count">—</span></div>
          <div class="nw-filters">
            <label for="pt-login-search">Search</label>
            <input id="pt-login-search" type="search" placeholder="Account, owner, asset or note">
            <label for="pt-login-type">Type</label>
            <select id="pt-login-type"><option value="all">All</option><option value="human">Human</option><option value="privileged">Privileged</option><option value="service">Service</option></select>
            <label for="pt-login-mfa">MFA</label>
            <select id="pt-login-mfa"><option value="all">All</option><option value="true">Enabled</option><option value="false">Missing</option><option value="unknown">Unverified</option></select>
            <label for="pt-login-risk">Risk</label>
            <select id="pt-login-risk"><option value="all">All</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select>
            <button class="nw-btn" type="button" data-clear="logins">Clear filters</button>
            <button class="nw-btn" type="button" data-export="logins">Export logins CSV</button>
          </div>
          <div class="nw-table-wrap" style="border:0">
            <table class="nw-table pt-login-table">
              <thead><tr><th>Account</th><th>Type</th><th>MFA</th><th>Last login</th><th class="num">Stale days</th><th class="num">Failed 24h</th><th>Linked assets</th><th>Risk</th></tr></thead>
              <tbody id="pt-login-body"></tbody>
            </table>
          </div>
        </div>
      </section>`;
  }

  function gapsHtml() {
    const counts = countBySeverity(state.derived.gaps);
    return `
      <section class="pt-view" id="pt-view-gaps" hidden>
        <div class="pt-gap-summary">
          ${["critical", "high", "medium", "low"].map((severity) => `
            <div class="pt-gap-stat"><span>${riskTag(severity)}</span><b>${fmtNumber(counts[severity] || 0)}</b><small>${severity} gaps</small></div>`).join("")}
          <div class="pt-gap-stat"><span class="nw-risk info">total</span><b>${fmtNumber(state.derived.gaps.length)}</b><small>across the register</small></div>
        </div>
        <div class="nw-panel" style="margin-top:12px">
          <div class="nw-panel-head"><h2>Prioritised gaps</h2><span id="pt-gap-count">—</span></div>
          <div class="nw-filters">
            <label for="pt-gap-search">Search</label>
            <input id="pt-gap-search" type="search" placeholder="Gap, asset or owner">
            <label for="pt-gap-severity">Severity</label>
            <select id="pt-gap-severity"><option value="all">All</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select>
            <label for="pt-gap-category">Category</label>
            <select id="pt-gap-category"><option value="all">All</option><option value="asset">Asset</option><option value="device">Device</option><option value="resource">Resource</option><option value="login">Login</option><option value="manual">Manual</option></select>
            <button class="nw-btn" type="button" data-clear="gaps">Clear filters</button>
            <button class="nw-btn" type="button" data-export="gaps">Export gaps CSV</button>
          </div>
          <div class="nw-table-wrap" style="border:0">
            <table class="nw-table pt-gap-table">
              <thead><tr><th>Severity</th><th>Gap</th><th>Asset / account</th><th>Category</th><th>Owner</th><th>Recommendation</th><th>Due</th></tr></thead>
              <tbody id="pt-gap-body"></tbody>
            </table>
          </div>
        </div>
      </section>`;
  }

  function coverageCell(summary) {
    if (summary.coverage == null) return '<span class="nw-risk info">unknown</span>';
    const width = Math.round(summary.coverage * 100);
    return `<div class="pt-coverage"><span style="width:${width}%"></span></div><small>${width}%${summary.unknown ? ` · ${summary.unknown} unverified` : ""}</small>`;
  }

  function renderTables() {
    renderAssetTable();
    renderDeviceTable();
    renderResourceTable();
    renderLoginTable();
    renderGapTable();
    if (state.selectedAsset) renderDetail(false);
  }

  function filteredAssets() {
    const search = lower($("pt-asset-search")?.value);
    const criticality = $("pt-asset-criticality")?.value || "all";
    const category = $("pt-asset-category")?.value || "all";
    const risk = $("pt-asset-risk")?.value || "all";
    return state.derived.assets.filter((asset) => {
      if (criticality !== "all" && asset.criticality !== criticality) return false;
      if (category !== "all" && asset.category !== category) return false;
      if (risk !== "all" && asset._risk !== risk) return false;
      if (!search) return true;
      return [asset.name, asset.type, asset.owner, asset.site, asset.category, asset.id].join(" ").toLowerCase().includes(search);
    }).sort((a, b) => b._score - a._score);
  }

  function renderAssetTable() {
    const body = $("pt-asset-body");
    if (!body) return;
    const rows = filteredAssets();
    const total = state.derived.assets.length;
    const count = $("pt-asset-count");
    if (count) count.textContent = `${rows.length} of ${total} assets`;
    if (!rows.length) {
      body.innerHTML = '<tr><td colspan="10" class="nw-empty">No assets match the filters.</td></tr>';
      return;
    }
    body.innerHTML = rows.map((asset) => `
      <tr data-asset="${esc(asset.id)}" class="${asset.criticality === "critical" ? "critical" : ""}">
        <td><strong>${esc(asset.name)}</strong><small>${esc(asset.type)} · ${esc(asset.site)}</small></td>
        <td>${esc(CATEGORY_LABELS[asset.category] || asset.category)}</td>
        <td>${criticalityTag(asset.criticality)}</td>
        <td>${esc(asset.exposure)}</td>
        <td>${esc(asset.owner)}</td>
        <td><strong>${asset._summary.met}/${asset._summary.applicable}</strong><small>${asset._summary.unknown} unverified</small></td>
        <td>${coverageCell(asset._summary)}</td>
        <td>${riskTag(asset._risk)}</td>
        <td class="num">${asset._gaps.length}</td>
        <td>${fmtDate(asset.last_verified)}</td>
      </tr>`).join("");
  }

  function filteredDevices() {
    const search = lower($("pt-device-search")?.value);
    const patch = $("pt-device-patch")?.value || "all";
    const edr = $("pt-device-edr")?.value || "all";
    const risk = $("pt-device-risk")?.value || "all";
    return state.derived.devices.filter((device) => {
      if (patch !== "all" && device.patch_status !== patch) return false;
      if (edr === "true" && device.edr !== true) return false;
      if (edr === "false" && device.edr !== false) return false;
      if (edr === "unknown" && device.edr !== null) return false;
      if (risk !== "all" && device._risk !== risk) return false;
      if (!search) return true;
      return [device.hostname, device.os, device.owner, device.site, device.asset_id].join(" ").toLowerCase().includes(search);
    }).sort((a, b) => b._score - a._score);
  }

  function renderDeviceTable() {
    const body = $("pt-device-body");
    if (!body) return;
    const rows = filteredDevices();
    const count = $("pt-device-count");
    if (count) count.textContent = `${rows.length} of ${state.derived.devices.length} devices`;
    if (!rows.length) {
      body.innerHTML = '<tr><td colspan="10" class="nw-empty">No devices match the filters.</td></tr>';
      return;
    }
    body.innerHTML = rows.map((device) => `
      <tr ${device.asset_id ? `data-asset="${esc(device.asset_id)}"` : ""}>
        <td><strong>${esc(device.hostname)}</strong><small>${esc(device.site)}</small></td>
        <td>${esc(device._linked?.name || "—")}</td>
        <td>${esc(device.os)}<small>${esc(device.os_version)}</small></td>
        <td>${device.patch_status === "current" ? '<span class="nw-risk low">current</span>' : device.patch_status === "outdated" ? '<span class="nw-risk high">outdated</span>' : '<span class="nw-risk info">unknown</span>'}</td>
        <td>${triTag(device.edr, "reported", "missing")}</td>
        <td>${triTag(device.disk_encryption, "yes", "no")}</td>
        <td>${triTag(device.firewall, "yes", "no")}</td>
        <td>${adminTag(device.admin_rights)}</td>
        <td>${riskTag(device._risk)}</td>
        <td>${fmtDate(device.last_seen)}</td>
      </tr>`).join("");
  }

  function filteredResources() {
    const search = lower($("pt-resource-search")?.value);
    const exposure = $("pt-resource-exposure")?.value || "all";
    const risk = $("pt-resource-risk")?.value || "all";
    return state.derived.resources.filter((resource) => {
      if (exposure === "true" && resource.internet_facing !== true) return false;
      if (exposure === "false" && resource.internet_facing !== false) return false;
      if (exposure === "unknown" && resource.internet_facing !== null) return false;
      if (risk !== "all" && resource._risk !== risk) return false;
      if (!search) return true;
      return [resource.name, resource.type, resource.auth, resource.owner, resource.exposure_path, resource.asset_id].join(" ").toLowerCase().includes(search);
    }).sort((a, b) => b._score - a._score);
  }

  function renderResourceTable() {
    const body = $("pt-resource-body");
    if (!body) return;
    const rows = filteredResources();
    const count = $("pt-resource-count");
    if (count) count.textContent = `${rows.length} of ${state.derived.resources.length} resources`;
    if (!rows.length) {
      body.innerHTML = '<tr><td colspan="8" class="nw-empty">No resources match the filters.</td></tr>';
      return;
    }
    body.innerHTML = rows.map((resource) => {
      const internet = resource.internet_facing === true
        ? '<span class="nw-risk high">internet</span>'
        : resource.internet_facing === false
          ? '<span class="nw-risk low">internal</span>'
          : '<span class="nw-risk info">unverified</span>';
      const auth = lower(resource.auth).includes("none") ? '<span class="nw-risk high">none</span>' : esc(resource.auth);
      const encryption = lower(resource.encryption).includes("none") ? '<span class="nw-risk high">none</span>' : esc(resource.encryption);
      return `<tr ${resource.asset_id ? `data-asset="${esc(resource.asset_id)}"` : ""}>
        <td><strong>${esc(resource.name)}</strong><small>${esc(resource.id)}</small></td>
        <td>${esc(resource.type)}</td>
        <td>${esc(resource._linked?.name || "—")}</td>
        <td>${internet}</td>
        <td>${auth}</td>
        <td>${encryption}</td>
        <td>${esc(resource.exposure_path)}</td>
        <td>${riskTag(resource._risk)}</td>
      </tr>`;
    }).join("");
  }

  function filteredLogins() {
    const search = lower($("pt-login-search")?.value);
    const type = $("pt-login-type")?.value || "all";
    const mfa = $("pt-login-mfa")?.value || "all";
    const risk = $("pt-login-risk")?.value || "all";
    return state.derived.logins.filter((login) => {
      if (type !== "all" && login.type !== type) return false;
      if (mfa === "true" && login.mfa !== true) return false;
      if (mfa === "false" && login.mfa !== false) return false;
      if (mfa === "unknown" && login.mfa !== null) return false;
      if (risk !== "all" && login._risk !== risk) return false;
      if (!search) return true;
      return [login.account, login.display_name, login.type, login.notes, ...login.assets].join(" ").toLowerCase().includes(search);
    }).sort((a, b) => b._score - a._score);
  }

  function renderLoginTable() {
    const body = $("pt-login-body");
    if (!body) return;
    const rows = filteredLogins();
    const count = $("pt-login-count");
    if (count) count.textContent = `${rows.length} of ${state.derived.logins.length} accounts`;
    if (!rows.length) {
      body.innerHTML = '<tr><td colspan="8" class="nw-empty">No accounts match the filters.</td></tr>';
      return;
    }
    body.innerHTML = rows.map((login) => {
      const mfa = login.mfa === true
        ? '<span class="nw-risk low">enabled</span>'
        : login.mfa === false
          ? '<span class="nw-risk high">missing</span>'
          : '<span class="nw-risk info">unverified</span>';
      const type = login.type === "privileged" ? '<span class="nw-risk high">privileged</span>' : login.type === "service" ? '<span class="nw-risk medium">service</span>' : "human";
      const assets = login.assets.map((id) => state.derived.assetMap.get(id)?.name || id).join(", ");
      return `<tr>
        <td><strong>${esc(login.display_name)}</strong><small>${esc(login.account)}</small></td>
        <td>${type}</td>
        <td>${mfa}</td>
        <td>${fmtDate(login.last_login)}</td>
        <td class="num">${login.stale_days == null ? "—" : fmtNumber(login.stale_days)}</td>
        <td class="num">${login.failed_24h == null ? "—" : fmtNumber(login.failed_24h)}</td>
        <td>${esc(assets || "—")}</td>
        <td>${riskTag(login._risk)}</td>
      </tr>`;
    }).join("");
  }

  function filteredGaps() {
    const search = lower($("pt-gap-search")?.value);
    const severity = $("pt-gap-severity")?.value || "all";
    const category = $("pt-gap-category")?.value || "all";
    return state.derived.gaps.filter((gap) => {
      if (severity !== "all" && gap.severity !== severity) return false;
      if (category !== "all" && gap.category !== category) return false;
      if (!search) return true;
      return [gap.title, gap.detail, gap.asset_name, gap.owner, gap.recommendation, gap.category].join(" ").toLowerCase().includes(search);
    });
  }

  function renderGapTable() {
    const body = $("pt-gap-body");
    if (!body) return;
    const rows = filteredGaps();
    const count = $("pt-gap-count");
    if (count) count.textContent = `${rows.length} of ${state.derived.gaps.length} gaps`;
    if (!rows.length) {
      body.innerHTML = '<tr><td colspan="7" class="nw-empty">No gaps match the filters.</td></tr>';
      return;
    }
    body.innerHTML = rows.map((gap) => `
      <tr ${gap.asset_id ? `data-asset="${esc(gap.asset_id)}"` : ""}>
        <td>${riskTag(gap.severity)}</td>
        <td class="pt-wrap"><strong>${esc(gap.title)}</strong><small>${esc(gap.detail)}</small></td>
        <td>${esc(gap.asset_name || "—")}</td>
        <td>${esc(gap.category)}</td>
        <td>${esc(gap.owner)}</td>
        <td class="pt-wrap">${esc(gap.recommendation)}</td>
        <td>${esc(gap.due || "—")}</td>
      </tr>`).join("");
  }

  function renderDetail(scroll = false) {
    const holder = $("pt-detail");
    if (!holder) return;
    const asset = state.derived.assetMap.get(state.selectedAsset);
    if (!asset) {
      holder.innerHTML = "";
      return;
    }
    const devices = state.derived.devices.filter((device) => device.asset_id === asset.id);
    const resources = state.derived.resources.filter((resource) => resource.asset_id === asset.id);
    const logins = state.derived.logins.filter((login) => login.assets.includes(asset.id));
    holder.innerHTML = `
      <div class="nw-panel pt-detail">
        <div class="pt-detail-head">
          <div>
            <p class="eyebrow">Asset detail</p>
            <h3>${esc(asset.name)}</h3>
            <p>${esc(asset.type)} · ${esc(CATEGORY_LABELS[asset.category] || asset.category)} · ${esc(asset.site)} · ${esc(asset.owner)}</p>
          </div>
          <button class="nw-btn" type="button" data-close-detail>Close</button>
        </div>
        <div class="pt-detail-grid">
          <div>
            <div class="pt-facts">
              <div><span>Criticality</span><b>${criticalityTag(asset.criticality)}</b></div>
              <div><span>Exposure</span><b>${esc(asset.exposure)}</b></div>
              <div><span>Coverage</span><b>${pct(asset._summary.coverage)}</b></div>
              <div><span>Risk</span><b>${riskTag(asset._risk)}</b></div>
              <div><span>Last verified</span><b>${fmtDate(asset.last_verified)}</b></div>
              <div><span>Environment</span><b>${esc(asset.environment)}</b></div>
            </div>
            <p class="pt-detail-evidence">${esc(asset.evidence || asset.notes || "No evidence note recorded.")}</p>
          </div>
          <div>
            <h4 class="pt-subhead">Controls</h4>
            <div class="pt-controls">
              ${CONTROLS.map((control) => {
                const value = asset.controls[control.key];
                const stateLabel = value === true ? "in place" : value === false ? "missing" : value === null ? "unverified" : "n/a";
                const stateClass = value === true ? "met" : value === false ? "missing" : value === null ? "unknown" : "na";
                return `<div class="pt-control ${stateClass}"><span>${esc(control.label)}</span><b>${stateLabel}</b></div>`;
              }).join("")}
            </div>
          </div>
        </div>
        <div class="pt-linked">
          <div><h4 class="pt-subhead">Devices</h4>${devices.length ? devices.map((device) => `<p>${esc(device.hostname)} · ${esc(device.os)} · ${riskTag(device._risk)}</p>`).join("") : '<p class="pt-muted">No linked device.</p>'}</div>
          <div><h4 class="pt-subhead">Resources</h4>${resources.length ? resources.map((resource) => `<p>${esc(resource.name)} · ${esc(resource.type)} · ${riskTag(resource._risk)}</p>`).join("") : '<p class="pt-muted">No linked resource.</p>'}</div>
          <div><h4 class="pt-subhead">Logins</h4>${logins.length ? logins.map((login) => `<p>${esc(login.account)} · ${esc(login.type)} · ${riskTag(login._risk)}</p>`).join("") : '<p class="pt-muted">No linked account.</p>'}</div>
        </div>
        <h4 class="pt-subhead" style="margin-top:16px">Gaps</h4>
        <div class="pt-detail-gaps">
          ${asset._gaps.length ? asset._gaps.map((gap) => `<div class="pt-detail-gap">${riskTag(gap.severity)}<span><b>${esc(gap.title)}</b><small>${esc(gap.recommendation)}</small></span></div>`).join("") : '<p class="pt-muted">No gaps recorded for this asset.</p>'}
        </div>
      </div>`;
    if (scroll) holder.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function clearFilters(scope) {
    if (scope === "assets") {
      ["pt-asset-search", "pt-asset-criticality", "pt-asset-category", "pt-asset-risk"].forEach((id) => {
        const el = $(id);
        if (el) el.value = id.endsWith("search") ? "" : "all";
      });
    }
    if (scope === "devices") {
      ["pt-device-search", "pt-device-patch", "pt-device-edr", "pt-device-risk"].forEach((id) => {
        const el = $(id);
        if (el) el.value = id.endsWith("search") ? "" : "all";
      });
    }
    if (scope === "resources") {
      ["pt-resource-search", "pt-resource-exposure", "pt-resource-risk"].forEach((id) => {
        const el = $(id);
        if (el) el.value = id.endsWith("search") ? "" : "all";
      });
    }
    if (scope === "logins") {
      ["pt-login-search", "pt-login-type", "pt-login-mfa", "pt-login-risk"].forEach((id) => {
        const el = $(id);
        if (el) el.value = id.endsWith("search") ? "" : "all";
      });
    }
    if (scope === "gaps") {
      ["pt-gap-search", "pt-gap-severity", "pt-gap-category"].forEach((id) => {
        const el = $(id);
        if (el) el.value = id.endsWith("search") ? "" : "all";
      });
    }
    renderTables();
  }

  function csvCell(value) {
    const output = value == null ? "" : String(value);
    return /[",\n]/.test(output) ? `"${output.replace(/"/g, '""')}"` : output;
  }

  function downloadText(filename, text, type = "text/plain") {
    const blob = new Blob([text], { type });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  }

  function downloadCsv(filename, headers, rows) {
    const text = [headers, ...rows].map((row) => row.map(csvCell).join(",")).join("\n");
    downloadText(filename, `${text}\n`, "text/csv;charset=utf-8");
  }

  function downloadJson(data, filename) {
    downloadText(filename, `${JSON.stringify(data, null, 2)}\n`, "application/json");
  }

  function exportData(scope) {
    const data = state.derived;
    if (scope === "assets") {
      downloadCsv("kavach-assets.csv",
        ["id", "name", "category", "type", "criticality", "owner", "site", "environment", "exposure", "controls_met", "controls_missing", "controls_unknown", "coverage", "risk_score", "risk", "gaps", "last_verified"],
        data.assets.map((asset) => [
          asset.id, asset.name, asset.category, asset.type, asset.criticality, asset.owner,
          asset.site, asset.environment, asset.exposure, asset._summary.met, asset._summary.missing,
          asset._summary.unknown, asset._summary.coverage == null ? "" : Math.round(asset._summary.coverage * 100),
          asset._score, asset._risk, asset._gaps.length, asset.last_verified,
        ]));
    }
    if (scope === "devices") {
      downloadCsv("kavach-devices.csv",
        ["id", "hostname", "asset", "os", "os_version", "owner", "site", "patch_status", "edr", "disk_encryption", "firewall", "admin_rights", "risk_score", "risk", "last_seen"],
        data.devices.map((device) => [
          device.id, device.hostname, device._linked?.name || "", device.os, device.os_version,
          device.owner, device.site, device.patch_status, device.edr, device.disk_encryption,
          device.firewall, device.admin_rights, device._score, device._risk, device.last_seen,
        ]));
    }
    if (scope === "resources") {
      downloadCsv("kavach-resources.csv",
        ["id", "name", "type", "asset", "internet_facing", "auth", "encryption", "exposure_path", "criticality", "owner", "risk_score", "risk"],
        data.resources.map((resource) => [
          resource.id, resource.name, resource.type, resource._linked?.name || "",
          resource.internet_facing, resource.auth, resource.encryption, resource.exposure_path,
          resource.criticality, resource.owner, resource._score, resource._risk,
        ]));
    }
    if (scope === "logins") {
      downloadCsv("kavach-logins.csv",
        ["account", "display_name", "type", "mfa", "last_login", "stale_days", "failed_24h", "risk_score", "risk", "assets", "notes"],
        data.logins.map((login) => [
          login.account, login.display_name, login.type, login.mfa, login.last_login,
          login.stale_days, login.failed_24h, login._score, login._risk,
          login.assets.join("; "), login.notes,
        ]));
    }
    if (scope === "gaps") {
      downloadCsv("kavach-protection-gaps.csv",
        ["severity", "title", "asset", "category", "owner", "recommendation", "due", "detail"],
        data.gaps.map((gap) => [
          gap.severity, gap.title, gap.asset_name, gap.category, gap.owner,
          gap.recommendation, gap.due, gap.detail,
        ]));
    }
  }

  function setStatus(message, kind = "") {
    const el = $("register-status");
    if (!el) return;
    el.textContent = message;
    el.className = `nw-import-status ${kind}`.trim();
  }

  function sampleSnapshot() {
    return JSON.parse(JSON.stringify(SAMPLE));
  }

  function loadSnapshot(raw, source = "demo", filename = "") {
    try {
      const normalized = normalizeSnapshot(raw);
      state.raw = normalized;
      state.derived = derive(normalized);
      state.source = source;
      state.filename = filename;
      state.selectedAsset = "";
      renderAll();
      if (source === "import") {
        setStatus(`Loaded ${filename || "register"} · ${normalized.assets.length} assets · ${state.derived.gaps.length} gaps. Nothing was uploaded.`, "success");
      } else {
        setStatus("Synthetic register loaded. Replace it with your own JSON when ready.", "");
      }
      return true;
    } catch (error) {
      setStatus(`Could not load the register: ${error.message}`, "error");
      return false;
    }
  }

  function importFile(file) {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const parsed = JSON.parse(String(reader.result));
        loadSnapshot(parsed, "import", file.name);
      } catch (error) {
        setStatus(`Could not parse ${file.name}: ${error.message}`, "error");
      }
    };
    reader.onerror = () => setStatus("Could not read the selected file.", "error");
    reader.readAsText(file);
  }

  function bindStaticEvents() {
    const choose = $("register-choose");
    const file = $("register-file");
    if (choose && file) choose.addEventListener("click", () => file.click());
    if (file) file.addEventListener("change", () => {
      importFile(file.files && file.files[0]);
      file.value = "";
    });

    const sample = $("register-sample");
    if (sample) sample.addEventListener("click", () => {
      loadSnapshot(sampleSnapshot(), "demo");
      $("register")?.scrollIntoView({ behavior: "smooth", block: "start" });
    });

    const heroSample = $("hero-sample");
    if (heroSample) heroSample.addEventListener("click", () => downloadJson(SAMPLE, "kavach-protection-sample.json"));

    const reset = $("reset-source");
    if (reset) reset.addEventListener("click", () => loadSnapshot(sampleSnapshot(), "demo"));

    const dropZone = $("drop-zone");
    if (dropZone) {
      ["dragenter", "dragover"].forEach((name) => dropZone.addEventListener(name, (event) => {
        event.preventDefault();
        dropZone.classList.add("dragging");
      }));
      ["dragleave", "drop"].forEach((name) => dropZone.addEventListener(name, (event) => {
        event.preventDefault();
        dropZone.classList.remove("dragging");
      }));
      dropZone.addEventListener("drop", (event) => {
        const dropped = event.dataTransfer?.files?.[0];
        if (dropped) importFile(dropped);
      });
    }

    const app = $("protection-app");
    if (!app) return;
    app.addEventListener("click", (event) => {
      const tab = event.target.closest("[data-tab]");
      if (tab) {
        state.tab = tab.dataset.tab || "overview";
        renderTabs();
        return;
      }
      const gapAsset = event.target.closest("[data-gap-asset]");
      if (gapAsset && gapAsset.dataset.gapAsset) {
        state.selectedAsset = gapAsset.dataset.gapAsset;
        state.tab = "assets";
        renderTabs();
        renderDetail(true);
        return;
      }
      const asset = event.target.closest("[data-asset]");
      if (asset && asset.dataset.asset) {
        state.selectedAsset = asset.dataset.asset;
        state.tab = "assets";
        renderTabs();
        renderDetail(true);
        return;
      }
      const close = event.target.closest("[data-close-detail]");
      if (close) {
        state.selectedAsset = "";
        renderDetail(false);
        return;
      }
      const clear = event.target.closest("[data-clear]");
      if (clear) {
        clearFilters(clear.dataset.clear || "");
        return;
      }
      const exportButton = event.target.closest("[data-export]");
      if (exportButton) {
        exportData(exportButton.dataset.export || "");
      }
    });
    app.addEventListener("input", (event) => {
      if (event.target.matches("input[type=search]")) renderTables();
    });
    app.addEventListener("change", (event) => {
      if (event.target.matches("select")) renderTables();
    });
  }

  function init() {
    bindStaticEvents();
    loadSnapshot(sampleSnapshot(), "demo");
  }

  window.KavachProtection = {
    load: (snapshot, source = "import", filename = "inline.json") => loadSnapshot(snapshot, source, filename),
    sample: () => sampleSnapshot(),
    getDerived: () => state.derived,
    getState: () => ({ ...state, raw: state.raw, derived: undefined }),
  };

  init();
})();
