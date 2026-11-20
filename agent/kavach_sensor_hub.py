#!/usr/bin/env python3
"""Kavach Sensor Hub — read-only sensor adapters, entity graph and triage.

Optional local service for authorised environments. It ingests normalised
events from Zeek JSON logs, osquery, Wazuh alerts and HTTP push, builds an
entity graph and produces evidence-cited triage cases.

It does not capture payloads and it does not take response actions.

Run:
    python3 agent/kavach_sensor_hub.py --demo
    python3 agent/kavach_sensor_hub.py --zeek-dir /opt/zeek/logs/current \\
        --osquery --wazuh-alerts /var/ossec/logs/alerts/alerts.json \\
        --critical-assets agent/critical-assets.example.json

Open http://127.0.0.1:8789/
"""

from __future__ import annotations

import argparse
import csv
import io
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid
from collections import Counter, deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

ROOT = Path(__file__).resolve().parent.parent
UI = Path(__file__).resolve().parent / "sensor_ui.html"
STYLES = ROOT / "styles.css"
ICON = ROOT / "icon.svg"

EVENT_LIMIT = 20000
CASE_LIMIT = 200
MAX_BODY = 5 * 1024 * 1024
SEVERITIES = ["info", "low", "medium", "high", "critical"]
SUSPICIOUS_PROCESSES = {
    "powershell", "powershell.exe", "pwsh", "cmd", "cmd.exe", "wscript",
    "wscript.exe", "cscript", "cscript.exe", "rundll32", "rundll32.exe",
    "regsvr32", "regsvr32.exe", "mshta", "mshta.exe", "curl", "wget",
    "bash", "sh", "python", "python3", "osascript",
}
SENSITIVE_PORTS = {22, 135, 139, 445, 3389, 5985, 5986}
OT_PORTS = {102, 502, 1883, 8883, 20000, 44818, 47808}


def now() -> float:
    return time.time()


def iso_utc(stamp: float) -> str:
    return datetime.fromtimestamp(stamp, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def parse_ts(value) -> float | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    if re.fullmatch(r"\d+(?:\.\d+)?", text):
        number = float(text)
        return number / 1000 if number > 1e12 else number
    candidate = text.replace("Z", "+00:00")
    if re.search(r"[+-]\d{4}$", candidate):
        candidate = candidate[:-5] + candidate[-5:-2] + ":" + candidate[-2:]
    try:
        return datetime.fromisoformat(candidate).timestamp()
    except ValueError:
        return None


def severity_rank(value: str) -> int:
    try:
        return SEVERITIES.index(value)
    except ValueError:
        return 0


def max_severity(*values: str) -> str:
    return max(values or ("info",), key=severity_rank)


def to_int(value, default: int = 0) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def as_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "success", "succeeded"}


def is_private_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(str(value).split("%")[0])
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def is_external_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(str(value).split("%")[0])
    except ValueError:
        return False
    return ip.is_global and not (ip.is_private or ip.is_loopback or ip.is_link_local)


def is_external_name(value: str) -> bool:
    text = str(value or "").strip().lower().rstrip(".")
    if not text:
        return False
    if text.endswith(".local") or text.endswith(".lan") or text.endswith(".internal"):
        return False
    return "." in text


def slug(value: str) -> str:
    return re.sub(r"[^a-z0-9._:-]+", "-", str(value or "").strip().lower()).strip("-")


class Assets:
    def __init__(self, rows: list[dict] | None = None, use_defaults: bool = False) -> None:
        if rows is None:
            rows = [
                {"value": "10.20.4.15", "label": "SAP S/4HANA production"},
                {"value": "10.30.7.40", "label": "PLC line 2"},
                {"value": "10.30.7.50", "label": "OT historian"},
            ] if use_defaults else []
        self.rows = []
        for row in rows:
            value = str(row.get("value", "") if isinstance(row, dict) else row).strip()
            if not value:
                continue
            label = str(row.get("label", value) if isinstance(row, dict) else value).strip()
            self.rows.append({"value": value, "label": label})

    @classmethod
    def from_file(cls, path: str | None) -> "Assets":
        if not path:
            return cls([])
        try:
            data = json.loads(Path(path).read_text())
        except (OSError, json.JSONDecodeError) as exc:
            print(f"critical assets could not be read: {exc}", file=sys.stderr)
            return cls([])
        if isinstance(data, dict):
            data = data.get("assets", [])
        return cls(data if isinstance(data, list) else [])

    def list(self) -> list[dict]:
        return [dict(row) for row in self.rows]

    def _matches(self, value: str, pattern: str) -> bool:
        needle = str(value or "").strip().lower().rstrip(".")
        target = str(pattern or "").strip().lower().rstrip(".")
        if not needle or not target:
            return False
        if "/" in target:
            try:
                return ipaddress.ip_address(needle) in ipaddress.ip_network(target, strict=False)
            except ValueError:
                return False
        if target.startswith("*."):
            return needle.endswith(target[1:]) and len(needle) > len(target) - 1
        return needle == target

    def match(self, event: dict) -> dict | None:
        values = [
            event.get("src_ip", ""), event.get("dst_ip", ""),
            event.get("host", ""), event.get("domain", ""),
        ]
        for row in self.rows:
            for value in values:
                if self._matches(value, row["value"]):
                    return row
        return None




def version_key(value: str) -> tuple:
    parts = re.findall(r"\d+|[a-zA-Z]+", str(value or "").lower())
    key = []
    for part in parts:
        key.append((0, int(part)) if part.isdigit() else (1, part))
    return tuple(key)


def version_less(current: str, minimum: str) -> bool:
    if not current or not minimum:
        return False
    return version_key(current) < version_key(minimum)


def version_text(value) -> str:
    return str(value or "").strip()


class Baseline:
    def __init__(self, data: dict | None = None, use_defaults: bool = False) -> None:
        data = data or {}
        if use_defaults and not data:
            data = {
                "software": [
                    {"name": "7-Zip", "minimum_version": "24.09"},
                    {"name": "Google Chrome", "minimum_version": "132.0"},
                    {"name": "OpenSSL", "minimum_version": "3.0.16"},
                    {"name": "Java", "minimum_version": "17.0.12"},
                    {"name": "SAP GUI", "minimum_version": "7.70"},
                ],
                "required_patches": {"windows": ["KB5049981", "KB5051987"]},
                "minimum_build": {"windows": "19045.5487", "macos": "15.3", "linux": ""},
            }
        self.software = [row for row in data.get("software", []) if isinstance(row, dict) and row.get("name")]
        raw_patches = data.get("required_patches", {})
        if isinstance(raw_patches, list):
            self.required_patches = {"*": [str(value).strip() for value in raw_patches if str(value).strip()]}
        else:
            self.required_patches = {
                str(key).lower(): [str(value).strip() for value in values if str(value).strip()]
                for key, values in raw_patches.items()
                if isinstance(values, list)
            }
        self.minimum_build = {str(key).lower(): str(value).strip() for key, value in data.get("minimum_build", {}).items() if str(value).strip()}

    @classmethod
    def from_file(cls, path: str | None, use_defaults: bool = False) -> "Baseline":
        if not path:
            return cls(use_defaults=use_defaults)
        try:
            data = json.loads(Path(path).read_text())
        except (OSError, json.JSONDecodeError) as exc:
            print(f"patch baseline could not be read: {exc}", file=sys.stderr)
            return cls(use_defaults=use_defaults)
        return cls(data if isinstance(data, dict) else {}, use_defaults=use_defaults)

    def software_for(self, name: str) -> dict | None:
        needle = str(name or "").strip().lower()
        if not needle:
            return None
        for row in self.software:
            target = str(row.get("name", "")).strip().lower()
            if not target:
                continue
            if needle == target:
                return row
            if re.search(r"(^|[^a-z0-9])" + re.escape(target) + r"([^a-z0-9]|$)", needle):
                return row
        return None

    def patches_for(self, family: str) -> list[str]:
        family = str(family or "").lower()
        return list(self.required_patches.get(family, [])) + list(self.required_patches.get("*", []))

    def apply(self, host: dict) -> dict:
        software = []
        outdated = 0
        for item in host.get("software", []):
            row = dict(item)
            name = str(row.get("name") or "").strip()
            current = version_text(row.get("version"))
            latest = version_text(row.get("latest"))
            baseline = self.software_for(name)
            baseline_min = version_text(baseline.get("minimum_version")) if baseline else ""
            update_source = ""
            status = "unknown"
            if current and baseline_min and version_less(current, baseline_min):
                status = "outdated"
                update_source = "baseline"
            elif current and latest and version_less(current, latest):
                status = "outdated"
                update_source = row.get("latest_source") or "package-manager"
            elif current:
                status = "current"
            row["name"] = name
            row["version"] = current
            row["latest"] = latest
            row["baseline_min"] = baseline_min
            row["status"] = status
            row["update_source"] = update_source
            software.append(row)
            if status == "outdated":
                outdated += 1

        patches = host.get("patches") or {}
        installed = [dict(row) for row in patches.get("installed", []) if isinstance(row, dict)]
        available = [dict(row) for row in patches.get("available", []) if isinstance(row, dict)]
        missing = [dict(row) for row in patches.get("missing", []) if isinstance(row, dict)]
        installed_ids = {str(row.get("id") or "").lower() for row in installed}
        for patch in self.patches_for(host.get("os_family", "")):
            if patch.lower() not in installed_ids:
                missing.append({
                    "id": patch,
                    "title": "Required baseline patch",
                    "severity": "required",
                    "source": "baseline",
                })
        missing_ids = set()
        unique_missing = []
        for row in missing:
            key = str(row.get("id") or row.get("title") or "").lower()
            if not key or key in missing_ids:
                continue
            missing_ids.add(key)
            unique_missing.append(row)

        family = str(host.get("os_family") or "").lower()
        minimum_build = self.minimum_build.get(family, "")
        build_outdated = bool(minimum_build and host.get("os_version") and version_less(str(host.get("os_version")), minimum_build))
        known_version = any(row.get("status") == "current" for row in software)
        risk = "low"
        if host.get("critical_asset") and (outdated or unique_missing or build_outdated):
            risk = "high"
        elif unique_missing or build_outdated:
            risk = "medium" if len(unique_missing) < 3 else "high"
        elif outdated or host.get("reboot_pending"):
            risk = "medium"

        host["software"] = software
        host["patches"] = {"installed": installed, "available": available, "missing": unique_missing}
        host["outdated_count"] = outdated
        host["missing_patch_count"] = len(unique_missing)
        host["build_outdated"] = build_outdated
        host["minimum_build"] = minimum_build
        host["risk"] = risk
        host["known_version"] = known_version
        host["gap_count"] = outdated + len(unique_missing) + (1 if build_outdated else 0)
        return host


class InventoryStore:
    def __init__(self, baseline: Baseline, assets: Assets) -> None:
        self.baseline = baseline
        self.assets = assets
        self.hosts: dict[str, dict] = {}

    def upsert(self, raw: dict) -> dict:
        host = dict(raw or {})
        hostname = str(host.get("hostname") or host.get("id") or "unknown").strip()
        host_id = slug(host.get("id") or hostname) or "unknown"
        ip_addresses = host.get("ip_addresses") or []
        if isinstance(ip_addresses, str):
            ip_addresses = [ip_addresses]
        ip_addresses = [str(value) for value in ip_addresses if value]
        asset = None
        for address in ip_addresses:
            asset = self.assets.match({"host": hostname, "src_ip": address, "dst_ip": ""})
            if asset:
                break
        if not asset:
            asset = self.assets.match({"host": hostname})
        previous = self.hosts.get(host_id, {})
        host.update({
            "id": host_id,
            "hostname": hostname,
            "ip_addresses": ip_addresses,
            "critical_asset": bool(host.get("critical_asset")) or bool(asset),
            "critical_label": str(host.get("critical_label") or (asset.get("label") if asset else "")),
            "software": host.get("software") or [],
            "patches": host.get("patches") or {},
            "notes": host.get("notes") or [],
            "last_scan": parse_ts(host.get("last_scan")) or now(),
            "scan_count": int(previous.get("scan_count", 0)) + 1,
        })
        host = self.baseline.apply(host)
        self.hosts[host_id] = host
        return host

    def host_rows(self) -> list[dict]:
        rows = []
        for host in self.hosts.values():
            rows.append({
                "id": host["id"],
                "hostname": host["hostname"],
                "os_family": host.get("os_family", ""),
                "os_name": host.get("os_name", ""),
                "os_version": host.get("os_version", ""),
                "kernel": host.get("kernel", ""),
                "last_scan": host.get("last_scan", 0),
                "software_count": len(host.get("software", [])),
                "outdated_count": host.get("outdated_count", 0),
                "missing_patch_count": host.get("missing_patch_count", 0),
                "available_count": len(host.get("patches", {}).get("available", [])),
                "build_outdated": host.get("build_outdated", False),
                "reboot_pending": host.get("reboot_pending", False),
                "critical_asset": host.get("critical_asset", False),
                "critical_label": host.get("critical_label", ""),
                "risk": host.get("risk", "low"),
                "gap_count": host.get("gap_count", 0),
            })
        rows.sort(key=lambda row: (row["critical_asset"], row["gap_count"], row["last_scan"]), reverse=True)
        return rows

    def summary(self) -> dict:
        hosts = list(self.hosts.values())
        os_counts = Counter(host.get("os_family") or "Unknown" for host in hosts)
        return {
            "hosts": len(hosts),
            "software": sum(len(host.get("software", [])) for host in hosts),
            "outdated": sum(host.get("outdated_count", 0) for host in hosts),
            "missingPatches": sum(host.get("missing_patch_count", 0) for host in hosts),
            "availableUpdates": sum(len(host.get("patches", {}).get("available", [])) for host in hosts),
            "criticalHosts": sum(1 for host in hosts if host.get("critical_asset")),
            "criticalGaps": sum(1 for host in hosts if host.get("critical_asset") and host.get("gap_count", 0)),
            "rebootPending": sum(1 for host in hosts if host.get("reboot_pending")),
            "buildOutdated": sum(1 for host in hosts if host.get("build_outdated")),
            "lastScan": max((host.get("last_scan", 0) for host in hosts), default=0),
            "os": [{"name": name, "count": count} for name, count in os_counts.most_common()],
            "baseline": {
                "software": len(self.baseline.software),
                "requiredPatches": sum(len(values) for values in self.baseline.required_patches.values()),
                "minimumBuild": self.baseline.minimum_build,
            },
        }

    def software(self, query: str = "") -> list[dict]:
        needle = str(query or "").strip().lower()
        rows = []
        for host in self.hosts.values():
            for item in host.get("software", []):
                haystack = " ".join([
                    str(item.get("name", "")), str(item.get("vendor", "")),
                    str(item.get("version", "")), host.get("hostname", ""),
                ]).lower()
                if needle and needle not in haystack:
                    continue
                rows.append({
                    "host": host["id"],
                    "hostname": host.get("hostname", ""),
                    "os": host.get("os_name", ""),
                    "name": item.get("name", ""),
                    "vendor": item.get("vendor", ""),
                    "version": item.get("version", ""),
                    "latest": item.get("latest", ""),
                    "baseline_min": item.get("baseline_min", ""),
                    "status": item.get("status", "unknown"),
                    "source": item.get("source", ""),
                    "update_source": item.get("update_source", ""),
                })
        rows.sort(key=lambda row: (row["status"] != "outdated", row["name"].lower(), row["hostname"]))
        return rows[:500]

    def patch_gaps(self) -> list[dict]:
        rows = []
        for host in self.hosts.values():
            if not host.get("missing_patch_count") and not host.get("build_outdated"):
                continue
            rows.append({
                "host": host["id"],
                "hostname": host.get("hostname", ""),
                "os": host.get("os_name", ""),
                "os_version": host.get("os_version", ""),
                "minimum_build": host.get("minimum_build", ""),
                "build_outdated": host.get("build_outdated", False),
                "missing": host.get("patches", {}).get("missing", []),
                "available": host.get("patches", {}).get("available", []),
                "reboot_pending": host.get("reboot_pending", False),
                "critical_asset": host.get("critical_asset", False),
                "risk": host.get("risk", "low"),
            })
        rows.sort(key=lambda row: (row["critical_asset"], row["risk"] == "high", len(row["missing"])), reverse=True)
        return rows

    def csv_text(self) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["host", "hostname", "os", "os_version", "software", "vendor", "version", "latest", "baseline_min", "status", "source", "critical_asset", "missing_patches", "reboot_pending", "last_scan"])
        for host in self.hosts.values():
            missing = ", ".join(str(row.get("id", "")) for row in host.get("patches", {}).get("missing", []))
            for item in host.get("software", []):
                writer.writerow([
                    host["id"], host.get("hostname", ""), host.get("os_name", ""),
                    host.get("os_version", ""), item.get("name", ""), item.get("vendor", ""),
                    item.get("version", ""), item.get("latest", ""), item.get("baseline_min", ""),
                    item.get("status", ""), item.get("source", ""), host.get("critical_asset", False),
                    missing, host.get("reboot_pending", False), iso_utc(host.get("last_scan", 0)),
                ])
        return output.getvalue()


class Graph:
    def __init__(self) -> None:
        self.nodes: dict[str, dict] = {}
        self.edges: dict[str, dict] = {}

    def touch(self, kind: str, value: str, stamp: float, label: str = "", key: str = "", risk: str = "info") -> str | None:
        value = str(value or "").strip()
        if not value:
            return None
        node_id = f"{kind}:{key or value}"
        node = self.nodes.get(node_id)
        if node is None:
            node = {
                "id": node_id,
                "type": kind,
                "value": value,
                "label": label or value,
                "firstSeen": stamp,
                "lastSeen": stamp,
                "count": 0,
                "risk": "info",
                "critical": False,
                "asset": "",
            }
            self.nodes[node_id] = node
        node["count"] += 1
        node["firstSeen"] = min(node["firstSeen"], stamp)
        node["lastSeen"] = max(node["lastSeen"], stamp)
        if severity_rank(risk) > severity_rank(node["risk"]):
            node["risk"] = risk
        return node_id

    def mark_critical(self, node_id: str | None, asset: dict) -> None:
        if not node_id or node_id not in self.nodes:
            return
        node = self.nodes[node_id]
        node["critical"] = True
        node["asset"] = asset.get("label") or asset.get("value", "")
        node["risk"] = "high"

    def link(self, src: str | None, dst: str | None, relation: str, stamp: float, sensor: str) -> None:
        if not src or not dst or src == dst:
            return
        key = f"{src}|{relation}|{dst}"
        edge = self.edges.get(key)
        if edge is None:
            edge = {
                "id": key,
                "src": src,
                "dst": dst,
                "relation": relation,
                "firstSeen": stamp,
                "lastSeen": stamp,
                "count": 0,
                "sensors": set(),
            }
            self.edges[key] = edge
        edge["count"] += 1
        edge["firstSeen"] = min(edge["firstSeen"], stamp)
        edge["lastSeen"] = max(edge["lastSeen"], stamp)
        edge["sensors"].add(sensor)

    def top_nodes(self, limit: int = 20) -> list[dict]:
        rows = sorted(self.nodes.values(), key=lambda node: (node["lastSeen"], node["count"]), reverse=True)
        return [{**node} for node in rows[:limit]]

    def node(self, node_id: str) -> dict | None:
        node = self.nodes.get(node_id)
        return {**node} if node else None

    def neighbors(self, node_id: str) -> list[dict]:
        out = []
        for edge in self.edges.values():
            if edge["src"] != node_id and edge["dst"] != node_id:
                continue
            other = edge["dst"] if edge["src"] == node_id else edge["src"]
            if other not in self.nodes:
                continue
            out.append({
                "node": {**self.nodes[other]},
                "relation": edge["relation"],
                "count": edge["count"],
                "firstSeen": edge["firstSeen"],
                "lastSeen": edge["lastSeen"],
                "direction": "out" if edge["src"] == node_id else "in",
            })
        return sorted(out, key=lambda row: row["lastSeen"], reverse=True)[:40]

    def stats(self) -> dict:
        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "critical": sum(1 for node in self.nodes.values() if node["critical"]),
        }


def normalize_event(raw: dict, sensor: str) -> dict:
    stamp = parse_ts(raw.get("ts") or raw.get("timestamp") or raw.get("time")) or now()
    kind = str(raw.get("kind") or "event").strip().lower()
    severity = str(raw.get("severity") or "info").strip().lower()
    if severity not in SEVERITIES:
        severity = "info"
    event = {
        "id": str(raw.get("id") or f"evt-{uuid.uuid4().hex[:16]}"),
        "ts": stamp,
        "sensor": str(raw.get("sensor") or sensor or "ingest"),
        "kind": kind,
        "action": str(raw.get("action") or ""),
        "user": str(raw.get("user") or ""),
        "host": str(raw.get("host") or ""),
        "src_ip": str(raw.get("src_ip") or ""),
        "dst_ip": str(raw.get("dst_ip") or ""),
        "src_port": to_int(raw.get("src_port")),
        "dst_port": to_int(raw.get("dst_port")),
        "proto": str(raw.get("proto") or ""),
        "domain": str(raw.get("domain") or "").lower(),
        "app": str(raw.get("app") or ""),
        "process": str(raw.get("process") or ""),
        "pid": to_int(raw.get("pid")),
        "result": str(raw.get("result") or ""),
        "message": str(raw.get("message") or "")[:500],
        "evidence": str(raw.get("evidence") or ""),
        "severity": severity,
        "bytes_in": to_int(raw.get("bytes_in")),
        "bytes_out": to_int(raw.get("bytes_out")),
    }
    return event


class Hub:
    def __init__(self, assets: Assets, archive: str | None = None, baseline: Baseline | None = None) -> None:
        self.assets = assets
        self.baseline = baseline or Baseline([])
        self.inventory = InventoryStore(self.baseline, self.assets)
        self.graph = Graph()
        self.events: deque[dict] = deque(maxlen=EVENT_LIMIT)
        self.cases: dict[str, dict] = {}
        self.case_seq = 0
        self.lock = threading.RLock()
        self.sensors: dict[str, dict] = {}
        self.archive = Path(archive) if archive else None

    def register_sensor(self, name: str, status: str = "waiting", detail: str = "", error: str = "") -> None:
        with self.lock:
            row = self.sensors.setdefault(name, {
                "name": name, "status": status, "detail": detail,
                "error": error, "events": 0, "lastEventAt": 0,
            })
            if detail:
                row["detail"] = detail
            row["status"] = status
            if error:
                row["error"] = error

    def set_sensor(self, name: str, status: str, detail: str = "", error: str = "") -> None:
        with self.lock:
            row = self.sensors.setdefault(name, {
                "name": name, "status": status, "detail": detail,
                "error": error, "events": 0, "lastEventAt": 0,
            })
            row["status"] = status
            if detail:
                row["detail"] = detail
            row["error"] = error

    def ingest(self, raws: list[dict], sensor: str = "ingest") -> int:
        if not isinstance(raws, list):
            raws = [raws]
        events = [normalize_event(raw, sensor) for raw in raws if isinstance(raw, dict)]
        if not events:
            return 0
        with self.lock:
            for event in events:
                self._graph_ingest(event)
                self.events.append(event)
                if self.archive:
                    try:
                        self.archive.parent.mkdir(parents=True, exist_ok=True)
                        with self.archive.open("a", encoding="utf-8") as handle:
                            handle.write(json.dumps(event, separators=(",", ":")) + "\n")
                    except OSError:
                        pass
            row = self.sensors.setdefault(sensor, {
                "name": sensor, "status": "online", "detail": "HTTP ingest",
                "error": "", "events": 0, "lastEventAt": 0,
            })
            row["events"] += len(events)
            row["lastEventAt"] = max(row["lastEventAt"], max(event["ts"] for event in events))
            row["status"] = "online"
            self._triage()
        return len(events)

    def _graph_ingest(self, event: dict) -> None:
        stamp = event["ts"]
        sensor = event["sensor"]
        risk = event["severity"]
        if event["severity"] in ("high", "critical") and event["kind"] == "alert":
            risk = event["severity"]

        user = self.graph.touch("user", event["user"], stamp, risk=risk) if event["user"] else None
        host = self.graph.touch("host", event["host"], stamp, risk=risk) if event["host"] else None
        src = self.graph.touch("ip", event["src_ip"], stamp, risk=risk) if event["src_ip"] else None
        dst = self.graph.touch("ip", event["dst_ip"], stamp, risk=risk) if event["dst_ip"] else None
        domain = self.graph.touch("domain", event["domain"], stamp, risk=risk) if event["domain"] else None
        app = self.graph.touch("app", event["app"], stamp, risk=risk) if event["app"] else None
        process_key = ""
        if event["process"]:
            process_key = f"{event['host'] or event['user'] or 'unknown'}:{event['process']}:{event['pid'] or 0}"
        process = self.graph.touch(
            "process", event["process"], stamp, label=event["process"], key=process_key, risk=risk,
        ) if event["process"] else None

        if user and host:
            self.graph.link(user, host, "authenticated_on" if event["kind"] == "auth" else "used", stamp, sensor)
        if host and src:
            self.graph.link(host, src, "connected_from", stamp, sensor)
        if host and dst:
            self.graph.link(host, dst, "connected_to", stamp, sensor)
        if host and process:
            self.graph.link(host, process, "ran", stamp, sensor)
        if process and dst:
            self.graph.link(process, dst, "opened", stamp, sensor)
        if process and domain:
            self.graph.link(process, domain, "contacted", stamp, sensor)
        if src and domain:
            self.graph.link(src, domain, "resolved_to", stamp, sensor)
        if host and domain:
            self.graph.link(host, domain, "queried", stamp, sensor)
        if user and app:
            self.graph.link(user, app, "accessed", stamp, sensor)
        if host and app:
            self.graph.link(host, app, "accessed", stamp, sensor)

        asset = self.assets.match(event)
        if asset:
            for node_id in (src, dst, host, domain):
                self.graph.mark_critical(node_id, asset)
            event["critical_asset"] = asset

    def _add_case(
        self,
        key: str,
        rule: str,
        title: str,
        severity: str,
        confidence: float,
        entity: str,
        summary: str,
        evidence: list[dict],
        recommendations: list[str],
    ) -> None:
        stamp = max((event["ts"] for event in evidence), default=now())
        case = self.cases.get(key)
        if case is None:
            self.case_seq += 1
            case = {
                "id": f"case-{self.case_seq:04d}",
                "key": key,
                "rule": rule,
                "title": title,
                "severity": severity,
                "confidence": round(confidence, 2),
                "status": "open",
                "entity": entity,
                "firstSeen": stamp,
                "lastSeen": stamp,
                "summary": summary,
                "evidence": [],
                "recommendations": recommendations,
            }
            self.cases[key] = case
        case["lastSeen"] = max(case["lastSeen"], stamp)
        case["severity"] = max_severity(case["severity"], severity)
        case["confidence"] = max(case["confidence"], round(confidence, 2))
        existing = {row["id"] for row in case["evidence"]}
        for event in evidence:
            if event["id"] in existing:
                continue
            case["evidence"].append({
                "id": event["id"],
                "ts": event["ts"],
                "sensor": event["sensor"],
                "kind": event["kind"],
                "message": event["message"] or event["evidence"] or event["kind"],
                "src": event["src_ip"],
                "dst": event["dst_ip"] or event["domain"],
                "user": event["user"],
                "host": event["host"],
            })
            existing.add(event["id"])
        case["evidence"] = sorted(case["evidence"], key=lambda row: row["ts"])[-12:]
        if len(self.cases) > CASE_LIMIT:
            oldest = min(self.cases.values(), key=lambda row: row["lastSeen"])
            self.cases.pop(oldest["key"], None)

    def _triage(self) -> None:
        recent = list(self.events)[-1200:]
        latest = recent[-1]["ts"] if recent else now()
        failures = [event for event in recent if event["kind"] == "auth" and event["result"] == "failure"]

        for event in recent:
            asset = event.get("critical_asset")
            if asset:
                entity = event["host"] or event["user"] or event["dst_ip"] or event["src_ip"]
                self._add_case(
                    f"critical:{asset['value']}:{entity}",
                    "critical-asset-access",
                    "Critical asset access",
                    "critical",
                    0.95,
                    entity,
                    f"{entity or 'An entity'} touched {asset['label'] or asset['value']} through {event['sensor']} {event['kind']}.",
                    [event],
                    [
                        "Confirm the business reason for the access.",
                        "Correlate the user, device and process on the target.",
                        "Check whether the source location and time are expected.",
                    ],
                )

            process_name = event["process"].lower().split("/")[-1].split("\\")[-1]
            if process_name in SUSPICIOUS_PROCESSES and is_external_ip(event["dst_ip"]):
                self._add_case(
                    f"process-egress:{event['host']}:{event['process']}:{event['dst_ip']}",
                    "suspicious-process-egress",
                    "Suspicious process external egress",
                    "high",
                    0.78,
                    event["host"] or event["process"],
                    f"{event['process']} on {event['host'] or 'an unknown host'} connected to external {event['dst_ip']}.",
                    [event],
                    [
                        "Identify the parent process and command line.",
                        "Check the destination reputation and first-seen time.",
                        "Collect the process tree and a short flow capture.",
                    ],
                )

            if event["kind"] == "auth" and event["user"] and event["result"] == "success" and is_external_ip(event["src_ip"]):
                related = [
                    row for row in recent
                    if row is not event
                    and abs(event["ts"] - row["ts"]) <= 1800
                    and row["kind"] in ("flow", "process", "tls", "http", "dns")
                    and (row["user"] == event["user"] or row["host"] == event["host"] or row["src_ip"] == event["src_ip"])
                ]
                if related:
                    self._add_case(
                        f"identity-network:{event['user']}:{event['src_ip']}:{event['host']}",
                        "identity-network-correlation",
                        "Identity and network activity correlate",
                        "high",
                        0.74,
                        event["user"],
                        f"{event['user']} authenticated on {event['host'] or 'a host'} while related network or process activity was observed.",
                        [event] + related[-4:],
                        [
                            "Verify the sign-in location and device.",
                            "Review the related process and destination.",
                            "Revoke the session if the user cannot confirm the activity.",
                        ],
                    )

        for event in failures:
            window_start = event["ts"] - 600
            same_user = [row for row in failures if row["user"] == event["user"] and row["ts"] >= window_start]
            same_ip = [row for row in failures if row["src_ip"] == event["src_ip"] and row["src_ip"] and row["ts"] >= window_start]
            distinct_users = {row["user"] for row in same_ip if row["user"]}
            if len(same_user) >= 5:
                self._add_case(
                    f"auth-burst:user:{event['user']}",
                    "authentication-burst",
                    "Repeated authentication failures",
                    "medium" if len(same_user) < 10 else "high",
                    min(0.9, 0.5 + len(same_user) / 20),
                    event["user"],
                    f"{len(same_user)} failed authentications for {event['user']} in ten minutes.",
                    same_user[-8:],
                    [
                        "Confirm whether the user is locked out or mistyping credentials.",
                        "Check the source IP and device.",
                        "Block the source only after confirming it is unauthorized.",
                    ],
                )
            if len(distinct_users) >= 3:
                self._add_case(
                    f"auth-spray:{event['src_ip']}",
                    "password-spray",
                    "Password spray across accounts",
                    "high",
                    0.86,
                    event["src_ip"],
                    f"{event['src_ip']} failed against {len(distinct_users)} distinct accounts in ten minutes.",
                    same_ip[-8:],
                    [
                        "Treat the source as hostile until verified.",
                        "Check for any successful sign-in after the failures.",
                        "Enforce MFA and review conditional access.",
                    ],
                )

        flows = [event for event in recent if event["kind"] == "flow" and event["ts"] >= latest - 600]
        by_host: dict[str, list[dict]] = {}
        for event in flows:
            if event["dst_port"] in SENSITIVE_PORTS and is_private_ip(event["dst_ip"]) and event["host"]:
                by_host.setdefault(event["host"], []).append(event)
        for host, rows in by_host.items():
            destinations = {row["dst_ip"] for row in rows if row["dst_ip"]}
            if len(destinations) >= 3:
                self._add_case(
                    f"lateral:{host}",
                    "lateral-movement",
                    "Lateral movement pattern",
                    "high",
                    0.72,
                    host,
                    f"{host} opened sensitive sessions to {len(destinations)} internal hosts in ten minutes.",
                    rows[-8:],
                    [
                        "Check whether the host is a jump server or backup appliance.",
                        "Review the user and process responsible for the sessions.",
                        "Inspect SMB, RDP or SSH logs on the destination hosts.",
                    ],
                )

    def snapshot(self) -> dict:
        with self.lock:
            events = list(self.events)
            cases = sorted(self.cases.values(), key=lambda row: row["lastSeen"], reverse=True)
            return {
                "generatedAt": now(),
                "sensors": sorted(self.sensors.values(), key=lambda row: row["name"]),
                "stats": {
                    "events": len(events),
                    "entities": self.graph.stats()["nodes"],
                    "edges": self.graph.stats()["edges"],
                    "cases": len(cases),
                    "criticalAssets": len(self.assets.list()),
                },
                "cases": cases[:40],
                "events": [
                    {
                        "id": event["id"], "ts": event["ts"], "sensor": event["sensor"],
                        "kind": event["kind"], "user": event["user"], "host": event["host"],
                        "src_ip": event["src_ip"], "dst_ip": event["dst_ip"],
                        "domain": event["domain"], "process": event["process"],
                        "message": event["message"], "severity": event["severity"],
                        "result": event["result"],
                    }
                    for event in sorted(events[-250:], key=lambda row: row["ts"], reverse=True)[:100]
                ],
                "entities": self.graph.top_nodes(16),
                "criticalAssets": self.assets.list(),
                "inventory": self.inventory.summary(),
            }

    def search_entities(self, query: str = "", kind: str = "", limit: int = 20) -> list[dict]:
        with self.lock:
            needle = str(query or "").strip().lower()
            rows = []
            for node in self.graph.nodes.values():
                if kind and node["type"] != kind:
                    continue
                if needle and needle not in node["value"].lower() and needle not in node["label"].lower():
                    continue
                rows.append({**node})
            rows.sort(key=lambda node: (node["critical"], node["lastSeen"], node["count"]), reverse=True)
            return rows[:limit]

    def entity_detail(self, node_id: str) -> dict | None:
        with self.lock:
            node = self.graph.node(node_id)
            if not node:
                return None
            timeline = []
            for event in reversed(self.events):
                haystack = " ".join([
                    event["user"], event["host"], event["src_ip"], event["dst_ip"],
                    event["domain"], event["process"], event["app"],
                ]).lower()
                if node["value"].lower() in haystack:
                    timeline.append({
                        "id": event["id"], "ts": event["ts"], "sensor": event["sensor"],
                        "kind": event["kind"], "message": event["message"],
                        "src_ip": event["src_ip"], "dst_ip": event["dst_ip"],
                        "user": event["user"], "host": event["host"],
                        "severity": event["severity"], "result": event["result"],
                    })
                if len(timeline) >= 80:
                    break
            return {
                "node": node,
                "neighbors": self.graph.neighbors(node_id),
                "timeline": sorted(timeline, key=lambda row: row["ts"], reverse=True),
                "cases": [
                    case for case in self.cases.values()
                    if case["entity"] == node["value"] or node["value"] in case["summary"]
                ][:8],
            }

    def case_detail(self, case_id: str) -> dict | None:
        with self.lock:
            for case in self.cases.values():
                if case["id"] == case_id:
                    return {**case}
            return None


class Sensor(threading.Thread):
    def __init__(self, hub: Hub, name: str) -> None:
        super().__init__(daemon=True)
        self.hub = hub
        self.name = name
        self.stop_event = threading.Event()

    def stop(self) -> None:
        self.stop_event.set()

    def run(self) -> None:
        raise NotImplementedError


class FileTail:
    def __init__(self, replay: bool = False) -> None:
        self.replay = replay
        self.offsets: dict[Path, int] = {}

    def read(self, path: Path) -> list[str]:
        try:
            size = path.stat().st_size
        except OSError:
            return []
        offset = self.offsets.get(path)
        if offset is None:
            offset = 0 if self.replay else size
        if size < offset:
            offset = 0
        if size == offset:
            return []
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                handle.seek(offset)
                lines = handle.readlines()
                self.offsets[path] = handle.tell()
                return [line.rstrip("\n") for line in lines if line.strip()]
        except OSError:
            return []


class ZeekSensor(Sensor):
    def __init__(self, hub: Hub, log_dir: str, replay: bool = False) -> None:
        super().__init__(hub, "zeek")
        self.log_dir = Path(log_dir)
        self.tail = FileTail(replay)
        self.hub.register_sensor("zeek", "waiting", f"JSON logs · {self.log_dir}")

    def normalize(self, obj: dict, path: Path) -> dict | None:
        stamp = parse_ts(obj.get("ts")) or now()
        log_name = str(obj.get("_path") or path.name.split(".")[0]).lower()
        uid = str(obj.get("uid") or "")
        ident = obj.get("id") or {}
        src_ip = str(ident.get("orig_h") or obj.get("src") or "")
        dst_ip = str(ident.get("resp_h") or obj.get("dst") or "")
        src_port = to_int(ident.get("orig_p"))
        dst_port = to_int(ident.get("resp_p"))
        proto = str(obj.get("proto") or "")
        service = str(obj.get("service") or "")
        severity = "info"
        if dst_port in OT_PORTS or src_port in OT_PORTS:
            severity = "medium"

        if log_name == "conn":
            message = f"{service or proto or 'flow'} {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
            return {
                "ts": stamp, "sensor": "zeek", "kind": "flow", "action": "connection",
                "host": src_ip, "src_ip": src_ip, "dst_ip": dst_ip,
                "src_port": src_port, "dst_port": dst_port, "proto": proto,
                "app": service or proto, "severity": severity,
                "bytes_in": to_int(obj.get("resp_bytes")),
                "bytes_out": to_int(obj.get("orig_bytes")),
                "message": message,
                "evidence": f"zeek:conn.log:{uid}" if uid else "zeek:conn.log",
            }
        if log_name == "dns":
            query = str(obj.get("query") or "")
            answers = obj.get("answers") or []
            if isinstance(answers, list):
                answers = ", ".join(str(answer) for answer in answers[:4])
            return {
                "ts": stamp, "sensor": "zeek", "kind": "dns", "action": "query",
                "host": src_ip, "src_ip": src_ip, "dst_ip": dst_ip,
                "domain": query, "app": "DNS",
                "message": f"DNS {query} -> {answers or obj.get('rcode_name', '')}",
                "evidence": f"zeek:dns.log:{uid}" if uid else "zeek:dns.log",
            }
        if log_name == "ssl":
            server = str(obj.get("server_name") or "")
            return {
                "ts": stamp, "sensor": "zeek", "kind": "tls", "action": "handshake",
                "host": src_ip, "src_ip": src_ip, "dst_ip": dst_ip,
                "src_port": src_port, "dst_port": dst_port,
                "domain": server, "app": "TLS", "proto": "tcp",
                "message": f"TLS {server or dst_ip} · {obj.get('ja3', '')}",
                "evidence": f"zeek:ssl.log:{uid}" if uid else "zeek:ssl.log",
            }
        if log_name == "http":
            host_header = str(obj.get("host") or "")
            return {
                "ts": stamp, "sensor": "zeek", "kind": "http", "action": "request",
                "host": src_ip, "src_ip": src_ip, "dst_ip": dst_ip,
                "src_port": src_port, "dst_port": dst_port,
                "domain": host_header, "app": "HTTP",
                "message": f"{obj.get('method', 'GET')} {host_header}{obj.get('uri', '')} · {obj.get('status_code', '')}",
                "evidence": f"zeek:http.log:{uid}" if uid else "zeek:http.log",
            }
        if log_name == "ssh":
            success = as_bool(obj.get("auth_success"))
            return {
                "ts": stamp, "sensor": "zeek", "kind": "auth", "action": "ssh",
                "host": src_ip, "src_ip": src_ip, "dst_ip": dst_ip,
                "src_port": src_port, "dst_port": dst_port,
                "result": "success" if success else "failure",
                "message": f"SSH {src_ip} -> {dst_ip} · {'success' if success else 'failure'}",
                "severity": "low" if success else "medium",
                "evidence": f"zeek:ssh.log:{uid}" if uid else "zeek:ssh.log",
            }
        if log_name in ("notice", "weird"):
            note = str(obj.get("note") or log_name)
            message = str(obj.get("msg") or note)
            return {
                "ts": stamp, "sensor": "zeek", "kind": "alert", "action": log_name,
                "host": src_ip, "src_ip": src_ip, "dst_ip": dst_ip,
                "severity": "high" if log_name == "notice" else "medium",
                "message": f"{note}: {message}"[:500],
                "evidence": f"zeek:{log_name}.log:{uid}" if uid else f"zeek:{log_name}.log",
            }
        if log_name in ("files", "smb_files"):
            name = str(obj.get("filename") or obj.get("name") or "")
            return {
                "ts": stamp, "sensor": "zeek", "kind": "file", "action": "observed",
                "host": str(obj.get("host") or src_ip), "src_ip": src_ip, "dst_ip": dst_ip,
                "domain": str(obj.get("server") or ""),
                "app": "SMB" if "smb" in log_name else "File transfer",
                "message": f"File metadata observed: {name or obj.get('mime_type', 'unknown')}",
                "evidence": f"zeek:{log_name}.log:{uid}" if uid else f"zeek:{log_name}.log",
            }
        return None

    def run(self) -> None:
        if not self.log_dir.exists():
            self.hub.set_sensor("zeek", "unavailable", "Log directory not found", str(self.log_dir))
            return
        self.hub.set_sensor("zeek", "online", f"JSON logs · {self.log_dir}")
        while not self.stop_event.is_set():
            count = 0
            for path in sorted(self.log_dir.glob("*.log")):
                for line in self.tail.read(path):
                    if not line.startswith("{"):
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    event = self.normalize(obj, path)
                    if event:
                        self.hub.ingest([event], "zeek")
                        count += 1
            if count:
                self.hub.set_sensor("zeek", "online", f"JSON logs · {self.log_dir}")
            elif not self.hub.sensors.get("zeek"):
                self.hub.set_sensor("zeek", "waiting", f"JSON logs · {self.log_dir}")
            self.stop_event.wait(1.5)


class OsquerySensor(Sensor):
    QUERY = (
        "SELECT p.pid AS pid, p.name AS name, p.path AS path, p.cmdline AS cmdline, "
        "u.username AS username, s.local_address AS local_address, s.local_port AS local_port, "
        "s.remote_address AS remote_address, s.remote_port AS remote_port, "
        "s.protocol AS protocol, s.state AS state "
        "FROM process_open_sockets s JOIN processes p ON p.pid = s.pid "
        "LEFT JOIN users u ON u.uid = p.uid WHERE s.remote_address != '';"
    )

    def __init__(self, hub: Hub, interval: int = 30, binary: str = "") -> None:
        super().__init__(hub, "osquery")
        self.interval = max(5, interval)
        self.binary = binary or shutil.which("osqueryi") or ""
        self.last_seen: dict[str, float] = {}
        self.host = socket.gethostname().split(".")[0]
        self.hub.register_sensor("osquery", "waiting", "Process/socket attribution")

    def normalize(self, row: dict, stamp: float) -> dict | None:
        remote = str(row.get("remote_address") or "")
        local = str(row.get("local_address") or "")
        if not remote:
            return None
        protocol = str(row.get("protocol") or "").lower()
        proto = "tcp" if protocol in ("6", "tcp") else "udp" if protocol in ("17", "udp") else protocol
        process = str(row.get("name") or "")
        pid = to_int(row.get("pid"))
        key = f"{pid}|{local}|{to_int(row.get('local_port'))}|{remote}|{to_int(row.get('remote_port'))}|{proto}"
        if stamp - self.last_seen.get(key, 0) < 300:
            return None
        self.last_seen[key] = stamp
        return {
            "ts": stamp, "sensor": "osquery", "kind": "process", "action": "socket",
            "user": str(row.get("username") or ""), "host": self.host,
            "src_ip": local, "src_port": to_int(row.get("local_port")),
            "dst_ip": remote, "dst_port": to_int(row.get("remote_port")),
            "proto": proto, "process": process, "pid": pid,
            "app": process,
            "message": f"{process or 'process'} -> {remote}:{to_int(row.get('remote_port'))} ({proto})",
            "evidence": f"osquery:pid={pid}",
        }

    def run(self) -> None:
        if not self.binary:
            self.hub.set_sensor("osquery", "unavailable", "osqueryi not installed", "Install osquery or pass --osqueryi")
            return
        self.hub.set_sensor("osquery", "online", f"process_open_sockets · {self.host}")
        while not self.stop_event.is_set():
            try:
                result = subprocess.run(
                    [self.binary, "--json", self.QUERY],
                    capture_output=True, text=True, timeout=20,
                )
                rows = json.loads(result.stdout or "[]")
                stamp = now()
                events = [event for row in rows if (event := self.normalize(row, stamp))]
                if events:
                    self.hub.ingest(events, "osquery")
                    self.hub.set_sensor("osquery", "online", f"{len(events)} sockets · {self.host}")
            except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
                self.hub.set_sensor("osquery", "error", "osquery query failed", str(exc)[:200])
            self.stop_event.wait(self.interval)


class WazuhSensor(Sensor):
    def __init__(self, hub: Hub, alerts_path: str, replay: bool = False) -> None:
        super().__init__(hub, "wazuh")
        self.path = Path(alerts_path)
        self.tail = FileTail(replay)
        self.hub.register_sensor("wazuh", "waiting", f"Alerts · {self.path}")

    def normalize(self, obj: dict) -> dict | None:
        rule = obj.get("rule") or {}
        agent = obj.get("agent") or {}
        data = obj.get("data") or {}
        win = data.get("win") or {}
        win_data = win.get("eventdata") or {}
        win_system = win.get("system") or {}
        stamp = parse_ts(obj.get("timestamp")) or now()
        level = to_int(rule.get("level"))
        severity = (
            "critical" if level >= 12 else "high" if level >= 10
            else "medium" if level >= 7 else "low" if level >= 4 else "info"
        )
        event_id = str(win_system.get("eventID") or win_data.get("eventID") or "")
        description = str(rule.get("description") or "")
        user = str(
            data.get("srcuser") or data.get("dstuser")
            or win_data.get("targetUserName") or win_data.get("subjectUserName") or ""
        )
        src_ip = str(data.get("srcip") or win_data.get("ipAddress") or "")
        host = str(agent.get("name") or agent.get("ip") or "")
        is_auth = event_id in ("4624", "4625") or "logon" in description.lower() or "authentication" in description.lower()
        result = ""
        if event_id == "4625" or re.search(r"fail|denied|invalid|error", description, re.IGNORECASE):
            result = "failure"
        elif event_id == "4624" or re.search(r"success|accepted", description, re.IGNORECASE):
            result = "success"
        if is_auth and result == "failure":
            severity = max_severity(severity, "medium")
        return {
            "ts": stamp, "sensor": "wazuh", "kind": "auth" if is_auth else "alert",
            "action": f"event-{event_id}" if event_id else "alert",
            "user": user, "host": host, "src_ip": src_ip,
            "result": result, "severity": severity,
            "message": description or f"Wazuh rule {rule.get('id', '')}",
            "evidence": f"wazuh:rule={rule.get('id', '')}",
        }

    def run(self) -> None:
        self.hub.set_sensor("wazuh", "waiting", f"Alerts · {self.path}")
        while not self.stop_event.is_set():
            if not self.path.exists():
                self.hub.set_sensor("wazuh", "waiting", f"Waiting for {self.path}")
                self.stop_event.wait(5)
                continue
            count = 0
            for line in self.tail.read(self.path):
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                event = self.normalize(obj)
                if event:
                    self.hub.ingest([event], "wazuh")
                    count += 1
            self.hub.set_sensor("wazuh", "online", f"Alerts · {self.path}")
            self.stop_event.wait(2)




def seed_inventory_demo(store: InventoryStore) -> None:
    stamp = now()

    def software(name, version, vendor="", source="", latest="", latest_source=""):
        return {
            "name": name, "version": version, "vendor": vendor, "source": source,
            "latest": latest, "latest_source": latest_source,
        }

    def patch(patch_id, title, installed_on="", severity="", source=""):
        return {
            "id": patch_id, "title": title, "installed_on": installed_on,
            "severity": severity, "source": source,
        }

    hosts = [
        {
            "id": "ws-priya", "hostname": "WS-PRIYA",
            "os_family": "windows", "os_name": "Windows 11 Pro", "os_version": "22631.4890",
            "kernel": "10.0.22631", "arch": "AMD64", "cpu": "Intel Core i7-1265U",
            "memory_bytes": 32 * 1024 ** 3, "disk_total": 512 * 1024 ** 3,
            "disk_used": 310 * 1024 ** 3, "ip_addresses": ["10.20.4.62"],
            "last_scan": stamp - 900, "reboot_pending": True, "scan_count": 4,
            "notes": ["Patch baseline applied", "Windows Update checked"],
            "software": [
                software("7-Zip", "23.01", "Igor Pavlov", "Registry", "24.09", "winget"),
                software("Google Chrome", "131.0.6778", "Google", "Registry", "132.0.6834", "winget"),
                software("OpenSSL", "3.0.15", "OpenSSL Project", "Registry", "3.0.16", "winget"),
                software("PowerShell", "7.4.6", "Microsoft", "Registry", "7.4.6", "winget"),
                software("Microsoft Teams", "24152.1", "Microsoft", "Registry", "24152.1", "winget"),
            ],
            "patches": {
                "installed": [patch("KB5049981", "Windows security update", "2025-01-14", "important", "Windows Update")],
                "available": [patch("KB5051987", "Windows security update", "", "important", "Windows Update")],
                "missing": [],
            },
        },
        {
            "id": "app-sap01", "hostname": "APP-SAP01",
            "os_family": "windows", "os_name": "Windows Server 2022", "os_version": "20348.3207",
            "kernel": "10.0.20348", "arch": "AMD64", "cpu": "Xeon Gold 6338",
            "memory_bytes": 64 * 1024 ** 3, "disk_total": 1024 * 1024 ** 3,
            "disk_used": 640 * 1024 ** 3, "ip_addresses": ["10.20.4.15"],
            "last_scan": stamp - 1800, "reboot_pending": False, "scan_count": 6,
            "notes": ["Critical SAP production host", "Patch baseline applied"],
            "software": [
                software("SAP GUI", "7.70", "SAP", "Registry", "7.70", "baseline"),
                software("OpenSSL", "3.0.14", "OpenSSL Project", "Registry", "3.0.16", "winget"),
                software("7-Zip", "24.09", "Igor Pavlov", "Registry", "24.09", "winget"),
                software("Java", "17.0.11", "Oracle", "Registry", "17.0.12", "winget"),
            ],
            "patches": {
                "installed": [
                    patch("KB5049981", "Windows security update", "2025-01-14", "important", "Windows Update"),
                    patch("KB5051987", "Windows security update", "2025-02-11", "important", "Windows Update"),
                ],
                "available": [],
                "missing": [],
            },
        },
        {
            "id": "mbp-design", "hostname": "MBP-DESIGN",
            "os_family": "macos", "os_name": "macOS Sequoia", "os_version": "15.2",
            "kernel": "Darwin 24.2.0", "arch": "arm64", "cpu": "Apple M3 Pro",
            "memory_bytes": 36 * 1024 ** 3, "disk_total": 1024 * 1024 ** 3,
            "disk_used": 454 * 1024 ** 3, "ip_addresses": ["10.20.4.71"],
            "last_scan": stamp - 2400, "reboot_pending": False, "scan_count": 3,
            "notes": ["macOS update available", "Homebrew inventory included"],
            "software": [
                software("Google Chrome", "131.0.6778", "Google", "Applications", "132.0.6834", "softwareupdate"),
                software("7-Zip", "24.09", "Igor Pavlov", "Homebrew", "24.09", "brew"),
                software("OpenSSL", "3.0.15", "OpenSSL Project", "Homebrew", "3.0.16", "brew"),
                software("Slack", "4.41.96", "Salesforce", "Applications", "4.41.96", "softwareupdate"),
            ],
            "patches": {
                "installed": [patch("macOS-15.2", "macOS Sequoia 15.2", "2025-01-20", "important", "InstallHistory")],
                "available": [patch("macOS-15.3", "macOS Sequoia 15.3", "", "important", "softwareupdate")],
                "missing": [],
            },
        },
        {
            "id": "linux-jump", "hostname": "LINUX-JUMP",
            "os_family": "linux", "os_name": "Ubuntu 24.04 LTS", "os_version": "24.04",
            "kernel": "6.8.0-51-generic", "arch": "x86_64", "cpu": "AMD EPYC 7B13",
            "memory_bytes": 16 * 1024 ** 3, "disk_total": 256 * 1024 ** 3,
            "disk_used": 88 * 1024 ** 3, "ip_addresses": ["10.20.4.12"],
            "last_scan": stamp - 1200, "reboot_pending": False, "scan_count": 5,
            "notes": ["Package-manager updates available"],
            "software": [
                software("OpenSSL", "3.0.13", "OpenSSL Project", "dpkg", "3.0.16", "apt"),
                software("Java", "17.0.11", "OpenJDK", "dpkg", "17.0.12", "apt"),
                software("nginx", "1.24.0", "nginx.org", "dpkg", "1.24.0", "apt"),
                software("OpenSSH", "9.6p1", "OpenBSD", "dpkg", "9.6p1", "apt"),
            ],
            "patches": {
                "installed": [],
                "available": [
                    patch("openssl", "OpenSSL package update", "", "important", "apt"),
                    patch("openjdk-17", "OpenJDK package update", "", "important", "apt"),
                ],
                "missing": [],
            },
        },
        {
            "id": "ot-historian", "hostname": "OT-HISTORIAN",
            "os_family": "linux", "os_name": "Red Hat Enterprise Linux 8.9", "os_version": "8.9",
            "kernel": "4.18.0-513", "arch": "x86_64", "cpu": "Xeon Silver 4210",
            "memory_bytes": 32 * 1024 ** 3, "disk_total": 512 * 1024 ** 3,
            "disk_used": 372 * 1024 ** 3, "ip_addresses": ["10.30.7.50"],
            "last_scan": stamp - 3000, "reboot_pending": True, "scan_count": 2,
            "notes": ["Critical OT historian", "Kernel update pending"],
            "software": [
                software("OpenSSL", "1.1.1k", "OpenSSL Project", "rpm", "3.0.16", "dnf"),
                software("Java", "8.0.392", "Oracle", "rpm", "17.0.12", "dnf"),
                software("nginx", "1.20.1", "nginx.org", "rpm", "1.20.1", "dnf"),
            ],
            "patches": {
                "installed": [],
                "available": [
                    patch("kernel", "Kernel security update", "", "critical", "dnf"),
                    patch("openssl", "OpenSSL package update", "", "critical", "dnf"),
                ],
                "missing": [],
            },
        },
    ]
    for host in hosts:
        store.upsert(host)


def seed_demo(hub: Hub) -> None:
    if not hub.assets.rows:
        hub.assets.rows = Assets(use_defaults=True).rows
    hub.inventory.assets = hub.assets
    stamp = now()
    events = []

    def add(offset: float, **kwargs) -> None:
        events.append({"ts": stamp + offset, **kwargs})

    for index, user in enumerate(["anita.rao", "rohit.mehta", "meera.iyer", "arjun.s", "priya.n", "svc.backup"]):
        add(-2400 + index * 30, sensor="wazuh", kind="auth", action="event-4625",
            user=user, host="WS-PRIYA", src_ip="45.77.12.34",
            result="failure", severity="medium", message="Windows logon failure (4625)")
    add(-2100, sensor="wazuh", kind="auth", action="event-4624",
        user="priya.n", host="WS-PRIYA", src_ip="45.33.32.156",
        result="success", severity="low", message="Windows logon success from a new external address")
    add(-1980, sensor="zeek", kind="flow", action="connection",
        host="10.20.4.62", src_ip="10.20.4.62", dst_ip="45.33.32.156",
        src_port=51544, dst_port=443, proto="tcp", app="TLS",
        bytes_in=4200, bytes_out=8800, message="TLS session to external update endpoint")
    add(-1970, sensor="osquery", kind="process", action="socket",
        user="priya.n", host="WS-PRIYA", src_ip="10.20.4.62", dst_ip="45.33.32.156",
        src_port=51544, dst_port=443, proto="tcp", process="powershell.exe",
        pid=7712, app="powershell.exe",
        message="powershell.exe opened an external TLS socket")
    add(-1890, sensor="zeek", kind="tls", action="handshake",
        host="10.20.4.62", src_ip="10.20.4.62", dst_ip="45.33.32.156",
        src_port=51544, dst_port=443, domain="update-check.example", app="TLS",
        message="TLS SNI update-check.example")
    add(-1800, sensor="zeek", kind="flow", action="connection",
        host="10.20.4.62", src_ip="10.20.4.62", dst_ip="10.20.4.15",
        src_port=51600, dst_port=443, proto="tcp", app="SAP",
        bytes_in=13000, bytes_out=4200, message="SAP S/4HANA session from a finance workstation")
    add(-600, sensor="zeek", kind="flow", action="connection",
        host="10.20.4.62", src_ip="10.20.4.62", dst_ip="10.20.4.30",
        src_port=51700, dst_port=445, proto="tcp", app="SMB",
        message="SMB session to file server")
    add(-540, sensor="zeek", kind="flow", action="connection",
        host="10.20.4.62", src_ip="10.20.4.62", dst_ip="10.20.4.40",
        src_port=51710, dst_port=445, proto="tcp", app="SMB",
        message="SMB session to backup server")
    add(-480, sensor="zeek", kind="flow", action="connection",
        host="10.20.4.62", src_ip="10.20.4.62", dst_ip="10.20.4.50",
        src_port=51720, dst_port=3389, proto="tcp", app="RDP",
        message="RDP session to an internal host")
    add(-300, sensor="zeek", kind="flow", action="connection",
        host="10.30.7.22", src_ip="10.30.7.22", dst_ip="10.30.7.40",
        src_port=52000, dst_port=502, proto="tcp", app="Modbus/TCP",
        message="Modbus/TCP session to PLC line 2")
    add(-120, sensor="zeek", kind="dns", action="query",
        host="10.20.4.62", src_ip="10.20.4.62", dst_ip="10.20.4.1",
        domain="update-check.example", app="DNS",
        message="DNS query update-check.example")

    hub.ingest(events, "demo")
    counts = Counter(event.get("sensor", "demo") for event in events)
    for name, count in counts.items():
        row = hub.sensors.setdefault(name, {
            "name": name, "status": "demo", "detail": "Synthetic demo event",
            "error": "", "events": 0, "lastEventAt": 0,
        })
        row["status"] = "demo"
        row["events"] += count
        row["lastEventAt"] = max(row["lastEventAt"], max(event["ts"] for event in events))
    hub.sensors.pop("demo", None)
    hub.set_sensor("zeek", "demo", "Synthetic Zeek flow, DNS and TLS events")
    hub.set_sensor("osquery", "demo", "Synthetic process-to-socket attribution")
    hub.set_sensor("wazuh", "demo", "Synthetic Windows 4624/4625 events")
    hub.set_sensor("ingest", "online", "HTTP ingest API ready")
    seed_inventory_demo(hub.inventory)
    hub.set_sensor("inventory", "demo", "Synthetic fleet inventory")


class Handler(BaseHTTPRequestHandler):
    server_version = "KavachSensorHub/1.0"

    def log_message(self, fmt: str, *args) -> None:
        return

    def _send(self, body: bytes, content_type: str, status: int = 200, headers: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if headers:
            for key, value in headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, value, status: int = 200) -> None:
        self._send(json.dumps(value, indent=2).encode(), "application/json", status)

    def _authorised(self) -> bool:
        token = getattr(self.server, "token", "")
        if not token:
            return True
        return self.headers.get("Authorization", "") == f"Bearer {token}"

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        query = parse_qs(parsed.query)
        hub: Hub = self.server.hub  # type: ignore[attr-defined]

        if path in ("/", "/sensors", "/sensors/"):
            self._send(UI.read_bytes(), "text/html; charset=utf-8")
            return
        if path == "/styles.css":
            self._send(STYLES.read_bytes(), "text/css; charset=utf-8")
            return
        if path == "/icon.svg":
            self._send(ICON.read_bytes(), "image/svg+xml")
            return
        if path == "/api/v1/health":
            self._json({"ok": True, "service": "kavach-sensor-hub", "readOnly": True})
            return
        if path == "/api/v1/snapshot":
            self._json(hub.snapshot())
            return
        if path == "/api/v1/events":
            limit = min(500, max(1, to_int(query.get("limit", ["100"])[0], 100)))
            with hub.lock:
                rows = list(hub.events)[-limit:][::-1]
            self._json({"events": rows})
            return
        if path == "/api/v1/cases":
            self._json({"cases": sorted(hub.cases.values(), key=lambda row: row["lastSeen"], reverse=True)[:100]})
            return
        if path.startswith("/api/v1/cases/"):
            case = hub.case_detail(path.rsplit("/", 1)[-1])
            if not case:
                self._json({"error": "case not found"}, 404)
            else:
                self._json(case)
            return
        if path == "/api/v1/inventory/summary":
            self._json({"summary": hub.inventory.summary(), "hosts": hub.inventory.host_rows()})
            return
        if path == "/api/v1/inventory/hosts":
            self._json({"hosts": hub.inventory.host_rows()})
            return
        if path.startswith("/api/v1/inventory/hosts/"):
            host = hub.inventory.hosts.get(path.rsplit("/", 1)[-1])
            if not host:
                self._json({"error": "host not found"}, 404)
            else:
                self._json(host)
            return
        if path == "/api/v1/inventory/software":
            self._json({"software": hub.inventory.software(query.get("q", [""])[0])})
            return
        if path == "/api/v1/inventory/patch-gaps":
            self._json({"gaps": hub.inventory.patch_gaps()})
            return
        if path == "/api/v1/inventory/export.csv":
            body = hub.inventory.csv_text().encode()
            self._send(body, "text/csv; charset=utf-8", headers={
                "Content-Disposition": "attachment; filename=kavach-inventory.csv",
            })
            return
        if path == "/api/v1/entities":
            self._json({
                "entities": hub.search_entities(
                    query.get("q", [""])[0],
                    query.get("type", [""])[0],
                    min(100, max(1, to_int(query.get("limit", ["20"])[0], 20))),
                ),
            })
            return
        if path == "/api/v1/entity":
            node_id = query.get("id", [""])[0]
            detail = hub.entity_detail(node_id)
            if not detail:
                self._json({"error": "entity not found"}, 404)
            else:
                self._json(detail)
            return
        self._json({"error": "not found"}, 404)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        hub: Hub = self.server.hub  # type: ignore[attr-defined]
        if path not in ("/api/v1/events", "/api/v1/demo", "/api/v1/inventory"):
            self._json({"error": "not found"}, 404)
            return
        if not self._authorised():
            self._json({"error": "unauthorised"}, 401)
            return
        length = to_int(self.headers.get("Content-Length"), 0)
        if length <= 0 or length > MAX_BODY:
            self._json({"error": "request body missing or too large"}, 413)
            return
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self._json({"error": "invalid JSON"}, 400)
            return
        if path == "/api/v1/demo":
            seed_demo(hub)
            self._json({"ok": True, "events": len(hub.events)})
            return
        if path == "/api/v1/inventory":
            host = payload.get("host") if isinstance(payload, dict) and isinstance(payload.get("host"), dict) else payload
            if not isinstance(host, dict):
                self._json({"error": "inventory snapshot must be an object"}, 400)
                return
            saved = hub.inventory.upsert(host)
            self._json({"ok": True, "host": saved["id"], "summary": hub.inventory.summary()})
            return
        raw_events = payload if isinstance(payload, list) else payload.get("events", [])
        if not isinstance(raw_events, list):
            self._json({"error": "events must be an array"}, 400)
            return
        count = hub.ingest(raw_events, str(payload.get("sensor") if isinstance(payload, dict) else "ingest") or "ingest")
        self._json({"ok": True, "ingested": count})


def main() -> None:
    parser = argparse.ArgumentParser(description="Kavach Sensor Hub — read-only triage")
    parser.add_argument("--host", default="127.0.0.1", help="bind host (default: localhost)")
    parser.add_argument("--port", type=int, default=8789, help="port (default: 8789)")
    parser.add_argument("--critical-assets", default="", help="JSON list of critical assets")
    parser.add_argument("--patch-baseline", default="", help="JSON software/patch baseline")
    parser.add_argument("--archive", default="", help="optional JSONL archive path")
    parser.add_argument("--zeek-dir", default="", help="Zeek JSON log directory")
    parser.add_argument("--zeek-replay", action="store_true", help="read existing Zeek logs")
    parser.add_argument("--osquery", action="store_true", help="enable osquery process/socket adapter")
    parser.add_argument("--osqueryi", default="", help="path to osqueryi")
    parser.add_argument("--osquery-interval", type=int, default=30, help="osquery poll seconds")
    parser.add_argument("--wazuh-alerts", default="", help="Wazuh alerts.json path")
    parser.add_argument("--wazuh-replay", action="store_true", help="read existing Wazuh alerts")
    parser.add_argument("--demo", action="store_true", help="load synthetic demo events")
    parser.add_argument("--token", default="", help="require Bearer token for POST requests")
    args = parser.parse_args()

    assets = Assets.from_file(args.critical_assets)
    baseline = Baseline.from_file(args.patch_baseline or None, use_defaults=args.demo)
    hub = Hub(assets, archive=args.archive or None, baseline=baseline)
    hub.register_sensor("ingest", "online", "HTTP ingest API ready")

    sensors: list[Sensor] = []
    if args.zeek_dir:
        sensors.append(ZeekSensor(hub, args.zeek_dir, args.zeek_replay))
    if args.osquery:
        sensors.append(OsquerySensor(hub, args.osquery_interval, args.osqueryi))
    if args.wazuh_alerts:
        sensors.append(WazuhSensor(hub, args.wazuh_alerts, args.wazuh_replay))
    for sensor in sensors:
        sensor.start()

    if args.demo:
        seed_demo(hub)

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.hub = hub  # type: ignore[attr-defined]
    server.token = args.token  # type: ignore[attr-defined]

    print("Kavach Sensor Hub")
    print(f"  dashboard : http://{args.host}:{args.port}/")
    print(f"  sensors   : {', '.join(sensor.name for sensor in sensors) or 'ingest only'}")
    print(f"  assets    : {len(hub.assets.list())}")
    print("  read-only triage · no payloads · no response actions")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping…")
    finally:
        for sensor in sensors:
            sensor.stop()
        server.server_close()


if __name__ == "__main__":
    main()
