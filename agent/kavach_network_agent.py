#!/usr/bin/env python3
"""Kavach Network watch — local, metadata-only capture agent.

Captures packet headers on one interface with tcpdump, aggregates them into
flows and serves the Kavach network dashboard at http://127.0.0.1:8787/.

It never reads or stores payloads, credentials or application content. Use it
only on networks you own or are explicitly authorized to monitor.

Run:
    sudo python3 agent/kavach_network_agent.py --interface en0

On macOS, en0 is usually Wi-Fi. Capturing other devices requires a TAP, SPAN or
an authorized monitor-mode deployment; a browser page cannot do that.
"""

from __future__ import annotations

import argparse
import json
import mimetypes
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import threading
import time
from collections import Counter, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

ROOT = Path(__file__).resolve().parent.parent
DASHBOARD = ROOT / "network" / "index.html"
AGENT_FILE = Path(__file__).resolve()

APP_PORTS = {
    443: "HTTPS/TLS",
    80: "HTTP",
    53: "DNS",
    853: "DNS over TLS",
    22: "SSH",
    445: "SMB",
    139: "NetBIOS",
    3389: "RDP",
    502: "Modbus/TCP",
    102: "IEC 60870-5-104",
    1883: "MQTT",
    8883: "MQTT/TLS",
    47808: "BACnet",
    161: "SNMP",
    123: "NTP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    25: "SMTP",
    587: "SMTP",
    993: "IMAPS",
    3478: "STUN/TURN",
    1900: "SSDP",
    5353: "mDNS",
    67: "DHCP",
    68: "DHCP",
    500: "IPsec",
    4500: "IPsec",
    1194: "OpenVPN",
    51820: "WireGuard",
    8080: "HTTP",
    8443: "HTTPS/TLS",
    623: "IPMI",
    20000: "DNP3",
    44818: "EtherNet/IP",
}

OT_PORTS = {102, 502, 1883, 8883, 20000, 44818, 47808}
CLEAR_PORTS = {21, 23, 80, 8080}
PRIVATE_RE = re.compile(
    r"^(10\.|127\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|fc|fd|fe80:|::1$)"
)


def now() -> float:
    return time.time()


def is_private_ip(value: str) -> bool:
    return bool(PRIVATE_RE.match(value or ""))


def local_addresses(interface: str) -> set[str]:
    addresses = {"127.0.0.1", "::1"}
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            addresses.add(info[4][0])
    except OSError:
        pass
    if shutil.which("ifconfig"):
        try:
            result = subprocess.run(
                ["ifconfig", interface], capture_output=True, text=True, timeout=3
            )
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("inet "):
                    addresses.add(line.split()[1])
                elif line.startswith("inet6 ") and " fe80:" not in line:
                    addresses.add(line.split()[1].split("%")[0])
        except (OSError, subprocess.SubprocessError):
            pass
    return addresses


def classify(port: int, protocol: str) -> tuple[str, str]:
    app = APP_PORTS.get(port, "Other")
    if protocol == "ICMP":
        return "ICMP", "ICMP"
    if port in OT_PORTS:
        return app, app
    if port == 443 or port == 8443:
        return app, "TLS"
    if port == 53 or port == 853:
        return app, "DNS"
    if port in (67, 68, 123, 161, 1900, 5353, 3478, 4500):
        return app, "UDP"
    if protocol == "UDP":
        return app, "UDP"
    return app, "TCP"


def endpoint(value: str, has_port: bool) -> tuple[str, int]:
    value = value.strip().rstrip(":")
    if not has_port:
        return value, 0
    if "." not in value:
        return value, 0
    host, port = value.rsplit(".", 1)
    try:
        return host, int(port)
    except ValueError:
        return value, 0


LINE_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s+(IP6?)\s+(.+?)\s+>\s+(.+)$")
LENGTH_RE = re.compile(r"length\s+(\d+)", re.IGNORECASE)


class TrafficState:
    def __init__(self, interface: str, bpf: str) -> None:
        self.interface = interface
        self.bpf = bpf
        self.local_ips = local_addresses(interface)
        self.local_name = socket.gethostname().split(".")[0] or "local"
        self.started_at = now()
        self.updated_at = now()
        self.status = "starting"
        self.error = ""
        self.lock = threading.Lock()
        self.packets = 0
        self.bytes_in = 0
        self.bytes_out = 0
        self.drops = 0
        self.series: dict[int, list[int]] = {}
        self.flows: deque[dict] = deque(maxlen=300)
        self.hosts: dict[str, dict] = {}
        self.protocols: Counter[str] = Counter()
        self.apps: dict[str, dict] = {}
        self.alerts: deque[dict] = deque(maxlen=40)
        self.seen: set[str] = set()
        self.last_alert: dict[str, float] = {}

    def alert(self, key: str, severity: str, title: str, detail: str) -> None:
        stamp = now()
        if stamp - self.last_alert.get(key, 0) < 60:
            return
        self.last_alert[key] = stamp
        self.alerts.appendleft(
            {"severity": severity, "title": title, "detail": detail, "time": stamp}
        )

    def add(self, src_ip: str, dst_ip: str, sport: int, dport: int, proto: str, size: int) -> None:
        if not src_ip or not dst_ip:
            return
        direction = "transit"
        if dst_ip in self.local_ips:
            direction = "inbound"
        elif src_ip in self.local_ips:
            direction = "outbound"

        remote_ip = src_ip if direction == "inbound" else dst_ip
        remote_name = remote_ip
        port = sport if direction == "inbound" else dport
        app, protocol = classify(port, proto)
        risk = "low"
        verdict = "normal"
        if port in CLEAR_PORTS:
            risk = "high"
            verdict = "cleartext"
        elif port in OT_PORTS:
            risk = "medium"
            verdict = "OT boundary"
        elif not is_private_ip(remote_ip):
            risk = "medium"
            verdict = "watch"
        if direction == "transit":
            risk = "high" if risk == "high" else "medium"
            verdict = "review"

        stamp = now()
        host_name = self.local_name if direction == "outbound" else remote_name
        dst_name = remote_name if direction == "outbound" else self.local_name
        flow = {
            "ts": stamp,
            "host": host_name,
            "src": src_ip if direction == "outbound" else remote_name,
            "srcIp": src_ip,
            "dst": dst_name,
            "dstIp": dst_ip,
            "vendor": "Local" if remote_ip in self.local_ips else ("Unknown" if not is_private_ip(remote_ip) else "LAN"),
            "app": app,
            "protocol": protocol,
            "port": port,
            "direction": direction,
            "bytes": size,
            "risk": risk,
            "verdict": verdict,
        }

        with self.lock:
            self.packets += 1
            self.updated_at = stamp
            if direction == "inbound":
                self.bytes_in += size
            elif direction == "outbound":
                self.bytes_out += size
            sec = int(stamp)
            bucket = self.series.setdefault(sec, [0, 0])
            if direction == "inbound":
                bucket[0] += size
            else:
                bucket[1] += size
            if len(self.series) > 180:
                cutoff = sec - 180
                for key in [k for k in self.series if k < cutoff]:
                    del self.series[key]

            if remote_ip and remote_ip not in self.local_ips:
                host = self.hosts.get(remote_ip)
                if host is None:
                    host = {
                        "ip": remote_ip,
                        "name": remote_name,
                        "vendor": flow["vendor"],
                        "bytesIn": 0,
                        "bytesOut": 0,
                        "apps": set(),
                        "lastSeen": stamp,
                        "risk": risk,
                    }
                    self.hosts[remote_ip] = host
                if direction == "inbound":
                    host["bytesIn"] += size
                else:
                    host["bytesOut"] += size
                host["apps"].add(app)
                host["lastSeen"] = stamp
                if risk == "high" or (risk == "medium" and host["risk"] == "low"):
                    host["risk"] = risk

                if remote_ip not in self.seen:
                    self.seen.add(remote_ip)
                    if not is_private_ip(remote_ip):
                        self.alert(
                            f"new:{remote_ip}",
                            "info",
                            "New host observed",
                            f"{remote_ip} appeared in the capture on {self.interface}.",
                        )

            self.protocols[protocol] += size
            record = self.apps.setdefault(app, {"bytes": 0, "flows": 0})
            record["bytes"] += size
            record["flows"] += 1
            self.flows.appendleft(flow)

            if port in CLEAR_PORTS:
                self.alert(f"clear:{remote_ip}:{port}", "critical", "Cleartext protocol", f"{app} traffic to {remote_ip}:{port} is unencrypted.")
            if port in OT_PORTS and direction == "outbound":
                self.alert(f"ot:{remote_ip}:{port}", "high", f"OT protocol observed · {app}", f"{self.local_name} reached {remote_ip} on port {port}.")
            if risk == "high" and verdict == "review":
                self.alert(f"review:{remote_ip}", "high", "Unusual flow", f"Transit traffic involving {remote_ip} needs review.")

    def snapshot(self) -> dict:
        with self.lock:
            stamp = now()
            sec = int(stamp)
            series = [
                {"in": self.series.get(i, [0, 0])[0], "out": self.series.get(i, [0, 0])[1]}
                for i in range(sec - 59, sec + 1)
            ]
            hosts = []
            for host in sorted(self.hosts.values(), key=lambda h: h["bytesIn"] + h["bytesOut"], reverse=True):
                hosts.append(
                    {
                        "ip": host["ip"],
                        "name": host["name"],
                        "vendor": host["vendor"],
                        "bytesIn": host["bytesIn"],
                        "bytesOut": host["bytesOut"],
                        "apps": sorted(host["apps"]),
                        "lastSeen": host["lastSeen"],
                        "risk": host["risk"],
                    }
                )
            return {
                "mode": "live",
                "interface": self.interface,
                "status": self.status,
                "error": self.error,
                "startedAt": self.started_at,
                "updatedAt": stamp,
                "stats": {
                    "packets": self.packets,
                    "flows": len(self.flows),
                    "drops": self.drops,
                    "hosts": len(self.hosts),
                    "bytesIn": self.bytes_in,
                    "bytesOut": self.bytes_out,
                },
                "series": series,
                "protocols": [{"name": k, "bytes": v} for k, v in self.protocols.most_common()],
                "apps": [{"name": k, **v} for k, v in sorted(self.apps.items(), key=lambda kv: kv[1]["bytes"], reverse=True)],
                "hosts": hosts,
                "flows": list(self.flows)[:80],
                "alerts": list(self.alerts)[:8],
            }


def parse_line(line: str) -> tuple[str, str, int, int, str, int] | None:
    """Return (src_ip, dst_ip, sport, dport, proto, size) from a tcpdump line."""
    match = LINE_RE.match(line)
    if not match:
        return None
    timestamp, family, src_raw, rest = match.groups()
    if ": " in rest:
        dst_raw, detail = rest.split(": ", 1)
    else:
        dst_raw, detail = rest.rstrip(":"), ""
    if "ICMP" in detail:
        proto = "ICMP"
        has_port = False
    elif "UDP" in detail:
        proto = "UDP"
        has_port = True
    else:
        proto = "TCP"
        has_port = True
    src_ip, sport = endpoint(src_raw, has_port)
    dst_ip, dport = endpoint(dst_raw, has_port)
    size_match = LENGTH_RE.search(detail)
    size = int(size_match.group(1)) if size_match else 0
    return src_ip, dst_ip, sport, dport, proto, size


class Capture(threading.Thread):
    def __init__(self, state: TrafficState) -> None:
        super().__init__(daemon=True)
        self.state = state
        self.process: subprocess.Popen | None = None

    def run(self) -> None:
        if os.geteuid() != 0:
            self.state.status = "error"
            self.state.error = "tcpdump requires root. Run: sudo python3 agent/kavach_network_agent.py --interface en0"
            print(self.state.error, file=sys.stderr)
            return
        tcpdump = shutil.which("tcpdump") or "/usr/sbin/tcpdump"
        if not Path(tcpdump).exists():
            self.state.status = "error"
            self.state.error = "tcpdump was not found on this host."
            print(self.state.error, file=sys.stderr)
            return
        command = [tcpdump, "-nn", "-tt", "-l", "-s", "96", "-i", self.state.interface]
        if self.state.bpf:
            command.extend(shlex.split(self.state.bpf))
        try:
            self.process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
        except OSError as exc:
            self.state.status = "error"
            self.state.error = str(exc)
            print(self.state.error, file=sys.stderr)
            return
        self.state.status = "capturing"
        assert self.process.stdout is not None
        for line in self.process.stdout:
            parsed = parse_line(line)
            if parsed:
                self.state.add(*parsed)
            if self.process.poll() is not None:
                break
        self.state.status = "stopped"
        if self.process.stderr is not None:
            error = self.process.stderr.read().strip()
            if error:
                self.state.error = error.splitlines()[-1][:240]
                print(f"tcpdump: {self.state.error}", file=sys.stderr)

    def stop(self) -> None:
        if self.process and self.process.poll() is None:
            self.process.terminate()


class Handler(BaseHTTPRequestHandler):
    server_version = "KavachNetworkWatch/1.0"

    def log_message(self, fmt: str, *args) -> None:
        return

    def _send(self, body: bytes, content_type: str, status: int = 200, extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if extra:
            for key, value in extra.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = unquote(urlparse(self.path).path)
        state = self.server.state  # type: ignore[attr-defined]
        if path == "/api/snapshot":
            self._send(json.dumps(state.snapshot()).encode(), "application/json")
            return
        if path == "/api/health":
            self._send(json.dumps({"ok": True, "mode": "live"}).encode(), "application/json")
            return
        if path == "/agent/kavach_network_agent.py":
            self._send(AGENT_FILE.read_bytes(), "text/x-python", extra={"Content-Disposition": "attachment; filename=kavach_network_agent.py"})
            return
        if path == "/agent/README.md":
            readme = ROOT / "agent" / "README.md"
            if readme.exists():
                self._send(readme.read_bytes(), "text/plain; charset=utf-8")
                return
        if path in ("/", "/network", "/network/"):
            self._send(DASHBOARD.read_bytes(), "text/html; charset=utf-8")
            return
        if path == "/styles.css":
            self._send((ROOT / "styles.css").read_bytes(), "text/css; charset=utf-8")
            return
        if path == "/icon.svg":
            self._send((ROOT / "icon.svg").read_bytes(), "image/svg+xml")
            return
        if path == "/network/app.js":
            self._send((ROOT / "network" / "app.js").read_bytes(), "text/javascript; charset=utf-8")
            return
        if path == "/favicon.ico":
            self._send(b"", "image/x-icon", status=204)
            return
        self._send(b"Not found", "text/plain", status=404)


def main() -> None:
    parser = argparse.ArgumentParser(description="Kavach Network watch local agent")
    parser.add_argument("--interface", default="en0", help="interface to capture (default: en0)")
    parser.add_argument("--bpf", default="ip or ip6", help="tcpdump filter (default: ip or ip6)")
    parser.add_argument("--port", type=int, default=8787, help="dashboard port (default: 8787)")
    args = parser.parse_args()

    state = TrafficState(args.interface, args.bpf)
    capture = Capture(state)
    capture.start()

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.state = state  # type: ignore[attr-defined]
    print("Kavach Network watch")
    print(f"  dashboard : http://127.0.0.1:{args.port}/")
    print(f"  interface : {args.interface}")
    print(f"  filter    : {args.bpf}")
    print(f"  local IPs : {', '.join(sorted(state.local_ips))}")
    print("  metadata only · no payloads · authorized networks only")
    if os.geteuid() != 0:
        print("  warning   : tcpdump needs root; run with sudo for live packets", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping…")
    finally:
        capture.stop()
        server.server_close()


if __name__ == "__main__":
    main()
