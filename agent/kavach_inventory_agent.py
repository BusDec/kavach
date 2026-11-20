#!/usr/bin/env python3
"""Kavach inventory collector — read-only software and patch posture.

Collects the local machine's OS facts, installed applications/packages,
installed updates and available updates, then either prints the snapshot or
pushes it to a Kavach Sensor Hub.

It does not run active vulnerability scans, does not use Win32_Product and does
not install or remove software.

Examples:
    python3 agent/kavach_inventory_agent.py
    python3 agent/kavach_inventory_agent.py --check-updates
    python3 agent/kavach_inventory_agent.py --hub http://127.0.0.1:8789
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

COLLECTOR = "kavach-inventory/1.0"


def now() -> float:
    return time.time()


def run(command: list[str], timeout: int = 60) -> tuple[int, str, str]:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout, result.stderr
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, "", str(exc)


def run_powershell(script: str, timeout: int = 90):
    exe = shutil.which("powershell") or shutil.which("pwsh")
    if not exe:
        return None, "PowerShell not found"
    code, out, err = run([exe, "-NoProfile", "-NonInteractive", "-Command", script], timeout=timeout)
    if code != 0:
        return None, (err or out or "PowerShell failed").strip()[:300]
    text = out.strip()
    if not text:
        return None, "PowerShell returned no data"
    try:
        return json.loads(text), ""
    except json.JSONDecodeError:
        return None, "PowerShell returned non-JSON output"


def parse_json_output(text: str):
    text = (text or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def text_value(value) -> str:
    return str(value or "").strip()


def bytes_from_gb(value) -> int:
    try:
        return int(float(value) * 1024 ** 3)
    except (TypeError, ValueError):
        return 0


def read_os_release() -> dict:
    data = {}
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            data[key] = value.strip().strip('"')
    except OSError:
        pass
    return data


def ip_addresses(hostname: str) -> list[str]:
    values = set()
    try:
        for info in socket.getaddrinfo(hostname, None):
            address = info[4][0]
            if address and not address.startswith("::ffff:"):
                values.add(address)
    except OSError:
        pass
    values.discard("127.0.0.1")
    values.discard("::1")
    return sorted(values)


def memory_bytes() -> int:
    system = platform.system()
    if system == "Linux":
        try:
            for line in Path("/proc/meminfo").read_text().splitlines():
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) * 1024
        except OSError:
            pass
    if system == "Darwin":
        code, out, _ = run(["/usr/sbin/sysctl", "-n", "hw.memsize"], timeout=10)
        if code == 0 and out.strip().isdigit():
            return int(out.strip())
    if system == "Windows":
        class MemoryStatus(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]
        status = MemoryStatus()
        status.dwLength = ctypes.sizeof(MemoryStatus)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return int(status.ullTotalPhys)
    return 0


def uptime_seconds() -> int:
    system = platform.system()
    if system == "Linux":
        try:
            return int(float(Path("/proc/uptime").read_text().split()[0]))
        except (OSError, ValueError, IndexError):
            return 0
    if system == "Darwin":
        code, out, _ = run(["/usr/sbin/sysctl", "-n", "kern.boottime"], timeout=10)
        if code == 0:
            match = re.search(r"sec\s*=\s*(\d+)", out)
            if match:
                return max(0, int(time.time()) - int(match.group(1)))
    if system == "Windows":
        try:
            return int(ctypes.windll.kernel32.GetTickCount64() / 1000)
        except (AttributeError, OSError):
            pass
    return 0


def cpu_name() -> str:
    system = platform.system()
    if system == "Darwin":
        code, out, _ = run(["/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string"], timeout=10)
        if code == 0 and out.strip():
            return out.strip()
    if system == "Linux":
        try:
            for line in Path("/proc/cpuinfo").read_text().splitlines():
                if line.lower().startswith("model name"):
                    return line.split(":", 1)[1].strip()
        except OSError:
            pass
    if system == "Windows":
        return os.environ.get("PROCESSOR_IDENTIFIER", platform.processor() or "")
    return platform.processor() or ""


def disk_usage() -> tuple[int, int]:
    target = os.environ.get("SystemDrive", "C:") + "\\" if platform.system() == "Windows" else "/"
    try:
        usage = shutil.disk_usage(target)
        return usage.total, usage.used
    except OSError:
        return 0, 0


def host_facts() -> dict:
    system = platform.system()
    hostname = socket.gethostname()
    facts = {
        "id": re.sub(r"[^a-z0-9._-]+", "-", hostname.lower()).strip("-") or "host",
        "hostname": hostname,
        "collector": COLLECTOR,
        "last_scan": now(),
        "arch": platform.machine(),
        "ip_addresses": ip_addresses(hostname),
        "notes": [],
    }
    total, used = disk_usage()
    facts["disk_total"] = total
    facts["disk_used"] = used
    facts["memory_bytes"] = memory_bytes()
    facts["uptime_seconds"] = uptime_seconds()
    facts["cpu"] = cpu_name()

    if system == "Darwin":
        version, _, _ = platform.mac_ver()
        facts.update({
            "os_family": "macos",
            "os_name": "macOS",
            "os_version": version,
            "kernel": f"Darwin {platform.release()}",
        })
    elif system == "Windows":
        build = getattr(sys.getwindowsversion(), "build", 0)
        ubr = 0
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
                ubr = int(winreg.QueryValueEx(key, "UBR")[0])
                product = str(winreg.QueryValueEx(key, "ProductName")[0])
        except (OSError, ValueError, ImportError):
            product = platform.system()
        facts.update({
            "os_family": "windows",
            "os_name": product,
            "os_version": f"{build}.{ubr}" if ubr else str(build),
            "kernel": platform.version(),
        })
    else:
        release = read_os_release()
        facts.update({
            "os_family": "linux",
            "os_name": release.get("PRETTY_NAME") or release.get("NAME") or platform.system(),
            "os_version": release.get("VERSION_ID") or platform.release(),
            "kernel": platform.release(),
        })
    return facts


def software_item(name, version="", vendor="", source="", latest="", latest_source="", location="", install_date="") -> dict:
    return {
        "name": text_value(name),
        "version": text_value(version),
        "vendor": text_value(vendor),
        "source": text_value(source),
        "latest": text_value(latest),
        "latest_source": text_value(latest_source),
        "location": text_value(location),
        "install_date": text_value(install_date),
    }


def patch_item(patch_id, title="", installed_on="", severity="", source="") -> dict:
    return {
        "id": text_value(patch_id),
        "title": text_value(title) or text_value(patch_id),
        "installed_on": text_value(installed_on),
        "severity": text_value(severity),
        "source": text_value(source),
    }


def parse_mac_apps(data) -> list[dict]:
    if not isinstance(data, dict):
        return []
    rows = data.get("SPApplicationsDataType") or []
    if not isinstance(rows, list):
        return []
    seen = set()
    out = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = text_value(row.get("_name"))
        version = text_value(row.get("version"))
        if not name or (name.lower(), version) in seen:
            continue
        seen.add((name.lower(), version))
        vendor = text_value(row.get("info")) or text_value(row.get("obtained_from")) or "Application"
        out.append(software_item(
            name, version, vendor, "Applications",
            location=text_value(row.get("path")),
            install_date=text_value(row.get("lastModified")),
        ))
    return out[:5000]


def parse_mac_install_history(data) -> list[dict]:
    if not isinstance(data, dict):
        return []
    rows = data.get("SPInstallHistoryDataType") or []
    out = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = text_value(row.get("_name"))
        version = text_value(row.get("package_version"))
        if not name:
            continue
        out.append(patch_item(
            version or name, name, text_value(row.get("install_date")), "", "InstallHistory",
        ))
    return out[:1000]


def parse_brew_outdated(data) -> dict[str, str]:
    latest = {}
    if not isinstance(data, dict):
        return latest
    for row in data.get("formulae", []) or []:
        name = text_value(row.get("name"))
        current = text_value(row.get("current_version"))
        if name and current:
            latest[name.lower()] = current
    for row in data.get("casks", []) or []:
        name = text_value(row.get("token") or row.get("name"))
        current = text_value(row.get("current_version"))
        if name and current:
            latest[name.lower()] = current
    return latest


def macos_inventory(check_updates: bool) -> tuple[list[dict], dict, list[str]]:
    notes = []
    profiler = shutil.which("system_profiler") or "/usr/sbin/system_profiler"
    code, out, err = run([profiler, "-json", "SPApplicationsDataType"], timeout=90)
    software = parse_mac_apps(parse_json_output(out)) if code == 0 else []
    if not software:
        notes.append("Application inventory returned no data")
    if err and not software:
        notes.append(err.strip()[:200])

    brew = shutil.which("brew")
    if brew:
        code, out, _ = run([brew, "list", "--versions"], timeout=60)
        if code == 0:
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    software.append(software_item(parts[0], parts[-1], "Homebrew", "Homebrew"))
        code, out, _ = run([brew, "list", "--cask", "--versions"], timeout=60)
        if code == 0:
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    software.append(software_item(parts[0], parts[-1], "Homebrew Cask", "Homebrew"))
        code, out, _ = run([brew, "outdated", "--json=v2"], timeout=60)
        latest = parse_brew_outdated(parse_json_output(out)) if code == 0 else {}
        for item in software:
            target = latest.get(item["name"].lower())
            if target:
                item["latest"] = target
                item["latest_source"] = "brew"
    else:
        notes.append("Homebrew not installed; Homebrew inventory skipped")

    patches = {"installed": [], "available": [], "missing": []}
    code, out, _ = run([profiler, "-json", "SPInstallHistoryDataType"], timeout=60)
    if code == 0:
        patches["installed"] = parse_mac_install_history(parse_json_output(out))
    notes.append("macOS install history is a record of updates, not a complete patch catalogue")

    if check_updates:
        update_bin = shutil.which("softwareupdate") or "/usr/sbin/softwareupdate"
        code, out, err = run([update_bin, "-l"], timeout=120)
        if code == 0:
            current = {}
            for line in out.splitlines():
                stripped = line.strip()
                if stripped.startswith("* Label:"):
                    current = {"label": stripped.split(":", 1)[1].strip()}
                elif stripped.startswith("Title:") and current is not None:
                    current["title"] = stripped.split(":", 1)[1].strip()
                elif stripped.startswith("Size:") and current:
                    current["size"] = stripped.split(":", 1)[1].strip()
                elif stripped.startswith("Recommended:") and current:
                    current["recommended"] = stripped.split(":", 1)[1].strip()
                    patches["available"].append(patch_item(
                        current.get("label") or current.get("title", ""),
                        current.get("title", ""), "", "recommended" if current.get("recommended", "").lower() == "yes" else "", "softwareupdate",
                    ))
                    current = {}
        else:
            notes.append("softwareupdate check failed or requires network access")
    else:
        notes.append("Available macOS updates not checked; pass --check-updates")
    return software, patches, notes


def parse_dpkg(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        out.append(software_item(parts[0], parts[1], parts[2] if len(parts) > 2 else "", "dpkg"))
    return out


def parse_rpm(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        install_date = ""
        if len(parts) > 3 and parts[3].isdigit():
            install_date = datetime.fromtimestamp(int(parts[3]), tz=timezone.utc).strftime("%Y-%m-%d")
        out.append(software_item(parts[0], parts[1], parts[2] if len(parts) > 2 else "", "rpm", install_date=install_date))
    return out


def parse_apk(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        name = line.strip()
        if not name:
            continue
        match = re.match(r"(.+?)-(\d[^\s-]*(?:-r\d+)?)$", name)
        if match:
            out.append(software_item(match.group(1), match.group(2), "Alpine", "apk"))
        else:
            out.append(software_item(name, "", "Alpine", "apk"))
    return out


def parse_apt_upgradable(text: str) -> tuple[dict[str, str], list[dict]]:
    latest = {}
    patches = []
    for line in text.splitlines():
        if "/" not in line or "upgradable from" not in line:
            continue
        match = re.match(r"([^/]+)/\S+\s+(\S+)\s+\S+\s+\[upgradable from:\s*([^\]]+)\]", line)
        if not match:
            continue
        name, new_version, old_version = match.groups()
        latest[name.lower()] = new_version
        patches.append(patch_item(name, f"{name} {old_version} → {new_version}", "", "", "apt"))
    return latest, patches


def parse_dnf_updates(text: str) -> tuple[dict[str, str], list[dict]]:
    latest = {}
    patches = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2 or line.startswith("Last metadata"):
            continue
        name_arch = parts[0]
        if "." not in name_arch:
            continue
        name = name_arch.rsplit(".", 1)[0]
        latest[name.lower()] = parts[1]
        patches.append(patch_item(name, f"{name} update → {parts[1]}", "", "", "dnf"))
    return latest, patches


def linux_inventory(check_updates: bool) -> tuple[list[dict], dict, list[str], bool]:
    notes = []
    software = []
    if shutil.which("dpkg-query"):
        code, out, _ = run(["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Maintainer}\n"], timeout=60)
        if code == 0:
            software.extend(parse_dpkg(out))
    if shutil.which("rpm"):
        code, out, _ = run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\t%{INSTALLTIME}\n"], timeout=60)
        if code == 0:
            software.extend(parse_rpm(out))
    if shutil.which("apk"):
        code, out, _ = run(["apk", "info", "-v"], timeout=60)
        if code == 0:
            software.extend(parse_apk(out))
    if not software:
        notes.append("No supported package manager inventory found")

    patches = {"installed": [], "available": [], "missing": []}
    if check_updates:
        if shutil.which("apt"):
            code, out, _ = run(["apt", "list", "--upgradable"], timeout=90)
            if code == 0:
                latest, updates = parse_apt_upgradable(out)
                for item in software:
                    target = latest.get(item["name"].lower())
                    if target:
                        item["latest"] = target
                        item["latest_source"] = "apt"
                patches["available"].extend(updates)
        if shutil.which("dnf"):
            code, out, _ = run(["dnf", "-q", "check-update"], timeout=90)
            if code in (0, 100):
                latest, updates = parse_dnf_updates(out)
                for item in software:
                    target = latest.get(item["name"].lower())
                    if target:
                        item["latest"] = target
                        item["latest_source"] = "dnf"
                patches["available"].extend(updates)
    else:
        notes.append("Package updates not checked; pass --check-updates")

    reboot = Path("/var/run/reboot-required").exists() or Path("/run/reboot-required").exists()
    return software, patches, notes, reboot


def windows_inventory(check_updates: bool) -> tuple[list[dict], dict, list[str], bool]:
    notes = []
    software = []
    try:
        import winreg
    except ImportError:
        return [], {"installed": [], "available": [], "missing": []}, ["winreg unavailable"], False

    keys = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    seen = set()
    for root, path in keys:
        try:
            with winreg.OpenKey(root, path) as parent:
                for index in range(winreg.QueryInfoKey(parent)[0]):
                    try:
                        name = winreg.EnumKey(parent, index)
                        with winreg.OpenKey(parent, name) as child:
                            values = {}
                            for value_index in range(winreg.QueryInfoKey(child)[1]):
                                key_name, key_value, _ = winreg.EnumValue(child, value_index)
                                values[key_name] = key_value
                            display = text_value(values.get("DisplayName"))
                            version = text_value(values.get("DisplayVersion"))
                            if not display or (display.lower(), version) in seen:
                                continue
                            seen.add((display.lower(), version))
                            software.append(software_item(
                                display, version, text_value(values.get("Publisher")), "Registry",
                                location=text_value(values.get("InstallLocation")),
                                install_date=text_value(values.get("InstallDate")),
                            ))
                    except OSError:
                        continue
        except OSError:
            continue

    appx, error = run_powershell(
        "Get-AppxPackage | Select-Object Name,Version,Publisher,InstallLocation | ConvertTo-Json -Compress",
        timeout=60,
    )
    if isinstance(appx, dict):
        appx = [appx]
    if isinstance(appx, list):
        for row in appx:
            name = text_value(row.get("Name"))
            version = text_value(row.get("Version"))
            if name and (name.lower(), version) not in seen:
                seen.add((name.lower(), version))
                software.append(software_item(name, version, text_value(row.get("Publisher")), "Store", location=text_value(row.get("InstallLocation"))))
    elif error:
        notes.append(f"Store app inventory unavailable: {error}")

    hotfix, error = run_powershell(
        "Get-HotFix | Select-Object HotFixID,Description,InstalledOn | ConvertTo-Json -Compress",
        timeout=60,
    )
    installed = []
    if isinstance(hotfix, dict):
        hotfix = [hotfix]
    if isinstance(hotfix, list):
        for row in hotfix:
            installed.append(patch_item(text_value(row.get("HotFixID")), text_value(row.get("Description")), text_value(row.get("InstalledOn")), "", "Get-HotFix"))
    elif error:
        notes.append(f"Hotfix inventory unavailable: {error}")

    available = []
    if check_updates:
        script = (
            "$ErrorActionPreference='Stop';"
            "$s=New-Object -ComObject Microsoft.Update.Session;"
            "$q=$s.CreateUpdateSearcher();"
            "$r=$q.Search(\"IsInstalled=0 and Type='Software'\");"
            "@($r.Updates) | ForEach-Object { [pscustomobject]@{Title=$_.Title; KB=($_.KBArticleIDs -join ','); Severity=$_.MsrcSeverity; Downloaded=$_.IsDownloaded} } | ConvertTo-Json -Compress"
        )
        data, error = run_powershell(script, timeout=180)
        if isinstance(data, dict):
            data = [data]
        if isinstance(data, list):
            for row in data:
                title = text_value(row.get("Title"))
                available.append(patch_item(text_value(row.get("KB")) or title, title, "", text_value(row.get("Severity")), "Windows Update"))
        elif error:
            notes.append(f"Windows Update check failed: {error}")
    else:
        notes.append("Windows Update check skipped; pass --check-updates")

    reboot = False
    checks = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations"),
    ]
    for root, path in checks:
        try:
            with winreg.OpenKey(root, path):
                reboot = True
                break
        except OSError:
            continue
    return software, {"installed": installed, "available": available, "missing": []}, notes, reboot


def scan(check_updates: bool = False) -> dict:
    host = host_facts()
    system = platform.system()
    if system == "Darwin":
        software, patches, notes = macos_inventory(check_updates)
        reboot = False
    elif system == "Windows":
        software, patches, notes, reboot = windows_inventory(check_updates)
    else:
        result = linux_inventory(check_updates)
        if len(result) == 4:
            software, patches, notes, reboot = result
        else:
            software, patches, notes = result
            reboot = False
    host["software"] = software
    host["patches"] = patches
    host["reboot_pending"] = reboot
    host["notes"] = list(host.get("notes", [])) + notes
    host["scan_count"] = 1
    return host


def post_to_hub(hub: str, snapshot: dict, token: str = "") -> dict:
    url = hub.rstrip("/") + "/api/v1/inventory"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, data=json.dumps(snapshot).encode(), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:500]
        raise RuntimeError(f"hub returned HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"hub unreachable: {exc.reason}") from exc


def main() -> None:
    parser = argparse.ArgumentParser(description="Kavach inventory collector")
    parser.add_argument("--hub", default="", help="Sensor hub base URL, e.g. http://127.0.0.1:8789")
    parser.add_argument("--token", default="", help="Bearer token for the hub")
    parser.add_argument("--output", default="", help="write the snapshot JSON to a file")
    parser.add_argument("--check-updates", action="store_true", help="check available updates (slower, uses network)")
    parser.add_argument("--interval", type=int, default=0, help="repeat scan every N seconds")
    args = parser.parse_args()

    while True:
        snapshot = scan(args.check_updates)
        text = json.dumps(snapshot, indent=2)
        if args.output:
            Path(args.output).write_text(text + "\n")
            print(f"inventory written: {args.output}")
        if args.hub:
            try:
                result = post_to_hub(args.hub, snapshot, args.token)
                print(f"pushed {snapshot['hostname']}: {json.dumps(result)}")
            except RuntimeError as exc:
                print(str(exc), file=sys.stderr)
                if not args.interval:
                    sys.exit(1)
        elif not args.output:
            print(text)
        if args.interval <= 0:
            break
        time.sleep(max(10, args.interval))


if __name__ == "__main__":
    main()
