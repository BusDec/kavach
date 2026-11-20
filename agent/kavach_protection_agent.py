#!/usr/bin/env python3
"""Kavach protection collector — read-only host posture.

Collects the local machine's protection posture into a portable JSON register:

- OS, owner, site and criticality supplied by the operator
- patch state from the Kavach inventory collector
- disk encryption, host firewall, EDR presence and local admin membership
- listening TCP services as unverified exposure candidates
- local administrator and current-user login records

It does not scan the network, query remote hosts, exploit services, install
software or change settings. Internet exposure of listeners is deliberately
left unverified; the dashboard should not assume a service is safe or exposed.

Examples:
    python3 agent/kavach_protection_agent.py
    python3 agent/kavach_protection_agent.py --asset-name WS-PRIYA --criticality high --output protection.json
    python3 agent/kavach_protection_agent.py --check-updates --output protection.json
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import kavach_inventory_agent as inventory  # noqa: E402

COLLECTOR = "kavach-protection/1.0"
EDR_SIGNATURES = (
    "falcon", "crowdstrike", "mdatp", "microsoft defender", "msmpeng",
    "sentinelone", "sentinelctl", "cbdefense", "carbonblack", "cylance",
    "sophos", "tanium", "trend micro", "tmccsf", "elastic-endpoint",
)


def text(value) -> str:
    return str(value or "").strip()


def slug(value: str) -> str:
    return re.sub(r"[^a-z0-9._-]+", "-", text(value).lower()).strip("-") or "host"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def run(command: list[str], timeout: int = 30) -> tuple[int, str, str]:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout, result.stderr
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, "", str(exc)


def disk_encryption() -> tuple[bool | None, str]:
    system = platform.system()
    if system == "Darwin":
        code, out, err = run(["/usr/bin/fdesetup", "status"], timeout=20)
        if code == 0:
            lowered = out.lower()
            if "filevault is on" in lowered:
                return True, "FileVault is on"
            if "filevault is off" in lowered:
                return False, "FileVault is off"
        return None, (err or out or "FileVault status unavailable").strip()[:200]

    if system == "Windows":
        script = (
            "$v=Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop;"
            "if($v.ProtectionStatus -eq 'On' -or $v.ProtectionStatus -eq 1){'true'}elseif($v.ProtectionStatus -eq 'Off' -or $v.ProtectionStatus -eq 0){'false'}else{'unknown'}"
        )
        data, error = inventory.run_powershell(script, timeout=45)
        if isinstance(data, bool):
            return data, "BitLocker protection is on" if data else "BitLocker protection is off"
        if isinstance(data, str):
            lowered = data.lower()
            if lowered == "true":
                return True, "BitLocker protection is on"
            if lowered == "false":
                return False, "BitLocker protection is off"
        code, out, err = run(["manage-bde", "-status", os.environ.get("SystemDrive", "C:") + "\\"], timeout=30)
        if code == 0:
            lowered = out.lower()
            if "protection on" in lowered:
                return True, "BitLocker protection is on"
            if "protection off" in lowered:
                return False, "BitLocker protection is off"
        return None, (error or err or "BitLocker status unavailable").strip()[:200]

    if shutil.which("lsblk"):
        code, out, err = run(["lsblk", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINT"], timeout=20)
        if code == 0:
            if "crypto_luks" in out.lower():
                return True, "LUKS volume present"
            return False, "No LUKS volume reported by lsblk"
        return None, (err or "lsblk failed").strip()[:200]
    return None, "No supported disk-encryption check available"


def firewall() -> tuple[bool | None, str]:
    system = platform.system()
    if system == "Darwin":
        code, out, err = run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"], timeout=20)
        if code == 0:
            lowered = out.lower()
            if "enabled" in lowered:
                return True, "Application firewall is enabled"
            if "disabled" in lowered:
                return False, "Application firewall is disabled"
        return None, (err or out or "Firewall status unavailable").strip()[:200]

    if system == "Windows":
        script = (
            "$p=Get-NetFirewallProfile -ErrorAction Stop;"
            "@($p)|ForEach-Object{ [pscustomobject]@{Name=$_.Name;Enabled=$_.Enabled} }|ConvertTo-Json -Compress"
        )
        data, error = inventory.run_powershell(script, timeout=30)
        if isinstance(data, dict):
            data = [data]
        if isinstance(data, list) and data:
            enabled = [str(row.get("Enabled")).strip().lower() in ("true", "1", "yes", "enabled") for row in data]
            if all(enabled):
                return True, "All firewall profiles enabled"
            if not any(enabled):
                return False, "All firewall profiles disabled"
            return None, "Firewall profiles are mixed"
        return None, (error or "Firewall status unavailable").strip()[:200]

    if shutil.which("ufw"):
        code, out, _ = run(["ufw", "status"], timeout=20)
        if code == 0:
            if "status: active" in out.lower():
                return True, "ufw is active"
            if "status: inactive" in out.lower():
                return False, "ufw is inactive"
    if shutil.which("firewall-cmd"):
        code, out, _ = run(["firewall-cmd", "--state"], timeout=20)
        if code == 0:
            return out.strip().lower() == "running", f"firewalld state: {out.strip()}"
    if shutil.which("nft"):
        code, out, _ = run(["nft", "list", "ruleset"], timeout=20)
        if code == 0:
            has_rules = bool(out.strip()) and "table" in out.lower()
            return has_rules, "nftables rules present" if has_rules else "nftables ruleset is empty"
    return None, "No supported firewall check available"


def process_names() -> tuple[list[str], str]:
    system = platform.system()
    if system == "Windows":
        script = "Get-Process | Select-Object -ExpandProperty ProcessName | ConvertTo-Json -Compress"
        data, error = inventory.run_powershell(script, timeout=30)
        if isinstance(data, str):
            return [data.lower()], ""
        if isinstance(data, list):
            return [text(row).lower() for row in data if text(row)], ""
        if error:
            return [], error
    code, out, err = run(["ps", "-axo", "comm="], timeout=20)
    if code == 0:
        return [line.strip().lower() for line in out.splitlines() if line.strip()], ""
    return [], (err or "ps failed").strip()[:200]


def edr_status() -> tuple[bool | None, str]:
    names, error = process_names()
    if not names:
        return None, error or "Process inventory unavailable"
    for name in names:
        for signature in EDR_SIGNATURES:
            if signature in name:
                return True, f"EDR process observed: {Path(name).name}"
    return False, "No known EDR process observed"


def admin_rights() -> tuple[bool | None, str]:
    system = platform.system()
    if system == "Darwin":
        code, out, err = run(["id", "-Gn"], timeout=10)
        if code == 0:
            groups = out.split()
            is_admin = "admin" in groups
            return is_admin, "Current user is in the macOS admin group" if is_admin else "Current user is not in the macOS admin group"
        return None, (err or "id failed").strip()[:200]
    if system == "Windows":
        script = (
            "$id=[Security.Principal.WindowsIdentity]::GetCurrent();"
            "$p=New-Object Security.Principal.WindowsPrincipal($id);"
            "if($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){'true'}else{'false'}"
        )
        data, error = inventory.run_powershell(script, timeout=20)
        if isinstance(data, bool):
            return data, "Current user is a local administrator" if data else "Current user is not a local administrator"
        if isinstance(data, str):
            lowered = data.lower()
            if lowered == "true":
                return True, "Current user is a local administrator"
            if lowered == "false":
                return False, "Current user is not a local administrator"
        return None, (error or "Admin check unavailable").strip()[:200]
    code, out, err = run(["id", "-nG"], timeout=10)
    if code == 0:
        groups = out.split()
        is_admin = bool({"sudo", "wheel"} & set(groups))
        return is_admin, "Current user is in sudo/wheel" if is_admin else "Current user is not in sudo/wheel"
    return None, (err or "id failed").strip()[:200]


def parse_lsof_listeners(output: str) -> list[dict]:
    rows = []
    seen = set()
    for line in output.splitlines():
        if not line.strip() or line.lower().startswith("command"):
            continue
        parts = line.split()
        if len(parts) < 9 or "(listen)" not in line.lower():
            continue
        command = parts[0]
        name = parts[-2] if parts[-1].upper() == "(LISTEN)" else parts[-1]
        match = re.match(r"^(.*):(\d+)$", name)
        if not match:
            continue
        address, port = match.group(1), int(match.group(2))
        if address.startswith("127.") or address in ("::1", "[::1]", "localhost"):
            continue
        key = (port, "tcp")
        if key in seen:
            continue
        seen.add(key)
        rows.append({"port": port, "proto": "tcp", "process": command, "address": address})
    return rows


def parse_ss_listeners(output: str) -> list[dict]:
    rows = []
    seen = set()
    for line in output.splitlines():
        if "LISTEN" not in line:
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[3]
        match = re.match(r"^(.*):(\d+)$", local)
        if not match:
            continue
        address, port = match.group(1), int(match.group(2))
        if address.startswith("127.") or address in ("::1", "[::1]", "localhost"):
            continue
        process = "unknown"
        proc_match = re.search(r'users:\(\("([^"]+)"', line)
        if proc_match:
            process = proc_match.group(1)
        key = (port, "tcp")
        if key in seen:
            continue
        seen.add(key)
        rows.append({"port": port, "proto": "tcp", "process": process, "address": address})
    return rows


def listening_services(limit: int = 50) -> tuple[list[dict], list[str]]:
    notes = []
    system = platform.system()
    rows = []
    if system == "Windows":
        script = (
            "Get-NetTCPConnection -State Listen -ErrorAction Stop | ForEach-Object {"
            "$p=Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue;"
            "[pscustomobject]@{Address=$_.LocalAddress;Port=$_.LocalPort;Process=$(if($p){$p.ProcessName}else{'unknown'})}"
            "} | ConvertTo-Json -Compress"
        )
        data, error = inventory.run_powershell(script, timeout=30)
        if isinstance(data, dict):
            data = [data]
        if isinstance(data, list):
            seen = set()
            for row in data:
                address = text(row.get("Address"))
                port = int(row.get("Port") or 0)
                if not port or address.startswith("127.") or address in ("::1", "[::1]", "localhost"):
                    continue
                key = (port, "tcp")
                if key in seen:
                    continue
                seen.add(key)
                rows.append({"port": port, "proto": "tcp", "process": text(row.get("Process")) or "unknown", "address": address})
        else:
            notes.append(f"Listening-service inventory unavailable: {error}")
    else:
        if shutil.which("ss"):
            code, out, err = run(["ss", "-ltnp"], timeout=20)
            if code == 0:
                rows = parse_ss_listeners(out)
            else:
                notes.append(f"ss failed: {err.strip()[:160]}")
        elif shutil.which("lsof"):
            code, out, err = run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"], timeout=20)
            if code == 0:
                rows = parse_lsof_listeners(out)
            else:
                notes.append(f"lsof failed: {err.strip()[:160]}")
        else:
            notes.append("No supported listener inventory tool found")
    rows = rows[:limit]
    if len(rows) == limit:
        notes.append(f"Listening services truncated at {limit} entries")
    return rows, notes


def local_admin_accounts() -> tuple[list[str], str]:
    system = platform.system()
    if system == "Darwin":
        code, out, err = run(["dscl", ".", "-read", "/Groups/admin", "GroupMembership"], timeout=20)
        if code == 0:
            value = out.split(":", 1)[1] if ":" in out else out
            return sorted({name for name in value.split() if name and name != "root"}), ""
        return [], (err or "dscl failed").strip()[:200]
    if system == "Windows":
        script = (
            "$g=Get-LocalGroupMember -Group Administrators -ErrorAction Stop;"
            "$g | Select-Object -ExpandProperty Name | ConvertTo-Json -Compress"
        )
        data, error = inventory.run_powershell(script, timeout=30)
        if isinstance(data, str):
            data = [data]
        if isinstance(data, list):
            names = []
            for value in data:
                name = text(value).split("\\")[-1]
                if name and name.lower() not in ("administrator",):
                    names.append(name)
            return sorted(set(names)), ""
        return [], (error or "Local administrators unavailable").strip()[:200]
    names = set()
    for group in ("sudo", "wheel"):
        code, out, _ = run(["getent", "group", group], timeout=10)
        if code == 0 and ":" in out:
            members = out.strip().split(":", 3)[-1]
            names.update(name for name in members.split(",") if name)
    return sorted(names), "" if names else "No sudo/wheel membership found"


def current_user() -> str:
    try:
        import getpass
        return getpass.getuser()
    except Exception:
        return text(os.environ.get("USER") or os.environ.get("USERNAME") or "unknown")


def build_snapshot(args) -> dict:
    host = inventory.host_facts()
    inventory_snapshot = inventory.scan(check_updates=bool(args.check_updates))
    notes = [f"Protection collector: {COLLECTOR}"]

    encrypted, encryption_evidence = disk_encryption()
    firewall_enabled, firewall_evidence = firewall()
    edr, edr_evidence = edr_status()
    is_admin, admin_evidence = admin_rights()

    available = (inventory_snapshot.get("patches") or {}).get("available") or []
    outdated_software = [item for item in inventory_snapshot.get("software", []) if item.get("status") == "outdated"]
    if available or outdated_software:
        patch_status = "outdated"
    elif args.check_updates and inventory_snapshot.get("software"):
        patch_status = "current"
    else:
        patch_status = "unknown"
        notes.append("Patch status is unverified; pass --check-updates to compare with the package manager.")

    hostname = text(args.asset_name) or text(host.get("hostname")) or socket.gethostname()
    asset_id = slug(args.asset_id or hostname)
    owner = text(args.owner) or current_user()
    site = text(args.site) or "Unspecified"
    asset_type = "Workstation" if platform.system() == "Darwin" else "Server" if platform.system() == "Linux" else "Windows host"

    controls = {
        "mfa": None,
        "logging": None,
        "backup": None,
        "segmentation": None,
        "edr": edr,
        "patching": True if patch_status == "current" else False if patch_status == "outdated" else None,
        "encryption": encrypted,
        "least_privilege": True if is_admin is False else False if is_admin is True else None,
    }

    asset = {
        "id": asset_id,
        "name": hostname,
        "category": "device",
        "type": asset_type,
        "criticality": args.criticality,
        "owner": owner,
        "site": site,
        "environment": args.environment,
        "exposure": args.exposure,
        "controls": controls,
        "evidence": f"Read-only local collection on {now_iso()}: {encryption_evidence}; {firewall_evidence}; {edr_evidence}; {admin_evidence}",
        "last_verified": now_iso(),
        "notes": "; ".join(notes),
    }

    device = {
        "id": asset_id,
        "asset_id": asset_id,
        "hostname": hostname,
        "os": text(inventory_snapshot.get("os_name")) or platform.system(),
        "os_version": text(inventory_snapshot.get("os_version")) or platform.release(),
        "owner": owner,
        "site": site,
        "criticality": args.criticality,
        "patch_status": patch_status,
        "edr": edr,
        "disk_encryption": encrypted,
        "firewall": firewall_enabled,
        "admin_rights": is_admin,
        "last_seen": now_iso(),
    }

    resources = []
    if not args.no_listeners:
        listeners, listener_notes = listening_services()
        notes.extend(listener_notes)
        for row in listeners:
            resources.append({
                "id": f"listener-{row['port']}-{row['proto']}",
                "asset_id": asset_id,
                "name": f"{row['proto'].upper()}/{row['port']} ({row['process']})",
                "type": "Host listener",
                "internet_facing": None,
                "auth": "Unknown",
                "encryption": "Unknown",
                "exposure_path": f"Local listener on {row['address']}; external exposure not verified",
                "criticality": "medium",
                "owner": owner,
            })
    else:
        notes.append("Listening-service inventory skipped")

    logins = []
    if not args.no_logins:
        admins, admin_error = local_admin_accounts()
        if admin_error:
            notes.append(admin_error)
        for account in admins:
            logins.append({
                "account": account,
                "display_name": account,
                "type": "privileged",
                "mfa": None,
                "last_login": "",
                "stale_days": None,
                "failed_24h": None,
                "assets": [asset_id],
                "notes": "Local administrator group; MFA and last login not collected",
            })
        user = current_user()
        if user and not any(row["account"] == user for row in logins):
            logins.append({
                "account": user,
                "display_name": user,
                "type": "human",
                "mfa": None,
                "last_login": "",
                "stale_days": None,
                "failed_24h": None,
                "assets": [asset_id],
                "notes": "Current collector user; MFA and failure history not collected",
            })
    else:
        notes.append("Local login inventory skipped")

    if edr is None:
        notes.append("EDR detection is best effort and could not be verified")
    if encrypted is None:
        notes.append("Disk-encryption state could not be verified")
    if firewall_enabled is None:
        notes.append("Firewall state could not be verified")
    notes.append("Listener internet exposure is not verified; treat it as unknown, not safe.")

    return {
        "schema": "kavach.protection.v1",
        "generated_at": now_iso(),
        "organization": text(args.organization) or "Local host",
        "collector": COLLECTOR,
        "assets": [asset],
        "devices": [device],
        "resources": resources,
        "logins": logins,
        "gaps": [],
        "notes": list(dict.fromkeys(notes)),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Kavach read-only protection posture collector")
    parser.add_argument("--output", default="", help="write the register JSON to a file")
    parser.add_argument("--asset-id", default="", help="stable asset id (default: hostname slug)")
    parser.add_argument("--asset-name", default="", help="display name (default: hostname)")
    parser.add_argument("--criticality", choices=["critical", "high", "medium", "low"], default="medium")
    parser.add_argument("--owner", default="", help="asset owner or team")
    parser.add_argument("--site", default="", help="site or location")
    parser.add_argument("--environment", default="production", help="production, staging, lab, etc.")
    parser.add_argument("--exposure", choices=["internet", "partner", "internal", "air-gapped"], default="internal")
    parser.add_argument("--organization", default="", help="organization label")
    parser.add_argument("--check-updates", action="store_true", help="compare installed packages with the local package manager (slower)")
    parser.add_argument("--no-listeners", action="store_true", help="skip listening-service inventory")
    parser.add_argument("--no-logins", action="store_true", help="skip local administrator and current-user inventory")
    args = parser.parse_args()

    snapshot = build_snapshot(args)
    body = json.dumps(snapshot, indent=2) + "\n"
    if args.output:
        Path(args.output).write_text(body)
        print(f"protection register written: {args.output}", file=sys.stderr)
        print(f"assets={len(snapshot['assets'])} devices={len(snapshot['devices'])} resources={len(snapshot['resources'])} logins={len(snapshot['logins'])}", file=sys.stderr)
    else:
        print(body, end="")


if __name__ == "__main__":
    main()
