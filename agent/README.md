# Kavach Network watch — local capture agent

Metadata-only traffic observation for an authorized network. The agent uses
`tcpdump` to read packet headers on one interface, aggregates them into flows
and serves the same dashboard that lives at `/network/`.

**It does not capture payloads, credentials or application content.** It does
not modify, inject or block traffic.

## Requirements

- Python 3.10+
- `tcpdump` (macOS ships it at `/usr/sbin/tcpdump`)
- Root privileges for packet capture
- Written authorization to monitor the network and a lawful basis for any
  personal data in the metadata

## Run

From the Kavach repository:

```bash
sudo python3 agent/kavach_network_agent.py --interface en0
```

Then open:

```text
http://127.0.0.1:8787/
```

On macOS, confirm the Wi-Fi interface with
`networksetup -listallhardwareports`; it is often `en0` or `en1`. The agent sees
the traffic visible to that host. Capturing other devices requires a TAP, SPAN
or an authorized monitor-mode deployment; a browser page cannot do that.

Options:

```bash
--interface en0          # capture interface
--bpf "ip or ip6"        # tcpdump filter
--port 8787              # dashboard port
```

## Analyze an existing capture

You do not need the agent to inspect a file that already exists. Open
`/network/`, choose **Choose a capture**, and select a `.pcap` or `.pcapng`
from tcpdump, Wireshark, a SPAN/TAP or an authorized Wi-Fi monitor. The file is
parsed in the browser tab, aggregated into 5-tuple conversations, and never
uploaded. This works for classic pcap, pcapng, raw IP, Linux SLL, Ethernet and
802.11/radiotap captures.

To record a file on the host you are authorized to monitor:

```bash
sudo tcpdump -i en0 -s 96 -w kavach-capture.pcap
```

Stop with `Ctrl-C`, then drop the file into `/network/`.

## Windows packet capture

The Python agent uses `tcpdump`, which is not the normal Windows capture path.
Use the built-in `pktmon` instead, in an Administrator PowerShell:

```powershell
pktmon start --capture --pkt-size 96 --file-name C:\temp\kavach.etl
# reproduce the activity, then:
pktmon stop
pktmon etl2pcap C:\temp\kavach.etl --out C:\temp\kavach.pcapng
```

Drop `kavach.pcapng` into `/network/`. To restrict the capture, add a filter
before starting:

```powershell
pktmon filter add -i 10.20.4.15
pktmon filter add -p 443
```

`pktmon filter remove` clears filters. `pktmon` works on Windows 10/11 and
Windows Server 2019+. For a Wireshark/Npcap install, use
`dumpcap -D` to list interfaces and then
`dumpcap -i 1 -s 96 -w C:\temp\kavach.pcapng`.

A Windows capture sees only that machine's networking stack. For another
machine, run the capture on that endpoint, use a SPAN/TAP, or deploy an
authorized agent. The browser importer supports the resulting pcapng file.

To collect from several Windows endpoints with PowerShell Remoting:

```powershell
$hosts = @("WIN01", "WIN02")
Invoke-Command -ComputerName $hosts -ScriptBlock {
  $etl  = "$env:WINDIR\Temp\kavach.etl"
  $pcap = "$env:WINDIR\Temp\kavach.pcapng"
  pktmon start --capture --pkt-size 96 --file-name $etl
  Start-Sleep -Seconds 300
  pktmon stop
  pktmon etl2pcap $etl --out $pcap
}
foreach ($hostName in $hosts) {
  Copy-Item "\\$hostName\C$\Windows\Temp\kavach.pcapng" ".\$hostName.pcapng"
}
```

Use an account with the required WinRM and local administrator rights, and
capture only hosts you are authorized to monitor. Adjust the duration and
`pktmon filter` to keep the capture small.

## Sensor hub

The optional sensor hub runs beside the capture agent and turns open-source
telemetry into a shared entity graph and read-only triage cases:

```bash
python3 agent/kavach_sensor_hub.py --demo
```

Open `http://127.0.0.1:8789/`. The demo seeds synthetic Zeek, osquery and
Wazuh events and six triage cases.

For real telemetry:

```bash
python3 agent/kavach_sensor_hub.py \
  --zeek-dir /opt/zeek/logs/current \
  --osquery \
  --wazuh-alerts /var/ossec/logs/alerts/alerts.json \
  --critical-assets agent/critical-assets.example.json
```

Optional flags:

```text
--zeek-replay            read existing Zeek logs instead of tailing new lines
--osqueryi PATH          path to osqueryi
--osquery-interval 30    socket poll interval in seconds
--wazuh-replay           read existing Wazuh alerts
--patch-baseline PATH    approved software/patch baseline JSON
--archive PATH           append normalised events to a JSONL archive
--token TOKEN            require Bearer TOKEN for POST requests
--host 127.0.0.1         bind address; keep it local unless you have controls
--port 8789              dashboard and API port
```

Zeek must write JSON logs. On a standard Zeek install:

```zeek
@load policy/tuning/json-logs
```

The hub reads `conn`, `dns`, `ssl`, `http`, `ssh`, `notice`, `weird`, `files`
and `smb_files` logs. It never stores packet payloads.

osquery is queried for `process_open_sockets` joined to `processes` and `users`,
which gives the missing process/user attribution for a socket. Wazuh
`alerts.json` supplies Windows 4624/4625 and other endpoint alerts.

### Ingest API

Push normalised events from any sensor:

```bash
curl -X POST http://127.0.0.1:8789/api/v1/events \
  -H 'Content-Type: application/json' \
  -d '{"events":[{"ts":1773306600,"sensor":"custom","kind":"auth","user":"priya.n","host":"WS-PRIYA","src_ip":"45.33.32.156","result":"success","message":"Sign-in"}]}'
```

Useful read-only endpoints:

```text
GET  /api/v1/health
GET  /api/v1/snapshot
GET  /api/v1/events?limit=100
GET  /api/v1/cases
GET  /api/v1/entities?q=priya.n
GET  /api/v1/entity?id=user:priya.n
POST /api/v1/events
```

The hub binds to `127.0.0.1` by default. It does not take containment actions.
The triage rules cover critical-asset access, identity/network correlation,
suspicious process egress, authentication bursts, password spray and lateral
movement. Cases cite the events that produced them.

### Asset & patch watch

The hub also keeps a read-only software and patch inventory. It answers what is
installed, what is outdated, which baseline patches are missing and which hosts
are critical assets. It does not install, remove or exploit anything.

The demo seeds five synthetic hosts (Windows, macOS and Linux) with software,
installed hotfixes, available updates and baseline gaps. The **Inventory**
section shows the fleet, a host detail view, patch gaps and a fleet-wide software
search. `GET /api/v1/inventory/export.csv` downloads the same data as CSV.

To collect the machine running the hub:

```bash
python3 agent/kavach_inventory_agent.py --hub http://127.0.0.1:8789
```

The collector is read-only and metadata-only. It writes a snapshot locally or
posts it to `POST /api/v1/inventory`. Available-update checks are opt-in because
they are slower and use the network:

```bash
python3 agent/kavach_inventory_agent.py --check-updates --interval 3600 \
  --hub http://127.0.0.1:8789
```

Collectors by platform:

- **Windows:** registry uninstall keys (64-bit, 32-bit and per-user), Microsoft
  Store apps via `Get-AppxPackage`, installed hotfixes via `Get-HotFix`, Windows
  Update available updates through the Windows Update Agent COM API, pending
  reboot flags. It deliberately avoids `Win32_Product`.
- **macOS:** applications via `system_profiler SPApplicationsDataType`, Homebrew
  formulae and casks, `brew outdated`, install history and optional
  `softwareupdate -l`.
- **Linux:** `dpkg-query`, `rpm -qa`, `apk info`, optional `apt list
  --upgradable` and `dnf check-update`, plus `/var/run/reboot-required`.

Patch baselines are optional. Without one the hub can only report “an update is
available” from the local package manager. With one it can report approved
minimum versions, required patch IDs and minimum OS builds. Copy
`agent/patch-baseline.example.json` and pass it to the hub:

```bash
python3 agent/kavach_sensor_hub.py --demo \
  --patch-baseline agent/patch-baseline.example.json
```

```json
{
  "software": [
    { "name": "OpenSSL", "minimum_version": "3.0.16" },
    { "name": "7-Zip", "minimum_version": "24.09" }
  ],
  "required_patches": {
    "windows": ["KB5049981", "KB5051987"],
    "linux": []
  },
  "minimum_build": {
    "windows": "19045.5487",
    "macos": "15.3",
    "linux": ""
  }
}
```

Inventory endpoints:

```text
GET  /api/v1/inventory/summary
GET  /api/v1/inventory/hosts
GET  /api/v1/inventory/hosts/{id}
GET  /api/v1/inventory/software?q=openssl
GET  /api/v1/inventory/patch-gaps
GET  /api/v1/inventory/export.csv
POST /api/v1/inventory
```

A snapshot is a JSON object with host facts, `software`, `patches` and
`reboot_pending`. The hub adds baseline status, risk and scan counts. It matches
hostnames and IPs against the critical-asset list, so a critical host with a
patch gap is ranked first.

```bash
curl -X POST http://127.0.0.1:8789/api/v1/inventory \
  -H 'Content-Type: application/json' \
  -d '{"host":{"hostname":"LAB-01","os_family":"linux","os_name":"Ubuntu 24.04","os_version":"24.04","software":[{"name":"OpenSSL","version":"3.0.13"}],"patches":{"installed":[],"available":[],"missing":[]}}}'
```

Limits:

- Inventory is a point-in-time snapshot from the last collector run. Snapshots
  are held in memory; restarting the hub clears them until the collector runs
  again.
- “Latest” means the newest version the local package manager can see, not a
  vendor-approved enterprise baseline.
- The collector reports installed updates; it does not prove a patch was
  effective or that a host is vulnerability-free.
- CVE, EPSS, KEV and end-of-life enrichment are not included yet. Use OSV, CISA
  KEV, FIRST EPSS or vendor advisories as a separate, cached enrichment step.
- For fleets, prefer existing agents (Wazuh Syscollector, osquery, SCCM, Intune
  or WSUS) and post their inventory to the same endpoint rather than deploying
  a new agent on every host.

### Protection collector

`agent/kavach_protection_agent.py` produces a portable protection register for
`/protect/`. It combines the host facts and patch state from the inventory
collector with host posture that is collected locally:

```bash
python3 agent/kavach_protection_agent.py \
  --asset-name "WS-PRIYA" \
  --criticality high \
  --owner "Operations" \
  --site "HQ" \
  --output protection.json
```

It records:

- OS, hostname, owner, site, criticality and exposure supplied by the operator
- patch status from the installed software and package-manager state
- disk encryption (FileVault, BitLocker or LUKS), host firewall and EDR presence
- local administrator membership and the current collector user
- listening TCP services as **unverified** exposure candidates

The output matches the JSON register accepted by `/protect/`. It is read-only:
it does not scan the network, query remote hosts, exploit services or change
settings. `--check-updates` adds a package-manager update check; without it,
patch status is reported as unverified rather than assumed current.

Useful flags:

```text
--check-updates          compare installed packages with the local package manager
--asset-name NAME        display name; defaults to the hostname
--asset-id ID            stable id; defaults to a slug of the name
--criticality LEVEL      critical, high, medium or low
--owner TEAM             asset owner
--site SITE              site or location
--environment ENV        production, staging, lab, etc.
--exposure MODE          internet, partner, internal or air-gapped
--organization NAME      organisation label
--no-listeners           skip listening-service inventory
--no-logins              skip local administrator/current-user inventory
--output PATH            write the register JSON
```

Limitations:

- EDR detection is best effort: it looks for known endpoint security processes
  and does not prove coverage or policy health.
- Listener inventory shows what is bound locally. Internet exposure, NAT,
  firewall rules and upstream gateways are deliberately left unverified.
- Patch status without `--check-updates` is unknown. With it, “current” means
  the local package manager has no newer candidate, not that an enterprise
  baseline is satisfied.
- Local administrator enumeration may need elevation on Windows. The collector
  does not read password hashes, tokens or authentication secrets.
- The register is a point-in-time snapshot. Re-run the collector and re-import it
  to refresh the view.

Tests:

```bash
python3 -m unittest agent/test_sensor_hub.py agent/test_protection_agent.py -v
```

## What it classifies

- Direction: inbound, outbound or transit, relative to the local interface
- Host: remote IP, bytes in/out, applications and last seen
- Application: inferred from the destination or source port (SAP HTTPS, DNS,
  SSH, SMB, MQTT, Modbus/TCP, IEC 60870-5-104, BACnet, etc.)
- Protocol: TCP, UDP, ICMP, TLS, DNS or the OT protocol name
- Risk flags: cleartext protocol, OT protocol observed, unknown public host,
  transit traffic, new host

## Limits

- Port-based classification is a heuristic; it does not decrypt TLS or inspect
  application payloads.
- A switched Wi-Fi network does not deliver other clients' unicast traffic to
  this host. Use an authorized sensor, TAP or SPAN for network-wide visibility.
- The agent stores flows in memory only; restarting clears the view.
- The critical-asset watchlist is browser-local. It flags live metadata while
  the dashboard is open, but the agent does not persist the list or send alerts
  when no dashboard is connected.
- Do not run it on a network you do not own or have explicit permission to
  monitor. Follow the privacy rules that apply to you (for example DPDP, GDPR
  or US state law).
