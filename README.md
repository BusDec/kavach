# Kavach

Cybersecurity portfolio of [Nirmana ERP](https://nirmanaerp.com).

**Live:** https://kavach.nirmanaerp.com/

Kavach covers SAP security and controls, OT/IT convergence, protection of critical assets, devices, resources and logins, cloud identity, and incident readiness for asset-intensive enterprises.

## Pages

- `/` — portfolio overview: SAP, OT/IT, protection, cloud identity and incident readiness
- `/business-case/` — C-suite business case: IT/OT risks, incident watch, the cost of waiting, privacy obligations across the US, Europe and India
- `/pilot/` — customer-connect and pilot request page
- `/privacy/` — privacy notice for the pilot form
- `/portfolio/` — handoff to the common Nirmana ERP portfolio page
- `/network/` — Network watch: metadata-only traffic dashboard for authorized networks
- `/access/` — Access watch: failed sign-ins, odd hours, geographies, host access and critical assets
- `/protect/` — Protection watch: critical assets, device posture, exposed resources, login risk and prioritised gaps

## Handouts

The `docs/` folder contains the downloadable board pack, generated from `docs-src/`:

- `Kavach-Board-Brief-2026.pdf` — 6 pages
- `Kavach-IT-OT-Business-Case.pdf` — 4 pages
- `Kavach-Privacy-Obligations.pdf` — 4 pages
- `Kavach-Incident-Response-Checklist.pdf` — 2 pages

Rebuild after editing the HTML sources:

```bash
cd docs-src
./build.sh
```

Requires Brave Browser for headless PDF printing.

## Preview

Open `index.html` locally, or serve the folder:

```bash
python3 -m http.server 8080
```

## Network watch

`/network/` is a synthetic demo of the traffic dashboard. It also accepts an
existing `.pcap` or `.pcapng` file from tcpdump, Wireshark, a SPAN/TAP or an
authorized Wi-Fi monitor. The import is parsed in the browser tab and never
uploaded; packets are aggregated into 5-tuple conversations before display.

The local capture agent in `agent/` turns the same dashboard into a live,
metadata-only view of one authorized interface:

```bash
sudo python3 agent/kavach_network_agent.py --interface en0
```

Open `http://127.0.0.1:8787/`. The agent reads packet headers with `tcpdump`;
it does not capture payloads, credentials or application content. See
`agent/README.md` for limits and authorization requirements.

To analyze traffic after the fact, capture to a file on the authorized host and
drop it into `/network/`:

```bash
sudo tcpdump -i en0 -s 96 -w kavach-capture.pcap
```

Nothing is uploaded. A synthetic file is available at
`network/samples/kavach-sample.pcap`.

### Windows packet capture

Windows 10/11 and Windows Server 2019+ include `pktmon`. Run PowerShell as
Administrator:

```powershell
pktmon start --capture --pkt-size 96 --file-name C:\temp\kavach.etl
# reproduce the activity, then:
pktmon stop
pktmon etl2pcap C:\temp\kavach.etl --out C:\temp\kavach.pcapng
```

Drop `kavach.pcapng` into `/network/`. To focus on a critical host, add a filter
before starting: `pktmon filter add -i 10.20.4.15`. Wireshark with Npcap works
too: `dumpcap -D` lists interfaces, then
`dumpcap -i 1 -s 96 -w C:\temp\kavach.pcapng`.

`pktmon` captures the Windows machine's own stack. Capturing other machines
requires a SPAN port, TAP or an authorized endpoint agent.

## Access watch

`/access/` analyzes a CSV or JSON export from Entra ID, Active Directory, SAP,
VPN/ZTNA, Linux or a SIEM. The file is parsed locally; timestamps use the
browser timezone. Required columns are `timestamp`, `user` and `result`; country,
latitude/longitude, target, application, MFA and privilege columns unlock the
other views.

The page includes failed sign-ins, success after failure, impossible travel,
off-hours access, new countries, host/application access, MFA and legacy-auth
posture, and critical-asset hits. A synthetic file is available at
`access/samples/kavach-access-sample.csv`.

## Protection watch

`/protect/` is a read-only protection register for critical assets, devices,
exposed resources and logins. It shows control coverage, missing controls,
device posture, internet-facing services, privileged and stale accounts,
prioritised gaps and owners.

The public page runs a synthetic register and accepts a JSON export from a CMDB,
EDR, vulnerability register, identity provider or the local collector. The file
is parsed in the browser tab and never uploaded. Unknown controls stay
unverified rather than being counted as protected.

Collect the current machine's posture with the read-only collector:

```bash
python3 agent/kavach_protection_agent.py \
  --asset-name "WS-PRIYA" \
  --criticality high \
  --owner "Operations" \
  --site "HQ" \
  --output protection.json
```

Then choose `protection.json` on `/protect/`. The collector checks patch state,
disk encryption, host firewall, EDR presence, local administrator membership and
listening services. It does not scan the network, exploit services or change the
machine. See `agent/README.md` for flags and limitations.

## Critical assets

Network and Access share a browser-local watchlist for exact IPs, CIDR ranges and
wildcard hostnames. It flags matching flows and access events locally; it is
never uploaded. The default examples are SAP, a PLC and an OT historian. Replace
them with the client's systems from the **Critical assets** panel on either page.

## Sensor hub

`agent/kavach_sensor_hub.py` is an optional local service for organisations
that already run open-source telemetry. It consumes Zeek JSON logs, osquery
process/socket data, Wazuh alerts and HTTP push, builds an entity graph, and
produces evidence-cited triage cases. It is read-only and takes no response
actions.

```bash
python3 agent/kavach_sensor_hub.py --demo
# or
python3 agent/kavach_sensor_hub.py \
  --zeek-dir /opt/zeek/logs/current \
  --osquery \
  --wazuh-alerts /var/ossec/logs/alerts/alerts.json \
  --critical-assets agent/critical-assets.example.json
```

Open `http://127.0.0.1:8789/`. See `agent/README.md` for the adapters, ingest
API and triage rules.

The hub includes a read-only **Inventory** section for software and patch
posture: installed applications and packages, installed updates, available
updates, baseline patch gaps, outdated software and critical-asset risk. A
local collector feeds it:

```bash
python3 agent/kavach_inventory_agent.py --hub http://127.0.0.1:8789
```

It reads Windows registry and hotfix data, macOS applications and Homebrew, or
Linux `dpkg`/`rpm`/`apk` packages. It never installs, removes or exploits
anything, and it avoids `Win32_Product`. Pass a baseline with
`--patch-baseline agent/patch-baseline.example.json` to compare against approved
minimum versions and required patch IDs.

## Contact

Dr. Santosh K Behera · [pilot@nirmanaerp.com](mailto:pilot@nirmanaerp.com)

## Deploy

Static site on GitHub Pages. The custom domain is `kavach.nirmanaerp.com`; the `CNAME` file and Pages custom-domain setting must agree.
