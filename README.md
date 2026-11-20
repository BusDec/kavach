# Kavach

Cybersecurity portfolio of [Nirmana ERP](https://nirmanaerp.com).

**Live:** https://kavach.nirmanaerp.com/

Kavach covers SAP security and controls, OT/IT convergence, cloud and identity, and incident readiness for asset-intensive enterprises.

## Pages

- `/` — portfolio overview: SAP, OT/IT, cloud identity and incident readiness
- `/business-case/` — C-suite business case: IT/OT risks, incident watch, the cost of waiting, privacy obligations across the US, Europe and India
- `/pilot/` — customer-connect and pilot request page
- `/privacy/` — privacy notice for the pilot form
- `/portfolio/` — handoff to the common Nirmana ERP portfolio page
- `/network/` — Network watch: metadata-only traffic dashboard for authorized networks
- `/access/` — Access watch: failed sign-ins, odd hours, geographies, host access and critical assets

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

## Critical assets

Both dashboards share a browser-local watchlist for exact IPs, CIDR ranges and
wildcard hostnames. It flags matching flows and access events locally; it is
never uploaded. The default examples are SAP, a PLC and an OT historian. Replace
them with the client's systems from the **Critical assets** panel on either page.

## Contact

Dr. Santosh K Behera · [pilot@nirmanaerp.com](mailto:pilot@nirmanaerp.com)

## Deploy

Static site on GitHub Pages. The custom domain is `kavach.nirmanaerp.com`; the `CNAME` file and Pages custom-domain setting must agree.
