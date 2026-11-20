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

## Contact

Dr. Santosh K Behera · [pilot@nirmanaerp.com](mailto:pilot@nirmanaerp.com)

## Deploy

Static site on GitHub Pages. The custom domain is `kavach.nirmanaerp.com`; the `CNAME` file and Pages custom-domain setting must agree.
