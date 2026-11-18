# Kavach

Cybersecurity portfolio of [Nirmana ERP](https://nirmanaerp.com).

**Live:** https://kavach.nirmanaerp.com/

Kavach covers SAP security and controls, OT/IT convergence, cloud and identity, and incident readiness for asset-intensive enterprises.

## Pages

- `/` — portfolio overview: SAP, OT/IT, cloud identity and incident readiness
- `/business-case/` — C-suite business case: IT/OT risks, incident watch, the cost of waiting, privacy obligations across the US, Europe and India
- `/pilot/` — customer-connect and pilot request page
- `/privacy/` — privacy notice for the pilot form

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

## Contact

Dr. Santosh K Behera · [pilot@nirmanaerp.com](mailto:pilot@nirmanaerp.com)

## Deploy

Static site on GitHub Pages. The custom domain is `kavach.nirmanaerp.com`; the `CNAME` file and Pages custom-domain setting must agree.
