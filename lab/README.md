# z3r0scan practice lab

A pair of intentionally-vulnerable web apps you can scan **legally and safely on
your own machine** — perfect for exercising z3r0scan's web scanning and the
nuclei-powered deep scan without touching anyone else's systems.

| App | URL | What it's good for |
| --- | --- | --- |
| [DVWA](https://github.com/digininja/DVWA) | http://localhost:8080 | Classic web vulns: SQLi, XSS, file upload, command injection |
| [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) | http://localhost:3000 | Modern SPA/API vulns, broad attack surface |

## Start

```bash
cd lab
docker compose up -d          # first run pulls the images (a few hundred MB)
```

Both apps bind to `127.0.0.1` only, so they are never reachable from the network.

## Scan them

```bash
# From the repo root, with your venv active:

# DVWA — full web + deep nuclei scan
z3r0scan http://localhost:8080 -y --modules web_probe,vuln_scan --html dvwa.html

# Juice Shop
z3r0scan http://localhost:3000 -y --modules web_probe,vuln_scan --html juice.html

# Or drive it from the dashboard
z3r0scan-web    # then open http://127.0.0.1:8000 and scan http://localhost:8080
```

> The `host_scan`/`subdomains`/`shodan` modules aren't useful against localhost,
> so the examples above select just `web_probe,vuln_scan`.

## Stop / clean up

```bash
docker compose down           # stop and remove the containers
```

## ⚠️ Reminder

These apps are deliberately insecure. Run them **only** locally, never on a
public IP or shared network.
