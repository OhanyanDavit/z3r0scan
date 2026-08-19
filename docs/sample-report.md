# z3r0scan report — `scanme.nmap.org`

- **Duration:** 18.04s
- **Top severity:** INFO

## Severity summary

| Severity | Count |
| --- | --- |
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 0 |
| Info | 5 |

## host_scan  _(status: ok)_
> nmap

- **[INFO]** 22/tcp open — ssh
  - Open TCP port 22 (ssh) — OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
- **[INFO]** 80/tcp open — http
  - Open TCP port 80 (http) — Apache httpd 2.4.7 ((Ubuntu))
- **[INFO]** 443/tcp open — tcpwrapped
  - Open TCP port 443 (tcpwrapped)
- **[INFO]** 9929/tcp open — nping-echo
  - Open TCP port 9929 (nping-echo) — Nping echo

## web_probe  _(status: ok)_
> httpx

- **[INFO]** http://scanme.nmap.org [200] Go ahead and ScanMe!
  - Live web service. Tech: Apache HTTP Server:2.4.7, Ubuntu
