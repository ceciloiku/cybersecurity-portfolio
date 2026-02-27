# Project 04 — Indicators of Compromise (IOCs)

> Defanged values are used where appropriate.

## Internal Source (suspected)
- `192.166.65.54` (low-volume source IP observed communicating externally)

## Domains
- `pastebin[.]com`

## IP Addresses
- `104.23.99.190` (Pastebin destination observed in logs)

## URLs (defanged)
- `hxxp://pastebin[.]com/yTg0Ah6a`

## Network
- Destination port: `80/tcp`
- Methods observed: `HEAD`, `GET`
- User-Agent observed: `bitsadmin`

## Retrieved Resource / Artifact
- Paste title: `secret.txt`
- Observed content: `{SECRET_CODE}`