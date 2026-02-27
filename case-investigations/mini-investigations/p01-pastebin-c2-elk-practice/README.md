# Project 04 — Suspected Pastebin C2 Activity (ELK HTTP Connection Logs)

## Overview
An IDS alert suggested potential command-and-control (C2) style communications from a workstation associated with an HR user. Using HTTP connection logs indexed in ELK for March 2022, I pivoted from baseline traffic to an outlier source IP that made HTTP requests to Pastebin using a suspicious user-agent string. I then reviewed the referenced Pastebin resource to determine what content was retrieved.

> Note: This is a lab/synthetic dataset. Screenshots are included as evidence and may be lightly sanitized.

## Dataset
- IDS alert metadata (scenario context)
- HTTP connection logs ingested into ELK (March 2022)

## Investigation Steps and Findings

### 1) Establish baseline and identify outlier source IP
March 2022 contained **1,482** HTTP connection events. Reviewing the `source_ip` distribution surfaced two primary internal source IPs:
- `192.166.65.52` (high volume)
- `192.166.65.54` (very low volume)

The low-volume IP was treated as an anomaly worth pivoting into.

![Source IP distribution highlighting outlier](images/01-source-ip-outlier.png)

---

### 2) Pivot into suspicious source IP and validate destination
Filtering to `source_ip: 192.166.65.54` returned **two** HTTP events to:
- `host: pastebin.com`
- `destination_ip: 104.23.99.190`
- `destination_port: 80`
- `uri: /yTg0Ah6a`
- `user_agent: bitsadmin`

Pastebin is a legitimate paste service, but it is sometimes abused for staging or lightweight C2 signaling. The `bitsadmin` user-agent string (a Windows BITS administration utility) increases suspicion in this context.

![HTTP events to Pastebin with bitsadmin user-agent](images/02-pastebin-http-events.png)

---

### 3) Review retrieved content
The referenced Pastebin resource contained a file labeled `secret.txt`, with content resembling a token/placeholder value:

![Pastebin secret.txt content](images/03-pastebin-secret.txt.png)

---

## Key Takeaways
- An outlier source IP (`192.166.65.54`) made HTTP requests to Pastebin over port 80.
- Requests used the `bitsadmin` user-agent string and referenced a specific Paste ID (`/yTg0Ah6a`).
- The Pastebin content appeared to hold a token-like value (`{SECRET_CODE}`), consistent with lightweight signaling or staging behavior in lab scenarios.

## Detection Ideas
- Alert on outbound HTTP requests to paste sites (Pastebin/Gist-like) from endpoints that do not typically communicate with them.
- Flag unusual or rare user-agent strings (e.g., `bitsadmin`) making external web requests.
- Hunt for low-frequency “outlier” internal IPs that only appear a handful of times during an incident window.

## Indicators of Compromise
See: [iocs/iocs.md](iocs/iocs.md)