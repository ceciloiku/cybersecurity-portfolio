# Project 05 — Indicators of Compromise (IOCs)

> Defanged values are used where appropriate.

## External IPs (suspicious)
- `40.80.148.42`
- `23.22.63.114`

## Internal Asset (victim)
- `192.168.250.70` (web server)

## Domains (defanged)
- `prankglassinebracket[.]jumpingcrab[.]com`

## URLs (defanged)
- `hxxp://prankglassinebracket[.]jumpingcrab[.]com:1337/poisonivy-is-coming-for-you-batman[.]jpeg`

## Web Paths / URIs of Interest
- `/joomla/administrator/index.php` (admin portal / login)
- `/joomla/agent.php` (suspicious)
- `/windows/win.ini` (recon/probing indicator)
- `/poisonivy-is-coming-for-you-batman.jpeg` (defacement-related artifact)

## Files
- `3791.exe`
- `agent.php`

## File Hashes
- MD5: `AAE3F5A29935E6ABCC2C2754D12A9AF0` (3791.exe)

## IDS / Exploit Indicators
- CVE: `CVE-2014-6271`
- Scanner indicator: `acunetix_wvs_security_test` (user-agent/payload artifact)
- Automation indicator: `Python-urllib/2.7` (user-agent)