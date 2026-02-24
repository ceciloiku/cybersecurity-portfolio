# Indicators of Compromise (IOCs)

> Extracted from email artefacts, macro inspection, and Volatility 3 memory analysis.  
> Sensitive or reconstructable payload content is intentionally excluded.

## Domains
- `files.boogeymanisback.lol` (macro-referenced payload hosting)

## URLs (sanitized)
- `https://files.boogeymanisback.lol/<redacted>/update.png` (stage retrieval)

## IP Addresses
- `128.199.95.189` (observed C2 endpoint)

## Ports
- `8080` (observed C2 port)

## File Names
- `Resume_WesleyTaylor.doc` (malicious attachment)
- `update.png` (stage retrieval name)
- `update.js` (written to disk by macro)
- `updater.exe` (malicious process/binary)

## File Paths
- `C:\ProgramData\update.js` (script written/executed via wscript)
- `C:\Windows\Tasks\updater.exe` (malicious binary location)
- `C:\Users\<user>\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\<folder>\Resume_WesleyTaylor (002).doc` (attachment artefact path in memory)

## Hashes (attachment)
- MD5: `52c4384a0b9e248b95804352ebec6c5b`

## Hashes (if you keep the VT screenshot and want to include them)
- SHA-1: `4d8cde4cb18469a1e45f93a3b3dfedc8ea7e2ce8`
- SHA-256: `4db25ee3c46be38aa219fe2192711af65d55d5d7e25a889bb9990beb19f9b8b0`