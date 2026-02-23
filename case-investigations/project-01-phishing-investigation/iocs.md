# Indicators of Compromise (IOCs)

> This IOC list was extracted from email artefacts, PowerShell script block logging, and PCAP analysis.  
> Note: Sensitive values (e.g., decoded secrets/credentials) are intentionally excluded from this public list.

## Domains
- `bpakcaging.xyz` (sender/infrastructure domain observed in the phishing email)
- `files.bpakcaging.xyz` (HTTP payload hosting observed in PCAP)
- `cdn.bpakcaging.xyz` (C2 / secondary hosting observed in PCAP; traffic seen on port 8080)

## IP Addresses
- `167.71.211.113` (HTTP server destination observed for downloads from `files.bpakcaging.xyz`)

## Network Indicators (HTTP)
**Observed paths/endpoints**
- `http://files.bpakcaging.xyz/update`
- `http://files.bpakcaging.xyz/sb.exe`
- `http://files.bpakcaging.xyz/sq3.exe`
- `http://cdn.bpakcaging.xyz:8080/` (POST-based C2 activity observed; specific endpoint IDs may vary)

## File Artefacts
**Delivered / staged**
- `Invoice.zip` (email attachment)

**Execution**
- `Invoice_20230103.lnk` (shortcut used to launch PowerShell)

**Downloaded**
- `sq3.exe`
- `sb.exe`
- `Invoke-Seatbelt.ps1` (referenced as downloaded tooling)

## Host Artefacts / Targeted Data
- `protected_data.kdbx` (KeePass database referenced in PowerShell activity)
- `plum.sqlite` (Windows Sticky Notes database file)
  - Typical path: `...\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`

## Execution / Command-line Pattern (High-level)
- `powershell.exe -nop -windowstyle hidden -enc <BASE64>` (encoded PowerShell execution via LNK)