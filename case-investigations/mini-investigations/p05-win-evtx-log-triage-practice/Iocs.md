# IoCs — Mini Investigation (merged.evtx)

## Host / Environment
- MachineName (log cleared event): `PC01.example.corp`
- MachineName (script block event): `DESKTOP-RIPCLIP`

## Key Event IDs
- 400 — PowerShell engine start
- 104 — System log cleared
- 4104 — PowerShell Script Block Logging
- 4799 — Local group membership enumeration

## Suspicious Events & Artifacts
### EID 104 — System log cleared
- TimeCreated: `2019-03-19 16:34:25`
- RecordId: `27736`
- Provider: `Microsoft-Windows-EventLog`

### EID 4104 — Script block (obfuscated)
- TimeCreated: `2020-08-25 22:09:28`
- ScriptBlock ID: `fdd51159-9602-40cb-839d-c31039ebbc3a`
- ProcessId: `6620`
- First variable observed: `$Va5w3n8`

### EID 4799 — Group enumeration
- Group: `Administrators`
- Group SID: `S-1-5-32-544`
- Process Name: `C:\Windows\System32\VSSVC.exe`

## Network Indicators
- Not extracted in this mini project (PowerShell script block is obfuscated in the available evidence).
- Recommended pivot: export ScriptBlockText and deobfuscate offline to recover URLs/domains.