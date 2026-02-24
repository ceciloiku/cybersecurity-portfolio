# Project 07 — Indicators of Compromise (IOCs)

> Defanged values are used where appropriate.

## Users / Accounts
- Possible homograph/impersonation account: `Ame1ia` (resembles “Amelia”)

## Persistence
- Scheduled task name: `OfficeUpdater`
- Scheduled task binary path (suspicious):
  - `C:\Users\Chris.fort\AppData\Local\Temp\update.exe`

## LOLBIN / Execution
- `schtasks.exe` (task creation / persistence)
- `certutil.exe` (payload retrieval)

## URLs (defanged)
- `hxxps://controlc[.]com/e4d11035`

## Files
- Downloaded payload name: `benign.exe`