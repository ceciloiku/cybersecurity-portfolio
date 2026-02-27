# Project 03 — Indicators of Compromise (IOCs)

> Defanged values are used where appropriate (e.g., `hxxp`, `[.]`) for safer sharing.

## External Network Indicators
- IP: `165.232.170.151` (HTTP/80) — observed external connectivity from `rundll32.exe`
- Domain: `ff[.]sillytechninja[.]io` — observed as a download source for ransomware payload (defanged)

## Suspicious Files / Payload Artifacts
- `ProjectFinancialSummary_Q3.pdf.hta` (HTA payload)
- `review.dat` (staged payload; later executed via `rundll32.exe`)
- `ransomboogey.exe` (ransomware payload name observed)
- `mimikatz_trunk.zip` (credential dumping tooling archive name observed)
- `mimikatz.exe` (credential dumping tool process name observed)
- `PowerView.ps1` (AD enumeration script name observed)
- `IT_Automation.ps1` (file name accessed on a remote share)

## Process / Execution Indicators
- Initial execution:
  - `mshta.exe` (execution of `.hta`)
- Staging / loader behavior:
  - `xcopy.exe` (file staging/copy)
  - `rundll32.exe` (payload execution)
- Privilege escalation signal:
  - `fodhelper.exe` (UAC bypass-associated binary)
- Remote execution / lateral movement signal:
  - `wsmprovhost.exe` (WinRM provider host observed as parent for activity)
- Living-off-the-land:
  - `powershell.exe` (including encoded command-line usage)
  - `whoami.exe` (discovery)

## Persistence Indicator
- Scheduled Task Name:
  - `Review`

## Command-Line / String Hunt Terms (for detection, not reproduction)
- `mshta` AND `.hta`
- `rundll32` AND `DllRegisterServer`
- `review.dat`
- `-enc` (PowerShell encoded command indicator)
- `mimikatz`
- `sekururlsa`
- `lsadump::dcsync`