# IoCs / Artifacts — Sysmon EVTX Investigation Practice

## Network
- Destination IP: 10.0.2.18
- Destination port: 4443
- Related process: mshta.exe (observed in Sysmon network connect context)

## Files / Paths
- HTA payload (example path from event context):
  - `C:\Users\IEUser\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5\...\update.hta`
- User-delivered file (parent context):
  - `C:\Users\IEUser\Downloads\update.html`
- Staged payload storage (ADS-style):
  - `C:\Users\q\AppData:blah.txt`

## Processes / LOLBins observed
- `mshta.exe`
- `powershell.exe` (hidden execution / encoded content behavior)
- `schtasks.exe`
- `rundll32.exe` (example early signed binary in process creation)

## Registry Keys
- Payload storage (observed as registry value set):
  - `HKLM\SOFTWARE\Microsoft\Network\debug`
- Persistence (IFEO hijack):
  - `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe\Debugger`

## Persistence
- Scheduled task name: `Updater`
- Execution pattern: hidden PowerShell decoding stored content (from ADS) and executing it

## Credential Access Signal
- Sysmon Event ID 10 indicates access to:
  - `C:\Windows\System32\lsass.exe`

## USB Artifacts (Investigation-1 context)
- USB/WPD/USBSTOR-related registry paths showing device friendly name and enumeration