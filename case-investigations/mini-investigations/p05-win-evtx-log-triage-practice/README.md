# Mini Investigation — Windows Event Logs (merged.evtx)

## Summary
This mini project demonstrates basic investigation techniques using Windows Event Logs contained in a single EVTX file (`merged.evtx`). The focus was on identifying signs of defense evasion (log clearing), suspicious PowerShell activity (script block logging), and local security reconnaissance (group membership enumeration).

## Dataset
- `merged.evtx` — Windows Event Logs (merged collection)

## Tools & Method
- PowerShell `Get-WinEvent` with XPath filtering
- Focused validation using:
  - Event IDs (PowerShell / Security / System)
  - Timestamps (TimeCreated)
  - Host identifiers (MachineName)
  - Execution artifacts (ProcessId, ScriptBlock ID)

---

## Findings

### 1) PowerShell engine events (possible downgrade detection pivot) — Event ID 400
**Why this matters:** PowerShell engine start events can help identify suspicious PowerShell startup patterns. “Downgrade” investigations often pivot from engine start telemetry (then confirm engine version and host details in the full event fields).

**Evidence**
- `Get-WinEvent -Path .\merged.evtx -FilterXPath '*[System[EventID=400]]' -MaxEvents 5`

**Observed**
- Multiple EID 400 entries on **2020-12-18** (earliest visible around **07:48:42**).

![EID 400 PowerShell Engine Start](images/01-powershell-engine-start-eid400.png)

---

### 2) System log cleared — Event ID 104
**Why this matters:** Clearing logs is a classic defense-evasion technique to reduce forensic visibility.

**Evidence**
- `Get-WinEvent -Path .\merged.evtx -FilterXPath '*[System[EventID=104]]' | fl *`

**Observed**
- Event: **“The System log file was cleared.”**
- **TimeCreated:** 2019-03-19 16:34:25
- **RecordId:** 27736
- **MachineName:** PC01.example.corp

![EID 104 System Log Cleared](images/02-system-log-cleared-eid104-recordid-host.png)

---

### 3) Suspicious PowerShell script block (obfuscated) — Event ID 4104
**Why this matters:** Script Block Logging (EID 4104) can capture attacker tradecraft, including obfuscation, download cradles, and execution logic.

**Evidence**
- `Get-WinEvent -Path .\merged.evtx -FilterXPath '*[System[EventID=4104]]' -Oldest -MaxEvents 1 | Sort-Object TimeCreated | fl *`

**Observed**
- Earliest visible script block execution timestamp: **2020-08-25 22:09:28**
- The script is heavily **obfuscated** (string concatenation / hidden logic).
- **First variable name observed:** `$Va5w3n8`

![EID 4104 ScriptBlock (first variable)](images/03-powershell-scriptblock-eid4104-first-variable.png)

**Metadata observed (same event)**
- **ScriptBlock ID:** `fdd51159-9602-40cb-839d-c31039ebbc3a`
- **ProcessId:** 6620
- **MachineName:** DESKTOP-RIPCLIP

![EID 4104 ScriptBlock (metadata)](images/04-powershell-scriptblock-eid4104-metadata.png)

---

### 4) Local group membership enumeration (Administrators) — Event ID 4799
**Why this matters:** Enumerating privileged local groups is common during discovery/recon or privilege validation.

**Evidence**
- `Get-WinEvent -Path .\merged.evtx -FilterXPath '*[System[EventID=4799]]' -MaxEvents 3 | Select-Object -Skip 1 | fl`

**Observed**
- Event: **“A security-enabled local group membership was enumerated.”**
- Group: **Administrators**
- **Group SID:** `S-1-5-32-544`
- Process associated: `C:\Windows\System32\VSSVC.exe`

![EID 4799 Administrators group enumeration](images/05-group-membership-enumeration-eid4799-admins-sid.png)

---

## Conclusion
Across the merged log set, multiple suspicious indicators were identified:
- A confirmed **System log clearing event (EID 104)**, indicating potential defense evasion.
- A highly **obfuscated PowerShell script block (EID 4104)** with identifiable execution metadata (ScriptBlock ID, ProcessId, host).
- **Administrators group enumeration (EID 4799)** consistent with discovery activity.

This mini project demonstrates how to quickly pivot from event IDs to actionable investigation artifacts and document them as portfolio-ready evidence.

## Notes 
- Extract full 4104 script block text into a file and deobfuscate safely (offline) to recover any network indicators.
- Correlate ProcessId (6620) with other logs (4688, Sysmon EID 1 if available) to identify the parent process chain.