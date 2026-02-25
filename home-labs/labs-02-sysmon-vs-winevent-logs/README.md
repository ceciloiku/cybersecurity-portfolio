# Sysmon vs Windows Event Logs — Validation Lab (Process, Network, File, Registry, PowerShell)

## Objective
Validate that the **same endpoint activity** is recorded across:
- **Sysmon** (Microsoft-Windows-Sysmon/Operational)
- **Windows Security log** (native auditing)
- **PowerShell Operational log** (script block logging)

## Data Sources
- Sysmon Operational: Event IDs **1, 3, 11, 13**
- Security log: Event IDs **4688, 4657**
- PowerShell Operational: Event ID **4104**

## Method
I generated several endpoint actions, then confirmed they appeared in the corresponding logs using Event Viewer and PowerShell (`Get-WinEvent`).

Actions tested:
- Process creation (Notepad)
- Child process + command line (cmd → `ipconfig /all`)
- Network connection (PowerShell → 1.1.1.1:443)
- File creation (`test.txt`)
- Registry create/set/modify (`HKCU:\Software\MVP2Key\MVP2_RegTest`)
- PowerShell ScriptBlock logging (4104)

---

## Findings

### 1) Process Creation — Notepad
**Sysmon EID 1** captured rich process creation details (image path, command line, parent process, hashes).

![Sysmon EID 1 - Notepad process creation](images/01-sysmon-eid1-notepad.png)

**Security EID 4688** recorded the corresponding native audit event (“A new process has been created.”) with process details.

![Security 4688 - Notepad process creation](images/02-security-4688-notepad.png)

---

### 2) Child Process + Command Line — cmd → `ipconfig /all`
**Sysmon EID 1** captured `ipconfig.exe` including the command line and parent (`cmd.exe`).

![Sysmon EID 1 - ipconfig /all with parent cmd.exe](images/03-sysmon-eid1-ipconfig.png)

**Security EID 4688** recorded the same process creation with the command line.

![Security 4688 - ipconfig /all](images/04-security-4688-ipconfig.png)

---

### 3) Network Connection — PowerShell → 1.1.1.1:443
A connectivity test was generated, then validated in Sysmon.

**Sysmon EID 3** captured:
- Process: `powershell.exe`
- Destination: `1.1.1.1`
- Port: `443/tcp`
- Destination hostname: `one.one.one.one`

![Sysmon EID 3 - PowerShell network connection to 1.1.1.1:443](images/05a-sysmon-eid3-network-443.png)

---

### 4) File Creation — `test.txt`
**Sysmon EID 11** captured the creation of `test.txt` with the creating process (`powershell.exe`) and the target file path.

![Sysmon EID 11 - test.txt file creation](images/06-sysmon-eid11-file-create-testtxt.png)

---

### 5) Registry Creation / Modification — `HKCU:\Software\MVP2Key\MVP2_RegTest`
**Sysmon EID 13** captured a registry value set event for `MVP2_RegTest`.

![Sysmon EID 13 - Registry value set](images/07-sysmon-eid13-registry-set.png)

**Security EID 4657** recorded the corresponding registry value modification, including **old vs new** value.

![Security 4657 - Registry modification with old/new value](images/08-security-4657-registry-modify.png)

---

### 6) PowerShell Script Visibility — Script Block Logging
**PowerShell Operational EID 4104** captured ScriptBlockText (visibility into what PowerShell executed).

![PowerShell 4104 - ScriptBlockText](images/09-powershell-4104-scriptblock.png)

---

## Key Takeaway
- **Sysmon** provides richer investigative detail (process lineage, command line, network metadata, and more).
- **Security** logs provide native audit proof (4688 for process creation, 4657 for registry changes).
- **PowerShell 4104** adds crucial context: **what PowerShell actually executed**.

## Detection Ideas (practical)
- Correlate **Sysmon EID 1** with **Security 4688** to validate process creation coverage.
- Alert on PowerShell making outbound connections (**Sysmon EID 3**) to unexpected external IPs/ports.
- Monitor “new file created by PowerShell” patterns (**Sysmon EID 11**) in sensitive directories.
- Watch for suspicious persistence-like registry writes (**Sysmon EID 13** + **Security 4657**) under common run keys / unusual HKCU paths.

## Observed Indicators / Artifacts
See: [iocs/iocs.md](iocs/iocs.md)