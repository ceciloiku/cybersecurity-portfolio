# Sysmon EVTX Investigation Practice (Mini Lab)

## Summary
This mini project demonstrates basic Sysmon investigation workflows using offline `.evtx` samples. The goal was to answer a set of investigation objectives by filtering Sysmon Event IDs and extracting relevant artifacts (process execution, network connections, registry persistence, and credential-access signals).

## Dataset
Source: public EVTX sample repositories (e.g., attack-sample collections) + Sysmon resources.

Files analyzed:
- Investigation-1.evtx
- Investigation-2.evtx
- Investigation-3.1.evtx
- Investigation-3.2.evtx
- Investigation-4.evtx

Evidence screenshots are stored in `evidence/`.

![EVTX files](evidence/01-evtx-files.png)

## Tools & Method
- Windows PowerShell
- `Get-WinEvent` with XPath filtering by Sysmon Event ID
- Sorting by `TimeCreated`
- Reviewing event message fields and, where needed, raw `.Properties`

Example patterns used:
- Event ID filter:
  - `Get-WinEvent -Path .\Investigation-1.evtx -FilterXPath '*[System[EventID=13]]'`
- Sort by time:
  - `... | Sort-Object TimeCreated`
- Quick inspection:
  - `... | fl`

---

## Key Findings (by objective)

### 1) USB device registry key and device identity (Sysmon EID 13)
Registry value updates indicate a USB storage device and its friendly name under USBSTOR/WPD-related paths.

![USB registry friendly name](evidence/02-usb-registry-friendlyname.png)

**Why it matters:** USB insertion artifacts often support data theft, staging, or lateral movement hypotheses.

---

### 2) RawAccessRead device name (Sysmon EID 9)
A RawAccessRead event shows direct access to a disk volume device path.

![RawAccessRead device](evidence/03-rawaccessread-device.png)

**Why it matters:** Raw disk reads are uncommon in normal user activity and may correlate with tooling that reads disks directly (forensics, imaging, or credential access patterns depending on context).

---

### 3) First notable process execution (Sysmon EID 1)
Early process activity includes Windows-signed binaries (example shown: `rundll32.exe`).

![First process example](evidence/04-first-process-rundll32.png)

**Why it matters:** Signed binaries are commonly abused for proxy execution / living-off-the-land behaviors. Parent/child relationships help validate whether execution was expected.

---

### 4) Payload execution via `mshta.exe` (Sysmon EID 1)
`mshta.exe` executed a `.hta` file, with a browser-related parent process chain consistent with user-driven execution from a downloaded file.

![mshta executing update.hta](evidence/05-mshta-exec-update-hta.png)

**Why it matters:** HTA execution is a common initial access / payload runner technique.

---

### 5) Suspicious network connection (Sysmon EID 3)
A network connection associated with the suspicious process chain shows outbound connectivity to a destination host/port consistent with C2-style traffic.

![Network connect to 10.0.2.18:4443](evidence/06-network-connect-10.0.2.18-4443.png)

**Why it matters:** Correlating process execution (EID 1) with network telemetry (EID 3) strengthens attribution of the activity to malware vs benign browsing.

---

### 6) Registry-based persistence (Sysmon EID 13)
Registry modifications show persistence via Image File Execution Options (IFEO) hijack of `sethc.exe` by setting a Debugger command.

![IFEO sethc debugger](evidence/07-ifeo-sethc-debugger.png)

**Why it matters:** IFEO hijacks can provide a reliable backdoor path that triggers when a target binary is launched.

---

### 7) Scheduled task persistence + staged payload location
Evidence shows a payload staged into an Alternate Data Stream (ADS)-style path and a scheduled task created to run hidden PowerShell that decodes/executes the stored content.

![Payload staged to ADS](evidence/08-payload-to-ads-blah.txt.png)

![Scheduled task command](evidence/09-schtasks-updater-command.png)

**Why it matters:** This persistence chain combines stealth storage (ADS) + scheduled execution + hidden PowerShell.

---

### 8) Credential access signal: process access to LSASS (Sysmon EID 10)
Process-access telemetry indicates access to `lsass.exe`.

![schtasks access to lsass](evidence/10-schtasks-access-lsass.png)

**Why it matters:** LSASS access is a common signal for credential dumping activity and should be treated as high priority for containment and scoping.

---

## Indicators & Next Steps
See `iocs.md` for extracted indicators (IPs, ports, file paths, registry keys, scheduled task name, and notable binaries).

Recommended next steps (defensive):
- Scope for additional instances of `mshta.exe`, hidden PowerShell, and scheduled task creation.
- Hunt for IFEO `sethc.exe\Debugger` across endpoints.
- Validate whether any credential material was accessed/exfiltrated after LSASS access.