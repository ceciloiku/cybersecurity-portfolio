# Microsoft 365 Security & Detection Engineering Lab

## Overview

This project demonstrates hands-on experience with Microsoft 365 security operations, including audit log analysis, incident investigation, and detection engineering using Microsoft Sentinel and KQL.

---

## Projects

### 1. Audit Log Analysis
- Reviewed Microsoft Purview audit logs
- Identified authentication and administrative activity
- Documented security-relevant events

📁 [View Report](../02-audit-log-analysis/audit-mini-report.md)

---

### 2. Identity Sign-In Investigation
- Simulated brute-force login behavior
- Built event timeline
- Determined risk level and response actions

📁 [View Investigation](../03-identity-signin-investigations/report.md)

---

### 3. Detection Engineering (Microsoft Sentinel)

- Deployed Microsoft Sentinel SIEM
- Ingested Windows Security Events via Azure Arc + AMA
- Developed KQL detection rules:

  - Brute Force / Password Spray (4625)
  - Suspicious PowerShell Execution (4688)
  - Failed Login — Success Correlation
  - New User Account Creation

📁 [View Detections](../04-sentinel-detections/01-endpoint-detections/README.md)

---

## Tools & Technologies

- Microsoft Sentinel (SIEM)
- Microsoft Purview (Audit Logs)
- Azure Log Analytics
- Kusto Query Language (KQL)
- Azure Arc + Azure Monitor Agent (AMA)

---

## Skills Demonstrated

- Security log analysis
- Incident investigation
- Detection engineering
- KQL query development
- SIEM deployment and configuration
- Threat pattern recognition

---