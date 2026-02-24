# Project 06 — Indicators of Compromise (IOCs)

> Defanged values are used where appropriate.

## Accounts / Persistence
- New local account: `Alberto` (created via EventID 4720)

## Registry Artifacts
- `HKLM\SAM\SAM\Domains\Account\Users\Names\Alberto`

## Command / Execution Techniques
- `WMIC.exe` remote process execution (`process call create`)
- `net user /add` (password redacted)

## PowerShell
- Encoded PowerShell execution (`-enc`) observed in EventID 4103
- AMSI bypass indicators: `AmsiUtils`, `amsiInitFailed` (observed in decoded script)

## Network / C2 (defanged)
- C2 base: `hxxp://10[.]10[.]10[.]5`
- Full path: `hxxp://10[.]10[.]10[.]5/news[.]php`