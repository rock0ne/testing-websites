# Hunt 03: Lateral Movement Detection

## Goal
Detect lateral movement techniques including PsExec, WMI, WinRM, and SMB-based remote execution used by attackers to spread across the network.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| **Techniques** | T1021.002 (SMB/Windows Admin Shares), T1047 (WMI), T1021.006 (WinRM) |
| **Tactic** | Lateral Movement |
| **Platforms** | Windows |
| **Data Sources** | Network traffic, Process monitoring, Authentication logs |

## Detection Categories

| Category | Technique | Indicators |
|----------|-----------|------------|
| PsExec | T1021.002 | PSEXESVC.exe, named pipes |
| WMI | T1047 | wmiprvse.exe spawning processes |
| WinRM | T1021.006 | wsmprovhost.exe activity |
| SMB | T1021.002 | Remote file copies, admin shares |

## False Positive Handling

| Source | Mitigation |
|--------|------------|
| SCCM/Intune | Whitelist management servers |
| Admin tools | Baseline normal admin activity |
| Backup software | Exclude known backup processes |

## References
- [MITRE T1021](https://attack.mitre.org/techniques/T1021/)
- [MITRE T1047](https://attack.mitre.org/techniques/T1047/)
