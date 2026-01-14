# Hunt 04: Registry Persistence Detection

## Goal
Detect persistence mechanisms using Windows Registry Run keys, Services, and other autostart locations.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| **Technique** | T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys |
| **Tactic** | Persistence |
| **Platforms** | Windows |
| **Data Sources** | Windows Registry |

## Key Registry Locations

| Location | Purpose |
|----------|---------|
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | Machine-wide autostart |
| `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | User-specific autostart |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce` | One-time execution |
| `HKLM\SYSTEM\CurrentControlSet\Services` | Service persistence |

## False Positive Handling

| Source | Mitigation |
|--------|------------|
| Software installation | Baseline after deployment |
| Windows updates | Exclude Microsoft-signed binaries |
| AV/EDR updates | Whitelist security software |

## References
- [MITRE T1547.001](https://attack.mitre.org/techniques/T1547/001/)
