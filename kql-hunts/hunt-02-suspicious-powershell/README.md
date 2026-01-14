# Hunt 02: Suspicious PowerShell Execution

## Goal
Detect malicious PowerShell usage including encoded commands, download cradles, AMSI bypass attempts, and other suspicious execution patterns commonly used by attackers.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| **Technique** | T1059.001 - Command and Scripting Interpreter: PowerShell |
| **Tactic** | Execution |
| **Sub-techniques** | T1059.001 |
| **Platforms** | Windows |
| **Data Sources** | Command execution, Process monitoring, Script execution |

## Attack Description

PowerShell is heavily abused by attackers for:
- **Download Cradles**: Downloading and executing payloads
- **Encoded Commands**: Obfuscating malicious commands
- **AMSI Bypass**: Disabling antimalware scanning
- **Fileless Attacks**: Running entirely in memory
- **Lateral Movement**: Remote execution via PSRemoting

## Query Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `lookback` | 24h | Time window to search |
| `min_encoded_length` | 100 | Minimum base64 length to flag |
| `exclude_signed` | true | Exclude Microsoft-signed scripts |

## Detection Categories

| Category | Severity | Description |
|----------|----------|-------------|
| Download Cradle | High | Downloading and executing remote content |
| Encoded Command | Medium-High | Base64 encoded command execution |
| AMSI Bypass | Critical | Attempts to disable AMSI |
| Obfuscation | Medium | String manipulation, concatenation |
| Credential Access | Critical | Credential harvesting commands |

## Expected Results

Detections should include:
- Full command line (decoded if possible)
- Parent process chain
- User context
- Obfuscation indicators
- Risk score

## False Positive Handling

| False Positive Source | Mitigation |
|----------------------|------------|
| SCCM/Intune scripts | Whitelist by script hash or path |
| Azure AD Connect | Exclude known sync processes |
| Legitimate admin scripts | Whitelist signed scripts |
| Software deployment | Exclude known deployment tools |

### Common False Positive Patterns
```kql
// Exclude legitimate encoded commands
| where not(ProcessCommandLine has "Microsoft.PowerShell.Utility")
| where not(InitiatingProcessFileName in~ ("ccmexec.exe", "intune"))
```

## Validation Steps

1. Run synthetic test data
2. Verify all malicious patterns detected
3. Confirm legitimate scripts not flagged
4. Tune thresholds for your environment
5. Create analytics rule in Sentinel

## Response Actions

1. **Isolate**: Quarantine affected endpoint
2. **Decode**: Analyze encoded commands
3. **Trace**: Follow parent process chain
4. **Hunt**: Search for similar activity across environment
5. **Block**: Add IOCs to blocklist

## References

- [MITRE ATT&CK T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [PowerShell Logging](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging)
- [Detecting PowerShell Attacks](https://www.microsoft.com/security/blog/2016/06/01/detecting-powershell-attacks/)
