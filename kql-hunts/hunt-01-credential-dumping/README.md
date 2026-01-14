# Hunt 01: Credential Dumping (LSASS Access)

## Goal
Detect attempts to dump credentials from the Local Security Authority Subsystem Service (LSASS) process, a common technique used by attackers to harvest credentials for lateral movement.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| **Technique** | T1003.001 - OS Credential Dumping: LSASS Memory |
| **Tactic** | Credential Access |
| **Platforms** | Windows |
| **Data Sources** | Process monitoring, API monitoring |
| **Permissions Required** | Administrator, SYSTEM |

## Attack Description

Attackers commonly target LSASS to extract:
- NTLM password hashes
- Kerberos tickets
- Plaintext passwords (if WDigest is enabled)

Common tools:
- Mimikatz
- ProcDump
- comsvcs.dll (MiniDump)
- Task Manager (manual dump)
- Out-Minidump (PowerShell)

## Query Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `lookback` | 24h | Time window to search |
| `sensitivity` | medium | low/medium/high - adjusts detection threshold |

## Detection Logic

The query detects:
1. Direct LSASS process access with suspicious access rights
2. Known credential dumping tools accessing LSASS
3. MiniDump creation targeting LSASS
4. Suspicious process lineage accessing LSASS

## Expected Results

When triggered, you should see:
- Process name that accessed LSASS
- Access rights requested
- Parent process chain
- User context
- Timestamp and device

## False Positive Handling

| False Positive Source | Mitigation |
|----------------------|------------|
| Antivirus/EDR scanning LSASS | Whitelist known AV process hashes |
| Windows Defender | Exclude `MsMpEng.exe` with valid signature |
| Legitimate admin tools | Whitelist by signed publisher |
| Crash dump collection | Verify WerFault.exe parent chain |

### Whitelist Recommendations
```kql
// Add to query to reduce false positives
| where not(InitiatingProcessFileName in~ ("MsMpEng.exe", "csrss.exe", "wininit.exe"))
| where not(InitiatingProcessFolderPath startswith "C:\\Program Files\\Windows Defender")
```

## Validation Steps

1. **Deploy test data**: Run `test-data.kql` in your Sentinel workspace
2. **Execute hunt query**: Run `query.kql` against the test data
3. **Verify detection**: Confirm all synthetic attacks are detected
4. **Check false positives**: Verify legitimate processes are not flagged
5. **Tune thresholds**: Adjust sensitivity based on your environment

## Response Actions

When this hunt triggers:
1. **Immediate**: Isolate the affected endpoint
2. **Investigate**: Check for lateral movement from this host
3. **Contain**: Reset credentials for affected users
4. **Remediate**: Scan for persistence mechanisms
5. **Report**: Document incident timeline

## References

- [MITRE ATT&CK T1003.001](https://attack.mitre.org/techniques/T1003/001/)
- [Microsoft Defender for Endpoint - Credential theft](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/credential-theft)
- [Detecting Mimikatz](https://www.microsoft.com/security/blog/2017/01/23/detecting-mimikatz/)
