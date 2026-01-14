# Hunt 05: Defense Evasion - Process Injection

## Goal
Detect process injection techniques used to evade security controls and execute malicious code within legitimate processes.

## MITRE ATT&CK Mapping

| Technique | Description |
|-----------|-------------|
| T1055.001 | DLL Injection |
| T1055.003 | Thread Execution Hijacking |
| T1055.012 | Process Hollowing |
| T1036.005 | Masquerading: Match Legitimate Name |
| T1562.001 | Impair Defenses: Disable or Modify Tools |

## Detection Categories

| Category | Severity | Indicators |
|----------|----------|------------|
| CreateRemoteThread | High | Cross-process thread creation |
| Process Hollowing | High | Legitimate process with suspicious parent |
| DLL Injection | Medium | DLLs loaded from temp directories |
| Masquerading | Critical | System processes in wrong locations |

## False Positive Handling

| Source | Mitigation |
|--------|------------|
| Debugging tools | Whitelist known debuggers |
| AV/EDR | Exclude security software |
| Software installers | Baseline during deployment |
