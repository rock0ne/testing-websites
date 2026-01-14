# Hunt 08: Privilege Escalation Detection

## Goal
Detect privilege escalation attempts including UAC bypass, token manipulation, and service abuse.

## MITRE ATT&CK Mapping

| Technique | Description |
|-----------|-------------|
| T1548.002 | Abuse Elevation Control: Bypass UAC |
| T1134 | Access Token Manipulation |
| T1134.001 | Token Impersonation/Theft |
| T1053.005 | Scheduled Task/Job |
| T1543.003 | Create or Modify System Process: Windows Service |

## Detection Categories

| Category | Severity | Tools/Techniques |
|----------|----------|------------------|
| UAC Bypass | High | fodhelper, eventvwr, cmstp |
| Token Manipulation | Critical | SeDebugPrivilege abuse |
| Potato Attacks | Critical | JuicyPotato, PrintSpoofer |
| Service Abuse | Critical | sc.exe config modifications |

## False Positive Handling

| Source | Mitigation |
|--------|------------|
| Admin tools | Whitelist legitimate admin activity |
| Software installers | Baseline during deployment |
| SCCM/Intune | Exclude management processes |
