# Hunt 09: Discovery & Enumeration Detection

## Goal
Detect reconnaissance and enumeration activities used by attackers to map the environment.

## MITRE ATT&CK Mapping

| Technique | Description |
|-----------|-------------|
| T1087 | Account Discovery |
| T1087.002 | Domain Account Discovery |
| T1082 | System Information Discovery |
| T1016 | System Network Configuration Discovery |
| T1018 | Remote System Discovery |
| T1135 | Network Share Discovery |
| T1518.001 | Security Software Discovery |

## Detection Categories

| Category | Severity | Indicators |
|----------|----------|------------|
| Rapid enumeration | Medium-High | 5+ discovery commands in 10 min |
| AD enumeration | High | Domain queries, BloodHound |
| Share enumeration | Medium | net view, Get-SmbShare |
| Security discovery | High | AV/EDR queries |

## False Positive Handling

| Source | Mitigation |
|--------|------------|
| IT administrators | Baseline normal admin activity |
| Monitoring scripts | Whitelist known scripts |
| Help desk tools | Exclude support tools |
