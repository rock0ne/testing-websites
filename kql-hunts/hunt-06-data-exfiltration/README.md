# Hunt 06: Data Exfiltration Detection

## Goal
Detect data exfiltration attempts including large transfers, DNS tunneling, cloud storage abuse, and unusual protocol usage.

## MITRE ATT&CK Mapping

| Technique | Description |
|-----------|-------------|
| T1048 | Exfiltration Over Alternative Protocol |
| T1048.003 | Exfiltration Over DNS |
| T1567.002 | Exfiltration to Cloud Storage |
| T1560.001 | Archive Collected Data |

## Detection Thresholds

| Metric | Threshold | Rationale |
|--------|-----------|-----------|
| Large upload | 50MB/hour | Unusual for most workstations |
| DNS query length | 50+ chars | Indicates encoded data |
| Cloud upload | 10MB total | Significant data movement |

## False Positive Handling

| Source | Mitigation |
|--------|------------|
| Backup software | Whitelist backup destinations |
| Cloud sync | Baseline normal sync patterns |
| Development uploads | Exclude CI/CD systems |
