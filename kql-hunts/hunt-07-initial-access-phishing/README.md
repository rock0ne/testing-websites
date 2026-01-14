# Hunt 07: Initial Access - Phishing Detection

## Goal
Detect phishing attempts including malicious attachments, credential harvesting URLs, and macro-enabled documents.

## MITRE ATT&CK Mapping

| Technique | Description |
|-----------|-------------|
| T1566.001 | Phishing: Spearphishing Attachment |
| T1566.002 | Phishing: Spearphishing Link |
| T1204.002 | User Execution: Malicious File |

## Data Sources

- EmailEvents
- EmailAttachmentInfo
- EmailUrlInfo
- DeviceProcessEvents

## Detection Categories

| Category | Severity | Indicators |
|----------|----------|------------|
| Executable attachments | Critical | .exe, .dll, .scr files |
| ISO/IMG containers | High | Disk image files |
| Macro documents | High | .docm, .xlsm from external |
| Password-protected archives | Critical | Archive + password in email |
| Credential phishing URLs | High | Login/verify keywords |

## False Positive Handling

| Source | Mitigation |
|--------|------------|
| Legitimate software delivery | Whitelist known vendors |
| Internal macro documents | Exclude internal domains |
| IT communications | Baseline normal patterns |
