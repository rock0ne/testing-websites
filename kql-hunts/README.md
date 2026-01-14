# KQL Threat Hunting Library

Production-grade KQL queries for Microsoft Defender XDR and Microsoft Sentinel, mapped to MITRE ATT&CK framework.

## Overview

This library contains 10 threat hunting queries designed for:
- **Microsoft Defender for Endpoint (MDE)**
- **Microsoft Sentinel**
- **Microsoft 365 Defender**

Each hunt includes synthetic test data for validation in your lab environment.

## Hunt Index

| # | Hunt Name | MITRE ATT&CK | Tactic | Data Source |
|---|-----------|--------------|--------|-------------|
| 01 | Credential Dumping (LSASS) | T1003.001 | Credential Access | DeviceProcessEvents |
| 02 | Suspicious PowerShell Execution | T1059.001 | Execution | DeviceProcessEvents |
| 03 | Lateral Movement (PsExec/WMI) | T1021.002, T1047 | Lateral Movement | DeviceNetworkEvents |
| 04 | Registry Persistence | T1547.001 | Persistence | DeviceRegistryEvents |
| 05 | Defense Evasion (Process Injection) | T1055 | Defense Evasion | DeviceProcessEvents |
| 06 | Data Exfiltration Detection | T1048 | Exfiltration | DeviceNetworkEvents |
| 07 | Initial Access (Phishing) | T1566.001 | Initial Access | EmailEvents |
| 08 | Privilege Escalation | T1068, T1548 | Privilege Escalation | DeviceProcessEvents |
| 09 | Discovery & Enumeration | T1087, T1082 | Discovery | DeviceProcessEvents |
| 10 | Command & Control Detection | T1071, T1573 | Command and Control | DeviceNetworkEvents |

## Directory Structure

```
kql-hunts/
├── README.md                          # This file
├── hunt-01-credential-dumping/
│   ├── README.md                      # Hunt documentation
│   ├── query.kql                      # Production query
│   ├── test-data.kql                  # Synthetic test data
│   └── validation.md                  # Validation steps
├── hunt-02-suspicious-powershell/
│   └── ...
└── ...
```

## Usage

### In Microsoft Sentinel
1. Navigate to **Logs** in your Sentinel workspace
2. Copy the query from `query.kql`
3. Adjust time range and parameters as needed
4. Run and analyze results

### In Microsoft 365 Defender
1. Go to **Advanced Hunting**
2. Paste the query
3. Modify for your environment
4. Save as custom detection rule if needed

### Testing with Synthetic Data
1. Use the `test-data.kql` file to generate test events
2. Run the hunt query against the synthetic data
3. Verify expected results match documentation

## Lab Environment Requirements

Based on your lab setup:
- Windows 11 endpoints with Defender for Endpoint
- Windows Server AD
- Microsoft 365 E5 or Defender for Endpoint P2
- Microsoft Sentinel workspace
- Log Analytics workspace with appropriate tables

## MITRE ATT&CK Coverage

```
┌─────────────────────────────────────────────────────────────────────┐
│                    MITRE ATT&CK Coverage Map                        │
├─────────────────────────────────────────────────────────────────────┤
│ Initial Access    │ ████████░░ │ T1566 (Phishing)                   │
│ Execution         │ ████████░░ │ T1059 (PowerShell)                 │
│ Persistence       │ ████████░░ │ T1547 (Registry Run Keys)          │
│ Privilege Esc.    │ ████████░░ │ T1068, T1548                       │
│ Defense Evasion   │ ████████░░ │ T1055 (Process Injection)          │
│ Credential Access │ ████████░░ │ T1003 (LSASS Dumping)              │
│ Discovery         │ ████████░░ │ T1087, T1082                       │
│ Lateral Movement  │ ████████░░ │ T1021, T1047                       │
│ Exfiltration      │ ████████░░ │ T1048                              │
│ Command & Control │ ████████░░ │ T1071, T1573                       │
└─────────────────────────────────────────────────────────────────────┘
```

## Contributing

When adding new hunts:
1. Follow the existing directory structure
2. Include synthetic test data
3. Document false positive handling
4. Map to MITRE ATT&CK
5. Include validation steps
