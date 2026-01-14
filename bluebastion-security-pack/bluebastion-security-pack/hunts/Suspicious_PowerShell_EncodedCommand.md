# Suspicious PowerShell EncodedCommand (ATT&CK T1059.001)

**Goal:** Identify PowerShell executions using `-EncodedCommand` (often used by attackers), with basic FP controls.

**Data source:** `DeviceProcessEvents` (Defender for Endpoint)

## KQL
```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has "-EncodedCommand" or ProcessCommandLine has "-enc"
| extend Account = AccountName, Host = DeviceName
| summarize count() by bin(Timestamp, 1h), Account, Host
| order by Timestamp desc
```

## Synthetic test data
```kusto
let demo=datatable(Timestamp:datetime, DeviceName:string, AccountName:string, ProcessCommandLine:string)[
    datetime(2026-01-14T10:00:00Z), "LAB-WIN11", "lab\rockson", "powershell -NoP -EncodedCommand JAB4AD0AIgB0AGUAcwB0ACIA" 
];
demo
| extend Account=AccountName, Host=DeviceName
| summarize count() by bin(Timestamp, 1h), Account, Host
```

## Validation steps
1. Run the synthetic data block; ensure one result.
2. In lab, generate a benign encoded command (e.g., base64 of `Write-Host`).
3. Confirm the hunt highlights the event.

## False positives / tuning
- Some admin scripts use encoding; exclude known signed scripts or admin paths.
