# New Local Admin Account Creation (ATT&CK T1136.001)

**Goal:** Detect creation of local users added to the local Administrators group.

**Data sources:** `DeviceEvents` (security event 4732), `DeviceInfo` for host context

## KQL (conceptual)
```kusto
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType in ("UserAccountAddedToLocalGroup")
| where AdditionalFields contains "Administrators"
| project Timestamp, DeviceName, AccountName, TargetAccount, InitiatingProcessAccountName
| order by Timestamp desc
```

## Synthetic test data
```kusto
let demo=datatable(Timestamp:datetime, DeviceName:string, AccountName:string, TargetAccount:string, ActionType:string, AdditionalFields:string)[
    datetime(2026-01-14T11:00:00Z), "LAB-DC", "lab\admin", "lab\newuser", "UserAccountAddedToLocalGroup", "Group=Administrators"
];
demo | order by Timestamp desc
```

## Validation steps
1. Create a temporary local user and add to Administrators on a lab VM.
2. Confirm telemetry appears and the hunt surfaces it.

## False positives / tuning
- Maintenance windows; exclude known build pipelines.
