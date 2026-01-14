# AD Hardening Checklist (blue-team)
- Enforce LDAP signing and channel binding
- Disable NTLM where possible; audit remaining
- Separate admin tiers and enforce PAWs (Privileged Access Workstations)
- LAPS/LCM for local admin passwords
- Protected Users/AS (AES-only), Kerberos armoring
- SMB signing + disable SMB1
- Admin SDHolder monitoring and alerts
