# BlueBastion Labs - KQL Detection Queries

These KQL (Kusto Query Language) queries are designed for Microsoft Sentinel to detect security events from the BlueBastion API.

## Prerequisites

1. Configure Azure Monitor Agent on Ubuntu server
2. Forward logs to Log Analytics workspace
3. Create custom table for API logs

---

## Query 1: Brute Force Detection

**Purpose:** Detect multiple failed login attempts from the same IP address.

**MITRE ATT&CK:** T1110 - Brute Force

```kql
// Brute Force Detection - Multiple Failed Logins
// Threshold: 5+ failed attempts in 15 minutes from same IP

let threshold = 5;
let timeWindow = 15m;

BlueBastion_API_CL
| where TimeGenerated > ago(timeWindow)
| where eventType_s in ("AUTH_FAILED_INVALID_PASSWORD", "AUTH_FAILED_USER_NOT_FOUND")
| summarize 
    FailedAttempts = count(),
    TargetedUsers = make_set(username_s),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by ip_s
| where FailedAttempts >= threshold
| extend 
    AlertSeverity = case(
        FailedAttempts >= 20, "High",
        FailedAttempts >= 10, "Medium",
        "Low"
    ),
    MitreAttack = "T1110",
    Description = strcat("Potential brute force attack detected from IP ", ip_s)
| project 
    TimeGenerated = LastAttempt,
    SourceIP = ip_s,
    FailedAttempts,
    TargetedUsers,
    Duration = LastAttempt - FirstAttempt,
    AlertSeverity,
    MitreAttack,
    Description
| order by FailedAttempts desc
```

### Expected Alert
When triggered, this query indicates:
- An attacker is attempting to guess credentials
- The IP should be investigated and potentially blocked
- Check if any successful logins followed the failed attempts

---

## Query 2: Account Lockout Events

**Purpose:** Monitor account lockouts which may indicate ongoing attacks.

**MITRE ATT&CK:** T1110 - Brute Force

```kql
// Account Lockout Monitoring
// Detects when accounts are locked due to failed attempts

BlueBastion_API_CL
| where TimeGenerated > ago(1h)
| where eventType_s == "AUTH_ACCOUNT_LOCKED"
| summarize 
    LockoutCount = count(),
    SourceIPs = make_set(ip_s),
    FirstLockout = min(TimeGenerated),
    LastLockout = max(TimeGenerated)
    by username_s
| extend 
    AlertSeverity = case(
        LockoutCount >= 5, "High",
        LockoutCount >= 2, "Medium",
        "Low"
    ),
    MitreAttack = "T1110",
    Description = strcat("Account ", username_s, " locked out ", LockoutCount, " times")
| project 
    TimeGenerated = LastLockout,
    Username = username_s,
    LockoutCount,
    SourceIPs,
    AlertSeverity,
    MitreAttack,
    Description
| order by LockoutCount desc
```

---

## Query 3: Privilege Escalation Attempts

**Purpose:** Detect unauthorized access attempts to admin resources.

**MITRE ATT&CK:** T1078.001 - Valid Accounts: Default Accounts

```kql
// Privilege Escalation / Unauthorized Access Attempts
// Detects users trying to access resources beyond their role

BlueBastion_API_CL
| where TimeGenerated > ago(24h)
| where eventType_s in ("AUTHZ_ROLE_DENIED", "AUTHZ_PERMISSION_DENIED", "AUTHZ_IDOR_ATTEMPT")
| summarize 
    AttemptCount = count(),
    TargetedPaths = make_set(path_s),
    Methods = make_set(method_s)
    by userId_s, userRole_s, ip_s
| where AttemptCount >= 3
| extend 
    AlertSeverity = case(
        AttemptCount >= 10, "High",
        AttemptCount >= 5, "Medium",
        "Low"
    ),
    MitreAttack = "T1078.001",
    Description = strcat("User ", userId_s, " (role: ", userRole_s, ") attempted unauthorized access ", AttemptCount, " times")
| project 
    TimeGenerated = now(),
    UserId = userId_s,
    UserRole = userRole_s,
    SourceIP = ip_s,
    AttemptCount,
    TargetedPaths,
    AlertSeverity,
    MitreAttack,
    Description
| order by AttemptCount desc
```

---

## Query 4: IDOR (Insecure Direct Object Reference) Detection

**Purpose:** Detect attempts to access resources belonging to other users.

**MITRE ATT&CK:** T1078 - Valid Accounts

```kql
// IDOR Attack Detection
// Detects sequential ID enumeration or access to other users' resources

BlueBastion_API_CL
| where TimeGenerated > ago(1h)
| where eventType_s == "AUTHZ_IDOR_ATTEMPT"
| summarize 
    AttemptCount = count(),
    TargetedResources = make_set(resourceId_s),
    ResourceTypes = make_set(resourceType_s)
    by userId_s, ip_s
| where AttemptCount >= 3
| extend 
    AlertSeverity = "High",
    MitreAttack = "T1078",
    Description = strcat("Potential IDOR attack: User ", userId_s, " attempted to access ", AttemptCount, " unauthorized resources")
| project 
    TimeGenerated = now(),
    UserId = userId_s,
    SourceIP = ip_s,
    AttemptCount,
    TargetedResources,
    ResourceTypes,
    AlertSeverity,
    MitreAttack,
    Description
```

---

## Query 5: Input Validation Failures (Injection Attempts)

**Purpose:** Detect potential injection attacks based on validation failures.

**MITRE ATT&CK:** T1190 - Exploit Public-Facing Application

```kql
// Injection Attack Detection
// Monitors validation failures that may indicate SQL injection, XSS, etc.

BlueBastion_API_CL
| where TimeGenerated > ago(1h)
| where eventType_s == "VALIDATION_FAILED"
| extend 
    InjectionIndicators = case(
        errors_s contains "SQL" or errors_s contains "SELECT" or errors_s contains "UNION", "SQL Injection",
        errors_s contains "script" or errors_s contains "javascript", "XSS",
        errors_s contains ".." or errors_s contains "etc/passwd", "Path Traversal",
        "Unknown"
    )
| summarize 
    AttemptCount = count(),
    InjectionTypes = make_set(InjectionIndicators),
    TargetedPaths = make_set(path_s)
    by ip_s
| where AttemptCount >= 5
| extend 
    AlertSeverity = case(
        AttemptCount >= 20, "High",
        AttemptCount >= 10, "Medium",
        "Low"
    ),
    MitreAttack = "T1190",
    Description = strcat("Potential injection attacks from IP ", ip_s, ": ", AttemptCount, " validation failures")
| project 
    TimeGenerated = now(),
    SourceIP = ip_s,
    AttemptCount,
    InjectionTypes,
    TargetedPaths,
    AlertSeverity,
    MitreAttack,
    Description
| order by AttemptCount desc
```

---

## Query 6: Rate Limit Violations

**Purpose:** Detect IPs that are hitting rate limits (potential DoS or scraping).

**MITRE ATT&CK:** T1498 - Network Denial of Service

```kql
// Rate Limit Violation Detection
// Identifies IPs repeatedly hitting rate limits

BlueBastion_API_CL
| where TimeGenerated > ago(1h)
| where eventType_s in ("RATE_LIMIT_EXCEEDED", "AUTH_RATE_LIMIT_EXCEEDED")
| summarize 
    ViolationCount = count(),
    TargetedPaths = make_set(path_s),
    FirstViolation = min(TimeGenerated),
    LastViolation = max(TimeGenerated)
    by ip_s
| where ViolationCount >= 3
| extend 
    AlertSeverity = case(
        ViolationCount >= 20, "High",
        ViolationCount >= 10, "Medium",
        "Low"
    ),
    MitreAttack = "T1498",
    Description = strcat("IP ", ip_s, " exceeded rate limits ", ViolationCount, " times")
| project 
    TimeGenerated = LastViolation,
    SourceIP = ip_s,
    ViolationCount,
    TargetedPaths,
    Duration = LastViolation - FirstViolation,
    AlertSeverity,
    MitreAttack,
    Description
| order by ViolationCount desc
```

---

## Query 7: Suspicious Token Activity

**Purpose:** Detect invalid or expired token usage patterns.

**MITRE ATT&CK:** T1078 - Valid Accounts

```kql
// Suspicious Token Activity
// Detects patterns of invalid/expired token usage

BlueBastion_API_CL
| where TimeGenerated > ago(1h)
| where eventType_s in ("AUTH_TOKEN_INVALID", "AUTH_TOKEN_EXPIRED", "AUTH_TOKEN_MALFORMED")
| summarize 
    InvalidTokenCount = count(),
    TokenErrors = make_set(eventType_s),
    TargetedPaths = make_set(path_s)
    by ip_s
| where InvalidTokenCount >= 5
| extend 
    AlertSeverity = case(
        InvalidTokenCount >= 20, "High",
        InvalidTokenCount >= 10, "Medium",
        "Low"
    ),
    MitreAttack = "T1078",
    Description = strcat("Suspicious token activity from IP ", ip_s, ": ", InvalidTokenCount, " invalid token attempts")
| project 
    TimeGenerated = now(),
    SourceIP = ip_s,
    InvalidTokenCount,
    TokenErrors,
    TargetedPaths,
    AlertSeverity,
    MitreAttack,
    Description
| order by InvalidTokenCount desc
```

---

## Query 8: Successful Login After Failed Attempts

**Purpose:** Detect successful logins that follow multiple failed attempts (potential credential stuffing success).

**MITRE ATT&CK:** T1110.004 - Credential Stuffing

```kql
// Successful Login After Failed Attempts
// Critical: May indicate successful credential compromise

let timeWindow = 1h;

let FailedLogins = BlueBastion_API_CL
| where TimeGenerated > ago(timeWindow)
| where eventType_s in ("AUTH_FAILED_INVALID_PASSWORD", "AUTH_FAILED_USER_NOT_FOUND")
| summarize FailedCount = count() by ip_s, username_s;

let SuccessfulLogins = BlueBastion_API_CL
| where TimeGenerated > ago(timeWindow)
| where eventType_s == "AUTH_SUCCESS"
| project ip_s, username_s, SuccessTime = TimeGenerated, userId_s;

FailedLogins
| join kind=inner SuccessfulLogins on ip_s, username_s
| where FailedCount >= 3
| extend 
    AlertSeverity = "Critical",
    MitreAttack = "T1110.004",
    Description = strcat("CRITICAL: Successful login for ", username_s, " after ", FailedCount, " failed attempts from same IP")
| project 
    TimeGenerated = SuccessTime,
    Username = username_s,
    UserId = userId_s,
    SourceIP = ip_s,
    PriorFailedAttempts = FailedCount,
    AlertSeverity,
    MitreAttack,
    Description
```

---

## Deployment Instructions

### 1. Create Custom Log Table

```kql
// Create custom table for BlueBastion API logs
.create table BlueBastion_API_CL (
    TimeGenerated: datetime,
    eventType_s: string,
    category_s: string,
    ip_s: string,
    userId_s: string,
    username_s: string,
    userRole_s: string,
    path_s: string,
    method_s: string,
    statusCode_d: int,
    requestId_s: string,
    mitre_s: string,
    errors_s: string,
    resourceId_s: string,
    resourceType_s: string
)
```

### 2. Configure Log Forwarding

On Ubuntu server, configure Azure Monitor Agent to forward logs:

```bash
# Install Azure Monitor Agent
wget https://aka.ms/InstallAzureMonitorAgentLinux -O InstallAzureMonitorAgentLinux.sh
sudo bash InstallAzureMonitorAgentLinux.sh

# Configure custom log collection
# Point to: /path/to/bluebastion-labs/api/logs/security.json
```

### 3. Create Analytics Rules

For each query above, create an Analytics Rule in Microsoft Sentinel:
1. Go to Sentinel > Analytics > Create > Scheduled query rule
2. Paste the KQL query
3. Set appropriate frequency (5-15 minutes for critical alerts)
4. Configure alert actions (email, Teams, Logic App)

---

## Alert Response Playbook

### For Brute Force Alerts:
1. Block source IP at firewall/WAF
2. Force password reset for targeted accounts
3. Enable MFA if not already enabled
4. Review logs for successful access

### For IDOR Alerts:
1. Review user's recent activity
2. Check if data was exfiltrated
3. Consider account suspension pending investigation
4. Audit access control implementation

### For Injection Alerts:
1. Block source IP
2. Review WAF rules
3. Check for successful exploitation
4. Audit input validation code
