# BlueBastion Labs - Verification Plan

This document outlines tests to verify that security controls are working correctly.

---

## Module 1: Secure API Foundations

### Test 1.1: JWT Authentication

| Test Case | Expected Result | How to Verify |
|-----------|-----------------|---------------|
| Login with valid credentials | Returns 200 + JWT token | `curl -X POST /api/auth/login -d '{"username":"admin","password":"Admin@123456!"}'` |
| Login with invalid password | Returns 401 | `curl -X POST /api/auth/login -d '{"username":"admin","password":"wrong"}'` |
| Access protected route without token | Returns 401 | `curl /api/auth/me` |
| Access protected route with valid token | Returns 200 + user data | `curl -H "Authorization: Bearer <token>" /api/auth/me` |
| Access with expired token | Returns 401 | Wait 15+ minutes, then use old token |

**Expected Defender Alert:** `AUTH_FAILED_INVALID_PASSWORD` events in security logs

### Test 1.2: Input Validation

| Test Case | Expected Result | How to Verify |
|-----------|-----------------|---------------|
| SQL injection in username | Returns 400 (validation failed) | `curl -X POST /api/auth/login -d '{"username":"admin'\''--","password":"x"}'` |
| XSS in username | Returns 400 (validation failed) | `curl -X POST /api/auth/login -d '{"username":"<script>alert(1)</script>","password":"x"}'` |
| Weak password on registration | Returns 400 (validation failed) | `curl -X POST /api/auth/register -d '{"username":"test","password":"weak",...}'` |
| Valid input | Returns 200/201 | Use properly formatted data |

**Expected Defender Alert:** `VALIDATION_FAILED` events with MITRE T1190

### Test 1.3: Rate Limiting

| Test Case | Expected Result | How to Verify |
|-----------|-----------------|---------------|
| 6+ login attempts in 15 min | Returns 429 after 5th attempt | Loop: `for i in {1..6}; do curl -X POST /api/auth/login ...; done` |
| 101+ API requests in 15 min | Returns 429 after 100th | Load test with 101 requests |
| Wait 15 minutes, retry | Returns 200 | Wait and retry |

**Expected Defender Alert:** `AUTH_RATE_LIMIT_EXCEEDED` or `RATE_LIMIT_EXCEEDED`

### Test 1.4: Security Headers

| Test Case | Expected Result | How to Verify |
|-----------|-----------------|---------------|
| Response includes CSP | `Content-Security-Policy` header present | `curl -I /health` |
| Response includes X-Frame-Options | `X-Frame-Options: DENY` | `curl -I /health` |
| Response includes X-Content-Type-Options | `nosniff` | `curl -I /health` |
| Response includes Request ID | `X-Request-ID` header present | `curl -I /health` |

### Test 1.5: Audit Logging

| Test Case | Expected Result | How to Verify |
|-----------|-----------------|---------------|
| Login generates log | `AUTH_SUCCESS` in security.json | `cat logs/security.json \| grep AUTH_SUCCESS` |
| Failed login generates log | `AUTH_FAILED_*` in security.json | `cat logs/security.json \| grep AUTH_FAILED` |
| CRUD operations logged | `AUDIT_*` events | `cat logs/api.json \| grep AUDIT` |

---

## Module 2: Web App Authorization

### Test 2.1: Role-Based Access Control

| Test Case | Expected Result | How to Verify |
|-----------|-----------------|---------------|
| Admin can access all projects | Returns 200 | Login as admin, GET /api/projects |
| Viewer can only read | Returns 403 on POST/PUT/DELETE | Login as viewer, try to create project |
| Analyst can read/write | Returns 200 on GET/POST, 403 on DELETE | Login as analyst, test CRUD |

**Expected Defender Alert:** `AUTHZ_ROLE_DENIED` events

### Test 2.2: IDOR Prevention

| Test Case | Expected Result | How to Verify |
|-----------|-----------------|---------------|
| User accesses own resource | Returns 200 | GET /api/projects/:ownProjectId |
| User accesses other's resource | Returns 404 (not 403) | GET /api/projects/:otherUsersProjectId |
| Admin accesses any resource | Returns 200 | Login as admin, access any project |

**Expected Defender Alert:** `AUTHZ_IDOR_ATTEMPT` events

---

## Module 3: Telemetry & Detection

### Test 3.1: Log Forwarding

| Test Case | Expected Result | How to Verify |
|-----------|-----------------|---------------|
| Logs written to files | Files exist and contain data | `ls -la logs/` |
| JSON format valid | Parseable JSON | `cat logs/security.json \| jq .` |
| CEF format valid | CEF prefix present | `head logs/api.cef` |

### Test 3.2: KQL Queries

| Test Case | Expected Result | How to Verify |
|-----------|-----------------|---------------|
| Brute force query returns results | Detects 5+ failed logins | Run query in Sentinel after test |
| IDOR query returns results | Detects unauthorized access | Run query after IDOR test |
| Rate limit query returns results | Detects rate limit violations | Run query after rate limit test |

---

## Verification Commands

### Quick Verification Script

```bash
#!/bin/bash
# BlueBastion Labs - Quick Verification Script

API_URL="http://localhost:12001"

echo "=== Test 1: Health Check ==="
curl -s $API_URL/health | jq .

echo -e "\n=== Test 2: Security Headers ==="
curl -sI $API_URL/health | grep -E "(X-|Content-Security)"

echo -e "\n=== Test 3: Valid Login ==="
TOKEN=$(curl -s -X POST $API_URL/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Admin@123456!"}' | jq -r '.accessToken')
echo "Token received: ${TOKEN:0:50}..."

echo -e "\n=== Test 4: Protected Route with Token ==="
curl -s -H "Authorization: Bearer $TOKEN" $API_URL/api/auth/me | jq .

echo -e "\n=== Test 5: SQL Injection Blocked ==="
curl -s -X POST $API_URL/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'\''--","password":"x"}' | jq .

echo -e "\n=== Test 6: XSS Blocked ==="
curl -s -X POST $API_URL/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"<script>alert(1)</script>","password":"x"}' | jq .

echo -e "\n=== Test 7: Invalid Token Rejected ==="
curl -s -H "Authorization: Bearer invalid.token.here" $API_URL/api/auth/me | jq .

echo -e "\n=== Test 8: Check Security Logs ==="
echo "Recent security events:"
tail -5 logs/security.json 2>/dev/null | jq -r '.message // .eventType' || echo "No logs yet"

echo -e "\n=== Verification Complete ==="
```

---

## Expected Alerts Summary

| Security Control | Test Action | Expected Log Event | MITRE ATT&CK |
|-----------------|-------------|-------------------|--------------|
| Authentication | Failed login | AUTH_FAILED_* | T1078, T1110 |
| Rate Limiting | Exceed limit | RATE_LIMIT_EXCEEDED | T1110 |
| Input Validation | Injection attempt | VALIDATION_FAILED | T1190 |
| Authorization | Access denied | AUTHZ_*_DENIED | T1078.001 |
| IDOR Prevention | Unauthorized access | AUTHZ_IDOR_ATTEMPT | T1078 |

---

## Troubleshooting

### Logs not appearing
1. Check logs directory exists: `ls -la logs/`
2. Check file permissions
3. Verify Winston is configured correctly

### Rate limiting not working
1. Check if behind proxy (X-Forwarded-For)
2. Verify rate limit configuration in config/security.js
3. Check if testing from same IP

### JWT validation failing
1. Check JWT_SECRET environment variable
2. Verify token hasn't expired (15 min default)
3. Check issuer/audience match configuration
