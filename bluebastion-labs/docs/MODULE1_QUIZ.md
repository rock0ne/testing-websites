# Module 1: Secure API Foundations - Quiz

Test your understanding of the security concepts covered in Module 1.

---

## Quiz Questions

### Question 1: JWT Security
**Why do we specify the algorithm explicitly when verifying JWT tokens?**

A) To improve performance  
B) To prevent algorithm confusion attacks where an attacker could use a different algorithm  
C) It's just a best practice with no security benefit  
D) To support multiple authentication methods  

<details>
<summary>Answer</summary>

**B) To prevent algorithm confusion attacks**

Without explicit algorithm specification, an attacker could potentially craft a token using a different algorithm (e.g., changing from RS256 to HS256) and trick the server into accepting it. This is known as an "algorithm confusion" or "algorithm substitution" attack.

```javascript
// SECURE: Explicit algorithm
jwt.verify(token, secret, { algorithms: ['HS256'] });

// VULNERABLE: No algorithm specified
jwt.verify(token, secret);
```
</details>

---

### Question 2: Rate Limiting
**What MITRE ATT&CK technique does rate limiting on login endpoints primarily defend against?**

A) T1190 - Exploit Public-Facing Application  
B) T1110 - Brute Force  
C) T1078 - Valid Accounts  
D) T1059 - Command and Scripting Interpreter  

<details>
<summary>Answer</summary>

**B) T1110 - Brute Force**

Rate limiting on authentication endpoints prevents attackers from making unlimited password guessing attempts. The T1110 technique covers various brute force methods including:
- T1110.001 - Password Guessing
- T1110.002 - Password Cracking
- T1110.003 - Password Spraying
- T1110.004 - Credential Stuffing
</details>

---

### Question 3: Input Validation
**Why do we return a 404 instead of 403 when a user tries to access another user's resource (IDOR attempt)?**

A) 404 is the correct HTTP status code for this situation  
B) To avoid revealing that the resource exists to unauthorized users  
C) 403 would cause browser caching issues  
D) It's required by the OAuth 2.0 specification  

<details>
<summary>Answer</summary>

**B) To avoid revealing that the resource exists to unauthorized users**

Returning 403 (Forbidden) confirms to an attacker that the resource exists but they don't have access. Returning 404 (Not Found) doesn't reveal whether the resource exists, making enumeration attacks more difficult.

```javascript
// SECURE: Don't reveal resource existence
if (!canAccessProject(req.user, project)) {
  return res.status(404).json({ error: 'Project not found' });
}

// LESS SECURE: Reveals resource exists
if (!canAccessProject(req.user, project)) {
  return res.status(403).json({ error: 'Access denied' });
}
```
</details>

---

### Question 4: Security Headers
**Which security header prevents clickjacking attacks?**

A) Content-Security-Policy  
B) X-Content-Type-Options  
C) X-Frame-Options  
D) Strict-Transport-Security  

<details>
<summary>Answer</summary>

**C) X-Frame-Options**

X-Frame-Options controls whether a page can be embedded in an iframe. Setting it to `DENY` or `SAMEORIGIN` prevents attackers from embedding your page in a malicious site to trick users into clicking hidden elements.

Note: Content-Security-Policy's `frame-ancestors` directive is the modern replacement, but X-Frame-Options is still widely used for backward compatibility.
</details>

---

### Question 5: Logging
**Why do we redact sensitive fields like passwords and tokens from logs?**

A) To reduce log file size  
B) To comply with GDPR  
C) To prevent credential exposure if logs are compromised or accessed by unauthorized personnel  
D) To improve log parsing performance  

<details>
<summary>Answer</summary>

**C) To prevent credential exposure if logs are compromised or accessed by unauthorized personnel**

Logs are often:
- Stored in less secure locations than databases
- Accessed by multiple team members for debugging
- Forwarded to third-party SIEM systems
- Retained for long periods

If credentials are logged, a breach of the logging system could expose user credentials. Always redact:
- Passwords
- API keys
- Tokens
- Session IDs
- Credit card numbers
</details>

---

## Follow-Up Challenges

### Challenge 1: Implement MFA
Extend the authentication service to support Time-based One-Time Passwords (TOTP):
1. Add TOTP secret generation during registration
2. Validate TOTP codes during login
3. Add recovery codes for account recovery

### Challenge 2: Token Blacklisting
Implement a token blacklist for immediate token revocation:
1. Create a Redis-backed blacklist
2. Add tokens to blacklist on logout
3. Check blacklist during token validation
4. Implement automatic cleanup of expired entries

### Challenge 3: Anomaly Detection
Create a middleware that detects anomalous behavior:
1. Track normal request patterns per user
2. Flag unusual activity (different IP, unusual hours, rapid requests)
3. Implement progressive security challenges (CAPTCHA, re-authentication)

---

## Score Interpretation

| Score | Level | Recommendation |
|-------|-------|----------------|
| 5/5 | Expert | Ready for Module 2 |
| 4/5 | Proficient | Review missed concept, then proceed |
| 3/5 | Developing | Re-read relevant sections |
| 0-2/5 | Needs Review | Complete Module 1 exercises again |
