/**
 * EDUCATIONAL WEB SECURITY LAB
 * 
 * This server demonstrates both VULNERABLE and SECURE implementations
 * Toggle SECURE_MODE environment variable to switch between modes
 * 
 * ⚠️ FOR EDUCATIONAL PURPOSES ONLY - Never deploy vulnerable code in production!
 */

const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const { body, validationResult } = require('express-validator');
const winston = require('winston');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 12000;
const SECURE_MODE = process.env.SECURE_MODE === 'true';

// ============================================================================
// LOGGING SETUP - Essential for attack detection
// ============================================================================
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/security.log' }),
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    })
  ]
});

// ============================================================================
// DATABASE SETUP
// ============================================================================
const db = new Database(':memory:');

// Create tables
db.exec(`
  CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email TEXT,
    role TEXT DEFAULT 'user',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  
  CREATE TABLE posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
  
  CREATE TABLE comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER,
    user_id INTEGER,
    content TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (post_id) REFERENCES posts(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
  
  CREATE TABLE security_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    details TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// Insert sample data with hashed passwords
const hashedPassword = bcrypt.hashSync('password123', 10);
const adminPassword = bcrypt.hashSync('admin_secret_2024', 10);

db.exec(`
  INSERT INTO users (username, password, email, role) VALUES 
    ('admin', '${adminPassword}', 'admin@example.com', 'admin'),
    ('alice', '${hashedPassword}', 'alice@example.com', 'user'),
    ('bob', '${hashedPassword}', 'bob@example.com', 'user');
    
  INSERT INTO posts (user_id, title, content) VALUES
    (1, 'Welcome to Security Lab', 'Learn about web security through hands-on practice!'),
    (2, 'My First Post', 'Hello everyone, this is Alice!'),
    (3, 'Security Tips', 'Always use strong passwords and enable 2FA.');
`);

// ============================================================================
// SECURITY MIDDLEWARE (Applied in SECURE_MODE)
// ============================================================================

if (SECURE_MODE) {
  // Helmet adds various security headers
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"],
        frameSrc: ["'none'"],
      },
    },
    crossOriginEmbedderPolicy: false,
  }));
  
  // Rate limiting to prevent brute force attacks
  const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: { error: 'Too many requests, please try again later.' },
    handler: (req, res) => {
      logSecurityEvent('RATE_LIMIT_EXCEEDED', req, 'Rate limit exceeded');
      res.status(429).json({ error: 'Too many requests, please try again later.' });
    }
  });
  app.use(limiter);
  
  // Stricter rate limit for login attempts
  const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5, // only 5 login attempts per 15 minutes
    message: { error: 'Too many login attempts, please try again later.' },
    handler: (req, res) => {
      logSecurityEvent('LOGIN_RATE_LIMIT', req, 'Login rate limit exceeded');
      res.status(429).json({ error: 'Too many login attempts, please try again later.' });
    }
  });
  app.use('/api/login', loginLimiter);
  
  logger.info('🔒 SECURE MODE ENABLED - All security features active');
} else {
  logger.warn('⚠️ VULNERABLE MODE - Security features disabled for educational purposes');
}

// Basic middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Session configuration
app.use(session({
  secret: SECURE_MODE ? uuidv4() : 'insecure-secret-key', // Secure: random, Vulnerable: predictable
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false, // Set to true in production with HTTPS
    httpOnly: SECURE_MODE, // Secure: true, Vulnerable: false
    sameSite: SECURE_MODE ? 'strict' : 'none', // CSRF protection
    maxAge: 3600000 // 1 hour
  }
}));

// ============================================================================
// SECURITY LOGGING FUNCTION
// ============================================================================
function logSecurityEvent(eventType, req, details) {
  const logEntry = {
    event_type: eventType,
    ip_address: req.ip || req.connection.remoteAddress,
    user_agent: req.get('User-Agent'),
    details: details,
    timestamp: new Date().toISOString()
  };
  
  logger.warn(`SECURITY EVENT: ${eventType}`, logEntry);
  
  // Store in database for analysis
  try {
    db.prepare(`
      INSERT INTO security_logs (event_type, ip_address, user_agent, details)
      VALUES (?, ?, ?, ?)
    `).run(eventType, logEntry.ip_address, logEntry.user_agent, details);
  } catch (err) {
    logger.error('Failed to log security event to database', err);
  }
}

// ============================================================================
// ATTACK DETECTION PATTERNS
// ============================================================================
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
  if (!input || typeof input !== 'string') return null;
  
  for (const [attackType, patterns] of Object.entries(ATTACK_PATTERNS)) {
    for (const pattern of patterns) {
      if (pattern.test(input)) {
        logSecurityEvent(`ATTACK_DETECTED_${attackType}`, req, `Suspicious input: ${input.substring(0, 100)}`);
        return attackType;
      }
    }
  }
  return null;
}

// Middleware to detect attacks (always active for logging)
app.use((req, res, next) => {
  // Check all input sources
  const inputs = [
    ...Object.values(req.query || {}),
    ...Object.values(req.body || {}),
    ...Object.values(req.params || {})
  ];
  
  for (const input of inputs) {
    if (typeof input === 'string') {
      const attackType = detectAttackPatterns(input, req);
      if (attackType && SECURE_MODE) {
        return res.status(400).json({ 
          error: 'Potentially malicious input detected',
          blocked: true 
        });
      }
    }
  }
  next();
});

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

// HTML encoding to prevent XSS
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

// Input validation
function validateInput(input, type) {
  if (!input) return false;
  
  const patterns = {
    username: /^[a-zA-Z0-9_]{3,20}$/,
    email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
    alphanumeric: /^[a-zA-Z0-9\s]+$/
  };
  
  return patterns[type] ? patterns[type].test(input) : true;
}

// Authentication middleware
function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  next();
}

// Admin middleware
function requireAdmin(req, res, next) {
  if (!req.session.userId || req.session.role !== 'admin') {
    logSecurityEvent('UNAUTHORIZED_ADMIN_ACCESS', req, `User ${req.session.userId} attempted admin access`);
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

// ============================================================================
// API ROUTES
// ============================================================================

// Get current mode
app.get('/api/mode', (req, res) => {
  res.json({ 
    secure: SECURE_MODE,
    mode: SECURE_MODE ? 'SECURE' : 'VULNERABLE'
  });
});

// ============================================================================
// AUTHENTICATION ROUTES
// ============================================================================

// LOGIN - Demonstrates SQL Injection vulnerability vs secure implementation
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }
  
  try {
    let user;
    
    if (SECURE_MODE) {
      // SECURE: Parameterized query prevents SQL injection
      user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
      
      if (!user || !bcrypt.compareSync(password, user.password)) {
        logSecurityEvent('LOGIN_FAILED', req, `Failed login attempt for user: ${username}`);
        return res.status(401).json({ error: 'Invalid credentials' });
      }
    } else {
      // VULNERABLE: String concatenation allows SQL injection
      // Example attack: username = "admin'--" or "' OR '1'='1"
      const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
      logger.info(`VULNERABLE QUERY: ${query}`);
      
      try {
        user = db.prepare(query).get();
      } catch (err) {
        // SQL error might reveal information
        return res.status(500).json({ error: `Database error: ${err.message}` });
      }
      
      if (!user) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
    }
    
    // Set session
    req.session.userId = user.id;
    req.session.username = user.username;
    req.session.role = user.role;
    
    logSecurityEvent('LOGIN_SUCCESS', req, `User ${username} logged in`);
    
    res.json({ 
      success: true, 
      user: { 
        id: user.id, 
        username: user.username, 
        role: user.role 
      }
    });
    
  } catch (err) {
    logger.error('Login error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// LOGOUT
app.post('/api/logout', (req, res) => {
  const username = req.session.username;
  req.session.destroy();
  logSecurityEvent('LOGOUT', req, `User ${username} logged out`);
  res.json({ success: true });
});

// GET CURRENT USER
app.get('/api/user', (req, res) => {
  if (!req.session.userId) {
    return res.json({ authenticated: false });
  }
  res.json({
    authenticated: true,
    user: {
      id: req.session.userId,
      username: req.session.username,
      role: req.session.role
    }
  });
});

// ============================================================================
// USER SEARCH - Demonstrates SQL Injection
// ============================================================================
app.get('/api/users/search', (req, res) => {
  const { q } = req.query;
  
  if (!q) {
    return res.status(400).json({ error: 'Search query required' });
  }
  
  try {
    let users;
    
    if (SECURE_MODE) {
      // SECURE: Parameterized query
      users = db.prepare(`
        SELECT id, username, email, role, created_at 
        FROM users 
        WHERE username LIKE ? OR email LIKE ?
      `).all(`%${q}%`, `%${q}%`);
    } else {
      // VULNERABLE: SQL Injection possible
      // Example attack: q = "' UNION SELECT id, username, password, role, created_at FROM users--"
      const query = `SELECT id, username, email, role, created_at FROM users WHERE username LIKE '%${q}%'`;
      logger.info(`VULNERABLE QUERY: ${query}`);
      users = db.prepare(query).all();
    }
    
    res.json({ users });
    
  } catch (err) {
    logger.error('Search error', err);
    res.status(500).json({ error: SECURE_MODE ? 'Search failed' : `Error: ${err.message}` });
  }
});

// ============================================================================
// POSTS ROUTES - Demonstrates XSS vulnerability
// ============================================================================

// GET ALL POSTS
app.get('/api/posts', (req, res) => {
  try {
    const posts = db.prepare(`
      SELECT p.*, u.username 
      FROM posts p 
      JOIN users u ON p.user_id = u.id 
      ORDER BY p.created_at DESC
    `).all();
    
    if (SECURE_MODE) {
      // SECURE: Escape HTML in output
      posts.forEach(post => {
        post.title = escapeHtml(post.title);
        post.content = escapeHtml(post.content);
      });
    }
    // VULNERABLE: Raw HTML output allows XSS
    
    res.json({ posts });
  } catch (err) {
    logger.error('Get posts error', err);
    res.status(500).json({ error: 'Failed to fetch posts' });
  }
});

// CREATE POST
app.post('/api/posts', requireAuth, (req, res) => {
  const { title, content } = req.body;
  
  if (!title || !content) {
    return res.status(400).json({ error: 'Title and content required' });
  }
  
  try {
    let safeTitle = title;
    let safeContent = content;
    
    if (SECURE_MODE) {
      // SECURE: Validate and sanitize input
      if (title.length > 200 || content.length > 10000) {
        return res.status(400).json({ error: 'Content too long' });
      }
      safeTitle = escapeHtml(title);
      safeContent = escapeHtml(content);
    }
    // VULNERABLE: Store raw input (XSS payload stored)
    
    const result = db.prepare(`
      INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)
    `).run(req.session.userId, safeTitle, safeContent);
    
    logSecurityEvent('POST_CREATED', req, `User ${req.session.username} created post ${result.lastInsertRowid}`);
    
    res.json({ 
      success: true, 
      postId: result.lastInsertRowid 
    });
    
  } catch (err) {
    logger.error('Create post error', err);
    res.status(500).json({ error: 'Failed to create post' });
  }
});

// ============================================================================
// COMMENTS - Demonstrates Stored XSS
// ============================================================================
app.post('/api/posts/:postId/comments', requireAuth, (req, res) => {
  const { postId } = req.params;
  const { content } = req.body;
  
  if (!content) {
    return res.status(400).json({ error: 'Comment content required' });
  }
  
  try {
    let safeContent = content;
    
    if (SECURE_MODE) {
      // SECURE: Sanitize input
      if (content.length > 1000) {
        return res.status(400).json({ error: 'Comment too long' });
      }
      safeContent = escapeHtml(content);
    }
    
    const result = db.prepare(`
      INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)
    `).run(postId, req.session.userId, safeContent);
    
    res.json({ success: true, commentId: result.lastInsertRowid });
    
  } catch (err) {
    logger.error('Create comment error', err);
    res.status(500).json({ error: 'Failed to create comment' });
  }
});

app.get('/api/posts/:postId/comments', (req, res) => {
  const { postId } = req.params;
  
  try {
    const comments = db.prepare(`
      SELECT c.*, u.username 
      FROM comments c 
      JOIN users u ON c.user_id = u.id 
      WHERE c.post_id = ?
      ORDER BY c.created_at ASC
    `).all(postId);
    
    if (SECURE_MODE) {
      comments.forEach(comment => {
        comment.content = escapeHtml(comment.content);
      });
    }
    
    res.json({ comments });
    
  } catch (err) {
    logger.error('Get comments error', err);
    res.status(500).json({ error: 'Failed to fetch comments' });
  }
});

// ============================================================================
// PROFILE UPDATE - Demonstrates CSRF vulnerability
// ============================================================================
app.post('/api/profile/update', requireAuth, (req, res) => {
  const { email } = req.body;
  
  // In SECURE_MODE, we would validate CSRF token here
  // For this demo, we're showing the concept
  
  if (SECURE_MODE) {
    // SECURE: Validate email format
    if (!validateInput(email, 'email')) {
      return res.status(400).json({ error: 'Invalid email format' });
    }
  }
  
  try {
    db.prepare('UPDATE users SET email = ? WHERE id = ?').run(email, req.session.userId);
    logSecurityEvent('PROFILE_UPDATED', req, `User ${req.session.username} updated email to ${email}`);
    res.json({ success: true });
  } catch (err) {
    logger.error('Profile update error', err);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// ============================================================================
// ADMIN ROUTES - Demonstrates Authorization bypass
// ============================================================================
app.get('/api/admin/users', requireAdmin, (req, res) => {
  try {
    const users = db.prepare('SELECT id, username, email, role, created_at FROM users').all();
    res.json({ users });
  } catch (err) {
    logger.error('Admin users error', err);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

app.get('/api/admin/logs', requireAdmin, (req, res) => {
  try {
    const logs = db.prepare(`
      SELECT * FROM security_logs 
      ORDER BY created_at DESC 
      LIMIT 100
    `).all();
    res.json({ logs });
  } catch (err) {
    logger.error('Admin logs error', err);
    res.status(500).json({ error: 'Failed to fetch logs' });
  }
});

// VULNERABLE: Direct object reference without proper authorization
app.get('/api/users/:id', (req, res) => {
  const { id } = req.params;
  
  try {
    if (SECURE_MODE) {
      // SECURE: Only allow users to view their own profile or admin to view all
      if (req.session.userId != id && req.session.role !== 'admin') {
        logSecurityEvent('IDOR_ATTEMPT', req, `User ${req.session.userId} tried to access user ${id}`);
        return res.status(403).json({ error: 'Access denied' });
      }
    }
    // VULNERABLE: Any authenticated user can view any profile
    
    const user = db.prepare('SELECT id, username, email, role, created_at FROM users WHERE id = ?').get(id);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({ user });
    
  } catch (err) {
    logger.error('Get user error', err);
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

// ============================================================================
// SECURITY TESTING ENDPOINTS (Educational)
// ============================================================================

// Endpoint to view security logs (for learning)
app.get('/api/security/logs', (req, res) => {
  try {
    const logs = db.prepare(`
      SELECT * FROM security_logs 
      ORDER BY created_at DESC 
      LIMIT 50
    `).all();
    res.json({ logs, mode: SECURE_MODE ? 'SECURE' : 'VULNERABLE' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch logs' });
  }
});

// Endpoint to clear logs (for testing)
app.delete('/api/security/logs', (req, res) => {
  try {
    db.prepare('DELETE FROM security_logs').run();
    res.json({ success: true, message: 'Logs cleared' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to clear logs' });
  }
});

// ============================================================================
// ERROR HANDLING
// ============================================================================
app.use((err, req, res, next) => {
  logger.error('Unhandled error', { error: err.message, stack: err.stack });
  
  if (SECURE_MODE) {
    // SECURE: Generic error message
    res.status(500).json({ error: 'An error occurred' });
  } else {
    // VULNERABLE: Detailed error information
    res.status(500).json({ 
      error: err.message,
      stack: err.stack 
    });
  }
});

// ============================================================================
// START SERVER
// ============================================================================
app.listen(PORT, '0.0.0.0', () => {
  console.log(`
╔══════════════════════════════════════════════════════════════════╗
║                    WEB SECURITY LAB                              ║
╠══════════════════════════════════════════════════════════════════╣
║  Mode: ${SECURE_MODE ? '🔒 SECURE' : '⚠️  VULNERABLE'}                                          ║
║  Port: ${PORT}                                                     ║
║                                                                  ║
║  ${SECURE_MODE ? 'All security features are ENABLED' : 'Security features DISABLED for educational testing'}              ║
╚══════════════════════════════════════════════════════════════════╝

📚 EDUCATIONAL ENDPOINTS:
   - GET  /api/mode              - Check current security mode
   - POST /api/login             - Login (try SQL injection in vulnerable mode)
   - GET  /api/users/search?q=   - Search users (SQL injection demo)
   - GET  /api/posts             - Get posts (XSS demo)
   - POST /api/posts             - Create post (stored XSS demo)
   - GET  /api/security/logs     - View security event logs

🔑 TEST CREDENTIALS:
   - admin / admin_secret_2024 (admin user)
   - alice / password123 (regular user)
   - bob / password123 (regular user)
  `);
});

module.exports = app;
