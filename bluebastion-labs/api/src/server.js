/**
 * BlueBastion Labs - Secure API Server
 * 
 * A secure REST API demonstrating:
 * - JWT authentication with refresh tokens
 * - Input validation with Zod
 * - Rate limiting
 * - Security headers
 * - Structured logging for SIEM integration
 * - RBAC authorization
 * - IDOR prevention
 */

const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');

// Security middleware
const {
  requestId,
  securityHeaders,
  generalLimiter
} = require('./middleware/security');

// Logger
const logger = require('./utils/logger');

// Routes
const authRoutes = require('./routes/auth');
const projectRoutes = require('./routes/projects');

// Configuration
const securityConfig = require('../config/security');

// ============================================================================
// APP INITIALIZATION
// ============================================================================

const app = express();
const PORT = process.env.PORT || 12001;

// Ensure logs directory exists
const logDir = path.join(__dirname, '../logs');
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir, { recursive: true });
}

// Make logger available to routes
app.locals.logger = logger;

// ============================================================================
// MIDDLEWARE STACK
// ============================================================================

// 1. Request ID (first - for correlation)
app.use(requestId);

// 2. Security headers
app.use(securityHeaders);

// 3. CORS
app.use(cors(securityConfig.cors));

// 4. Body parsing
app.use(express.json({ limit: '10kb' })); // Limit body size
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// 5. Cookie parsing
app.use(cookieParser());

// 6. Request logging
app.use(logger.requestLogger());

// 7. Rate limiting (general)
app.use(generalLimiter);

// ============================================================================
// HEALTH CHECK (No auth required)
// ============================================================================

app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

// ============================================================================
// API ROUTES
// ============================================================================

app.use('/api/auth', authRoutes);
app.use('/api/projects', projectRoutes);

// ============================================================================
// API DOCUMENTATION ENDPOINT
// ============================================================================

app.get('/api', (req, res) => {
  res.json({
    name: 'BlueBastion Labs API',
    version: '1.0.0',
    description: 'Secure API for BlueBastion Labs - Educational Purpose',
    endpoints: {
      auth: {
        'POST /api/auth/login': 'User login',
        'POST /api/auth/register': 'User registration',
        'POST /api/auth/refresh': 'Refresh access token',
        'POST /api/auth/logout': 'Logout',
        'GET /api/auth/me': 'Get current user'
      },
      projects: {
        'GET /api/projects': 'List projects',
        'GET /api/projects/:id': 'Get project by ID',
        'POST /api/projects': 'Create project',
        'PUT /api/projects/:id': 'Update project',
        'DELETE /api/projects/:id': 'Delete project'
      }
    },
    testCredentials: {
      admin: { username: 'admin', password: 'Admin@123456!' },
      analyst: { username: 'analyst', password: 'Analyst@123456!' },
      viewer: { username: 'viewer', password: 'Viewer@123456!' }
    }
  });
});

// ============================================================================
// ERROR HANDLING
// ============================================================================

// 404 handler
app.use((req, res) => {
  logger.warn('NOT_FOUND', {
    method: req.method,
    path: req.path,
    ip: req.ip,
    requestId: req.requestId
  });
  
  res.status(404).json({ error: 'Endpoint not found' });
});

// Global error handler
app.use((err, req, res, next) => {
  logger.error('UNHANDLED_ERROR', {
    error: err.message,
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
    path: req.path,
    method: req.method,
    requestId: req.requestId
  });
  
  // Don't leak error details in production
  res.status(500).json({
    error: process.env.NODE_ENV === 'development' 
      ? err.message 
      : 'Internal server error'
  });
});

// ============================================================================
// START SERVER
// ============================================================================

app.listen(PORT, '0.0.0.0', () => {
  console.log(`
╔══════════════════════════════════════════════════════════════════╗
║              BlueBastion Labs - Secure API Server                ║
╠══════════════════════════════════════════════════════════════════╣
║  Port: ${PORT}                                                     ║
║  Environment: ${process.env.NODE_ENV || 'development'}                                  ║
║                                                                  ║
║  Security Controls:                                              ║
║  ✓ JWT Authentication                                            ║
║  ✓ Input Validation (Zod)                                        ║
║  ✓ Rate Limiting                                                 ║
║  ✓ Security Headers (Helmet)                                     ║
║  ✓ RBAC Authorization                                            ║
║  ✓ Audit Logging                                                 ║
╚══════════════════════════════════════════════════════════════════╝

📚 API Documentation: http://localhost:${PORT}/api
🔑 Test Credentials:
   - admin / Admin@123456!
   - analyst / Analyst@123456!
   - viewer / Viewer@123456!
  `);
  
  logger.info('SERVER_STARTED', {
    port: PORT,
    environment: process.env.NODE_ENV || 'development'
  });
});

module.exports = app;
