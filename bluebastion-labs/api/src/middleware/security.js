/**
 * BlueBastion Labs - Security Middleware
 * 
 * This module implements core security controls:
 * 1. Request ID tracking (for log correlation)
 * 2. Security headers (via Helmet)
 * 3. Rate limiting
 * 4. Input sanitization
 * 5. JWT authentication
 */

const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const securityConfig = require('../../config/security');

/**
 * REQUEST ID MIDDLEWARE
 * 
 * SECURITY RATIONALE:
 * - Assigns unique ID to each request for log correlation
 * - Essential for incident investigation and forensics
 * - Maps to: MITRE ATT&CK detection of T1078, T1190
 */
const requestId = (req, res, next) => {
  // Use client-provided ID if valid UUID, otherwise generate new one
  const clientId = req.headers['x-request-id'];
  const isValidUuid = clientId && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(clientId);
  
  req.requestId = isValidUuid ? clientId : uuidv4();
  res.setHeader('X-Request-ID', req.requestId);
  next();
};

/**
 * SECURITY HEADERS MIDDLEWARE
 * 
 * SECURITY RATIONALE:
 * - Content-Security-Policy: Prevents XSS by controlling resource loading
 * - X-Frame-Options: Prevents clickjacking
 * - X-Content-Type-Options: Prevents MIME sniffing
 * - Strict-Transport-Security: Forces HTTPS
 */
const securityHeaders = helmet({
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
      upgradeInsecureRequests: []
    }
  },
  crossOriginEmbedderPolicy: false,
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
});

/**
 * RATE LIMITERS
 * 
 * SECURITY RATIONALE:
 * - Prevents brute force attacks (T1110)
 * - Mitigates DoS attempts
 * - Different limits for different endpoint sensitivity
 */
const generalLimiter = rateLimit({
  ...securityConfig.rateLimit.general,
  keyGenerator: (req) => {
    return req.headers['x-forwarded-for']?.split(',')[0] || req.ip;
  },
  handler: (req, res) => {
    req.app.locals.logger?.warn('RATE_LIMIT_EXCEEDED', {
      ip: req.ip,
      path: req.path,
      requestId: req.requestId
    });
    res.status(429).json(securityConfig.rateLimit.general.message);
  }
});

const authLimiter = rateLimit({
  ...securityConfig.rateLimit.auth,
  keyGenerator: (req) => {
    const username = req.body?.username || req.body?.email || 'unknown';
    const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.ip;
    return `${ip}:${username}`;
  },
  handler: (req, res) => {
    req.app.locals.logger?.warn('AUTH_RATE_LIMIT_EXCEEDED', {
      ip: req.ip,
      username: req.body?.username || req.body?.email,
      requestId: req.requestId,
      mitre: 'T1110'
    });
    res.status(429).json(securityConfig.rateLimit.auth.message);
  }
});

/**
 * JWT AUTHENTICATION MIDDLEWARE
 * 
 * SECURITY RATIONALE:
 * - Validates JWT tokens for protected routes
 * - Checks expiration, issuer, audience
 * - Logs authentication failures for detection
 */
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    req.app.locals.logger?.warn('AUTH_MISSING_TOKEN', {
      ip: req.ip,
      path: req.path,
      requestId: req.requestId
    });
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  const token = authHeader.split(' ')[1];
  
  try {
    const decoded = jwt.verify(token, securityConfig.jwt.secret, {
      algorithms: [securityConfig.jwt.algorithm],
      issuer: securityConfig.jwt.issuer,
      audience: securityConfig.jwt.audience
    });
    
    req.user = {
      id: decoded.sub,
      username: decoded.username,
      role: decoded.role,
      permissions: decoded.permissions || []
    };
    
    req.app.locals.logger?.info('AUTH_SUCCESS', {
      userId: decoded.sub,
      username: decoded.username,
      ip: req.ip,
      path: req.path,
      requestId: req.requestId
    });
    
    next();
  } catch (err) {
    let errorType = 'AUTH_TOKEN_INVALID';
    if (err.name === 'TokenExpiredError') {
      errorType = 'AUTH_TOKEN_EXPIRED';
    } else if (err.name === 'JsonWebTokenError') {
      errorType = 'AUTH_TOKEN_MALFORMED';
    }
    
    req.app.locals.logger?.warn(errorType, {
      ip: req.ip,
      path: req.path,
      requestId: req.requestId,
      error: err.message,
      mitre: 'T1078'
    });
    
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};

/**
 * OPTIONAL AUTHENTICATION
 */
const optionalAuth = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    req.user = null;
    return next();
  }
  
  const token = authHeader.split(' ')[1];
  
  try {
    const decoded = jwt.verify(token, securityConfig.jwt.secret, {
      algorithms: [securityConfig.jwt.algorithm],
      issuer: securityConfig.jwt.issuer,
      audience: securityConfig.jwt.audience
    });
    
    req.user = {
      id: decoded.sub,
      username: decoded.username,
      role: decoded.role,
      permissions: decoded.permissions || []
    };
  } catch (err) {
    req.user = null;
  }
  
  next();
};

/**
 * ROLE-BASED ACCESS CONTROL MIDDLEWARE
 */
const requireRole = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    if (!allowedRoles.includes(req.user.role)) {
      req.app.locals.logger?.warn('AUTHZ_ROLE_DENIED', {
        userId: req.user.id,
        userRole: req.user.role,
        requiredRoles: allowedRoles,
        path: req.path,
        method: req.method,
        requestId: req.requestId,
        mitre: 'T1078.001'
      });
      
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    
    next();
  };
};

/**
 * PERMISSION-BASED ACCESS CONTROL
 */
const requirePermission = (...requiredPermissions) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    const hasPermission = requiredPermissions.every(
      perm => req.user.permissions.includes(perm)
    );
    
    if (!hasPermission) {
      req.app.locals.logger?.warn('AUTHZ_PERMISSION_DENIED', {
        userId: req.user.id,
        userPermissions: req.user.permissions,
        requiredPermissions,
        path: req.path,
        method: req.method,
        requestId: req.requestId
      });
      
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    
    next();
  };
};

module.exports = {
  requestId,
  securityHeaders,
  generalLimiter,
  authLimiter,
  authenticateJWT,
  optionalAuth,
  requireRole,
  requirePermission
};
