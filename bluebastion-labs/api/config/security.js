/**
 * BlueBastion Labs - Security Configuration
 * 
 * SECURITY RATIONALE:
 * - All secrets should come from environment variables or a vault in production
 * - These defaults are for LAB USE ONLY
 * - In production: use Azure Key Vault, HashiCorp Vault, or AWS Secrets Manager
 */

const crypto = require('crypto');

// Generate a secure random secret for lab use if not provided
const generateLabSecret = () => crypto.randomBytes(64).toString('hex');

module.exports = {
  // JWT Configuration
  jwt: {
    // SECURITY: In production, load from vault. Lab uses env var or generated secret.
    secret: process.env.JWT_SECRET || generateLabSecret(),
    
    // SECURITY: Short-lived tokens reduce window of compromise
    accessTokenExpiry: '15m',  // 15 minutes - short lived
    refreshTokenExpiry: '7d',  // 7 days - for refresh flow
    
    // SECURITY: Specify algorithm explicitly to prevent algorithm confusion attacks
    algorithm: 'HS256',
    
    // SECURITY: Issuer and audience validation prevents token misuse
    issuer: 'bluebastion-labs',
    audience: 'bluebastion-api'
  },

  // Rate Limiting Configuration
  rateLimit: {
    // General API rate limit
    general: {
      windowMs: 15 * 60 * 1000,  // 15 minutes
      max: 100,                   // 100 requests per window
      message: { error: 'Too many requests. Please try again later.' },
      standardHeaders: true,      // Return rate limit info in headers
      legacyHeaders: false
    },
    
    // Stricter limit for authentication endpoints
    // SECURITY: Prevents brute force attacks on login
    auth: {
      windowMs: 15 * 60 * 1000,  // 15 minutes
      max: 5,                     // Only 5 attempts
      message: { error: 'Too many authentication attempts. Account temporarily locked.' },
      standardHeaders: true,
      legacyHeaders: false
    },
    
    // API key/token generation limit
    tokenGeneration: {
      windowMs: 60 * 60 * 1000,  // 1 hour
      max: 10,                    // 10 token generations per hour
      message: { error: 'Token generation limit exceeded.' }
    }
  },

  // Password Policy
  password: {
    minLength: 12,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChars: true,
    // SECURITY: bcrypt cost factor - higher = slower but more secure
    bcryptRounds: 12
  },

  // Session Configuration
  session: {
    // SECURITY: Secure cookie settings
    cookie: {
      httpOnly: true,      // Prevent XSS access to cookies
      secure: process.env.NODE_ENV === 'production',  // HTTPS only in prod
      sameSite: 'strict',  // CSRF protection
      maxAge: 3600000      // 1 hour
    }
  },

  // CORS Configuration
  cors: {
    // SECURITY: Whitelist allowed origins - never use '*' in production
    origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID']
  },

  // Logging Configuration
  logging: {
    level: process.env.LOG_LEVEL || 'info',
    // SECURITY: Fields to redact from logs
    redactFields: ['password', 'token', 'authorization', 'cookie', 'secret'],
    // Include these fields in all security logs for correlation
    securityFields: ['ip', 'userAgent', 'userId', 'requestId', 'action']
  }
};
