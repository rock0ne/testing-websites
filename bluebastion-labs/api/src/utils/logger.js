/**
 * BlueBastion Labs - Security-Focused Logger
 * 
 * SECURITY RATIONALE:
 * - Structured logging for SIEM integration (Microsoft Sentinel)
 * - Automatic redaction of sensitive fields
 * - Correlation IDs for incident investigation
 * - CEF/JSON format for Defender ingestion
 * 
 * LOG FORWARDING:
 * - Logs are written to files that can be forwarded to:
 *   - Microsoft Sentinel via Azure Monitor Agent
 *   - Defender for Endpoint via custom connectors
 *   - Syslog for traditional SIEM
 */

const winston = require('winston');
const path = require('path');
const securityConfig = require('../../config/security');

// ============================================================================
// SENSITIVE DATA REDACTION
// ============================================================================

/**
 * Redacts sensitive fields from log objects
 * 
 * SECURITY: Prevents accidental logging of credentials, tokens, etc.
 */
const redactSensitiveData = (obj, fieldsToRedact = securityConfig.logging.redactFields) => {
  if (!obj || typeof obj !== 'object') return obj;
  
  const redacted = Array.isArray(obj) ? [...obj] : { ...obj };
  
  for (const key of Object.keys(redacted)) {
    const lowerKey = key.toLowerCase();
    
    // Check if field should be redacted
    if (fieldsToRedact.some(field => lowerKey.includes(field.toLowerCase()))) {
      redacted[key] = '[REDACTED]';
    } else if (typeof redacted[key] === 'object' && redacted[key] !== null) {
      // Recursively redact nested objects
      redacted[key] = redactSensitiveData(redacted[key], fieldsToRedact);
    }
  }
  
  return redacted;
};

// ============================================================================
// CUSTOM LOG FORMATS
// ============================================================================

/**
 * JSON format for SIEM ingestion
 * Compatible with Microsoft Sentinel and Defender
 */
const jsonFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DDTHH:mm:ss.SSSZ' }),
  winston.format.errors({ stack: true }),
  winston.format((info) => {
    // Redact sensitive data
    return redactSensitiveData(info);
  })(),
  winston.format.json()
);

/**
 * Human-readable format for console/development
 */
const consoleFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.colorize(),
  winston.format.printf(({ timestamp, level, message, ...meta }) => {
    const metaStr = Object.keys(meta).length ? JSON.stringify(redactSensitiveData(meta), null, 2) : '';
    return `${timestamp} [${level}] ${message} ${metaStr}`;
  })
);

/**
 * CEF (Common Event Format) for traditional SIEM
 * Format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
 */
const cefFormat = winston.format.combine(
  winston.format.timestamp(),
  winston.format((info) => {
    const severity = {
      error: 10,
      warn: 7,
      info: 5,
      debug: 3
    }[info.level] || 5;
    
    const extension = Object.entries(redactSensitiveData(info))
      .filter(([key]) => !['level', 'message', 'timestamp'].includes(key))
      .map(([key, value]) => `${key}=${typeof value === 'object' ? JSON.stringify(value) : value}`)
      .join(' ');
    
    info.cef = `CEF:0|BlueBastion|API|1.0|${info.eventType || 'GENERIC'}|${info.message}|${severity}|${extension}`;
    return info;
  })(),
  winston.format.printf(({ cef }) => cef)
);

// ============================================================================
// LOGGER INSTANCE
// ============================================================================

const logDir = process.env.LOG_DIR || path.join(__dirname, '../../logs');

const logger = winston.createLogger({
  level: securityConfig.logging.level,
  defaultMeta: {
    service: 'bluebastion-api',
    environment: process.env.NODE_ENV || 'development'
  },
  transports: [
    // JSON logs for SIEM (primary)
    new winston.transports.File({
      filename: path.join(logDir, 'api.json'),
      format: jsonFormat,
      maxsize: 10 * 1024 * 1024,  // 10MB
      maxFiles: 10,
      tailable: true
    }),
    
    // Security-specific logs (for Defender/Sentinel)
    new winston.transports.File({
      filename: path.join(logDir, 'security.json'),
      format: jsonFormat,
      level: 'warn',  // Only warnings and above
      maxsize: 10 * 1024 * 1024,
      maxFiles: 10,
      tailable: true
    }),
    
    // Error logs
    new winston.transports.File({
      filename: path.join(logDir, 'error.json'),
      format: jsonFormat,
      level: 'error',
      maxsize: 10 * 1024 * 1024,
      maxFiles: 5
    }),
    
    // CEF format for traditional SIEM
    new winston.transports.File({
      filename: path.join(logDir, 'api.cef'),
      format: cefFormat,
      maxsize: 10 * 1024 * 1024,
      maxFiles: 5
    })
  ]
});

// Add console transport in development
if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: consoleFormat
  }));
}

// ============================================================================
// SECURITY EVENT LOGGING HELPERS
// ============================================================================

/**
 * Log authentication events
 * 
 * @param {string} eventType - AUTH_SUCCESS, AUTH_FAILED, AUTH_LOGOUT, etc.
 * @param {object} details - Event details
 */
logger.authEvent = (eventType, details) => {
  const level = eventType.includes('FAILED') || eventType.includes('DENIED') ? 'warn' : 'info';
  logger.log(level, eventType, {
    eventType,
    category: 'authentication',
    ...details
  });
};

/**
 * Log authorization events
 */
logger.authzEvent = (eventType, details) => {
  const level = eventType.includes('DENIED') ? 'warn' : 'info';
  logger.log(level, eventType, {
    eventType,
    category: 'authorization',
    ...details
  });
};

/**
 * Log security violations
 * 
 * @param {string} eventType - RATE_LIMIT, VALIDATION_FAILED, INJECTION_ATTEMPT, etc.
 * @param {object} details - Event details including MITRE ATT&CK mapping
 */
logger.securityEvent = (eventType, details) => {
  logger.warn(eventType, {
    eventType,
    category: 'security',
    severity: details.severity || 'medium',
    ...details
  });
};

/**
 * Log audit trail events
 * 
 * @param {string} action - CREATE, READ, UPDATE, DELETE
 * @param {string} resource - Resource type
 * @param {object} details - Event details
 */
logger.auditEvent = (action, resource, details) => {
  logger.info(`AUDIT_${action}_${resource.toUpperCase()}`, {
    eventType: `AUDIT_${action}`,
    category: 'audit',
    action,
    resource,
    ...details
  });
};

/**
 * Log API request/response
 */
logger.apiEvent = (req, res, responseTime) => {
  const level = res.statusCode >= 400 ? 'warn' : 'info';
  logger.log(level, 'API_REQUEST', {
    eventType: 'API_REQUEST',
    category: 'api',
    method: req.method,
    path: req.path,
    statusCode: res.statusCode,
    responseTime,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    userId: req.user?.id,
    requestId: req.requestId
  });
};

// ============================================================================
// REQUEST LOGGING MIDDLEWARE
// ============================================================================

/**
 * Express middleware for request/response logging
 */
logger.requestLogger = () => {
  return (req, res, next) => {
    const startTime = Date.now();
    
    // Log response when finished
    res.on('finish', () => {
      const responseTime = Date.now() - startTime;
      logger.apiEvent(req, res, responseTime);
    });
    
    next();
  };
};

module.exports = logger;
