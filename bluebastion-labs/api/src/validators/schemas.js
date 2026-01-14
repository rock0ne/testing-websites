/**
 * BlueBastion Labs - Input Validation Schemas
 * 
 * SECURITY RATIONALE:
 * - All user input MUST be validated before processing
 * - Prevents injection attacks (SQL, NoSQL, Command, XSS)
 * - Uses Zod for type-safe schema validation
 * - Maps to: MITRE ATT&CK T1190 (Exploit Public-Facing Application)
 */

const { z } = require('zod');
const securityConfig = require('../../config/security');

// ============================================================================
// COMMON PATTERNS
// ============================================================================

// UUID v4 pattern
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// Safe string pattern - alphanumeric with limited special chars
const safeStringPattern = /^[a-zA-Z0-9\s\-_.,!?@#$%&*()+=:;'"]+$/;

// Username pattern - alphanumeric, underscore, hyphen
const usernamePattern = /^[a-zA-Z][a-zA-Z0-9_-]{2,29}$/;

// Email pattern (RFC 5322 simplified)
const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// ============================================================================
// AUTHENTICATION SCHEMAS
// ============================================================================

/**
 * Login Request Schema
 * 
 * SECURITY CONTROLS:
 * - Username: alphanumeric only, prevents injection
 * - Password: no pattern restriction (would leak info), but length limited
 */
const loginSchema = z.object({
  username: z.string()
    .min(3, 'Username must be at least 3 characters')
    .max(30, 'Username must not exceed 30 characters')
    .regex(usernamePattern, 'Username must start with a letter and contain only letters, numbers, underscores, or hyphens'),
  
  password: z.string()
    .min(1, 'Password is required')
    .max(128, 'Password must not exceed 128 characters'),
  
  // Optional MFA token
  mfaToken: z.string()
    .length(6, 'MFA token must be 6 digits')
    .regex(/^\d{6}$/, 'MFA token must contain only digits')
    .optional()
});

/**
 * Registration Schema
 * 
 * SECURITY CONTROLS:
 * - Enforces password policy
 * - Validates email format
 * - Limits field lengths to prevent DoS
 */
const registrationSchema = z.object({
  username: z.string()
    .min(3, 'Username must be at least 3 characters')
    .max(30, 'Username must not exceed 30 characters')
    .regex(usernamePattern, 'Username must start with a letter and contain only letters, numbers, underscores, or hyphens'),
  
  email: z.string()
    .email('Invalid email format')
    .max(254, 'Email must not exceed 254 characters')
    .toLowerCase(),
  
  password: z.string()
    .min(securityConfig.password.minLength, `Password must be at least ${securityConfig.password.minLength} characters`)
    .max(128, 'Password must not exceed 128 characters')
    .refine(
      (val) => !securityConfig.password.requireUppercase || /[A-Z]/.test(val),
      'Password must contain at least one uppercase letter'
    )
    .refine(
      (val) => !securityConfig.password.requireLowercase || /[a-z]/.test(val),
      'Password must contain at least one lowercase letter'
    )
    .refine(
      (val) => !securityConfig.password.requireNumbers || /\d/.test(val),
      'Password must contain at least one number'
    )
    .refine(
      (val) => !securityConfig.password.requireSpecialChars || /[!@#$%^&*(),.?":{}|<>]/.test(val),
      'Password must contain at least one special character'
    ),
  
  confirmPassword: z.string(),
  
  firstName: z.string()
    .min(1, 'First name is required')
    .max(50, 'First name must not exceed 50 characters')
    .regex(/^[a-zA-Z\s'-]+$/, 'First name contains invalid characters'),
  
  lastName: z.string()
    .min(1, 'Last name is required')
    .max(50, 'Last name must not exceed 50 characters')
    .regex(/^[a-zA-Z\s'-]+$/, 'Last name contains invalid characters')
    
}).refine((data) => data.password === data.confirmPassword, {
  message: 'Passwords do not match',
  path: ['confirmPassword']
});

/**
 * Password Change Schema
 */
const passwordChangeSchema = z.object({
  currentPassword: z.string()
    .min(1, 'Current password is required')
    .max(128),
  
  newPassword: z.string()
    .min(securityConfig.password.minLength, `Password must be at least ${securityConfig.password.minLength} characters`)
    .max(128, 'Password must not exceed 128 characters')
    .refine(
      (val) => !securityConfig.password.requireUppercase || /[A-Z]/.test(val),
      'Password must contain at least one uppercase letter'
    )
    .refine(
      (val) => !securityConfig.password.requireLowercase || /[a-z]/.test(val),
      'Password must contain at least one lowercase letter'
    )
    .refine(
      (val) => !securityConfig.password.requireNumbers || /\d/.test(val),
      'Password must contain at least one number'
    )
    .refine(
      (val) => !securityConfig.password.requireSpecialChars || /[!@#$%^&*(),.?":{}|<>]/.test(val),
      'Password must contain at least one special character'
    ),
  
  confirmNewPassword: z.string()
}).refine((data) => data.newPassword === data.confirmNewPassword, {
  message: 'Passwords do not match',
  path: ['confirmNewPassword']
}).refine((data) => data.currentPassword !== data.newPassword, {
  message: 'New password must be different from current password',
  path: ['newPassword']
});

// ============================================================================
// RESOURCE SCHEMAS
// ============================================================================

/**
 * Project Schema
 * 
 * Example resource for demonstrating CRUD validation
 */
const projectSchema = z.object({
  name: z.string()
    .min(3, 'Project name must be at least 3 characters')
    .max(100, 'Project name must not exceed 100 characters')
    .regex(safeStringPattern, 'Project name contains invalid characters'),
  
  description: z.string()
    .max(2000, 'Description must not exceed 2000 characters')
    .optional(),
  
  status: z.enum(['draft', 'active', 'completed', 'archived'])
    .default('draft'),
  
  priority: z.enum(['low', 'medium', 'high', 'critical'])
    .default('medium'),
  
  tags: z.array(
    z.string()
      .min(1)
      .max(30)
      .regex(/^[a-zA-Z0-9-]+$/, 'Tags must be alphanumeric')
  )
    .max(10, 'Maximum 10 tags allowed')
    .optional(),
  
  dueDate: z.string()
    .datetime({ message: 'Invalid date format' })
    .optional()
});

/**
 * Project Update Schema (partial)
 */
const projectUpdateSchema = projectSchema.partial();

/**
 * Document Schema
 */
const documentSchema = z.object({
  title: z.string()
    .min(1, 'Title is required')
    .max(200, 'Title must not exceed 200 characters')
    .regex(safeStringPattern, 'Title contains invalid characters'),
  
  content: z.string()
    .max(50000, 'Content must not exceed 50000 characters'),
  
  projectId: z.string()
    .regex(uuidPattern, 'Invalid project ID format'),
  
  visibility: z.enum(['private', 'team', 'public'])
    .default('private')
});

// ============================================================================
// QUERY PARAMETER SCHEMAS
// ============================================================================

/**
 * Pagination Schema
 * 
 * SECURITY: Limits page size to prevent DoS via large queries
 */
const paginationSchema = z.object({
  page: z.coerce.number()
    .int()
    .min(1)
    .default(1),
  
  limit: z.coerce.number()
    .int()
    .min(1)
    .max(100, 'Maximum 100 items per page')
    .default(20),
  
  sortBy: z.string()
    .regex(/^[a-zA-Z_]+$/, 'Invalid sort field')
    .optional(),
  
  sortOrder: z.enum(['asc', 'desc'])
    .default('desc')
});

/**
 * Search Schema
 * 
 * SECURITY: Sanitizes search input to prevent injection
 */
const searchSchema = z.object({
  q: z.string()
    .min(1, 'Search query is required')
    .max(200, 'Search query too long')
    .transform((val) => {
      // Remove potentially dangerous characters
      return val.replace(/[<>'"`;\\]/g, '');
    }),
  
  fields: z.array(z.string().regex(/^[a-zA-Z_]+$/))
    .max(10)
    .optional()
});

// ============================================================================
// ID PARAMETER SCHEMA
// ============================================================================

/**
 * UUID Parameter Schema
 * 
 * SECURITY: Validates ID format to prevent injection
 */
const idParamSchema = z.object({
  id: z.string()
    .regex(uuidPattern, 'Invalid ID format')
});

// ============================================================================
// VALIDATION MIDDLEWARE FACTORY
// ============================================================================

/**
 * Creates validation middleware for a given schema
 * 
 * @param {z.ZodSchema} schema - Zod schema to validate against
 * @param {string} source - Request property to validate ('body', 'query', 'params')
 */
const validate = (schema, source = 'body') => {
  return (req, res, next) => {
    try {
      const result = schema.safeParse(req[source]);
      
      if (!result.success) {
        // Log validation failure for security monitoring
        req.app.locals.logger?.warn('VALIDATION_FAILED', {
          ip: req.ip,
          path: req.path,
          method: req.method,
          source,
          errors: result.error.errors.map(e => ({
            field: e.path.join('.'),
            message: e.message
          })),
          requestId: req.requestId,
          // MITRE ATT&CK: T1190 - Exploit Public-Facing Application
          mitre: 'T1190'
        });
        
        return res.status(400).json({
          error: 'Validation failed',
          details: result.error.errors.map(e => ({
            field: e.path.join('.'),
            message: e.message
          }))
        });
      }
      
      // Replace request data with validated/transformed data
      req[source] = result.data;
      next();
    } catch (err) {
      req.app.locals.logger?.error('VALIDATION_ERROR', {
        ip: req.ip,
        path: req.path,
        error: err.message,
        requestId: req.requestId
      });
      
      return res.status(500).json({ error: 'Validation error' });
    }
  };
};

module.exports = {
  // Schemas
  loginSchema,
  registrationSchema,
  passwordChangeSchema,
  projectSchema,
  projectUpdateSchema,
  documentSchema,
  paginationSchema,
  searchSchema,
  idParamSchema,
  
  // Middleware factory
  validate,
  
  // Patterns for reuse
  patterns: {
    uuid: uuidPattern,
    safeString: safeStringPattern,
    username: usernamePattern,
    email: emailPattern
  }
};
