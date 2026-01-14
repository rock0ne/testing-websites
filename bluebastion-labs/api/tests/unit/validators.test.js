/**
 * BlueBastion Labs - Validator Unit Tests
 * 
 * Tests input validation schemas to ensure:
 * - Valid input is accepted
 * - Invalid input is rejected
 * - Injection attempts are blocked
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');

const {
  loginSchema,
  registrationSchema,
  projectSchema,
  paginationSchema,
  idParamSchema
} = require('../../src/validators/schemas');

describe('Login Schema Validation', () => {
  
  it('should accept valid login credentials', () => {
    const validInput = {
      username: 'testuser',
      password: 'SecurePass123!'
    };
    
    const result = loginSchema.safeParse(validInput);
    assert.strictEqual(result.success, true);
  });
  
  it('should reject username with SQL injection attempt', () => {
    const maliciousInput = {
      username: "admin'--",
      password: 'password'
    };
    
    const result = loginSchema.safeParse(maliciousInput);
    assert.strictEqual(result.success, false);
  });
  
  it('should reject username with special characters', () => {
    const maliciousInput = {
      username: '<script>alert(1)</script>',
      password: 'password'
    };
    
    const result = loginSchema.safeParse(maliciousInput);
    assert.strictEqual(result.success, false);
  });
  
  it('should reject empty username', () => {
    const invalidInput = {
      username: '',
      password: 'password'
    };
    
    const result = loginSchema.safeParse(invalidInput);
    assert.strictEqual(result.success, false);
  });
  
  it('should reject username that is too short', () => {
    const invalidInput = {
      username: 'ab',
      password: 'password'
    };
    
    const result = loginSchema.safeParse(invalidInput);
    assert.strictEqual(result.success, false);
  });
  
  it('should reject username that is too long', () => {
    const invalidInput = {
      username: 'a'.repeat(31),
      password: 'password'
    };
    
    const result = loginSchema.safeParse(invalidInput);
    assert.strictEqual(result.success, false);
  });
  
  it('should accept valid MFA token', () => {
    const validInput = {
      username: 'testuser',
      password: 'password',
      mfaToken: '123456'
    };
    
    const result = loginSchema.safeParse(validInput);
    assert.strictEqual(result.success, true);
  });
  
  it('should reject invalid MFA token format', () => {
    const invalidInput = {
      username: 'testuser',
      password: 'password',
      mfaToken: 'abcdef'
    };
    
    const result = loginSchema.safeParse(invalidInput);
    assert.strictEqual(result.success, false);
  });
});

describe('Registration Schema Validation', () => {
  
  const validRegistration = {
    username: 'newuser',
    email: 'newuser@example.com',
    password: 'SecurePass123!',
    confirmPassword: 'SecurePass123!',
    firstName: 'John',
    lastName: 'Doe'
  };
  
  it('should accept valid registration data', () => {
    const result = registrationSchema.safeParse(validRegistration);
    assert.strictEqual(result.success, true);
  });
  
  it('should reject weak password (no uppercase)', () => {
    const weakPassword = {
      ...validRegistration,
      password: 'securepass123!',
      confirmPassword: 'securepass123!'
    };
    
    const result = registrationSchema.safeParse(weakPassword);
    assert.strictEqual(result.success, false);
  });
  
  it('should reject weak password (no special char)', () => {
    const weakPassword = {
      ...validRegistration,
      password: 'SecurePass1234',
      confirmPassword: 'SecurePass1234'
    };
    
    const result = registrationSchema.safeParse(weakPassword);
    assert.strictEqual(result.success, false);
  });
  
  it('should reject password mismatch', () => {
    const mismatch = {
      ...validRegistration,
      confirmPassword: 'DifferentPass123!'
    };
    
    const result = registrationSchema.safeParse(mismatch);
    assert.strictEqual(result.success, false);
  });
  
  it('should reject invalid email format', () => {
    const invalidEmail = {
      ...validRegistration,
      email: 'not-an-email'
    };
    
    const result = registrationSchema.safeParse(invalidEmail);
    assert.strictEqual(result.success, false);
  });
  
  it('should reject XSS in first name', () => {
    const xssAttempt = {
      ...validRegistration,
      firstName: '<script>alert(1)</script>'
    };
    
    const result = registrationSchema.safeParse(xssAttempt);
    assert.strictEqual(result.success, false);
  });
});

describe('Project Schema Validation', () => {
  
  it('should accept valid project data', () => {
    const validProject = {
      name: 'Security Assessment',
      description: 'Quarterly security review',
      status: 'active',
      priority: 'high',
      tags: ['security', 'assessment']
    };
    
    const result = projectSchema.safeParse(validProject);
    assert.strictEqual(result.success, true);
  });
  
  it('should reject project name with dangerous characters', () => {
    const invalidProject = {
      name: '<script>alert(1)</script>',
      status: 'active'
    };
    
    const result = projectSchema.safeParse(invalidProject);
    assert.strictEqual(result.success, false);
  });
  
  it('should reject invalid status value', () => {
    const invalidProject = {
      name: 'Valid Name',
      status: 'invalid_status'
    };
    
    const result = projectSchema.safeParse(invalidProject);
    assert.strictEqual(result.success, false);
  });
  
  it('should reject too many tags', () => {
    const tooManyTags = {
      name: 'Valid Name',
      tags: Array(11).fill('tag')
    };
    
    const result = projectSchema.safeParse(tooManyTags);
    assert.strictEqual(result.success, false);
  });
  
  it('should reject description that is too long', () => {
    const longDescription = {
      name: 'Valid Name',
      description: 'a'.repeat(2001)
    };
    
    const result = projectSchema.safeParse(longDescription);
    assert.strictEqual(result.success, false);
  });
});

describe('Pagination Schema Validation', () => {
  
  it('should accept valid pagination params', () => {
    const validPagination = {
      page: '1',
      limit: '20',
      sortBy: 'createdAt',
      sortOrder: 'desc'
    };
    
    const result = paginationSchema.safeParse(validPagination);
    assert.strictEqual(result.success, true);
    assert.strictEqual(result.data.page, 1);
    assert.strictEqual(result.data.limit, 20);
  });
  
  it('should reject page size over limit', () => {
    const tooLarge = {
      page: '1',
      limit: '101'
    };
    
    const result = paginationSchema.safeParse(tooLarge);
    assert.strictEqual(result.success, false);
  });
  
  it('should reject SQL injection in sortBy', () => {
    const sqlInjection = {
      page: '1',
      limit: '20',
      sortBy: 'name; DROP TABLE users;--'
    };
    
    const result = paginationSchema.safeParse(sqlInjection);
    assert.strictEqual(result.success, false);
  });
  
  it('should use default values when not provided', () => {
    const result = paginationSchema.safeParse({});
    assert.strictEqual(result.success, true);
    assert.strictEqual(result.data.page, 1);
    assert.strictEqual(result.data.limit, 20);
    assert.strictEqual(result.data.sortOrder, 'desc');
  });
});

describe('ID Parameter Schema Validation', () => {
  
  it('should accept valid UUID', () => {
    const validId = {
      id: '550e8400-e29b-41d4-a716-446655440000'
    };
    
    const result = idParamSchema.safeParse(validId);
    assert.strictEqual(result.success, true);
  });
  
  it('should reject invalid UUID format', () => {
    const invalidId = {
      id: 'not-a-uuid'
    };
    
    const result = idParamSchema.safeParse(invalidId);
    assert.strictEqual(result.success, false);
  });
  
  it('should reject SQL injection in ID', () => {
    const sqlInjection = {
      id: "1' OR '1'='1"
    };
    
    const result = idParamSchema.safeParse(sqlInjection);
    assert.strictEqual(result.success, false);
  });
  
  it('should reject path traversal attempt', () => {
    const pathTraversal = {
      id: '../../../etc/passwd'
    };
    
    const result = idParamSchema.safeParse(pathTraversal);
    assert.strictEqual(result.success, false);
  });
});

console.log('✅ All validator tests completed');
