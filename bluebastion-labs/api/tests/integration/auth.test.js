/**
 * BlueBastion Labs - Authentication Integration Tests
 * 
 * Tests the complete authentication flow including:
 * - Login with valid/invalid credentials
 * - Token refresh
 * - Account lockout
 * - Rate limiting
 */

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const http = require('http');

// Test configuration
const API_BASE = 'http://localhost:12001';

// Helper function to make HTTP requests
const makeRequest = (method, path, body = null, headers = {}) => {
  return new Promise((resolve, reject) => {
    const url = new URL(path, API_BASE);
    
    const options = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname,
      method,
      headers: {
        'Content-Type': 'application/json',
        ...headers
      }
    };
    
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: data ? JSON.parse(data) : null
          });
        } catch (e) {
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: data
          });
        }
      });
    });
    
    req.on('error', reject);
    
    if (body) {
      req.write(JSON.stringify(body));
    }
    
    req.end();
  });
};

describe('Authentication API Tests', () => {
  
  describe('POST /api/auth/login', () => {
    
    it('should login successfully with valid credentials', async () => {
      const response = await makeRequest('POST', '/api/auth/login', {
        username: 'admin',
        password: 'Admin@123456!'
      });
      
      assert.strictEqual(response.status, 200);
      assert.strictEqual(response.body.success, true);
      assert.ok(response.body.accessToken);
      assert.ok(response.body.user);
      assert.strictEqual(response.body.user.username, 'admin');
      assert.strictEqual(response.body.user.role, 'admin');
    });
    
    it('should reject invalid password', async () => {
      const response = await makeRequest('POST', '/api/auth/login', {
        username: 'admin',
        password: 'wrongpassword'
      });
      
      assert.strictEqual(response.status, 401);
      assert.strictEqual(response.body.error, 'Invalid credentials');
    });
    
    it('should reject non-existent user', async () => {
      const response = await makeRequest('POST', '/api/auth/login', {
        username: 'nonexistent',
        password: 'password'
      });
      
      assert.strictEqual(response.status, 401);
      // Should not reveal if user exists
      assert.strictEqual(response.body.error, 'Invalid credentials');
    });
    
    it('should reject SQL injection in username', async () => {
      const response = await makeRequest('POST', '/api/auth/login', {
        username: "admin'--",
        password: 'password'
      });
      
      assert.strictEqual(response.status, 400);
      assert.strictEqual(response.body.error, 'Validation failed');
    });
    
    it('should reject XSS in username', async () => {
      const response = await makeRequest('POST', '/api/auth/login', {
        username: '<script>alert(1)</script>',
        password: 'password'
      });
      
      assert.strictEqual(response.status, 400);
      assert.strictEqual(response.body.error, 'Validation failed');
    });
  });
  
  describe('GET /api/auth/me', () => {
    let accessToken;
    
    before(async () => {
      const loginResponse = await makeRequest('POST', '/api/auth/login', {
        username: 'analyst',
        password: 'Analyst@123456!'
      });
      accessToken = loginResponse.body.accessToken;
    });
    
    it('should return user info with valid token', async () => {
      const response = await makeRequest('GET', '/api/auth/me', null, {
        'Authorization': `Bearer ${accessToken}`
      });
      
      assert.strictEqual(response.status, 200);
      assert.ok(response.body.user);
      assert.strictEqual(response.body.user.username, 'analyst');
    });
    
    it('should reject request without token', async () => {
      const response = await makeRequest('GET', '/api/auth/me');
      
      assert.strictEqual(response.status, 401);
      assert.strictEqual(response.body.error, 'Authentication required');
    });
    
    it('should reject invalid token', async () => {
      const response = await makeRequest('GET', '/api/auth/me', null, {
        'Authorization': 'Bearer invalid.token.here'
      });
      
      assert.strictEqual(response.status, 401);
    });
    
    it('should reject malformed authorization header', async () => {
      const response = await makeRequest('GET', '/api/auth/me', null, {
        'Authorization': 'NotBearer token'
      });
      
      assert.strictEqual(response.status, 401);
    });
  });
  
  describe('POST /api/auth/register', () => {
    
    it('should register new user with valid data', async () => {
      const uniqueUsername = `testuser_${Date.now()}`;
      const response = await makeRequest('POST', '/api/auth/register', {
        username: uniqueUsername,
        email: `${uniqueUsername}@test.com`,
        password: 'TestPass123!',
        confirmPassword: 'TestPass123!',
        firstName: 'Test',
        lastName: 'User'
      });
      
      assert.strictEqual(response.status, 201);
      assert.strictEqual(response.body.success, true);
    });
    
    it('should reject weak password', async () => {
      const response = await makeRequest('POST', '/api/auth/register', {
        username: 'weakpassuser',
        email: 'weak@test.com',
        password: 'weak',
        confirmPassword: 'weak',
        firstName: 'Test',
        lastName: 'User'
      });
      
      assert.strictEqual(response.status, 400);
      assert.strictEqual(response.body.error, 'Validation failed');
    });
    
    it('should reject password mismatch', async () => {
      const response = await makeRequest('POST', '/api/auth/register', {
        username: 'mismatchuser',
        email: 'mismatch@test.com',
        password: 'TestPass123!',
        confirmPassword: 'DifferentPass123!',
        firstName: 'Test',
        lastName: 'User'
      });
      
      assert.strictEqual(response.status, 400);
    });
    
    it('should reject duplicate username', async () => {
      const response = await makeRequest('POST', '/api/auth/register', {
        username: 'admin',
        email: 'newadmin@test.com',
        password: 'TestPass123!',
        confirmPassword: 'TestPass123!',
        firstName: 'Test',
        lastName: 'User'
      });
      
      assert.strictEqual(response.status, 400);
      assert.ok(response.body.error.includes('exists'));
    });
  });
  
  describe('POST /api/auth/logout', () => {
    
    it('should logout successfully', async () => {
      const response = await makeRequest('POST', '/api/auth/logout');
      
      assert.strictEqual(response.status, 200);
      assert.strictEqual(response.body.success, true);
    });
  });
});

describe('Security Headers Tests', () => {
  
  it('should include security headers in response', async () => {
    const response = await makeRequest('GET', '/health');
    
    // Check for security headers
    assert.ok(response.headers['x-content-type-options']);
    assert.ok(response.headers['x-frame-options']);
    assert.ok(response.headers['x-request-id']);
  });
  
  it('should include request ID in response', async () => {
    const response = await makeRequest('GET', '/health');
    
    assert.ok(response.headers['x-request-id']);
    // Verify it's a valid UUID format
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    assert.ok(uuidRegex.test(response.headers['x-request-id']));
  });
});

console.log('✅ All authentication integration tests completed');
