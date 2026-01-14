/**
 * BlueBastion Labs - Authentication Service
 * 
 * SECURITY CONTROLS:
 * - Secure password hashing with bcrypt
 * - JWT token generation with proper claims
 * - Refresh token rotation
 * - Account lockout after failed attempts
 */

const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const securityConfig = require('../../config/security');

// ============================================================================
// IN-MEMORY STORE (Replace with database in production)
// ============================================================================

// Simulated user database for lab purposes
const users = new Map();
const refreshTokens = new Map();
const failedAttempts = new Map();

// Initialize with test users
const initTestUsers = async () => {
  const testUsers = [
    {
      id: uuidv4(),
      username: 'admin',
      email: 'admin@bluebastion.lab',
      password: await bcrypt.hash('Admin@123456!', securityConfig.password.bcryptRounds),
      role: 'admin',
      permissions: ['read', 'write', 'delete', 'admin'],
      firstName: 'Admin',
      lastName: 'User',
      active: true,
      createdAt: new Date().toISOString()
    },
    {
      id: uuidv4(),
      username: 'analyst',
      email: 'analyst@bluebastion.lab',
      password: await bcrypt.hash('Analyst@123456!', securityConfig.password.bcryptRounds),
      role: 'analyst',
      permissions: ['read', 'write'],
      firstName: 'Security',
      lastName: 'Analyst',
      active: true,
      createdAt: new Date().toISOString()
    },
    {
      id: uuidv4(),
      username: 'viewer',
      email: 'viewer@bluebastion.lab',
      password: await bcrypt.hash('Viewer@123456!', securityConfig.password.bcryptRounds),
      role: 'viewer',
      permissions: ['read'],
      firstName: 'Read',
      lastName: 'Only',
      active: true,
      createdAt: new Date().toISOString()
    }
  ];
  
  for (const user of testUsers) {
    users.set(user.username, user);
  }
};

// Initialize test users
initTestUsers();

// ============================================================================
// ACCOUNT LOCKOUT
// ============================================================================

const LOCKOUT_THRESHOLD = 5;
const LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes

/**
 * Check if account is locked
 */
const isAccountLocked = (username) => {
  const attempts = failedAttempts.get(username);
  if (!attempts) return false;
  
  if (attempts.count >= LOCKOUT_THRESHOLD) {
    const lockoutEnd = attempts.lastAttempt + LOCKOUT_DURATION;
    if (Date.now() < lockoutEnd) {
      return true;
    }
    // Lockout expired, reset
    failedAttempts.delete(username);
  }
  return false;
};

/**
 * Record failed login attempt
 */
const recordFailedAttempt = (username) => {
  const attempts = failedAttempts.get(username) || { count: 0, lastAttempt: 0 };
  attempts.count += 1;
  attempts.lastAttempt = Date.now();
  failedAttempts.set(username, attempts);
  return attempts.count;
};

/**
 * Clear failed attempts on successful login
 */
const clearFailedAttempts = (username) => {
  failedAttempts.delete(username);
};

// ============================================================================
// TOKEN GENERATION
// ============================================================================

/**
 * Generate JWT access token
 * 
 * SECURITY:
 * - Short expiry (15 min) limits window of compromise
 * - Includes role and permissions for authorization
 * - Specifies algorithm to prevent confusion attacks
 */
const generateAccessToken = (user) => {
  const payload = {
    sub: user.id,
    username: user.username,
    email: user.email,
    role: user.role,
    permissions: user.permissions,
    type: 'access'
  };
  
  return jwt.sign(payload, securityConfig.jwt.secret, {
    algorithm: securityConfig.jwt.algorithm,
    expiresIn: securityConfig.jwt.accessTokenExpiry,
    issuer: securityConfig.jwt.issuer,
    audience: securityConfig.jwt.audience
  });
};

/**
 * Generate refresh token
 * 
 * SECURITY:
 * - Longer expiry for convenience
 * - Stored server-side for revocation capability
 * - Rotated on each use
 */
const generateRefreshToken = (user) => {
  const tokenId = uuidv4();
  const payload = {
    sub: user.id,
    tokenId,
    type: 'refresh'
  };
  
  const token = jwt.sign(payload, securityConfig.jwt.secret, {
    algorithm: securityConfig.jwt.algorithm,
    expiresIn: securityConfig.jwt.refreshTokenExpiry,
    issuer: securityConfig.jwt.issuer,
    audience: securityConfig.jwt.audience
  });
  
  // Store refresh token for revocation
  refreshTokens.set(tokenId, {
    userId: user.id,
    createdAt: Date.now(),
    expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000 // 7 days
  });
  
  return { token, tokenId };
};

// ============================================================================
// AUTHENTICATION METHODS
// ============================================================================

/**
 * Authenticate user with username and password
 * 
 * @param {string} username 
 * @param {string} password 
 * @param {object} logger - Logger instance for security events
 * @returns {object} - { success, user, tokens, error }
 */
const authenticate = async (username, password, logger) => {
  // Check account lockout
  if (isAccountLocked(username)) {
    logger?.warn('AUTH_ACCOUNT_LOCKED', {
      username,
      mitre: 'T1110'
    });
    return {
      success: false,
      error: 'Account temporarily locked due to too many failed attempts'
    };
  }
  
  // Find user
  const user = users.get(username);
  
  if (!user) {
    // SECURITY: Don't reveal if username exists
    recordFailedAttempt(username);
    logger?.warn('AUTH_FAILED_USER_NOT_FOUND', {
      username,
      mitre: 'T1078'
    });
    return {
      success: false,
      error: 'Invalid credentials'
    };
  }
  
  // Check if account is active
  if (!user.active) {
    logger?.warn('AUTH_FAILED_ACCOUNT_DISABLED', {
      username,
      userId: user.id
    });
    return {
      success: false,
      error: 'Account is disabled'
    };
  }
  
  // Verify password
  const isValidPassword = await bcrypt.compare(password, user.password);
  
  if (!isValidPassword) {
    const attemptCount = recordFailedAttempt(username);
    logger?.warn('AUTH_FAILED_INVALID_PASSWORD', {
      username,
      userId: user.id,
      attemptCount,
      mitre: 'T1110'
    });
    return {
      success: false,
      error: 'Invalid credentials'
    };
  }
  
  // Clear failed attempts on success
  clearFailedAttempts(username);
  
  // Generate tokens
  const accessToken = generateAccessToken(user);
  const { token: refreshToken, tokenId } = generateRefreshToken(user);
  
  logger?.info('AUTH_SUCCESS', {
    username,
    userId: user.id,
    role: user.role
  });
  
  return {
    success: true,
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
      firstName: user.firstName,
      lastName: user.lastName
    },
    tokens: {
      accessToken,
      refreshToken,
      expiresIn: 900 // 15 minutes in seconds
    }
  };
};

/**
 * Refresh access token using refresh token
 */
const refreshAccessToken = async (refreshToken, logger) => {
  try {
    const decoded = jwt.verify(refreshToken, securityConfig.jwt.secret, {
      algorithms: [securityConfig.jwt.algorithm],
      issuer: securityConfig.jwt.issuer,
      audience: securityConfig.jwt.audience
    });
    
    if (decoded.type !== 'refresh') {
      throw new Error('Invalid token type');
    }
    
    // Check if refresh token is still valid (not revoked)
    const storedToken = refreshTokens.get(decoded.tokenId);
    if (!storedToken || storedToken.userId !== decoded.sub) {
      logger?.warn('AUTH_REFRESH_TOKEN_INVALID', {
        tokenId: decoded.tokenId,
        userId: decoded.sub
      });
      return { success: false, error: 'Invalid refresh token' };
    }
    
    // Find user
    let user = null;
    for (const u of users.values()) {
      if (u.id === decoded.sub) {
        user = u;
        break;
      }
    }
    
    if (!user || !user.active) {
      return { success: false, error: 'User not found or disabled' };
    }
    
    // Revoke old refresh token (rotation)
    refreshTokens.delete(decoded.tokenId);
    
    // Generate new tokens
    const accessToken = generateAccessToken(user);
    const { token: newRefreshToken } = generateRefreshToken(user);
    
    logger?.info('AUTH_TOKEN_REFRESHED', {
      userId: user.id,
      username: user.username
    });
    
    return {
      success: true,
      tokens: {
        accessToken,
        refreshToken: newRefreshToken,
        expiresIn: 900
      }
    };
  } catch (err) {
    logger?.warn('AUTH_REFRESH_FAILED', {
      error: err.message
    });
    return { success: false, error: 'Invalid or expired refresh token' };
  }
};

/**
 * Logout - revoke refresh token
 */
const logout = (refreshToken, logger) => {
  try {
    const decoded = jwt.verify(refreshToken, securityConfig.jwt.secret, {
      algorithms: [securityConfig.jwt.algorithm]
    });
    
    if (decoded.tokenId) {
      refreshTokens.delete(decoded.tokenId);
      logger?.info('AUTH_LOGOUT', {
        userId: decoded.sub,
        tokenId: decoded.tokenId
      });
    }
    
    return { success: true };
  } catch (err) {
    // Token might be expired, but still try to logout
    return { success: true };
  }
};

/**
 * Register new user
 */
const register = async (userData, logger) => {
  // Check if username exists
  if (users.has(userData.username)) {
    return { success: false, error: 'Username already exists' };
  }
  
  // Check if email exists
  for (const user of users.values()) {
    if (user.email === userData.email) {
      return { success: false, error: 'Email already registered' };
    }
  }
  
  // Hash password
  const hashedPassword = await bcrypt.hash(
    userData.password,
    securityConfig.password.bcryptRounds
  );
  
  // Create user
  const newUser = {
    id: uuidv4(),
    username: userData.username,
    email: userData.email,
    password: hashedPassword,
    role: 'viewer', // Default role
    permissions: ['read'],
    firstName: userData.firstName,
    lastName: userData.lastName,
    active: true,
    createdAt: new Date().toISOString()
  };
  
  users.set(newUser.username, newUser);
  
  logger?.info('USER_REGISTERED', {
    userId: newUser.id,
    username: newUser.username,
    email: newUser.email
  });
  
  return {
    success: true,
    user: {
      id: newUser.id,
      username: newUser.username,
      email: newUser.email,
      role: newUser.role
    }
  };
};

/**
 * Get user by ID
 */
const getUserById = (userId) => {
  for (const user of users.values()) {
    if (user.id === userId) {
      return {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        permissions: user.permissions,
        firstName: user.firstName,
        lastName: user.lastName,
        createdAt: user.createdAt
      };
    }
  }
  return null;
};

module.exports = {
  authenticate,
  refreshAccessToken,
  logout,
  register,
  getUserById,
  // For testing
  _users: users,
  _refreshTokens: refreshTokens
};
