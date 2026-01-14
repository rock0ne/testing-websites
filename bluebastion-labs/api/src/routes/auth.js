/**
 * BlueBastion Labs - Authentication Routes
 * 
 * Endpoints:
 * - POST /api/auth/login     - User login
 * - POST /api/auth/register  - User registration
 * - POST /api/auth/refresh   - Refresh access token
 * - POST /api/auth/logout    - Logout (revoke refresh token)
 * - GET  /api/auth/me        - Get current user info
 */

const express = require('express');
const router = express.Router();

const { authLimiter, authenticateJWT } = require('../middleware/security');
const { validate, loginSchema, registrationSchema } = require('../validators/schemas');
const authService = require('../services/authService');

/**
 * POST /api/auth/login
 * 
 * SECURITY:
 * - Rate limited to prevent brute force
 * - Input validated
 * - Logs all attempts for detection
 */
router.post('/login',
  authLimiter,
  validate(loginSchema, 'body'),
  async (req, res) => {
    const { username, password, mfaToken } = req.body;
    const logger = req.app.locals.logger;
    
    try {
      const result = await authService.authenticate(username, password, logger);
      
      if (!result.success) {
        return res.status(401).json({ error: result.error });
      }
      
      // Set refresh token in httpOnly cookie for security
      res.cookie('refreshToken', result.tokens.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
      });
      
      res.json({
        success: true,
        user: result.user,
        accessToken: result.tokens.accessToken,
        expiresIn: result.tokens.expiresIn
      });
    } catch (err) {
      logger?.error('AUTH_LOGIN_ERROR', {
        error: err.message,
        requestId: req.requestId
      });
      res.status(500).json({ error: 'Authentication failed' });
    }
  }
);

/**
 * POST /api/auth/register
 * 
 * SECURITY:
 * - Rate limited
 * - Strong password validation
 * - Input sanitization
 */
router.post('/register',
  authLimiter,
  validate(registrationSchema, 'body'),
  async (req, res) => {
    const logger = req.app.locals.logger;
    
    try {
      const result = await authService.register(req.body, logger);
      
      if (!result.success) {
        return res.status(400).json({ error: result.error });
      }
      
      res.status(201).json({
        success: true,
        user: result.user,
        message: 'Registration successful. Please login.'
      });
    } catch (err) {
      logger?.error('AUTH_REGISTER_ERROR', {
        error: err.message,
        requestId: req.requestId
      });
      res.status(500).json({ error: 'Registration failed' });
    }
  }
);

/**
 * POST /api/auth/refresh
 * 
 * SECURITY:
 * - Refresh token rotation (old token invalidated)
 * - Token stored in httpOnly cookie
 */
router.post('/refresh', async (req, res) => {
  const logger = req.app.locals.logger;
  const refreshToken = req.cookies?.refreshToken || req.body?.refreshToken;
  
  if (!refreshToken) {
    return res.status(401).json({ error: 'Refresh token required' });
  }
  
  try {
    const result = await authService.refreshAccessToken(refreshToken, logger);
    
    if (!result.success) {
      res.clearCookie('refreshToken');
      return res.status(401).json({ error: result.error });
    }
    
    // Set new refresh token
    res.cookie('refreshToken', result.tokens.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });
    
    res.json({
      success: true,
      accessToken: result.tokens.accessToken,
      expiresIn: result.tokens.expiresIn
    });
  } catch (err) {
    logger?.error('AUTH_REFRESH_ERROR', {
      error: err.message,
      requestId: req.requestId
    });
    res.status(500).json({ error: 'Token refresh failed' });
  }
});

/**
 * POST /api/auth/logout
 * 
 * SECURITY:
 * - Revokes refresh token
 * - Clears cookie
 */
router.post('/logout', async (req, res) => {
  const logger = req.app.locals.logger;
  const refreshToken = req.cookies?.refreshToken || req.body?.refreshToken;
  
  if (refreshToken) {
    authService.logout(refreshToken, logger);
  }
  
  res.clearCookie('refreshToken');
  res.json({ success: true, message: 'Logged out successfully' });
});

/**
 * GET /api/auth/me
 * 
 * Returns current authenticated user info
 */
router.get('/me', authenticateJWT, (req, res) => {
  const user = authService.getUserById(req.user.id);
  
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  res.json({ user });
});

module.exports = router;
