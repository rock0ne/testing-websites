/**
 * BlueBastion Labs - Projects Routes
 * 
 * Demonstrates secure CRUD operations with:
 * - RBAC (Role-Based Access Control)
 * - IDOR prevention
 * - Input validation
 * - Audit logging
 */

const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');

const { authenticateJWT, requireRole, requirePermission } = require('../middleware/security');
const { validate, projectSchema, projectUpdateSchema, paginationSchema, idParamSchema } = require('../validators/schemas');

// ============================================================================
// IN-MEMORY STORE (Replace with database in production)
// ============================================================================

const projects = new Map();

// Initialize with sample data
const initSampleProjects = () => {
  const sampleProjects = [
    {
      id: uuidv4(),
      name: 'Security Assessment Q1',
      description: 'Quarterly security assessment for BlueBastion infrastructure',
      status: 'active',
      priority: 'high',
      ownerId: 'admin-user-id',
      teamMembers: [],
      tags: ['security', 'assessment'],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    },
    {
      id: uuidv4(),
      name: 'Incident Response Plan',
      description: 'Update incident response procedures',
      status: 'draft',
      priority: 'critical',
      ownerId: 'admin-user-id',
      teamMembers: [],
      tags: ['incident-response', 'documentation'],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    }
  ];
  
  for (const project of sampleProjects) {
    projects.set(project.id, project);
  }
};

initSampleProjects();

// ============================================================================
// AUTHORIZATION HELPERS
// ============================================================================

/**
 * Check if user can access a project
 * 
 * SECURITY: Prevents IDOR by verifying ownership/membership
 */
const canAccessProject = (user, project) => {
  // Admins can access all projects
  if (user.role === 'admin') return true;
  
  // Owner can access
  if (project.ownerId === user.id) return true;
  
  // Team members can access
  if (project.teamMembers?.includes(user.id)) return true;
  
  return false;
};

/**
 * Check if user can modify a project
 */
const canModifyProject = (user, project) => {
  // Admins can modify all
  if (user.role === 'admin') return true;
  
  // Only owner can modify
  if (project.ownerId === user.id) return true;
  
  return false;
};

// ============================================================================
// ROUTES
// ============================================================================

/**
 * GET /api/projects
 * 
 * List projects accessible to the user
 * Supports pagination and filtering
 */
router.get('/',
  authenticateJWT,
  requirePermission('read'),
  validate(paginationSchema, 'query'),
  (req, res) => {
    const logger = req.app.locals.logger;
    const { page, limit, sortBy, sortOrder } = req.query;
    
    // Filter projects user can access
    let accessibleProjects = [];
    for (const project of projects.values()) {
      if (canAccessProject(req.user, project)) {
        accessibleProjects.push(project);
      }
    }
    
    // Sort
    if (sortBy) {
      accessibleProjects.sort((a, b) => {
        const aVal = a[sortBy] || '';
        const bVal = b[sortBy] || '';
        return sortOrder === 'asc' 
          ? aVal.localeCompare(bVal)
          : bVal.localeCompare(aVal);
      });
    }
    
    // Paginate
    const startIndex = (page - 1) * limit;
    const endIndex = startIndex + limit;
    const paginatedProjects = accessibleProjects.slice(startIndex, endIndex);
    
    logger?.auditEvent('READ', 'projects', {
      userId: req.user.id,
      count: paginatedProjects.length,
      requestId: req.requestId
    });
    
    res.json({
      data: paginatedProjects,
      pagination: {
        page,
        limit,
        total: accessibleProjects.length,
        totalPages: Math.ceil(accessibleProjects.length / limit)
      }
    });
  }
);

/**
 * GET /api/projects/:id
 * 
 * Get single project by ID
 * SECURITY: Validates access before returning data (IDOR prevention)
 */
router.get('/:id',
  authenticateJWT,
  requirePermission('read'),
  validate(idParamSchema, 'params'),
  (req, res) => {
    const logger = req.app.locals.logger;
    const { id } = req.params;
    
    const project = projects.get(id);
    
    if (!project) {
      return res.status(404).json({ error: 'Project not found' });
    }
    
    // SECURITY: Check access before returning data
    if (!canAccessProject(req.user, project)) {
      logger?.warn('AUTHZ_IDOR_ATTEMPT', {
        userId: req.user.id,
        resourceType: 'project',
        resourceId: id,
        requestId: req.requestId,
        mitre: 'T1078'
      });
      
      // Return 404 instead of 403 to not reveal resource existence
      return res.status(404).json({ error: 'Project not found' });
    }
    
    logger?.auditEvent('READ', 'project', {
      userId: req.user.id,
      projectId: id,
      requestId: req.requestId
    });
    
    res.json({ data: project });
  }
);

/**
 * POST /api/projects
 * 
 * Create new project
 */
router.post('/',
  authenticateJWT,
  requirePermission('write'),
  validate(projectSchema, 'body'),
  (req, res) => {
    const logger = req.app.locals.logger;
    
    const newProject = {
      id: uuidv4(),
      ...req.body,
      ownerId: req.user.id,
      teamMembers: [],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    
    projects.set(newProject.id, newProject);
    
    logger?.auditEvent('CREATE', 'project', {
      userId: req.user.id,
      projectId: newProject.id,
      projectName: newProject.name,
      requestId: req.requestId
    });
    
    res.status(201).json({
      success: true,
      data: newProject
    });
  }
);

/**
 * PUT /api/projects/:id
 * 
 * Update project
 * SECURITY: Validates ownership before allowing modification
 */
router.put('/:id',
  authenticateJWT,
  requirePermission('write'),
  validate(idParamSchema, 'params'),
  validate(projectUpdateSchema, 'body'),
  (req, res) => {
    const logger = req.app.locals.logger;
    const { id } = req.params;
    
    const project = projects.get(id);
    
    if (!project) {
      return res.status(404).json({ error: 'Project not found' });
    }
    
    // SECURITY: Check modification permission
    if (!canModifyProject(req.user, project)) {
      logger?.warn('AUTHZ_MODIFICATION_DENIED', {
        userId: req.user.id,
        resourceType: 'project',
        resourceId: id,
        requestId: req.requestId
      });
      
      return res.status(403).json({ error: 'You do not have permission to modify this project' });
    }
    
    // Update project
    const updatedProject = {
      ...project,
      ...req.body,
      id: project.id, // Prevent ID modification
      ownerId: project.ownerId, // Prevent owner change via this endpoint
      updatedAt: new Date().toISOString()
    };
    
    projects.set(id, updatedProject);
    
    logger?.auditEvent('UPDATE', 'project', {
      userId: req.user.id,
      projectId: id,
      changes: Object.keys(req.body),
      requestId: req.requestId
    });
    
    res.json({
      success: true,
      data: updatedProject
    });
  }
);

/**
 * DELETE /api/projects/:id
 * 
 * Delete project
 * SECURITY: Only owner or admin can delete
 */
router.delete('/:id',
  authenticateJWT,
  requirePermission('delete'),
  validate(idParamSchema, 'params'),
  (req, res) => {
    const logger = req.app.locals.logger;
    const { id } = req.params;
    
    const project = projects.get(id);
    
    if (!project) {
      return res.status(404).json({ error: 'Project not found' });
    }
    
    // SECURITY: Check delete permission
    if (!canModifyProject(req.user, project)) {
      logger?.warn('AUTHZ_DELETE_DENIED', {
        userId: req.user.id,
        resourceType: 'project',
        resourceId: id,
        requestId: req.requestId
      });
      
      return res.status(403).json({ error: 'You do not have permission to delete this project' });
    }
    
    projects.delete(id);
    
    logger?.auditEvent('DELETE', 'project', {
      userId: req.user.id,
      projectId: id,
      projectName: project.name,
      requestId: req.requestId
    });
    
    res.json({
      success: true,
      message: 'Project deleted successfully'
    });
  }
);

/**
 * POST /api/projects/:id/members
 * 
 * Add team member to project
 */
router.post('/:id/members',
  authenticateJWT,
  requirePermission('write'),
  validate(idParamSchema, 'params'),
  (req, res) => {
    const logger = req.app.locals.logger;
    const { id } = req.params;
    const { userId } = req.body;
    
    if (!userId) {
      return res.status(400).json({ error: 'userId is required' });
    }
    
    const project = projects.get(id);
    
    if (!project) {
      return res.status(404).json({ error: 'Project not found' });
    }
    
    if (!canModifyProject(req.user, project)) {
      return res.status(403).json({ error: 'You do not have permission to modify this project' });
    }
    
    if (!project.teamMembers.includes(userId)) {
      project.teamMembers.push(userId);
      project.updatedAt = new Date().toISOString();
      projects.set(id, project);
    }
    
    logger?.auditEvent('UPDATE', 'project_member', {
      userId: req.user.id,
      projectId: id,
      addedMember: userId,
      requestId: req.requestId
    });
    
    res.json({
      success: true,
      data: project
    });
  }
);

module.exports = router;
