/**
 * Agentic Workflows API Routes
 * RESTful endpoints for agent-based workflow management with comprehensive security
 */

import express from 'express';
import { AgentOrchestrationService } from '../agentic/agent-orchestrator';
import { MCPSecurityGateway } from '../agentic/mcp-security-gateway';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';

const router = express.Router();

// Initialize services
const agentOrchestrator = new AgentOrchestrationService();
const mcpGateway = new MCPSecurityGateway();

// Rate limiting for agentic operations
const agenticRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many agentic requests from this IP'
});

router.use(agenticRateLimit);

// Validation schemas
const AgentConfigSchema = z.object({
  name: z.string().min(1).max(255),
  type: z.enum(['autonomous', 'supervised', 'collaborative']),
  capabilities: z.array(z.string()).min(1),
  securityLevel: z.enum(['low', 'medium', 'high', 'critical']),
  maxResourceUsage: z.object({
    cpu: z.number().positive(),
    memory: z.number().positive(),
    networkBandwidth: z.number().positive()
  }),
  accessPolicies: z.array(z.object({
    resource: z.string(),
    permissions: z.array(z.string()),
    conditions: z.array(z.object({
      field: z.string(),
      operator: z.enum(['equals', 'contains', 'matches', 'in']),
      value: z.any()
    }))
  })),
  complianceRequirements: z.array(z.string())
});

const WorkflowDefinitionSchema = z.object({
  id: z.string().uuid(),
  name: z.string().min(1).max(255),
  description: z.string().max(1000),
  agents: z.array(z.string().uuid()).min(1),
  steps: z.array(z.object({
    id: z.string(),
    type: z.enum(['task', 'decision', 'approval', 'notification']),
    agentId: z.string().uuid(),
    action: z.string(),
    inputs: z.any(),
    dependencies: z.array(z.string()),
    securityChecks: z.array(z.string())
  })),
  securityRequirements: z.array(z.object({
    type: z.enum(['authentication', 'authorization', 'encryption', 'audit']),
    level: z.enum(['required', 'optional']),
    parameters: z.record(z.any())
  })),
  complianceFrameworks: z.array(z.string())
});

const MCPContextSchema = z.object({
  type: z.enum(['conversation', 'document', 'data', 'model_state', 'tool_result']),
  content: z.any(),
  metadata: z.object({
    sensitivity_level: z.enum(['public', 'internal', 'confidential', 'restricted']).optional(),
    data_classification: z.array(z.string()).optional(),
    access_controls: z.array(z.object({
      agent_id: z.string().uuid().optional(),
      role: z.string().optional(),
      permissions: z.array(z.object({
        action: z.enum(['read', 'write', 'share', 'delete']),
        granted: z.boolean()
      })),
      conditions: z.array(z.object({
        type: z.enum(['time_based', 'location_based', 'context_based']),
        parameters: z.record(z.any())
      })).optional()
    })).optional(),
    retention_policy: z.object({
      retain_for_days: z.number().positive(),
      auto_delete: z.boolean(),
      archive_after_days: z.number().positive().optional()
    }).optional()
  })
});

// Middleware for authentication check
const requireAuth = (req: express.Request, res: express.Response, next: express.NextFunction) => {
  // Implementation would verify JWT token or session
  // For demo, we'll assume user is authenticated
  (req as any).user = { id: 'user-123', roles: ['agent-manager'] };
  next();
};

// Middleware for agent management permissions
const requireAgentManagement = (req: express.Request, res: express.Response, next: express.NextFunction) => {
  const user = (req as any).user;
  if (!user || !user.roles.includes('agent-manager')) {
    return res.status(403).json({ error: 'Agent management permissions required' });
  }
  next();
};

// =============================================================================
// Agent Management Endpoints
// =============================================================================

/**
 * Register a new agent
 */
router.post('/agents', requireAuth, requireAgentManagement, async (req, res) => {
  try {
    const config = AgentConfigSchema.parse(req.body);
    const agentId = await agentOrchestrator.registerAgent(config);
    
    res.status(201).json({
      success: true,
      agentId,
      message: 'Agent registered successfully'
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({
        error: 'Validation failed',
        details: error.errors
      });
    }
    
    res.status(500).json({
      error: 'Failed to register agent',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Get agent details
 */
router.get('/agents/:agentId', requireAuth, async (req, res) => {
  try {
    const { agentId } = req.params;
    const agent = await agentOrchestrator.getAgentStatus(agentId);
    
    if (!agent) {
      return res.status(404).json({ error: 'Agent not found' });
    }
    
    res.json({
      success: true,
      agent
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to get agent details',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Deploy agent to environment
 */
router.post('/agents/:agentId/deploy', requireAuth, requireAgentManagement, async (req, res) => {
  try {
    const { agentId } = req.params;
    const { environment = 'default' } = req.body;
    
    await agentOrchestrator.deployAgent(agentId, environment);
    
    res.json({
      success: true,
      message: 'Agent deployed successfully'
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to deploy agent',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Suspend agent
 */
router.post('/agents/:agentId/suspend', requireAuth, requireAgentManagement, async (req, res) => {
  try {
    const { agentId } = req.params;
    const { reason = 'Manual suspension' } = req.body;
    
    await agentOrchestrator.suspendAgent(agentId, reason);
    
    res.json({
      success: true,
      message: 'Agent suspended successfully'
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to suspend agent',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Terminate agent
 */
router.delete('/agents/:agentId', requireAuth, requireAgentManagement, async (req, res) => {
  try {
    const { agentId } = req.params;
    
    await agentOrchestrator.terminateAgent(agentId);
    
    res.json({
      success: true,
      message: 'Agent terminated successfully'
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to terminate agent',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// =============================================================================
// Workflow Management Endpoints
// =============================================================================

/**
 * Create a new workflow
 */
router.post('/workflows', requireAuth, requireAgentManagement, async (req, res) => {
  try {
    const workflow = WorkflowDefinitionSchema.parse(req.body);
    const workflowId = await agentOrchestrator.createWorkflow(workflow);
    
    res.status(201).json({
      success: true,
      workflowId,
      message: 'Workflow created successfully'
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({
        error: 'Validation failed',
        details: error.errors
      });
    }
    
    res.status(500).json({
      error: 'Failed to create workflow',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Execute workflow
 */
router.post('/workflows/:workflowId/execute', requireAuth, async (req, res) => {
  try {
    const { workflowId } = req.params;
    const { context = {} } = req.body;
    
    const result = await agentOrchestrator.executeWorkflow(workflowId, context);
    
    res.json({
      success: true,
      result,
      message: 'Workflow executed successfully'
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to execute workflow',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Get workflow execution status
 */
router.get('/workflows/executions/:executionId', requireAuth, async (req, res) => {
  try {
    const { executionId } = req.params;
    const execution = await agentOrchestrator.getWorkflowExecution(executionId);
    
    if (!execution) {
      return res.status(404).json({ error: 'Workflow execution not found' });
    }
    
    res.json({
      success: true,
      execution
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to get workflow execution',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// =============================================================================
// MCP Context Management Endpoints
// =============================================================================

/**
 * Create secure MCP context
 */
router.post('/mcp/contexts', requireAuth, async (req, res) => {
  try {
    const contextData = MCPContextSchema.parse(req.body);
    const userId = (req as any).user.id;
    
    const context = await mcpGateway.createSecureContext(
      contextData.content,
      contextData.metadata,
      userId
    );
    
    res.status(201).json({
      success: true,
      contextId: context.id,
      context,
      message: 'Secure context created successfully'
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({
        error: 'Validation failed',
        details: error.errors
      });
    }
    
    res.status(500).json({
      error: 'Failed to create context',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Get MCP context with access control
 */
router.get('/mcp/contexts/:contextId', requireAuth, async (req, res) => {
  try {
    const { contextId } = req.params;
    const userId = (req as any).user.id;
    
    const context = await mcpGateway.getContext(contextId, userId);
    
    if (!context) {
      return res.status(404).json({ error: 'Context not found or access denied' });
    }
    
    res.json({
      success: true,
      context
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to get context',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Share MCP context with agents
 */
router.post('/mcp/contexts/:contextId/share', requireAuth, async (req, res) => {
  try {
    const { contextId } = req.params;
    const { recipientAgents, permissions } = req.body;
    
    if (!Array.isArray(recipientAgents) || !Array.isArray(permissions)) {
      return res.status(400).json({
        error: 'recipientAgents and permissions must be arrays'
      });
    }
    
    const result = await mcpGateway.shareContext(contextId, recipientAgents, permissions);
    
    res.json({
      success: result.success,
      shared_with: result.shared_with,
      errors: result.errors,
      message: result.success ? 'Context shared successfully' : 'Context sharing partially failed'
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to share context',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Validate MCP context security
 */
router.post('/mcp/contexts/:contextId/validate', requireAuth, async (req, res) => {
  try {
    const { contextId } = req.params;
    const userId = (req as any).user.id;
    
    const context = await mcpGateway.getContext(contextId, userId);
    if (!context) {
      return res.status(404).json({ error: 'Context not found or access denied' });
    }
    
    const validation = await mcpGateway.validateContext(context);
    
    res.json({
      success: true,
      validation,
      message: validation.valid ? 'Context validation passed' : 'Context validation issues found'
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to validate context',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Get context access audit log
 */
router.get('/mcp/contexts/:contextId/audit', requireAuth, async (req, res) => {
  try {
    const { contextId } = req.params;
    
    const auditLog = await mcpGateway.getContextAuditLog(contextId);
    
    res.json({
      success: true,
      auditLog,
      message: 'Context audit log retrieved successfully'
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to get context audit log',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Analyze content sensitivity
 */
router.post('/mcp/analyze-sensitivity', requireAuth, async (req, res) => {
  try {
    const { content } = req.body;
    
    if (!content) {
      return res.status(400).json({ error: 'Content is required' });
    }
    
    const analysis = await mcpGateway.analyzeSensitivity(content);
    
    res.json({
      success: true,
      analysis,
      message: 'Sensitivity analysis completed'
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to analyze content sensitivity',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Delete MCP context
 */
router.delete('/mcp/contexts/:contextId', requireAuth, async (req, res) => {
  try {
    const { contextId } = req.params;
    const userId = (req as any).user.id;
    
    const result = await mcpGateway.deleteContext(contextId, userId);
    
    if (!result.success) {
      return res.status(400).json({
        error: 'Failed to delete context',
        reason: result.reason
      });
    }
    
    res.json({
      success: true,
      message: 'Context deleted successfully'
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to delete context',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// =============================================================================
// Security and Compliance Endpoints
// =============================================================================

/**
 * Get agent security assessment
 */
router.get('/agents/:agentId/security-assessment', requireAuth, async (req, res) => {
  try {
    const { agentId } = req.params;
    
    // This would integrate with the security monitoring system
    const assessment = {
      agentId,
      securityScore: 85,
      lastAssessment: new Date(),
      vulnerabilities: [
        {
          severity: 'medium',
          type: 'access_control',
          description: 'Agent has broad file system access',
          recommendation: 'Restrict file system permissions to required directories only'
        }
      ],
      complianceStatus: {
        GDPR: 'compliant',
        'AI-Act': 'compliant',
        'SOC-2': 'partial'
      }
    };
    
    res.json({
      success: true,
      assessment,
      message: 'Security assessment retrieved successfully'
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to get security assessment',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Get agentic compliance report
 */
router.get('/compliance/agentic-report', requireAuth, async (req, res) => {
  try {
    const { framework, startDate, endDate } = req.query;
    
    // This would integrate with the compliance engine
    const report = {
      framework: framework || 'all',
      period: {
        start: startDate || new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
        end: endDate || new Date()
      },
      overallScore: 92,
      agentCompliance: [
        {
          agentId: 'agent-123',
          name: 'Data Processing Agent',
          complianceScore: 95,
          frameworks: {
            GDPR: 'compliant',
            'AI-Act': 'compliant'
          }
        }
      ],
      violations: [],
      recommendations: [
        'Implement additional logging for autonomous decision-making processes',
        'Add bias detection monitoring for ML-based agents'
      ]
    };
    
    res.json({
      success: true,
      report,
      message: 'Agentic compliance report generated successfully'
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to generate compliance report',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

export { router as agenticRoutes };