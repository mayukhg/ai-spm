/**
 * AI Threat Detection Configuration API Routes
 * Allows runtime configuration of threat detection rules
 */

import express from 'express';
import { z } from 'zod';
import fs from 'fs/promises';
import path from 'path';

const router = express.Router();

// Configuration file path
const THREAT_CONFIG_PATH = path.join(__dirname, '../config/threat-detection-config.json');
const COMPLIANCE_CONFIG_PATH = path.join(__dirname, '../config/compliance-policies.json');

// Validation schemas
const ThreatUpdateSchema = z.object({
  threatName: z.string(),
  enabled: z.boolean(),
  severity: z.enum(['critical', 'high', 'medium', 'low']).optional(),
  thresholds: z.record(z.number()).optional(),
  responseActions: z.array(z.string()).optional()
});

const CustomThreatSchema = z.object({
  name: z.string(),
  enabled: z.boolean().default(true),
  severity: z.enum(['critical', 'high', 'medium', 'low']),
  detectionMethods: z.array(z.string()),
  thresholds: z.record(z.number()),
  responseActions: z.array(z.string())
});

// Middleware for authentication (simplified for demo)
const requireAuth = (req: express.Request, res: express.Response, next: express.NextFunction) => {
  // In production, implement proper JWT verification
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  // Mock user context
  (req as any).user = { id: 'user-123', roles: ['security_admin'] };
  next();
};

// Middleware for admin permissions
const requireSecurityAdmin = (req: express.Request, res: express.Response, next: express.NextFunction) => {
  const user = (req as any).user;
  if (!user || !user.roles.includes('security_admin')) {
    return res.status(403).json({ error: 'Security administrator permissions required' });
  }
  next();
};

/**
 * Get current threat detection configuration
 */
router.get('/threat-config', requireAuth, async (req, res) => {
  try {
    const configData = await fs.readFile(THREAT_CONFIG_PATH, 'utf8');
    const config = JSON.parse(configData);
    
    res.json({
      success: true,
      config,
      message: 'Threat detection configuration retrieved successfully'
    });
  } catch (error) {
    console.error('Failed to read threat configuration:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to read threat configuration',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Update threat detection status
 */
router.patch('/threat-config/:threatName/status', requireAuth, requireSecurityAdmin, async (req, res) => {
  try {
    const { threatName } = req.params;
    const { enabled } = req.body;
    
    if (typeof enabled !== 'boolean') {
      return res.status(400).json({
        success: false,
        error: 'enabled field must be a boolean'
      });
    }
    
    // Read current configuration
    const configData = await fs.readFile(THREAT_CONFIG_PATH, 'utf8');
    const config = JSON.parse(configData);
    
    // Update threat status
    if (!config.aiSpecificThreats || !config.aiSpecificThreats[threatName]) {
      return res.status(404).json({
        success: false,
        error: `Threat '${threatName}' not found in configuration`
      });
    }
    
    config.aiSpecificThreats[threatName].enabled = enabled;
    
    // Write back to file
    await fs.writeFile(THREAT_CONFIG_PATH, JSON.stringify(config, null, 2));
    
    // Notify AI Scanner service to reload configuration
    await notifyMicroservice('ai-scanner', 'reload-config');
    
    res.json({
      success: true,
      message: `Threat '${threatName}' ${enabled ? 'enabled' : 'disabled'} successfully`,
      threat: {
        name: threatName,
        enabled,
        severity: config.aiSpecificThreats[threatName].severity
      }
    });
    
  } catch (error) {
    console.error('Failed to update threat status:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update threat status',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Update threat thresholds
 */
router.patch('/threat-config/:threatName/thresholds', requireAuth, requireSecurityAdmin, async (req, res) => {
  try {
    const { threatName } = req.params;
    const { thresholds } = req.body;
    
    if (!thresholds || typeof thresholds !== 'object') {
      return res.status(400).json({
        success: false,
        error: 'thresholds must be an object with numeric values'
      });
    }
    
    // Validate that all threshold values are numbers
    for (const [key, value] of Object.entries(thresholds)) {
      if (typeof value !== 'number') {
        return res.status(400).json({
          success: false,
          error: `Threshold '${key}' must be a number`
        });
      }
    }
    
    // Read current configuration
    const configData = await fs.readFile(THREAT_CONFIG_PATH, 'utf8');
    const config = JSON.parse(configData);
    
    // Update thresholds
    if (!config.aiSpecificThreats || !config.aiSpecificThreats[threatName]) {
      return res.status(404).json({
        success: false,
        error: `Threat '${threatName}' not found in configuration`
      });
    }
    
    config.aiSpecificThreats[threatName].thresholds = {
      ...config.aiSpecificThreats[threatName].thresholds,
      ...thresholds
    };
    
    // Write back to file
    await fs.writeFile(THREAT_CONFIG_PATH, JSON.stringify(config, null, 2));
    
    // Notify AI Scanner service to reload configuration
    await notifyMicroservice('ai-scanner', 'reload-config');
    
    res.json({
      success: true,
      message: `Thresholds for '${threatName}' updated successfully`,
      updatedThresholds: config.aiSpecificThreats[threatName].thresholds
    });
    
  } catch (error) {
    console.error('Failed to update threat thresholds:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update threat thresholds',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Add custom threat detection rule
 */
router.post('/threat-config/custom', requireAuth, requireSecurityAdmin, async (req, res) => {
  try {
    const customThreat = CustomThreatSchema.parse(req.body);
    
    // Read current configuration
    const configData = await fs.readFile(THREAT_CONFIG_PATH, 'utf8');
    const config = JSON.parse(configData);
    
    // Check if threat already exists
    if (config.aiSpecificThreats && config.aiSpecificThreats[customThreat.name]) {
      return res.status(409).json({
        success: false,
        error: `Threat '${customThreat.name}' already exists`
      });
    }
    
    // Add custom threat
    if (!config.aiSpecificThreats) {
      config.aiSpecificThreats = {};
    }
    
    config.aiSpecificThreats[customThreat.name] = {
      enabled: customThreat.enabled,
      severity: customThreat.severity,
      detectionMethods: customThreat.detectionMethods,
      thresholds: customThreat.thresholds,
      responseActions: customThreat.responseActions
    };
    
    // Write back to file
    await fs.writeFile(THREAT_CONFIG_PATH, JSON.stringify(config, null, 2));
    
    // Notify AI Scanner service to reload configuration
    await notifyMicroservice('ai-scanner', 'reload-config');
    
    res.status(201).json({
      success: true,
      message: `Custom threat '${customThreat.name}' added successfully`,
      threat: customThreat
    });
    
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({
        success: false,
        error: 'Validation failed',
        details: error.errors
      });
    }
    
    console.error('Failed to add custom threat:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to add custom threat',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Get compliance policies configuration
 */
router.get('/compliance-config', requireAuth, async (req, res) => {
  try {
    const configData = await fs.readFile(COMPLIANCE_CONFIG_PATH, 'utf8');
    const config = JSON.parse(configData);
    
    res.json({
      success: true,
      config,
      message: 'Compliance policies configuration retrieved successfully'
    });
  } catch (error) {
    console.error('Failed to read compliance configuration:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to read compliance configuration',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Reload threat detection configuration in microservices
 */
router.post('/reload-config', requireAuth, requireSecurityAdmin, async (req, res) => {
  try {
    // Notify all relevant microservices to reload configuration
    const services = ['ai-scanner', 'data-integrity', 'compliance-engine'];
    const results = await Promise.allSettled(
      services.map(service => notifyMicroservice(service, 'reload-config'))
    );
    
    const successCount = results.filter(r => r.status === 'fulfilled').length;
    const failureCount = results.length - successCount;
    
    res.json({
      success: failureCount === 0,
      message: `Configuration reload: ${successCount} services updated, ${failureCount} failed`,
      details: {
        successful: successCount,
        failed: failureCount,
        total: results.length
      }
    });
    
  } catch (error) {
    console.error('Failed to reload configuration:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to reload configuration',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Get threat detection statistics
 */
router.get('/threat-stats', requireAuth, async (req, res) => {
  try {
    // This would integrate with the actual threat detection system
    // For now, return mock statistics
    const stats = {
      totalThreats: 4,
      enabledThreats: 3,
      disabledThreats: 1,
      detectedIncidents: {
        last24Hours: 5,
        lastWeek: 23,
        lastMonth: 87
      },
      threatBreakdown: {
        modelInversionAttacks: { detected: 2, severity: 'high' },
        adversarialInputs: { detected: 1, severity: 'medium' },
        dataExtraction: { detected: 0, severity: 'critical' },
        modelStealing: { detected: 2, severity: 'high' }
      }
    };
    
    res.json({
      success: true,
      stats,
      message: 'Threat detection statistics retrieved successfully'
    });
  } catch (error) {
    console.error('Failed to get threat statistics:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get threat statistics',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// Helper function to notify microservices
async function notifyMicroservice(serviceName: string, action: string): Promise<void> {
  try {
    const serviceUrls = {
      'ai-scanner': process.env.AI_SCANNER_URL || 'http://localhost:8001',
      'data-integrity': process.env.DATA_INTEGRITY_URL || 'http://localhost:8002',
      'compliance-engine': process.env.COMPLIANCE_ENGINE_URL || 'http://localhost:8004'
    };
    
    const serviceUrl = serviceUrls[serviceName as keyof typeof serviceUrls];
    if (!serviceUrl) {
      throw new Error(`Unknown service: ${serviceName}`);
    }
    
    const response = await fetch(`${serviceUrl}/admin/${action}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Internal-Service': 'true'
      }
    });
    
    if (!response.ok) {
      throw new Error(`Service ${serviceName} responded with status ${response.status}`);
    }
    
    console.log(`Successfully notified ${serviceName} to ${action}`);
  } catch (error) {
    console.error(`Failed to notify ${serviceName}:`, error);
    throw error;
  }
}

export { router as threatConfigRoutes };