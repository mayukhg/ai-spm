import express from 'express';
import { SecurityEventCorrelationEngine, SIEMIntegration, SplunkConnector } from '../security/siem-integration';
import { ModelSecurityManager } from '../ai-security/model-security';
import { PrivacyGovernanceEngine } from '../compliance/privacy-governance';
import passport from 'passport';
import rateLimit from 'express-rate-limit';

const router = express.Router();

// Rate limiting for security endpoints
const securityLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 100, // 100 requests per window
  standardHeaders: true,
  legacyHeaders: false,
});

// Initialize security engines
const securityEngine = new SecurityEventCorrelationEngine();
const modelSecurity = new ModelSecurityManager();
const privacyEngine = new PrivacyGovernanceEngine();

// Initialize SIEM integrations
const siemIntegration = new SIEMIntegration(securityEngine);

// Add Splunk connector if configured
if (process.env.SPLUNK_ENDPOINT && process.env.SPLUNK_TOKEN) {
  const splunkConnector = new SplunkConnector(
    process.env.SPLUNK_ENDPOINT,
    process.env.SPLUNK_TOKEN
  );
  siemIntegration.addIntegration('splunk', splunkConnector);
}

// Middleware to require authentication and log security events
const requireAuth = passport.authenticate('jwt', { session: false });

const logSecurityEvent = (action: string, resource: string) => {
  return (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const user = req.user as any;
    
    securityEngine.ingestEvent({
      source: 'api-gateway',
      type: 'data_access',
      severity: 'low',
      category: 'api_access',
      description: `User accessed ${resource}`,
      actor: {
        userId: user?.id,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      },
      target: {
        resource,
        action,
      },
      metadata: {
        endpoint: req.originalUrl,
        method: req.method,
        correlationId: req.headers['x-correlation-id'],
      },
    });
    
    next();
  };
};

// Security Events and Alerts Routes
router.get('/events', securityLimiter, requireAuth, logSecurityEvent('read', 'security_events'), (req, res) => {
  try {
    const { startTime, endTime, limit = 100 } = req.query;
    
    let events = securityEngine.getEventsByTimeRange(
      startTime ? new Date(startTime as string) : new Date(Date.now() - 24 * 60 * 60 * 1000),
      endTime ? new Date(endTime as string) : new Date()
    );

    events = events.slice(0, Number(limit));

    res.json({
      events,
      total: events.length,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error('Error fetching security events:', error);
    res.status(500).json({ error: 'Failed to fetch security events' });
  }
});

router.get('/alerts', securityLimiter, requireAuth, logSecurityEvent('read', 'security_alerts'), (req, res) => {
  try {
    const { status } = req.query;
    
    let alerts = status === 'active' 
      ? securityEngine.getActiveAlerts()
      : securityEngine.getActiveAlerts(); // Would extend to get all alerts

    res.json({
      alerts,
      total: alerts.length,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error('Error fetching security alerts:', error);
    res.status(500).json({ error: 'Failed to fetch security alerts' });
  }
});

router.post('/alerts/:alertId/acknowledge', securityLimiter, requireAuth, logSecurityEvent('update', 'security_alerts'), (req, res) => {
  try {
    const { alertId } = req.params;
    const user = req.user as any;
    
    // Log alert acknowledgment
    securityEngine.ingestEvent({
      source: 'security-console',
      type: 'system',
      severity: 'low',
      category: 'alert_acknowledged',
      description: 'Security alert acknowledged',
      actor: {
        userId: user.id,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      },
      target: {
        resource: 'security_alert',
        resourceId: alertId,
        action: 'acknowledge',
      },
      metadata: {},
    });

    res.json({ success: true, alertId, acknowledgedBy: user.id });
  } catch (error) {
    console.error('Error acknowledging alert:', error);
    res.status(500).json({ error: 'Failed to acknowledge alert' });
  }
});

// Threat Intelligence Routes
router.post('/threat-intelligence', securityLimiter, requireAuth, logSecurityEvent('create', 'threat_intelligence'), (req, res) => {
  try {
    const { indicators } = req.body;
    const user = req.user as any;

    if (!user.permissions?.includes('threat:manage')) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    securityEngine.addThreatIntelligence(indicators);

    res.json({ 
      success: true, 
      count: indicators.length,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error('Error adding threat intelligence:', error);
    res.status(500).json({ error: 'Failed to add threat intelligence' });
  }
});

// Model Security Routes
router.post('/models/:modelId/versions', securityLimiter, requireAuth, logSecurityEvent('create', 'model_version'), (req, res) => {
  try {
    const { modelId } = req.params;
    const versionData = req.body;
    const user = req.user as any;

    if (!user.permissions?.includes('models:write')) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    const version = modelSecurity.createModelVersion({
      ...versionData,
      modelId,
      createdBy: user.id,
    });

    res.json(version);
  } catch (error) {
    console.error('Error creating model version:', error);
    res.status(500).json({ error: 'Failed to create model version' });
  }
});

router.get('/models/:modelId/versions', securityLimiter, requireAuth, logSecurityEvent('read', 'model_versions'), (req, res) => {
  try {
    const { modelId } = req.params;
    const versions = modelSecurity.getModelVersions(modelId);

    res.json({ versions, total: versions.length });
  } catch (error) {
    console.error('Error fetching model versions:', error);
    res.status(500).json({ error: 'Failed to fetch model versions' });
  }
});

router.post('/models/:modelId/versions/:versionId/promote', securityLimiter, requireAuth, logSecurityEvent('update', 'model_version'), (req, res) => {
  try {
    const { modelId, versionId } = req.params;
    const { targetStatus } = req.body;
    const user = req.user as any;

    if (!user.permissions?.includes('models:promote')) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    modelSecurity.promoteModelVersion(modelId, versionId, targetStatus);

    res.json({ success: true, modelId, versionId, targetStatus });
  } catch (error) {
    console.error('Error promoting model version:', error);
    res.status(500).json({ error: error instanceof Error ? error.message : 'Failed to promote model version' });
  }
});

router.post('/models/:modelId/versions/:versionId/bias-detection', securityLimiter, requireAuth, logSecurityEvent('create', 'bias_detection'), (req, res) => {
  try {
    const { modelId, versionId } = req.params;
    const user = req.user as any;

    if (!user.permissions?.includes('models:analyze')) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    const versions = modelSecurity.getModelVersions(modelId);
    const version = versions.find(v => v.id === versionId);

    if (!version) {
      return res.status(404).json({ error: 'Model version not found' });
    }

    // Run bias detection
    modelSecurity.detectBias(version).then(result => {
      res.json(result);
    }).catch(error => {
      res.status(500).json({ error: 'Bias detection failed' });
    });
  } catch (error) {
    console.error('Error running bias detection:', error);
    res.status(500).json({ error: 'Failed to run bias detection' });
  }
});

// Data Lineage Routes
router.post('/models/:modelId/lineage', securityLimiter, requireAuth, logSecurityEvent('create', 'data_lineage'), (req, res) => {
  try {
    const { modelId } = req.params;
    const lineageData = req.body;
    const user = req.user as any;

    if (!user.permissions?.includes('data:manage')) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    const lineage = modelSecurity.addDataLineage({
      ...lineageData,
      modelId,
    });

    res.json(lineage);
  } catch (error) {
    console.error('Error adding data lineage:', error);
    res.status(500).json({ error: 'Failed to add data lineage' });
  }
});

router.get('/models/:modelId/lineage', securityLimiter, requireAuth, logSecurityEvent('read', 'data_lineage'), (req, res) => {
  try {
    const { modelId } = req.params;
    const lineage = modelSecurity.getDataLineage(modelId);

    res.json({ lineage, total: lineage.length });
  } catch (error) {
    console.error('Error fetching data lineage:', error);
    res.status(500).json({ error: 'Failed to fetch data lineage' });
  }
});

// Privacy and Governance Routes
router.post('/privacy/policies', securityLimiter, requireAuth, logSecurityEvent('create', 'privacy_policy'), (req, res) => {
  try {
    const policyData = req.body;
    const user = req.user as any;

    if (!user.permissions?.includes('privacy:manage')) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    const policy = privacyEngine.createPolicy({
      ...policyData,
      createdBy: user.id,
    });

    res.json(policy);
  } catch (error) {
    console.error('Error creating privacy policy:', error);
    res.status(500).json({ error: 'Failed to create privacy policy' });
  }
});

router.get('/privacy/policies', securityLimiter, requireAuth, logSecurityEvent('read', 'privacy_policies'), (req, res) => {
  try {
    const { framework } = req.query;
    const policies = privacyEngine.getActivePolicies(framework as any);

    res.json({ policies, total: policies.length });
  } catch (error) {
    console.error('Error fetching privacy policies:', error);
    res.status(500).json({ error: 'Failed to fetch privacy policies' });
  }
});

router.post('/privacy/requests', securityLimiter, requireAuth, logSecurityEvent('create', 'privacy_request'), (req, res) => {
  try {
    const requestData = req.body;
    const user = req.user as any;

    const privacyRequest = privacyEngine.submitPrivacyRequest({
      ...requestData,
      verificationStatus: 'verified', // Would implement proper verification
    });

    res.json(privacyRequest);
  } catch (error) {
    console.error('Error submitting privacy request:', error);
    res.status(500).json({ error: 'Failed to submit privacy request' });
  }
});

router.post('/privacy/subjects', securityLimiter, requireAuth, logSecurityEvent('create', 'data_subject'), (req, res) => {
  try {
    const subjectData = req.body;
    const user = req.user as any;

    if (!user.permissions?.includes('privacy:manage')) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    const subject = privacyEngine.registerDataSubject(subjectData);

    res.json(subject);
  } catch (error) {
    console.error('Error registering data subject:', error);
    res.status(500).json({ error: 'Failed to register data subject' });
  }
});

router.put('/privacy/subjects/:subjectId/consent', securityLimiter, requireAuth, logSecurityEvent('update', 'consent_status'), (req, res) => {
  try {
    const { subjectId } = req.params;
    const consentData = req.body;
    const user = req.user as any;

    privacyEngine.updateConsentStatus(subjectId, consentData);

    res.json({ success: true, subjectId });
  } catch (error) {
    console.error('Error updating consent status:', error);
    res.status(500).json({ error: 'Failed to update consent status' });
  }
});

// PII Detection Route
router.post('/privacy/detect-pii', securityLimiter, requireAuth, logSecurityEvent('analyze', 'pii_detection'), (req, res) => {
  try {
    const { data } = req.body;
    const user = req.user as any;

    if (!user.permissions?.includes('data:analyze')) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    modelSecurity.detectPII(data).then(result => {
      res.json(result);
    }).catch(error => {
      res.status(500).json({ error: 'PII detection failed' });
    });
  } catch (error) {
    console.error('Error detecting PII:', error);
    res.status(500).json({ error: 'Failed to detect PII' });
  }
});

// Privacy Assessment Routes
router.post('/privacy/assessments', securityLimiter, requireAuth, logSecurityEvent('create', 'privacy_assessment'), (req, res) => {
  try {
    const assessmentData = req.body;
    const user = req.user as any;

    if (!user.permissions?.includes('privacy:assess')) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    const assessment = privacyEngine.createAssessment(assessmentData);

    res.json(assessment);
  } catch (error) {
    console.error('Error creating privacy assessment:', error);
    res.status(500).json({ error: 'Failed to create privacy assessment' });
  }
});

// SIEM Integration Status
router.get('/siem/status', securityLimiter, requireAuth, logSecurityEvent('read', 'siem_status'), (req, res) => {
  try {
    const user = req.user as any;

    if (!user.permissions?.includes('siem:read')) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    const status = siemIntegration.getIntegrationStatus();

    res.json({
      integrations: status,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error('Error fetching SIEM status:', error);
    res.status(500).json({ error: 'Failed to fetch SIEM status' });
  }
});

export { router as securityRoutes, securityEngine, modelSecurity, privacyEngine };