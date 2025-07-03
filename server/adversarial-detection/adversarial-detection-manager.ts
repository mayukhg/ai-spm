/**
 * Adversarial Detection Manager
 * =============================
 * 
 * Centralized manager for all adversarial attack detection engines.
 * Coordinates real-time threat detection, automated response actions,
 * and comprehensive security monitoring for AI/ML systems.
 * 
 * Features:
 * - Real-time attack detection across multiple vectors
 * - Automated blocking and quarantine of malicious inputs/models
 * - Intelligent alert escalation and incident response
 * - Comprehensive audit logging and compliance reporting
 * - Configurable threat thresholds and response policies
 * 
 * @author AI-SPM Security Team
 * @version 1.0.0
 */

import { logger } from '../monitoring/logger';
import { metrics } from '../monitoring/metrics-collector';
import { DataPoisoningDetector } from './data-poisoning-detector';
import { ModelEvasionDetector } from './model-evasion-detector';
import { MembershipInferenceDetector } from './membership-inference-detector';
import { AttributeInferenceDetector } from './attribute-inference-detector';

// Comprehensive threat detection result
interface ThreatDetectionResult {
  id: string;
  timestamp: Date;
  threatType: 'data_poisoning' | 'model_evasion' | 'membership_inference' | 'attribute_inference';
  isAttack: boolean;
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: number;
  attackDetails: any;
  automatedActions: string[];
  recommendations: string[];
  affectedAssets: string[];
}

// Automated response configuration
interface ResponseConfiguration {
  enableAutomatedBlocking: boolean;
  enableModelQuarantine: boolean;
  enableAlertEscalation: boolean;
  severityThresholds: {
    blockThreshold: 'low' | 'medium' | 'high' | 'critical';
    quarantineThreshold: 'low' | 'medium' | 'high' | 'critical';
    escalationThreshold: 'low' | 'medium' | 'high' | 'critical';
  };
  responseDelays: {
    blockingDelayMs: number;
    quarantineDelayMs: number;
    escalationDelayMs: number;
  };
}

// Asset quarantine status
interface QuarantineStatus {
  assetId: string;
  assetType: 'model' | 'dataset' | 'input';
  quarantinedAt: Date;
  reason: string;
  severity: string;
  autoRelease: boolean;
  releaseAt?: Date;
}

/**
 * Adversarial Detection Manager
 * 
 * Orchestrates all adversarial attack detection engines and manages
 * automated security responses with comprehensive audit logging.
 */
export class AdversarialDetectionManager {
  private dataPoisoningDetector: DataPoisoningDetector;
  private modelEvasionDetector: ModelEvasionDetector;
  private membershipInferenceDetector: MembershipInferenceDetector;
  private attributeInferenceDetector: AttributeInferenceDetector;

  private responseConfig: ResponseConfiguration;
  private detectionHistory: ThreatDetectionResult[] = [];
  private quarantinedAssets: Map<string, QuarantineStatus> = new Map();
  private blockedInputs: Set<string> = new Set();
  private activeIncidents: Map<string, any> = new Map();

  constructor() {
    // Initialize detection engines with shared monitoring components
    this.dataPoisoningDetector = new DataPoisoningDetector(metrics, this.createMockNotificationManager());
    this.modelEvasionDetector = new ModelEvasionDetector(metrics, this.createMockNotificationManager());
    this.membershipInferenceDetector = new MembershipInferenceDetector();
    this.attributeInferenceDetector = new AttributeInferenceDetector();

    // Initialize response configuration with secure defaults
    this.responseConfig = {
      enableAutomatedBlocking: true,
      enableModelQuarantine: true,
      enableAlertEscalation: true,
      severityThresholds: {
        blockThreshold: 'medium',
        quarantineThreshold: 'high',
        escalationThreshold: 'high'
      },
      responseDelays: {
        blockingDelayMs: 100,    // Near-instant blocking
        quarantineDelayMs: 5000, // 5 second delay for quarantine
        escalationDelayMs: 30000 // 30 second delay for escalation
      }
    };

    this.initializeResponseSystem();
  }

  /**
   * Create a mock notification manager for development
   * In production, this would use the actual NotificationManager
   */
  private createMockNotificationManager(): any {
    return {
      sendAlert: async (alertData: any) => {
        logger.warn('Security alert would be sent', alertData);
        return Promise.resolve();
      }
    };
  }

  /**
   * Initialize automated response system
   */
  private initializeResponseSystem(): void {
    logger.info('Adversarial detection manager initialized', {
      engines: ['data_poisoning', 'model_evasion', 'membership_inference', 'attribute_inference'],
      automatedBlocking: this.responseConfig.enableAutomatedBlocking,
      modelQuarantine: this.responseConfig.enableModelQuarantine,
      alertEscalation: this.responseConfig.enableAlertEscalation,
      component: 'AdversarialDetectionManager'
    });

    // Set up periodic cleanup of expired quarantines
    setInterval(() => {
      this.cleanupExpiredQuarantines();
    }, 60000); // Check every minute
  }

  /**
   * Analyze dataset for data poisoning attacks
   */
  async analyzeDataset(
    datasetId: string,
    samples: any[],
    modelPredictions?: any[]
  ): Promise<ThreatDetectionResult> {
    const startTime = Date.now();
    
    try {
      const result = await this.dataPoisoningDetector.analyzeDataset(
        datasetId,
        samples,
        modelPredictions
      );

      const threatResult: ThreatDetectionResult = {
        id: `dp_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        timestamp: new Date(),
        threatType: 'data_poisoning',
        isAttack: result.isAttack,
        severity: result.severity,
        confidence: result.confidence,
        attackDetails: result,
        automatedActions: [],
        recommendations: result.recommendations,
        affectedAssets: [datasetId]
      };

      // Execute automated responses
      if (result.isAttack) {
        await this.executeAutomatedResponse(threatResult);
      }

      // Record detection
      this.recordDetection(threatResult);

      logger.info('Data poisoning analysis completed', {
        datasetId,
        isAttack: result.isAttack,
        severity: result.severity,
        confidence: result.confidence,
        duration: Date.now() - startTime,
        component: 'AdversarialDetectionManager'
      });

      return threatResult;

    } catch (error) {
      logger.error('Data poisoning analysis failed', {
        datasetId,
        error: error instanceof Error ? error.message : 'Unknown error',
        component: 'AdversarialDetectionManager'
      });
      throw error;
    }
  }

  /**
   * Analyze input for model evasion attacks
   */
  async analyzeInput(
    inputSample: any,
    predictions: any[],
    baselineInput?: any
  ): Promise<ThreatDetectionResult> {
    const startTime = Date.now();
    
    try {
      const result = await this.modelEvasionDetector.analyzeInput(
        inputSample,
        predictions,
        baselineInput
      );

      const threatResult: ThreatDetectionResult = {
        id: `me_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        timestamp: new Date(),
        threatType: 'model_evasion',
        isAttack: result.isAttack,
        severity: result.severity,
        confidence: result.confidence,
        attackDetails: result,
        automatedActions: [],
        recommendations: result.recommendations,
        affectedAssets: [inputSample.id, result.metadata.modelId]
      };

      // Execute automated responses
      if (result.isAttack) {
        await this.executeAutomatedResponse(threatResult);
      }

      // Record detection
      this.recordDetection(threatResult);

      logger.info('Model evasion analysis completed', {
        inputId: inputSample.id,
        isAttack: result.isAttack,
        severity: result.severity,
        confidence: result.confidence,
        duration: Date.now() - startTime,
        component: 'AdversarialDetectionManager'
      });

      return threatResult;

    } catch (error) {
      logger.error('Model evasion analysis failed', {
        inputId: inputSample.id,
        error: error instanceof Error ? error.message : 'Unknown error',
        component: 'AdversarialDetectionManager'
      });
      throw error;
    }
  }

  /**
   * Analyze queries for membership inference attacks
   */
  async analyzeMembershipInference(
    queryId: string,
    modelId: string,
    samples: any[],
    shadowPredictions?: any[]
  ): Promise<ThreatDetectionResult> {
    const startTime = Date.now();
    
    try {
      const result = await this.membershipInferenceDetector.analyzeQueries(
        queryId,
        modelId,
        samples,
        shadowPredictions
      );

      const threatResult: ThreatDetectionResult = {
        id: `mi_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        timestamp: new Date(),
        threatType: 'membership_inference',
        isAttack: result.isAttack,
        severity: result.severity,
        confidence: result.confidence,
        attackDetails: result,
        automatedActions: [],
        recommendations: result.recommendations,
        affectedAssets: [modelId]
      };

      // Execute automated responses
      if (result.isAttack) {
        await this.executeAutomatedResponse(threatResult);
      }

      // Record detection
      this.recordDetection(threatResult);

      logger.info('Membership inference analysis completed', {
        queryId,
        modelId,
        isAttack: result.isAttack,
        severity: result.severity,
        confidence: result.confidence,
        duration: Date.now() - startTime,
        component: 'AdversarialDetectionManager'
      });

      return threatResult;

    } catch (error) {
      logger.error('Membership inference analysis failed', {
        queryId,
        modelId,
        error: error instanceof Error ? error.message : 'Unknown error',
        component: 'AdversarialDetectionManager'
      });
      throw error;
    }
  }

  /**
   * Analyze predictions for attribute inference attacks
   */
  async analyzeAttributeInference(
    queryId: string,
    modelId: string,
    samples: any[],
    targetAttributes: string[]
  ): Promise<ThreatDetectionResult> {
    const startTime = Date.now();
    
    try {
      const result = await this.attributeInferenceDetector.analyzeAttributeInference(
        queryId,
        modelId,
        samples,
        targetAttributes
      );

      const threatResult: ThreatDetectionResult = {
        id: `ai_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        timestamp: new Date(),
        threatType: 'attribute_inference',
        isAttack: result.isAttack,
        severity: result.severity,
        confidence: result.confidence,
        attackDetails: result,
        automatedActions: [],
        recommendations: result.recommendations,
        affectedAssets: [modelId]
      };

      // Execute automated responses
      if (result.isAttack) {
        await this.executeAutomatedResponse(threatResult);
      }

      // Record detection
      this.recordDetection(threatResult);

      logger.info('Attribute inference analysis completed', {
        queryId,
        modelId,
        isAttack: result.isAttack,
        severity: result.severity,
        confidence: result.confidence,
        duration: Date.now() - startTime,
        component: 'AdversarialDetectionManager'
      });

      return threatResult;

    } catch (error) {
      logger.error('Attribute inference analysis failed', {
        queryId,
        modelId,
        error: error instanceof Error ? error.message : 'Unknown error',
        component: 'AdversarialDetectionManager'
      });
      throw error;
    }
  }

  /**
   * Execute automated response actions based on threat detection
   */
  private async executeAutomatedResponse(threatResult: ThreatDetectionResult): Promise<void> {
    const actions: string[] = [];

    try {
      // 1. Automated Blocking
      if (this.shouldExecuteAction('block', threatResult.severity)) {
        setTimeout(async () => {
          await this.blockMaliciousInputs(threatResult);
          actions.push('malicious_inputs_blocked');
        }, this.responseConfig.responseDelays.blockingDelayMs);
      }

      // 2. Model/Dataset Quarantine
      if (this.shouldExecuteAction('quarantine', threatResult.severity)) {
        setTimeout(async () => {
          await this.quarantineAffectedAssets(threatResult);
          actions.push('assets_quarantined');
        }, this.responseConfig.responseDelays.quarantineDelayMs);
      }

      // 3. Alert Escalation
      if (this.shouldExecuteAction('escalate', threatResult.severity)) {
        setTimeout(async () => {
          await this.escalateSecurityIncident(threatResult);
          actions.push('incident_escalated');
        }, this.responseConfig.responseDelays.escalationDelayMs);
      }

      threatResult.automatedActions = actions;

      logger.info('Automated response actions initiated', {
        threatId: threatResult.id,
        threatType: threatResult.threatType,
        severity: threatResult.severity,
        actions,
        component: 'AdversarialDetectionManager'
      });

    } catch (error) {
      logger.error('Automated response execution failed', {
        threatId: threatResult.id,
        error: error instanceof Error ? error.message : 'Unknown error',
        component: 'AdversarialDetectionManager'
      });
    }
  }

  /**
   * Check if automated action should be executed based on severity thresholds
   */
  private shouldExecuteAction(actionType: 'block' | 'quarantine' | 'escalate', severity: string): boolean {
    const thresholdMap = {
      'low': 1,
      'medium': 2,
      'high': 3,
      'critical': 4
    };

    const severityLevel = thresholdMap[severity as keyof typeof thresholdMap] || 0;
    let thresholdLevel = 0;

    switch (actionType) {
      case 'block':
        if (!this.responseConfig.enableAutomatedBlocking) return false;
        thresholdLevel = thresholdMap[this.responseConfig.severityThresholds.blockThreshold];
        break;
      case 'quarantine':
        if (!this.responseConfig.enableModelQuarantine) return false;
        thresholdLevel = thresholdMap[this.responseConfig.severityThresholds.quarantineThreshold];
        break;
      case 'escalate':
        if (!this.responseConfig.enableAlertEscalation) return false;
        thresholdLevel = thresholdMap[this.responseConfig.severityThresholds.escalationThreshold];
        break;
    }

    return severityLevel >= thresholdLevel;
  }

  /**
   * Block malicious inputs
   */
  private async blockMaliciousInputs(threatResult: ThreatDetectionResult): Promise<void> {
    if (threatResult.threatType === 'model_evasion') {
      const inputId = threatResult.attackDetails.metadata?.inputId;
      if (inputId) {
        this.blockedInputs.add(inputId);
        
        logger.warn('Malicious input blocked', {
          inputId,
          threatId: threatResult.id,
          severity: threatResult.severity,
          component: 'AdversarialDetectionManager'
        });
      }
    }

    // Record metrics
    metrics.securityEvents.inc({
      event_type: 'input_blocked',
      severity: threatResult.severity,
      source: 'adversarial_detection'
    });
  }

  /**
   * Quarantine affected assets (models, datasets)
   */
  private async quarantineAffectedAssets(threatResult: ThreatDetectionResult): Promise<void> {
    for (const assetId of threatResult.affectedAssets) {
      const assetType = this.determineAssetType(assetId, threatResult.threatType);
      
      const quarantineStatus: QuarantineStatus = {
        assetId,
        assetType,
        quarantinedAt: new Date(),
        reason: `${threatResult.threatType}: ${threatResult.attackDetails.attackType}`,
        severity: threatResult.severity,
        autoRelease: threatResult.severity !== 'critical',
        releaseAt: threatResult.severity !== 'critical' ? 
          new Date(Date.now() + 24 * 60 * 60 * 1000) : // 24 hours for non-critical
          undefined // Manual release for critical
      };

      this.quarantinedAssets.set(assetId, quarantineStatus);

      logger.warn('Asset quarantined', {
        assetId,
        assetType,
        threatId: threatResult.id,
        severity: threatResult.severity,
        autoRelease: quarantineStatus.autoRelease,
        component: 'AdversarialDetectionManager'
      });
    }

    // Record metrics
    metrics.securityEvents.inc({
      event_type: 'asset_quarantined',
      severity: threatResult.severity,
      source: 'adversarial_detection'
    });
  }

  /**
   * Escalate security incident
   */
  private async escalateSecurityIncident(threatResult: ThreatDetectionResult): Promise<void> {
    const incidentId = `inc_${threatResult.id}`;
    
    const incident = {
      id: incidentId,
      threatId: threatResult.id,
      type: threatResult.threatType,
      severity: threatResult.severity,
      confidence: threatResult.confidence,
      affectedAssets: threatResult.affectedAssets,
      createdAt: new Date(),
      status: 'open',
      assignedTo: null,
      escalationLevel: 1
    };

    this.activeIncidents.set(incidentId, incident);

    // Send escalation alert
    await this.sendEscalationAlert(incident, threatResult);

    logger.warn('Security incident escalated', {
      incidentId,
      threatId: threatResult.id,
      threatType: threatResult.threatType,
      severity: threatResult.severity,
      component: 'AdversarialDetectionManager'
    });

    // Record metrics
    metrics.securityEvents.inc({
      event_type: 'incident_escalated',
      severity: threatResult.severity,
      source: 'adversarial_detection'
    });
  }

  /**
   * Determine asset type based on ID and threat type
   */
  private determineAssetType(assetId: string, threatType: string): 'model' | 'dataset' | 'input' {
    if (threatType === 'data_poisoning') return 'dataset';
    if (threatType === 'model_evasion') return assetId.includes('input') ? 'input' : 'model';
    return 'model'; // membership_inference and attribute_inference typically target models
  }

  /**
   * Send escalation alert
   */
  private async sendEscalationAlert(incident: any, threatResult: ThreatDetectionResult): Promise<void> {
    const alertData = {
      type: 'security_incident_escalation',
      severity: threatResult.severity,
      title: `CRITICAL: ${threatResult.threatType.toUpperCase()} Attack Detected`,
      description: `High-confidence adversarial attack requires immediate attention`,
      details: {
        incidentId: incident.id,
        threatId: threatResult.id,
        threatType: threatResult.threatType,
        attackType: threatResult.attackDetails.attackType,
        confidence: threatResult.confidence,
        affectedAssets: threatResult.affectedAssets,
        automatedActions: threatResult.automatedActions,
        recommendations: threatResult.recommendations
      },
      timestamp: new Date()
    };

    // Use logger for now, in production this would integrate with notification system
    logger.error('SECURITY INCIDENT ESCALATION', alertData);
  }

  /**
   * Record threat detection for audit and analytics
   */
  private recordDetection(threatResult: ThreatDetectionResult): void {
    this.detectionHistory.push(threatResult);

    // Keep only last 10000 detections in memory
    if (this.detectionHistory.length > 10000) {
      this.detectionHistory = this.detectionHistory.slice(-10000);
    }

    // Record comprehensive metrics
    metrics.securityEvents.inc({
      event_type: 'threat_detected',
      severity: threatResult.severity,
      source: 'adversarial_detection'
    });

    // Record threat-specific metrics
    const metricName = `adversarial_detection_${threatResult.threatType}_total`;
    metrics.recordMetric(metricName, {
      threat_id: threatResult.id,
      is_attack: threatResult.isAttack,
      severity: threatResult.severity,
      confidence: threatResult.confidence,
      automated_actions: threatResult.automatedActions.length
    });
  }

  /**
   * Cleanup expired quarantines
   */
  private cleanupExpiredQuarantines(): void {
    const now = new Date();
    const releasedAssets: string[] = [];

    for (const [assetId, status] of this.quarantinedAssets.entries()) {
      if (status.autoRelease && status.releaseAt && now >= status.releaseAt) {
        this.quarantinedAssets.delete(assetId);
        releasedAssets.push(assetId);
      }
    }

    if (releasedAssets.length > 0) {
      logger.info('Assets released from quarantine', {
        releasedAssets,
        count: releasedAssets.length,
        component: 'AdversarialDetectionManager'
      });
    }
  }

  /**
   * Get comprehensive threat detection statistics
   */
  getDetectionStats(): {
    totalDetections: number;
    attackDetections: number;
    severeAttacks: number;
    blockedInputs: number;
    quarantinedAssets: number;
    activeIncidents: number;
    detectionsByType: Record<string, number>;
    avgConfidence: number;
    recentThreats: ThreatDetectionResult[];
  } {
    const attackDetections = this.detectionHistory.filter(d => d.isAttack);
    const severeAttacks = attackDetections.filter(d => d.severity === 'high' || d.severity === 'critical');
    
    const detectionsByType: Record<string, number> = {};
    for (const detection of attackDetections) {
      detectionsByType[detection.threatType] = (detectionsByType[detection.threatType] || 0) + 1;
    }

    const avgConfidence = attackDetections.length > 0 ? 
      attackDetections.reduce((sum, d) => sum + d.confidence, 0) / attackDetections.length : 0;

    const recentThreats = this.detectionHistory
      .filter(d => d.isAttack)
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
      .slice(0, 10);

    return {
      totalDetections: this.detectionHistory.length,
      attackDetections: attackDetections.length,
      severeAttacks: severeAttacks.length,
      blockedInputs: this.blockedInputs.size,
      quarantinedAssets: this.quarantinedAssets.size,
      activeIncidents: this.activeIncidents.size,
      detectionsByType,
      avgConfidence,
      recentThreats
    };
  }

  /**
   * Get quarantined assets
   */
  getQuarantinedAssets(): QuarantineStatus[] {
    return Array.from(this.quarantinedAssets.values());
  }

  /**
   * Get active security incidents
   */
  getActiveIncidents(): any[] {
    return Array.from(this.activeIncidents.values());
  }

  /**
   * Update response configuration
   */
  updateResponseConfiguration(config: Partial<ResponseConfiguration>): void {
    this.responseConfig = { ...this.responseConfig, ...config };
    
    logger.info('Response configuration updated', {
      config: this.responseConfig,
      component: 'AdversarialDetectionManager'
    });
  }

  /**
   * Manually release asset from quarantine
   */
  releaseFromQuarantine(assetId: string, reason: string): boolean {
    if (this.quarantinedAssets.has(assetId)) {
      this.quarantinedAssets.delete(assetId);
      
      logger.info('Asset manually released from quarantine', {
        assetId,
        reason,
        component: 'AdversarialDetectionManager'
      });
      
      return true;
    }
    return false;
  }

  /**
   * Clear blocked inputs (for testing or manual override)
   */
  clearBlockedInputs(): void {
    this.blockedInputs.clear();
    this.modelEvasionDetector.clearBlockedInputs();
    
    logger.info('All blocked inputs cleared', {
      component: 'AdversarialDetectionManager'
    });
  }
}