/**
 * Membership Inference Attack Detection Engine
 * ===========================================
 * 
 * This module implements advanced detection mechanisms for membership inference attacks
 * where adversaries attempt to determine if specific data points were used in model training.
 * These attacks pose serious privacy risks, especially for models trained on sensitive data.
 * 
 * Detection Methods:
 * - Confidence score analysis and distribution modeling
 * - Loss function analysis for overfitting indicators
 * - Shadow model comparison techniques
 * - Statistical distance measurements
 * - Gradient magnitude analysis
 * - Model behavior consistency checks
 * 
 * @author AI-SPM Security Team
 * @version 1.0.0
 */

import { logger } from '../monitoring/logger';
import { metrics } from '../monitoring/metrics-collector';

// Membership inference attack signature patterns
interface MembershipInferenceSignature {
  id: string;
  name: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  pattern: {
    highConfidenceThreshold: boolean;
    lowLossThreshold: boolean;
    distributionAnomaly: boolean;
    gradientMagnitudeAnomaly: boolean;
    overfittingIndicators: boolean;
    shadowModelDisagreement: boolean;
  };
  thresholds: {
    confidenceThreshold: number;
    lossThreshold: number;
    distributionKLDivergence: number;
    gradientMagnitudeThreshold: number;
    overfittingScore: number;
    shadowModelAgreementThreshold: number;
  };
}

// Detection result interface
interface MembershipInferenceDetectionResult {
  isAttack: boolean;
  attackType: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: number;
  detectionMethods: string[];
  privacyRisk: 'low' | 'medium' | 'high' | 'critical';
  affectedRecords: number;
  recommendations: string[];
  timestamp: Date;
  metadata: {
    queryId: string;
    modelId: string;
    targetSamples: number;
    avgConfidence: number;
    avgLoss: number;
    distributionScore: number;
    gradientScore: number;
    overfittingScore: number;
    shadowModelScore: number;
  };
}

// Query sample interface for analysis
interface QuerySample {
  id: string;
  features: number[];
  label?: string | number;
  confidence?: number;
  loss?: number;
  gradients?: number[];
  timestamp: Date;
  source: string;
  metadata?: Record<string, any>;
}

// Shadow model prediction interface
interface ShadowModelPrediction {
  modelId: string;
  prediction: any;
  confidence: number;
  loss: number;
  membershipScore: number;
}

/**
 * Membership Inference Detection Engine
 * 
 * Implements advanced privacy attack detection to identify attempts
 * to infer training data membership through model behavior analysis.
 */
export class MembershipInferenceDetector {
  private signatures: MembershipInferenceSignature[] = [];
  private detectionHistory: Map<string, MembershipInferenceDetectionResult[]> = new Map();
  private baselineDistributions: Map<string, { confidence: number[]; loss: number[] }> = new Map();
  private shadowModels: Map<string, ShadowModelPrediction[]> = new Map();

  constructor() {
    this.initializeSignatures();
  }

  /**
   * Initialize predefined membership inference attack signatures
   * These signatures define patterns and thresholds for various attack types
   */
  private initializeSignatures(): void {
    this.signatures = [
      {
        id: 'threshold_attack',
        name: 'Threshold-based Membership Inference',
        description: 'Simple threshold attack using prediction confidence',
        severity: 'medium',
        pattern: {
          highConfidenceThreshold: true,
          lowLossThreshold: true,
          distributionAnomaly: false,
          gradientMagnitudeAnomaly: false,
          overfittingIndicators: true,
          shadowModelDisagreement: false
        },
        thresholds: {
          confidenceThreshold: 0.9,
          lossThreshold: 0.1,
          distributionKLDivergence: 0.1,
          gradientMagnitudeThreshold: 0.1,
          overfittingScore: 0.7,
          shadowModelAgreementThreshold: 0.8
        }
      },
      {
        id: 'shadow_model_attack',
        name: 'Shadow Model-based Attack',
        description: 'Advanced attack using shadow models to infer membership',
        severity: 'high',
        pattern: {
          highConfidenceThreshold: true,
          lowLossThreshold: true,
          distributionAnomaly: true,
          gradientMagnitudeAnomaly: false,
          overfittingIndicators: true,
          shadowModelDisagreement: true
        },
        thresholds: {
          confidenceThreshold: 0.85,
          lossThreshold: 0.15,
          distributionKLDivergence: 0.2,
          gradientMagnitudeThreshold: 0.1,
          overfittingScore: 0.8,
          shadowModelAgreementThreshold: 0.6
        }
      },
      {
        id: 'gradient_attack',
        name: 'Gradient-based Membership Inference',
        description: 'Attack using gradient information for membership inference',
        severity: 'critical',
        pattern: {
          highConfidenceThreshold: false,
          lowLossThreshold: false,
          distributionAnomaly: true,
          gradientMagnitudeAnomaly: true,
          overfittingIndicators: true,
          shadowModelDisagreement: true
        },
        thresholds: {
          confidenceThreshold: 0.8,
          lossThreshold: 0.2,
          distributionKLDivergence: 0.25,
          gradientMagnitudeThreshold: 0.2,
          overfittingScore: 0.75,
          shadowModelAgreementThreshold: 0.5
        }
      },
      {
        id: 'distribution_attack',
        name: 'Distribution-based Attack',
        description: 'Statistical attack analyzing prediction distributions',
        severity: 'high',
        pattern: {
          highConfidenceThreshold: true,
          lowLossThreshold: true,
          distributionAnomaly: true,
          gradientMagnitudeAnomaly: false,
          overfittingIndicators: false,
          shadowModelDisagreement: false
        },
        thresholds: {
          confidenceThreshold: 0.88,
          lossThreshold: 0.12,
          distributionKLDivergence: 0.3,
          gradientMagnitudeThreshold: 0.1,
          overfittingScore: 0.6,
          shadowModelAgreementThreshold: 0.7
        }
      }
    ];

    logger.info('Membership inference detection signatures initialized', {
      signatureCount: this.signatures.length,
      component: 'MembershipInferenceDetector'
    });
  }

  /**
   * Analyze query patterns for membership inference attacks
   * 
   * @param queryId - Unique identifier for the query batch
   * @param modelId - Target model identifier
   * @param samples - Array of query samples to analyze
   * @param shadowPredictions - Optional shadow model predictions
   * @returns Detection result with privacy risk assessment
   */
  async analyzeQueries(
    queryId: string,
    modelId: string,
    samples: QuerySample[],
    shadowPredictions?: ShadowModelPrediction[]
  ): Promise<MembershipInferenceDetectionResult> {
    const startTime = Date.now();
    
    logger.info('Starting membership inference analysis', {
      queryId,
      modelId,
      sampleCount: samples.length,
      component: 'MembershipInferenceDetector'
    });

    try {
      // Perform multiple detection analyses
      const confidenceAnalysis = this.analyzeConfidencePatterns(samples);
      const lossAnalysis = this.analyzeLossPatterns(samples);
      const distributionAnalysis = this.analyzeDistributionPatterns(modelId, samples);
      const gradientAnalysis = this.analyzeGradientPatterns(samples);
      const overfittingAnalysis = this.analyzeOverfittingIndicators(samples);
      const shadowModelAnalysis = shadowPredictions ? 
        this.analyzeShadowModelDisagreement(samples, shadowPredictions) : null;

      // Combine analysis results
      const detectionResult = this.combineAnalysisResults({
        queryId,
        modelId,
        samples,
        confidenceAnalysis,
        lossAnalysis,
        distributionAnalysis,
        gradientAnalysis,
        overfittingAnalysis,
        shadowModelAnalysis
      });

      // Record metrics
      metrics.recordMetric('adversarial_detection_membership_inference_analysis', {
        query_id: queryId,
        model_id: modelId,
        sample_count: samples.length,
        analysis_duration_ms: Date.now() - startTime,
        is_attack: detectionResult.isAttack,
        severity: detectionResult.severity,
        privacy_risk: detectionResult.privacyRisk,
        confidence: detectionResult.confidence
      });

      // Store detection history
      if (!this.detectionHistory.has(modelId)) {
        this.detectionHistory.set(modelId, []);
      }
      this.detectionHistory.get(modelId)!.push(detectionResult);

      // Send alerts if attack detected
      if (detectionResult.isAttack) {
        await this.sendPrivacyAlert(detectionResult);
      }

      logger.info('Membership inference analysis completed', {
        queryId,
        modelId,
        isAttack: detectionResult.isAttack,
        severity: detectionResult.severity,
        privacyRisk: detectionResult.privacyRisk,
        confidence: detectionResult.confidence,
        duration: Date.now() - startTime,
        component: 'MembershipInferenceDetector'
      });

      return detectionResult;

    } catch (error) {
      logger.error('Membership inference analysis failed', {
        queryId,
        modelId,
        error: error instanceof Error ? error.message : 'Unknown error',
        component: 'MembershipInferenceDetector'
      });
      
      throw new Error(`Membership inference analysis failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Analyze confidence score patterns for membership inference indicators
   */
  private analyzeConfidencePatterns(samples: QuerySample[]): {
    avgConfidence: number;
    confidenceVariance: number;
    highConfidenceRatio: number;
    isHighConfidencePattern: boolean;
  } {
    const confidenceScores = samples
      .filter(s => s.confidence !== undefined)
      .map(s => s.confidence!);

    if (confidenceScores.length === 0) {
      return {
        avgConfidence: 0,
        confidenceVariance: 0,
        highConfidenceRatio: 0,
        isHighConfidencePattern: false
      };
    }

    const avgConfidence = confidenceScores.reduce((sum, conf) => sum + conf, 0) / confidenceScores.length;
    const confidenceVariance = confidenceScores.reduce((sum, conf) => 
      sum + Math.pow(conf - avgConfidence, 2), 0) / confidenceScores.length;
    
    const highConfidenceCount = confidenceScores.filter(conf => conf > 0.9).length;
    const highConfidenceRatio = highConfidenceCount / confidenceScores.length;
    const isHighConfidencePattern = highConfidenceRatio > 0.3 && avgConfidence > 0.85;

    return {
      avgConfidence,
      confidenceVariance,
      highConfidenceRatio,
      isHighConfidencePattern
    };
  }

  /**
   * Analyze loss patterns for overfitting indicators
   */
  private analyzeLossPatterns(samples: QuerySample[]): {
    avgLoss: number;
    lossVariance: number;
    lowLossRatio: number;
    isLowLossPattern: boolean;
  } {
    const lossValues = samples
      .filter(s => s.loss !== undefined)
      .map(s => s.loss!);

    if (lossValues.length === 0) {
      return {
        avgLoss: 0,
        lossVariance: 0,
        lowLossRatio: 0,
        isLowLossPattern: false
      };
    }

    const avgLoss = lossValues.reduce((sum, loss) => sum + loss, 0) / lossValues.length;
    const lossVariance = lossValues.reduce((sum, loss) => 
      sum + Math.pow(loss - avgLoss, 2), 0) / lossValues.length;
    
    const lowLossCount = lossValues.filter(loss => loss < 0.1).length;
    const lowLossRatio = lowLossCount / lossValues.length;
    const isLowLossPattern = lowLossRatio > 0.4 && avgLoss < 0.15;

    return {
      avgLoss,
      lossVariance,
      lowLossRatio,
      isLowLossPattern
    };
  }

  /**
   * Analyze distribution patterns compared to baseline
   */
  private analyzeDistributionPatterns(modelId: string, samples: QuerySample[]): {
    klDivergence: number;
    jsDistance: number;
    isDistributionAnomaly: boolean;
  } {
    const baseline = this.baselineDistributions.get(modelId);
    if (!baseline) {
      // Initialize baseline if not exists
      this.updateBaseline(modelId, samples);
      return { klDivergence: 0, jsDistance: 0, isDistributionAnomaly: false };
    }

    const currentConfidences = samples
      .filter(s => s.confidence !== undefined)
      .map(s => s.confidence!);

    if (currentConfidences.length === 0) {
      return { klDivergence: 0, jsDistance: 0, isDistributionAnomaly: false };
    }

    // Calculate KL divergence and JS distance
    const klDivergence = this.calculateKLDivergence(baseline.confidence, currentConfidences);
    const jsDistance = this.calculateJSDistance(baseline.confidence, currentConfidences);
    const isDistributionAnomaly = klDivergence > 0.2 || jsDistance > 0.15;

    return { klDivergence, jsDistance, isDistributionAnomaly };
  }

  /**
   * Analyze gradient magnitude patterns
   */
  private analyzeGradientPatterns(samples: QuerySample[]): {
    avgGradientMagnitude: number;
    gradientVariance: number;
    isGradientAnomaly: boolean;
  } {
    const gradientMagnitudes: number[] = [];

    for (const sample of samples) {
      if (sample.gradients && sample.gradients.length > 0) {
        const magnitude = Math.sqrt(
          sample.gradients.reduce((sum, grad) => sum + grad * grad, 0)
        );
        gradientMagnitudes.push(magnitude);
      }
    }

    if (gradientMagnitudes.length === 0) {
      return { avgGradientMagnitude: 0, gradientVariance: 0, isGradientAnomaly: false };
    }

    const avgGradientMagnitude = gradientMagnitudes.reduce((sum, mag) => sum + mag, 0) / gradientMagnitudes.length;
    const gradientVariance = gradientMagnitudes.reduce((sum, mag) => 
      sum + Math.pow(mag - avgGradientMagnitude, 2), 0) / gradientMagnitudes.length;
    
    const isGradientAnomaly = avgGradientMagnitude > 0.2 || gradientVariance > 0.1;

    return { avgGradientMagnitude, gradientVariance, isGradientAnomaly };
  }

  /**
   * Analyze overfitting indicators
   */
  private analyzeOverfittingIndicators(samples: QuerySample[]): {
    overfittingScore: number;
    isOverfittingDetected: boolean;
  } {
    const confidenceScores = samples
      .filter(s => s.confidence !== undefined)
      .map(s => s.confidence!);
    
    const lossValues = samples
      .filter(s => s.loss !== undefined)
      .map(s => s.loss!);

    if (confidenceScores.length === 0 || lossValues.length === 0) {
      return { overfittingScore: 0, isOverfittingDetected: false };
    }

    // Simple overfitting score based on high confidence + low loss combination
    const highConfidenceLowLoss = samples.filter(s => 
      s.confidence !== undefined && s.loss !== undefined && 
      s.confidence > 0.9 && s.loss < 0.1
    ).length;

    const overfittingScore = highConfidenceLowLoss / samples.length;
    const isOverfittingDetected = overfittingScore > 0.3;

    return { overfittingScore, isOverfittingDetected };
  }

  /**
   * Analyze shadow model disagreement patterns
   */
  private analyzeShadowModelDisagreement(
    samples: QuerySample[],
    shadowPredictions: ShadowModelPrediction[]
  ): {
    agreementScore: number;
    membershipScore: number;
    isDisagreementPattern: boolean;
  } {
    if (shadowPredictions.length === 0) {
      return { agreementScore: 1.0, membershipScore: 0, isDisagreementPattern: false };
    }

    // Calculate agreement between main model and shadow models
    let totalAgreement = 0;
    let totalMembershipScore = 0;

    for (let i = 0; i < Math.min(samples.length, shadowPredictions.length); i++) {
      const sample = samples[i];
      const shadowPred = shadowPredictions[i];

      // Simple agreement calculation (can be enhanced with more sophisticated methods)
      const agreement = sample.confidence && shadowPred.confidence ? 
        1 - Math.abs(sample.confidence - shadowPred.confidence) : 0;
      
      totalAgreement += agreement;
      totalMembershipScore += shadowPred.membershipScore;
    }

    const agreementScore = totalAgreement / Math.min(samples.length, shadowPredictions.length);
    const membershipScore = totalMembershipScore / shadowPredictions.length;
    const isDisagreementPattern = agreementScore < 0.7 && membershipScore > 0.6;

    return { agreementScore, membershipScore, isDisagreementPattern };
  }

  /**
   * Calculate KL divergence between two distributions
   */
  private calculateKLDivergence(baseline: number[], current: number[]): number {
    // Simplified KL divergence calculation
    // In practice, you'd want to bin the data and create proper probability distributions
    const baselineMean = baseline.reduce((sum, val) => sum + val, 0) / baseline.length;
    const currentMean = current.reduce((sum, val) => sum + val, 0) / current.length;
    
    return Math.abs(currentMean - baselineMean) / Math.max(baselineMean, 0.01);
  }

  /**
   * Calculate Jensen-Shannon distance
   */
  private calculateJSDistance(baseline: number[], current: number[]): number {
    // Simplified JS distance calculation
    const baselineMean = baseline.reduce((sum, val) => sum + val, 0) / baseline.length;
    const currentMean = current.reduce((sum, val) => sum + val, 0) / current.length;
    
    return Math.abs(currentMean - baselineMean) / (baselineMean + currentMean + 0.01);
  }

  /**
   * Update baseline distribution for model
   */
  private updateBaseline(modelId: string, samples: QuerySample[]): void {
    const confidenceScores = samples
      .filter(s => s.confidence !== undefined)
      .map(s => s.confidence!);
    
    const lossValues = samples
      .filter(s => s.loss !== undefined)
      .map(s => s.loss!);

    this.baselineDistributions.set(modelId, {
      confidence: confidenceScores,
      loss: lossValues
    });
  }

  /**
   * Combine analysis results and determine attack presence
   */
  private combineAnalysisResults({
    queryId,
    modelId,
    samples,
    confidenceAnalysis,
    lossAnalysis,
    distributionAnalysis,
    gradientAnalysis,
    overfittingAnalysis,
    shadowModelAnalysis
  }: {
    queryId: string;
    modelId: string;
    samples: QuerySample[];
    confidenceAnalysis: any;
    lossAnalysis: any;
    distributionAnalysis: any;
    gradientAnalysis: any;
    overfittingAnalysis: any;
    shadowModelAnalysis: any;
  }): MembershipInferenceDetectionResult {
    const detectionMethods: string[] = [];
    let maxSeverity: 'low' | 'medium' | 'high' | 'critical' = 'low';
    let confidence = 0;
    let attackType = 'unknown';
    let privacyRisk: 'low' | 'medium' | 'high' | 'critical' = 'low';

    // Check each signature against analysis results
    for (const signature of this.signatures) {
      let signatureMatches = 0;
      let totalChecks = 0;

      if (signature.pattern.highConfidenceThreshold) {
        totalChecks++;
        if (confidenceAnalysis.isHighConfidencePattern) {
          signatureMatches++;
          detectionMethods.push('high_confidence_pattern');
        }
      }

      if (signature.pattern.lowLossThreshold) {
        totalChecks++;
        if (lossAnalysis.isLowLossPattern) {
          signatureMatches++;
          detectionMethods.push('low_loss_pattern');
        }
      }

      if (signature.pattern.distributionAnomaly) {
        totalChecks++;
        if (distributionAnalysis.isDistributionAnomaly) {
          signatureMatches++;
          detectionMethods.push('distribution_anomaly');
        }
      }

      if (signature.pattern.gradientMagnitudeAnomaly) {
        totalChecks++;
        if (gradientAnalysis.isGradientAnomaly) {
          signatureMatches++;
          detectionMethods.push('gradient_anomaly');
        }
      }

      if (signature.pattern.overfittingIndicators) {
        totalChecks++;
        if (overfittingAnalysis.isOverfittingDetected) {
          signatureMatches++;
          detectionMethods.push('overfitting_indicators');
        }
      }

      if (signature.pattern.shadowModelDisagreement && shadowModelAnalysis) {
        totalChecks++;
        if (shadowModelAnalysis.isDisagreementPattern) {
          signatureMatches++;
          detectionMethods.push('shadow_model_disagreement');
        }
      }

      // Calculate confidence for this signature
      const signatureConfidence = totalChecks > 0 ? signatureMatches / totalChecks : 0;
      
      if (signatureConfidence > 0.6) {
        confidence = Math.max(confidence, signatureConfidence);
        attackType = signature.name;
        
        if (this.getSeverityLevel(signature.severity) > this.getSeverityLevel(maxSeverity)) {
          maxSeverity = signature.severity;
          privacyRisk = signature.severity; // Privacy risk correlates with severity
        }
      }
    }

    const isAttack = confidence > 0.6;
    const affectedRecords = Math.floor(samples.length * confidence);

    return {
      isAttack,
      attackType,
      severity: maxSeverity,
      confidence,
      detectionMethods: [...new Set(detectionMethods)],
      privacyRisk,
      affectedRecords,
      recommendations: this.generateRecommendations(attackType, maxSeverity),
      timestamp: new Date(),
      metadata: {
        queryId,
        modelId,
        targetSamples: samples.length,
        avgConfidence: confidenceAnalysis.avgConfidence,
        avgLoss: lossAnalysis.avgLoss,
        distributionScore: distributionAnalysis.klDivergence,
        gradientScore: gradientAnalysis.avgGradientMagnitude,
        overfittingScore: overfittingAnalysis.overfittingScore,
        shadowModelScore: shadowModelAnalysis?.membershipScore || 0
      }
    };
  }

  /**
   * Convert severity string to numeric level for comparison
   */
  private getSeverityLevel(severity: string): number {
    switch (severity) {
      case 'low': return 1;
      case 'medium': return 2;
      case 'high': return 3;
      case 'critical': return 4;
      default: return 0;
    }
  }

  /**
   * Generate privacy protection recommendations based on attack type and severity
   */
  private generateRecommendations(attackType: string, severity: string): string[] {
    const recommendations: string[] = [];

    if (attackType.includes('Threshold')) {
      recommendations.push('Implement differential privacy techniques');
      recommendations.push('Add noise to model outputs');
      recommendations.push('Use confidence score calibration');
    }

    if (attackType.includes('Shadow Model')) {
      recommendations.push('Deploy privacy-preserving training methods');
      recommendations.push('Implement model ensemble diversity');
      recommendations.push('Use federated learning approaches');
    }

    if (attackType.includes('Gradient')) {
      recommendations.push('Implement gradient clipping');
      recommendations.push('Use secure aggregation techniques');
      recommendations.push('Deploy gradient noise injection');
    }

    if (attackType.includes('Distribution')) {
      recommendations.push('Implement output distribution smoothing');
      recommendations.push('Use privacy-preserving aggregation');
      recommendations.push('Deploy statistical disclosure control');
    }

    if (severity === 'critical' || severity === 'high') {
      recommendations.push('Implement immediate query throttling');
      recommendations.push('Trigger privacy incident response');
      recommendations.push('Notify data protection officer');
      recommendations.push('Consider model retraining with privacy techniques');
    }

    recommendations.push('Update privacy impact assessment');
    recommendations.push('Archive detection results for compliance');
    recommendations.push('Review data retention policies');

    return recommendations;
  }

  /**
   * Send privacy alert for detected membership inference attack
   */
  private async sendPrivacyAlert(result: MembershipInferenceDetectionResult): Promise<void> {
    const alertData = {
      type: 'membership_inference_attack',
      severity: result.severity,
      title: `Privacy Attack Detected: ${result.attackType}`,
      description: `Membership inference attack detected with ${(result.confidence * 100).toFixed(1)}% confidence`,
      details: {
        queryId: result.metadata.queryId,
        modelId: result.metadata.modelId,
        attackType: result.attackType,
        confidence: result.confidence,
        privacyRisk: result.privacyRisk,
        affectedRecords: result.affectedRecords,
        detectionMethods: result.detectionMethods,
        recommendations: result.recommendations
      },
      timestamp: result.timestamp
    };

    // Use logger for now, in production this would integrate with notification system
    logger.warn('Privacy attack detected - sending alert', alertData);
  }

  /**
   * Get detection history for a model
   */
  getDetectionHistory(modelId: string): MembershipInferenceDetectionResult[] {
    return this.detectionHistory.get(modelId) || [];
  }

  /**
   * Get current detection statistics
   */
  getDetectionStats(): {
    totalDetections: number;
    attackDetections: number;
    severeAttacks: number;
    avgPrivacyRisk: string;
    avgConfidence: number;
  } {
    const allDetections = Array.from(this.detectionHistory.values()).flat();
    const attackDetections = allDetections.filter(d => d.isAttack);
    const severeAttacks = attackDetections.filter(d => d.severity === 'high' || d.severity === 'critical');
    
    const privacyRiskLevels = attackDetections.map(d => this.getSeverityLevel(d.privacyRisk));
    const avgPrivacyRiskLevel = privacyRiskLevels.length > 0 ? 
      privacyRiskLevels.reduce((sum, level) => sum + level, 0) / privacyRiskLevels.length : 0;
    
    const avgPrivacyRisk = avgPrivacyRiskLevel > 3 ? 'critical' : 
                          avgPrivacyRiskLevel > 2 ? 'high' : 
                          avgPrivacyRiskLevel > 1 ? 'medium' : 'low';

    const avgConfidence = attackDetections.length > 0 ? 
      attackDetections.reduce((sum, d) => sum + d.confidence, 0) / attackDetections.length : 0;

    return {
      totalDetections: allDetections.length,
      attackDetections: attackDetections.length,
      severeAttacks: severeAttacks.length,
      avgPrivacyRisk,
      avgConfidence
    };
  }
}