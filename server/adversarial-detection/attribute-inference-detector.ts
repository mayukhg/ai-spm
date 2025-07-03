/**
 * Attribute Inference Attack Detection Engine
 * ==========================================
 * 
 * This module implements advanced detection mechanisms for attribute inference attacks
 * where adversaries attempt to infer sensitive attributes about individuals from model
 * predictions, even when those attributes were not part of the training data directly.
 * 
 * Detection Methods:
 * - Correlation analysis between predictions and sensitive attributes
 * - Information leakage measurement through mutual information
 * - Auxiliary model attack detection
 * - Feature importance analysis for sensitive attribute correlation
 * - Statistical inference pattern recognition
 * - Privacy leakage quantification
 * 
 * @author AI-SPM Security Team
 * @version 1.0.0
 */

import { logger } from '../monitoring/logger';
import { metrics } from '../monitoring/metrics-collector';

// Attribute inference attack signature patterns
interface AttributeInferenceSignature {
  id: string;
  name: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  sensitiveAttributes: string[];
  pattern: {
    highCorrelation: boolean;
    informationLeakage: boolean;
    auxiliaryModelSuccess: boolean;
    featureImportanceAnomaly: boolean;
    statisticalInference: boolean;
    privacyLeakage: boolean;
  };
  thresholds: {
    correlationThreshold: number;
    mutualInformationThreshold: number;
    auxiliaryModelAccuracy: number;
    featureImportanceThreshold: number;
    statisticalSignificance: number;
    privacyLeakageThreshold: number;
  };
}

// Detection result interface
interface AttributeInferenceDetectionResult {
  isAttack: boolean;
  attackType: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: number;
  detectionMethods: string[];
  sensitiveAttributes: string[];
  privacyRisk: 'low' | 'medium' | 'high' | 'critical';
  leakageScore: number;
  recommendations: string[];
  timestamp: Date;
  metadata: {
    queryId: string;
    modelId: string;
    targetAttributes: string[];
    correlationScores: Record<string, number>;
    mutualInformation: Record<string, number>;
    auxiliaryModelAccuracy: Record<string, number>;
    featureImportance: Record<string, number>;
    statisticalSignificance: Record<string, number>;
    privacyLeakageScore: number;
  };
}

// Prediction sample with auxiliary information
interface PredictionSample {
  id: string;
  prediction: any;
  confidence: number;
  features: number[];
  auxiliaryFeatures?: Record<string, any>;
  knownAttributes?: Record<string, any>;
  timestamp: Date;
  source: string;
  metadata?: Record<string, any>;
}

// Auxiliary model for attribute inference testing
interface AuxiliaryModel {
  targetAttribute: string;
  accuracy: number;
  predictions: any[];
  confidence: number;
  trainingData: PredictionSample[];
}

/**
 * Attribute Inference Detection Engine
 * 
 * Implements advanced privacy attack detection to identify attempts
 * to infer sensitive attributes through model behavior analysis.
 */
export class AttributeInferenceDetector {
  private signatures: AttributeInferenceSignature[] = [];
  private detectionHistory: Map<string, AttributeInferenceDetectionResult[]> = new Map();
  private auxiliaryModels: Map<string, AuxiliaryModel[]> = new Map();
  private baselineCorrelations: Map<string, Record<string, number>> = new Map();

  constructor() {
    this.initializeSignatures();
  }

  /**
   * Initialize predefined attribute inference attack signatures
   * These signatures define patterns and thresholds for various attack types
   */
  private initializeSignatures(): void {
    this.signatures = [
      {
        id: 'direct_attribute_inference',
        name: 'Direct Attribute Inference Attack',
        description: 'Direct inference of sensitive attributes from model predictions',
        severity: 'high',
        sensitiveAttributes: ['age', 'gender', 'race', 'income', 'health_status'],
        pattern: {
          highCorrelation: true,
          informationLeakage: true,
          auxiliaryModelSuccess: true,
          featureImportanceAnomaly: false,
          statisticalInference: true,
          privacyLeakage: true
        },
        thresholds: {
          correlationThreshold: 0.7,
          mutualInformationThreshold: 0.3,
          auxiliaryModelAccuracy: 0.8,
          featureImportanceThreshold: 0.1,
          statisticalSignificance: 0.05,
          privacyLeakageThreshold: 0.6
        }
      },
      {
        id: 'indirect_attribute_inference',
        name: 'Indirect Attribute Inference Attack',
        description: 'Inference through auxiliary features and correlation patterns',
        severity: 'medium',
        sensitiveAttributes: ['political_affiliation', 'sexual_orientation', 'religion'],
        pattern: {
          highCorrelation: false,
          informationLeakage: true,
          auxiliaryModelSuccess: true,
          featureImportanceAnomaly: true,
          statisticalInference: true,
          privacyLeakage: true
        },
        thresholds: {
          correlationThreshold: 0.5,
          mutualInformationThreshold: 0.2,
          auxiliaryModelAccuracy: 0.7,
          featureImportanceThreshold: 0.15,
          statisticalSignificance: 0.1,
          privacyLeakageThreshold: 0.4
        }
      },
      {
        id: 'property_inference',
        name: 'Property Inference Attack',
        description: 'Inference of dataset properties through model behavior',
        severity: 'critical',
        sensitiveAttributes: ['dataset_demographics', 'population_statistics'],
        pattern: {
          highCorrelation: true,
          informationLeakage: true,
          auxiliaryModelSuccess: true,
          featureImportanceAnomaly: true,
          statisticalInference: true,
          privacyLeakage: true
        },
        thresholds: {
          correlationThreshold: 0.8,
          mutualInformationThreshold: 0.4,
          auxiliaryModelAccuracy: 0.85,
          featureImportanceThreshold: 0.2,
          statisticalSignificance: 0.01,
          privacyLeakageThreshold: 0.7
        }
      },
      {
        id: 'linkage_attack',
        name: 'Linkage-based Attribute Inference',
        description: 'Attribute inference through record linkage and auxiliary datasets',
        severity: 'critical',
        sensitiveAttributes: ['identity', 'personal_identifiers', 'location'],
        pattern: {
          highCorrelation: true,
          informationLeakage: true,
          auxiliaryModelSuccess: false,
          featureImportanceAnomaly: false,
          statisticalInference: true,
          privacyLeakage: true
        },
        thresholds: {
          correlationThreshold: 0.75,
          mutualInformationThreshold: 0.35,
          auxiliaryModelAccuracy: 0.6,
          featureImportanceThreshold: 0.1,
          statisticalSignificance: 0.05,
          privacyLeakageThreshold: 0.8
        }
      }
    ];

    logger.info('Attribute inference detection signatures initialized', {
      signatureCount: this.signatures.length,
      sensitiveAttributeTypes: this.signatures.flatMap(s => s.sensitiveAttributes).length,
      component: 'AttributeInferenceDetector'
    });
  }

  /**
   * Analyze predictions for attribute inference attacks
   * 
   * @param queryId - Unique identifier for the query batch
   * @param modelId - Target model identifier
   * @param samples - Array of prediction samples to analyze
   * @param targetAttributes - Sensitive attributes to monitor
   * @returns Detection result with privacy risk assessment
   */
  async analyzeAttributeInference(
    queryId: string,
    modelId: string,
    samples: PredictionSample[],
    targetAttributes: string[]
  ): Promise<AttributeInferenceDetectionResult> {
    const startTime = Date.now();
    
    logger.info('Starting attribute inference analysis', {
      queryId,
      modelId,
      sampleCount: samples.length,
      targetAttributes: targetAttributes.length,
      component: 'AttributeInferenceDetector'
    });

    try {
      // Perform multiple detection analyses
      const correlationAnalysis = this.analyzeCorrelationPatterns(samples, targetAttributes);
      const informationLeakageAnalysis = this.analyzeInformationLeakage(samples, targetAttributes);
      const auxiliaryModelAnalysis = await this.analyzeAuxiliaryModelAttacks(modelId, samples, targetAttributes);
      const featureImportanceAnalysis = this.analyzeFeatureImportance(samples, targetAttributes);
      const statisticalAnalysis = this.analyzeStatisticalInference(samples, targetAttributes);
      const privacyLeakageAnalysis = this.analyzePrivacyLeakage(samples, targetAttributes);

      // Combine analysis results
      const detectionResult = this.combineAnalysisResults({
        queryId,
        modelId,
        samples,
        targetAttributes,
        correlationAnalysis,
        informationLeakageAnalysis,
        auxiliaryModelAnalysis,
        featureImportanceAnalysis,
        statisticalAnalysis,
        privacyLeakageAnalysis
      });

      // Record metrics
      metrics.recordMetric('adversarial_detection_attribute_inference_analysis', {
        query_id: queryId,
        model_id: modelId,
        sample_count: samples.length,
        target_attributes: targetAttributes.length,
        analysis_duration_ms: Date.now() - startTime,
        is_attack: detectionResult.isAttack,
        severity: detectionResult.severity,
        privacy_risk: detectionResult.privacyRisk,
        confidence: detectionResult.confidence,
        leakage_score: detectionResult.leakageScore
      });

      // Store detection history
      if (!this.detectionHistory.has(modelId)) {
        this.detectionHistory.set(modelId, []);
      }
      this.detectionHistory.get(modelId)!.push(detectionResult);

      // Send alerts if attack detected
      if (detectionResult.isAttack) {
        await this.sendAttributeInferenceAlert(detectionResult);
      }

      logger.info('Attribute inference analysis completed', {
        queryId,
        modelId,
        isAttack: detectionResult.isAttack,
        severity: detectionResult.severity,
        privacyRisk: detectionResult.privacyRisk,
        leakageScore: detectionResult.leakageScore,
        confidence: detectionResult.confidence,
        duration: Date.now() - startTime,
        component: 'AttributeInferenceDetector'
      });

      return detectionResult;

    } catch (error) {
      logger.error('Attribute inference analysis failed', {
        queryId,
        modelId,
        error: error instanceof Error ? error.message : 'Unknown error',
        component: 'AttributeInferenceDetector'
      });
      
      throw new Error(`Attribute inference analysis failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Analyze correlation patterns between predictions and sensitive attributes
   */
  private analyzeCorrelationPatterns(samples: PredictionSample[], targetAttributes: string[]): {
    correlationScores: Record<string, number>;
    highCorrelationAttributes: string[];
    isHighCorrelation: boolean;
  } {
    const correlationScores: Record<string, number> = {};
    const highCorrelationAttributes: string[] = [];

    for (const attribute of targetAttributes) {
      const attributeValues: number[] = [];
      const predictions: number[] = [];

      for (const sample of samples) {
        if (sample.knownAttributes && sample.knownAttributes[attribute] !== undefined) {
          // Convert attribute value to numeric for correlation calculation
          const attrValue = this.convertToNumeric(sample.knownAttributes[attribute]);
          const predValue = this.convertToNumeric(sample.prediction);
          
          if (!isNaN(attrValue) && !isNaN(predValue)) {
            attributeValues.push(attrValue);
            predictions.push(predValue);
          }
        }
      }

      if (attributeValues.length > 1) {
        const correlation = this.calculatePearsonCorrelation(attributeValues, predictions);
        correlationScores[attribute] = Math.abs(correlation);

        if (Math.abs(correlation) > 0.6) {
          highCorrelationAttributes.push(attribute);
        }
      } else {
        correlationScores[attribute] = 0;
      }
    }

    const isHighCorrelation = highCorrelationAttributes.length > 0;

    return { correlationScores, highCorrelationAttributes, isHighCorrelation };
  }

  /**
   * Analyze information leakage through mutual information
   */
  private analyzeInformationLeakage(samples: PredictionSample[], targetAttributes: string[]): {
    mutualInformation: Record<string, number>;
    leakageAttributes: string[];
    isInformationLeakage: boolean;
  } {
    const mutualInformation: Record<string, number> = {};
    const leakageAttributes: string[] = [];

    for (const attribute of targetAttributes) {
      // Simplified mutual information calculation
      // In practice, you'd use proper entropy and mutual information formulas
      const mi = this.calculateMutualInformation(samples, attribute);
      mutualInformation[attribute] = mi;

      if (mi > 0.2) {
        leakageAttributes.push(attribute);
      }
    }

    const isInformationLeakage = leakageAttributes.length > 0;

    return { mutualInformation, leakageAttributes, isInformationLeakage };
  }

  /**
   * Analyze auxiliary model attacks for attribute inference
   */
  private async analyzeAuxiliaryModelAttacks(
    modelId: string,
    samples: PredictionSample[],
    targetAttributes: string[]
  ): Promise<{
    auxiliaryModelAccuracy: Record<string, number>;
    successfulAttacks: string[];
    isAuxiliaryModelSuccess: boolean;
  }> {
    const auxiliaryModelAccuracy: Record<string, number> = {};
    const successfulAttacks: string[] = [];

    for (const attribute of targetAttributes) {
      // Simulate auxiliary model training and testing
      const accuracy = await this.trainAuxiliaryModel(modelId, samples, attribute);
      auxiliaryModelAccuracy[attribute] = accuracy;

      if (accuracy > 0.7) {
        successfulAttacks.push(attribute);
      }
    }

    const isAuxiliaryModelSuccess = successfulAttacks.length > 0;

    return { auxiliaryModelAccuracy, successfulAttacks, isAuxiliaryModelSuccess };
  }

  /**
   * Analyze feature importance for sensitive attribute correlation
   */
  private analyzeFeatureImportance(samples: PredictionSample[], targetAttributes: string[]): {
    featureImportance: Record<string, number>;
    importantFeatures: string[];
    isFeatureImportanceAnomaly: boolean;
  } {
    const featureImportance: Record<string, number> = {};
    const importantFeatures: string[] = [];

    // Simplified feature importance analysis based on correlation with predictions
    for (const attribute of targetAttributes) {
      let importance = 0;
      let validSamples = 0;

      for (const sample of samples) {
        if (sample.knownAttributes && sample.knownAttributes[attribute] !== undefined) {
          // Calculate feature importance as correlation with prediction confidence
          const attrValue = this.convertToNumeric(sample.knownAttributes[attribute]);
          if (!isNaN(attrValue)) {
            importance += Math.abs(sample.confidence - (attrValue / 100)); // Normalized
            validSamples++;
          }
        }
      }

      if (validSamples > 0) {
        importance = importance / validSamples;
        featureImportance[attribute] = importance;

        if (importance > 0.15) {
          importantFeatures.push(attribute);
        }
      } else {
        featureImportance[attribute] = 0;
      }
    }

    const isFeatureImportanceAnomaly = importantFeatures.length > 0;

    return { featureImportance, importantFeatures, isFeatureImportanceAnomaly };
  }

  /**
   * Analyze statistical inference patterns
   */
  private analyzeStatisticalInference(samples: PredictionSample[], targetAttributes: string[]): {
    statisticalSignificance: Record<string, number>;
    significantAttributes: string[];
    isStatisticalInference: boolean;
  } {
    const statisticalSignificance: Record<string, number> = {};
    const significantAttributes: string[] = [];

    for (const attribute of targetAttributes) {
      // Simplified statistical significance test (Chi-square or t-test simulation)
      const pValue = this.calculateStatisticalSignificance(samples, attribute);
      statisticalSignificance[attribute] = pValue;

      if (pValue < 0.05) {
        significantAttributes.push(attribute);
      }
    }

    const isStatisticalInference = significantAttributes.length > 0;

    return { statisticalSignificance, significantAttributes, isStatisticalInference };
  }

  /**
   * Analyze privacy leakage quantification
   */
  private analyzePrivacyLeakage(samples: PredictionSample[], targetAttributes: string[]): {
    privacyLeakageScore: number;
    leakageByAttribute: Record<string, number>;
    isPrivacyLeakage: boolean;
  } {
    const leakageByAttribute: Record<string, number> = {};
    let totalLeakage = 0;

    for (const attribute of targetAttributes) {
      // Calculate privacy leakage score based on prediction-attribute correlation
      let leakageScore = 0;
      let validSamples = 0;

      for (const sample of samples) {
        if (sample.knownAttributes && sample.knownAttributes[attribute] !== undefined) {
          const attrValue = this.convertToNumeric(sample.knownAttributes[attribute]);
          const predValue = this.convertToNumeric(sample.prediction);
          
          if (!isNaN(attrValue) && !isNaN(predValue)) {
            // Simplified leakage calculation
            leakageScore += Math.abs(sample.confidence - 0.5) * Math.abs(attrValue - 50) / 50;
            validSamples++;
          }
        }
      }

      if (validSamples > 0) {
        leakageScore = leakageScore / validSamples;
        leakageByAttribute[attribute] = leakageScore;
        totalLeakage += leakageScore;
      } else {
        leakageByAttribute[attribute] = 0;
      }
    }

    const privacyLeakageScore = targetAttributes.length > 0 ? totalLeakage / targetAttributes.length : 0;
    const isPrivacyLeakage = privacyLeakageScore > 0.3;

    return { privacyLeakageScore, leakageByAttribute, isPrivacyLeakage };
  }

  /**
   * Convert various data types to numeric for calculations
   */
  private convertToNumeric(value: any): number {
    if (typeof value === 'number') return value;
    if (typeof value === 'string') {
      const num = parseFloat(value);
      if (!isNaN(num)) return num;
      // Convert categorical to numeric (simplified)
      return value.length * 10; // Basic hash-like conversion
    }
    if (typeof value === 'boolean') return value ? 1 : 0;
    return 0;
  }

  /**
   * Calculate Pearson correlation coefficient
   */
  private calculatePearsonCorrelation(x: number[], y: number[]): number {
    if (x.length !== y.length || x.length === 0) return 0;

    const n = x.length;
    const sumX = x.reduce((sum, val) => sum + val, 0);
    const sumY = y.reduce((sum, val) => sum + val, 0);
    const sumXY = x.reduce((sum, val, i) => sum + val * y[i], 0);
    const sumX2 = x.reduce((sum, val) => sum + val * val, 0);
    const sumY2 = y.reduce((sum, val) => sum + val * val, 0);

    const numerator = n * sumXY - sumX * sumY;
    const denominator = Math.sqrt((n * sumX2 - sumX * sumX) * (n * sumY2 - sumY * sumY));

    return denominator === 0 ? 0 : numerator / denominator;
  }

  /**
   * Calculate mutual information (simplified)
   */
  private calculateMutualInformation(samples: PredictionSample[], attribute: string): number {
    // Simplified mutual information calculation
    // In practice, you'd use proper entropy calculations
    let mutualInfo = 0;
    let validSamples = 0;

    for (const sample of samples) {
      if (sample.knownAttributes && sample.knownAttributes[attribute] !== undefined) {
        const attrValue = this.convertToNumeric(sample.knownAttributes[attribute]);
        const predValue = this.convertToNumeric(sample.prediction);
        
        if (!isNaN(attrValue) && !isNaN(predValue)) {
          // Simplified MI calculation
          mutualInfo += Math.log(1 + Math.abs(sample.confidence - 0.5) * Math.abs(attrValue - 50) / 50);
          validSamples++;
        }
      }
    }

    return validSamples > 0 ? mutualInfo / validSamples : 0;
  }

  /**
   * Train auxiliary model for attribute inference (simplified simulation)
   */
  private async trainAuxiliaryModel(
    modelId: string,
    samples: PredictionSample[],
    targetAttribute: string
  ): Promise<number> {
    // Simulate auxiliary model training and testing
    // In practice, this would involve actual ML model training
    
    const trainingData = samples.filter(s => 
      s.knownAttributes && s.knownAttributes[targetAttribute] !== undefined
    );

    if (trainingData.length < 10) {
      return 0; // Insufficient data for training
    }

    // Simulate model accuracy based on correlation strength
    const correlationStrength = Math.abs(this.calculatePearsonCorrelation(
      trainingData.map(s => this.convertToNumeric(s.knownAttributes![targetAttribute])),
      trainingData.map(s => s.confidence)
    ));

    // Accuracy simulation based on correlation
    const baseAccuracy = 0.5; // Random baseline
    const accuracyBoost = correlationStrength * 0.4; // Max 40% boost
    const noise = (Math.random() - 0.5) * 0.1; // ±5% noise

    return Math.min(0.95, Math.max(0.5, baseAccuracy + accuracyBoost + noise));
  }

  /**
   * Calculate statistical significance (simplified)
   */
  private calculateStatisticalSignificance(samples: PredictionSample[], attribute: string): number {
    // Simplified p-value calculation
    // In practice, you'd use proper statistical tests
    
    const validSamples = samples.filter(s => 
      s.knownAttributes && s.knownAttributes[attribute] !== undefined
    );

    if (validSamples.length < 5) {
      return 1.0; // Not significant
    }

    const correlation = Math.abs(this.calculatePearsonCorrelation(
      validSamples.map(s => this.convertToNumeric(s.knownAttributes![attribute])),
      validSamples.map(s => s.confidence)
    ));

    // Simulate p-value based on correlation strength and sample size
    const sampleSizeEffect = Math.log(validSamples.length) / 10;
    const pValue = Math.max(0.001, 1 - correlation - sampleSizeEffect);

    return pValue;
  }

  /**
   * Combine analysis results and determine attack presence
   */
  private combineAnalysisResults({
    queryId,
    modelId,
    samples,
    targetAttributes,
    correlationAnalysis,
    informationLeakageAnalysis,
    auxiliaryModelAnalysis,
    featureImportanceAnalysis,
    statisticalAnalysis,
    privacyLeakageAnalysis
  }: {
    queryId: string;
    modelId: string;
    samples: PredictionSample[];
    targetAttributes: string[];
    correlationAnalysis: any;
    informationLeakageAnalysis: any;
    auxiliaryModelAnalysis: any;
    featureImportanceAnalysis: any;
    statisticalAnalysis: any;
    privacyLeakageAnalysis: any;
  }): AttributeInferenceDetectionResult {
    const detectionMethods: string[] = [];
    let maxSeverity: 'low' | 'medium' | 'high' | 'critical' = 'low';
    let confidence = 0;
    let attackType = 'unknown';
    let privacyRisk: 'low' | 'medium' | 'high' | 'critical' = 'low';
    let sensitiveAttributes: string[] = [];

    // Check each signature against analysis results
    for (const signature of this.signatures) {
      let signatureMatches = 0;
      let totalChecks = 0;

      if (signature.pattern.highCorrelation) {
        totalChecks++;
        if (correlationAnalysis.isHighCorrelation) {
          signatureMatches++;
          detectionMethods.push('high_correlation');
          sensitiveAttributes = [...sensitiveAttributes, ...correlationAnalysis.highCorrelationAttributes];
        }
      }

      if (signature.pattern.informationLeakage) {
        totalChecks++;
        if (informationLeakageAnalysis.isInformationLeakage) {
          signatureMatches++;
          detectionMethods.push('information_leakage');
          sensitiveAttributes = [...sensitiveAttributes, ...informationLeakageAnalysis.leakageAttributes];
        }
      }

      if (signature.pattern.auxiliaryModelSuccess) {
        totalChecks++;
        if (auxiliaryModelAnalysis.isAuxiliaryModelSuccess) {
          signatureMatches++;
          detectionMethods.push('auxiliary_model_attack');
          sensitiveAttributes = [...sensitiveAttributes, ...auxiliaryModelAnalysis.successfulAttacks];
        }
      }

      if (signature.pattern.featureImportanceAnomaly) {
        totalChecks++;
        if (featureImportanceAnalysis.isFeatureImportanceAnomaly) {
          signatureMatches++;
          detectionMethods.push('feature_importance_anomaly');
        }
      }

      if (signature.pattern.statisticalInference) {
        totalChecks++;
        if (statisticalAnalysis.isStatisticalInference) {
          signatureMatches++;
          detectionMethods.push('statistical_inference');
        }
      }

      if (signature.pattern.privacyLeakage) {
        totalChecks++;
        if (privacyLeakageAnalysis.isPrivacyLeakage) {
          signatureMatches++;
          detectionMethods.push('privacy_leakage');
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
    const uniqueSensitiveAttributes = [...new Set(sensitiveAttributes)];

    return {
      isAttack,
      attackType,
      severity: maxSeverity,
      confidence,
      detectionMethods: [...new Set(detectionMethods)],
      sensitiveAttributes: uniqueSensitiveAttributes,
      privacyRisk,
      leakageScore: privacyLeakageAnalysis.privacyLeakageScore,
      recommendations: this.generateRecommendations(attackType, maxSeverity, uniqueSensitiveAttributes),
      timestamp: new Date(),
      metadata: {
        queryId,
        modelId,
        targetAttributes,
        correlationScores: correlationAnalysis.correlationScores,
        mutualInformation: informationLeakageAnalysis.mutualInformation,
        auxiliaryModelAccuracy: auxiliaryModelAnalysis.auxiliaryModelAccuracy,
        featureImportance: featureImportanceAnalysis.featureImportance,
        statisticalSignificance: statisticalAnalysis.statisticalSignificance,
        privacyLeakageScore: privacyLeakageAnalysis.privacyLeakageScore
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
   * Generate privacy protection recommendations based on attack type and affected attributes
   */
  private generateRecommendations(
    attackType: string,
    severity: string,
    sensitiveAttributes: string[]
  ): string[] {
    const recommendations: string[] = [];

    if (attackType.includes('Direct Attribute')) {
      recommendations.push('Implement differential privacy for model outputs');
      recommendations.push('Add calibrated noise to prediction confidence scores');
      recommendations.push('Use output perturbation techniques');
    }

    if (attackType.includes('Indirect Attribute')) {
      recommendations.push('Remove or mask auxiliary features that correlate with sensitive attributes');
      recommendations.push('Implement feature suppression for high-correlation features');
      recommendations.push('Use adversarial training to reduce attribute leakage');
    }

    if (attackType.includes('Property Inference')) {
      recommendations.push('Implement dataset-level privacy protection');
      recommendations.push('Use federated learning to avoid centralized sensitive data');
      recommendations.push('Deploy secure multi-party computation techniques');
    }

    if (attackType.includes('Linkage')) {
      recommendations.push('Implement k-anonymity or l-diversity techniques');
      recommendations.push('Use pseudonymization for all identifiable features');
      recommendations.push('Deploy record linkage protection mechanisms');
    }

    if (sensitiveAttributes.length > 0) {
      recommendations.push(`Immediate protection needed for attributes: ${sensitiveAttributes.join(', ')}`);
      recommendations.push('Conduct privacy impact assessment for affected attributes');
    }

    if (severity === 'critical' || severity === 'high') {
      recommendations.push('Implement immediate query throttling for sensitive attributes');
      recommendations.push('Trigger privacy incident response procedures');
      recommendations.push('Notify data protection officer and relevant stakeholders');
      recommendations.push('Consider temporary model quarantine');
    }

    recommendations.push('Update privacy monitoring and audit procedures');
    recommendations.push('Enhance consent management for affected data subjects');
    recommendations.push('Review and update data retention and deletion policies');

    return recommendations;
  }

  /**
   * Send privacy alert for detected attribute inference attack
   */
  private async sendAttributeInferenceAlert(result: AttributeInferenceDetectionResult): Promise<void> {
    const alertData = {
      type: 'attribute_inference_attack',
      severity: result.severity,
      title: `Attribute Inference Attack Detected: ${result.attackType}`,
      description: `Attribute inference attack detected with ${(result.confidence * 100).toFixed(1)}% confidence`,
      details: {
        queryId: result.metadata.queryId,
        modelId: result.metadata.modelId,
        attackType: result.attackType,
        confidence: result.confidence,
        privacyRisk: result.privacyRisk,
        sensitiveAttributes: result.sensitiveAttributes,
        leakageScore: result.leakageScore,
        detectionMethods: result.detectionMethods,
        recommendations: result.recommendations
      },
      timestamp: result.timestamp
    };

    // Use logger for now, in production this would integrate with notification system
    logger.warn('Attribute inference attack detected - sending alert', alertData);
  }

  /**
   * Get detection history for a model
   */
  getDetectionHistory(modelId: string): AttributeInferenceDetectionResult[] {
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
    avgLeakageScore: number;
    avgConfidence: number;
    mostTargetedAttributes: string[];
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

    const avgLeakageScore = attackDetections.length > 0 ? 
      attackDetections.reduce((sum, d) => sum + d.leakageScore, 0) / attackDetections.length : 0;

    const avgConfidence = attackDetections.length > 0 ? 
      attackDetections.reduce((sum, d) => sum + d.confidence, 0) / attackDetections.length : 0;

    // Find most targeted attributes
    const attributeCount: Record<string, number> = {};
    attackDetections.forEach(d => {
      d.sensitiveAttributes.forEach(attr => {
        attributeCount[attr] = (attributeCount[attr] || 0) + 1;
      });
    });

    const mostTargetedAttributes = Object.entries(attributeCount)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 5)
      .map(([attr]) => attr);

    return {
      totalDetections: allDetections.length,
      attackDetections: attackDetections.length,
      severeAttacks: severeAttacks.length,
      avgPrivacyRisk,
      avgLeakageScore,
      avgConfidence,
      mostTargetedAttributes
    };
  }
}