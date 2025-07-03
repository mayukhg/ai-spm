/**
 * Model Evasion Attack Detection Engine
 * ====================================
 * 
 * This module implements advanced detection mechanisms for adversarial examples
 * and model evasion attacks. These attacks craft inputs designed to fool AI models
 * into making incorrect predictions while appearing normal to humans.
 * 
 * Detection Methods:
 * - Input preprocessing anomaly detection
 * - Feature perturbation analysis
 * - Prediction confidence scoring
 * - Gradient-based adversarial detection
 * - Ensemble disagreement analysis
 * - Statistical deviation detection
 * 
 * @author AI-SPM Security Team
 * @version 1.0.0
 */

import { logger } from '../monitoring/logger';
import { MetricsCollector } from '../monitoring/metrics-collector';
import { NotificationManager } from '../monitoring/notification-manager';

// Model evasion attack signature patterns
interface ModelEvasionSignature {
  id: string;
  name: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  pattern: {
    lowConfidence: boolean;
    highPerturbation: boolean;
    ensembleDisagreement: boolean;
    gradientAnomaly: boolean;
    statisticalDeviation: boolean;
    inputAnomaly: boolean;
  };
  thresholds: {
    confidenceThreshold: number;
    perturbationThreshold: number;
    ensembleAgreementThreshold: number;
    gradientMagnitudeThreshold: number;
    statisticalZScoreThreshold: number;
    inputAnomalyThreshold: number;
  };
}

// Detection result interface
interface ModelEvasionDetectionResult {
  isAttack: boolean;
  attackType: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: number;
  detectionMethods: string[];
  blockedInputs: number;
  recommendations: string[];
  timestamp: Date;
  metadata: {
    inputId: string;
    modelId: string;
    originalPrediction: any;
    confidenceScore: number;
    perturbationScore: number;
    ensembleScore: number;
    gradientScore: number;
    statisticalScore: number;
    inputAnomalyScore: number;
  };
}

// Input sample interface for analysis
interface InputSample {
  id: string;
  features: number[];
  rawInput: any;
  timestamp: Date;
  source: string;
  metadata?: Record<string, any>;
}

// Model prediction interface
interface ModelPrediction {
  modelId: string;
  prediction: any;
  confidence: number;
  processingTime: number;
  gradients?: number[];
}

/**
 * Model Evasion Detection Engine
 * 
 * Implements real-time detection of adversarial examples and evasion attacks
 * designed to fool AI models while maintaining automated response capabilities.
 */
export class ModelEvasionDetector {
  private signatures: ModelEvasionSignature[] = [];
  private metricsCollector: MetricsCollector;
  private notificationManager: NotificationManager;
  private detectionHistory: Map<string, ModelEvasionDetectionResult[]> = new Map();
  private baselineStats: Map<string, { mean: number; stdDev: number }> = new Map();
  private blockedInputs: Set<string> = new Set();

  constructor(
    metricsCollector: MetricsCollector,
    notificationManager: NotificationManager
  ) {
    this.metricsCollector = metricsCollector;
    this.notificationManager = notificationManager;
    this.initializeSignatures();
  }

  /**
   * Initialize predefined model evasion attack signatures
   * These signatures define patterns and thresholds for various attack types
   */
  private initializeSignatures(): void {
    this.signatures = [
      {
        id: 'fgsm_attack',
        name: 'Fast Gradient Sign Method (FGSM)',
        description: 'Single-step adversarial attack using gradient sign',
        severity: 'high',
        pattern: {
          lowConfidence: true,
          highPerturbation: true,
          ensembleDisagreement: true,
          gradientAnomaly: true,
          statisticalDeviation: true,
          inputAnomaly: false
        },
        thresholds: {
          confidenceThreshold: 0.6,
          perturbationThreshold: 0.1,
          ensembleAgreementThreshold: 0.7,
          gradientMagnitudeThreshold: 0.15,
          statisticalZScoreThreshold: 2.5,
          inputAnomalyThreshold: 0.1
        }
      },
      {
        id: 'pgd_attack',
        name: 'Projected Gradient Descent (PGD)',
        description: 'Multi-step iterative adversarial attack',
        severity: 'critical',
        pattern: {
          lowConfidence: true,
          highPerturbation: true,
          ensembleDisagreement: true,
          gradientAnomaly: true,
          statisticalDeviation: true,
          inputAnomaly: true
        },
        thresholds: {
          confidenceThreshold: 0.5,
          perturbationThreshold: 0.08,
          ensembleAgreementThreshold: 0.6,
          gradientMagnitudeThreshold: 0.2,
          statisticalZScoreThreshold: 3.0,
          inputAnomalyThreshold: 0.12
        }
      },
      {
        id: 'carlini_wagner',
        name: 'Carlini & Wagner Attack',
        description: 'Optimization-based adversarial attack with minimal perturbation',
        severity: 'critical',
        pattern: {
          lowConfidence: false,
          highPerturbation: false,
          ensembleDisagreement: true,
          gradientAnomaly: true,
          statisticalDeviation: true,
          inputAnomaly: true
        },
        thresholds: {
          confidenceThreshold: 0.8,
          perturbationThreshold: 0.05,
          ensembleAgreementThreshold: 0.5,
          gradientMagnitudeThreshold: 0.25,
          statisticalZScoreThreshold: 3.5,
          inputAnomalyThreshold: 0.15
        }
      },
      {
        id: 'deepfool_attack',
        name: 'DeepFool Attack',
        description: 'Iterative attack finding minimal perturbation to decision boundary',
        severity: 'high',
        pattern: {
          lowConfidence: true,
          highPerturbation: false,
          ensembleDisagreement: true,
          gradientAnomaly: true,
          statisticalDeviation: true,
          inputAnomaly: false
        },
        thresholds: {
          confidenceThreshold: 0.55,
          perturbationThreshold: 0.06,
          ensembleAgreementThreshold: 0.65,
          gradientMagnitudeThreshold: 0.18,
          statisticalZScoreThreshold: 2.8,
          inputAnomalyThreshold: 0.08
        }
      },
      {
        id: 'universal_adversarial',
        name: 'Universal Adversarial Perturbation',
        description: 'Input-agnostic perturbation that fools most inputs',
        severity: 'medium',
        pattern: {
          lowConfidence: true,
          highPerturbation: true,
          ensembleDisagreement: false,
          gradientAnomaly: false,
          statisticalDeviation: true,
          inputAnomaly: true
        },
        thresholds: {
          confidenceThreshold: 0.7,
          perturbationThreshold: 0.12,
          ensembleAgreementThreshold: 0.8,
          gradientMagnitudeThreshold: 0.1,
          statisticalZScoreThreshold: 2.0,
          inputAnomalyThreshold: 0.2
        }
      }
    ];

    logger.info('Model evasion detection signatures initialized', {
      signatureCount: this.signatures.length,
      component: 'ModelEvasionDetector'
    });
  }

  /**
   * Analyze input for model evasion attacks in real-time
   * 
   * @param inputSample - Input sample to analyze
   * @param predictions - Array of model predictions
   * @param baselineInput - Optional baseline input for comparison
   * @returns Detection result with attack assessment
   */
  async analyzeInput(
    inputSample: InputSample,
    predictions: ModelPrediction[],
    baselineInput?: InputSample
  ): Promise<ModelEvasionDetectionResult> {
    const startTime = Date.now();
    
    logger.info('Starting model evasion analysis', {
      inputId: inputSample.id,
      modelCount: predictions.length,
      component: 'ModelEvasionDetector'
    });

    try {
      // Check if input is already blocked
      if (this.blockedInputs.has(inputSample.id)) {
        return this.createBlockedResult(inputSample, predictions[0]);
      }

      // Perform multiple detection analyses
      const confidenceAnalysis = this.analyzeConfidence(predictions);
      const perturbationAnalysis = baselineInput ? 
        this.analyzePerturbation(inputSample, baselineInput) : { score: 0, isHighPerturbation: false };
      const ensembleAnalysis = this.analyzeEnsembleAgreement(predictions);
      const gradientAnalysis = this.analyzeGradients(predictions);
      const statisticalAnalysis = this.analyzeStatisticalDeviation(inputSample);
      const inputAnomalyAnalysis = this.analyzeInputAnomaly(inputSample);

      // Combine analysis results
      const detectionResult = this.combineAnalysisResults({
        inputSample,
        predictions,
        confidenceAnalysis,
        perturbationAnalysis,
        ensembleAnalysis,
        gradientAnalysis,
        statisticalAnalysis,
        inputAnomalyAnalysis
      });

      // Record metrics
      this.metricsCollector.recordMetric('adversarial_detection_model_evasion_analysis', {
        input_id: inputSample.id,
        model_count: predictions.length,
        analysis_duration_ms: Date.now() - startTime,
        is_attack: detectionResult.isAttack,
        severity: detectionResult.severity,
        confidence: detectionResult.confidence
      });

      // Store detection history
      const modelId = predictions[0]?.modelId || 'unknown';
      if (!this.detectionHistory.has(modelId)) {
        this.detectionHistory.set(modelId, []);
      }
      this.detectionHistory.get(modelId)!.push(detectionResult);

      // Block input and send alerts if attack detected
      if (detectionResult.isAttack) {
        await this.blockInput(inputSample.id);
        await this.sendAlert(detectionResult);
      }

      logger.info('Model evasion analysis completed', {
        inputId: inputSample.id,
        isAttack: detectionResult.isAttack,
        severity: detectionResult.severity,
        confidence: detectionResult.confidence,
        duration: Date.now() - startTime,
        component: 'ModelEvasionDetector'
      });

      return detectionResult;

    } catch (error) {
      logger.error('Model evasion analysis failed', {
        inputId: inputSample.id,
        error: error instanceof Error ? error.message : 'Unknown error',
        component: 'ModelEvasionDetector'
      });
      
      throw new Error(`Model evasion analysis failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Analyze prediction confidence scores for anomalies
   */
  private analyzeConfidence(predictions: ModelPrediction[]): {
    avgConfidence: number;
    minConfidence: number;
    isLowConfidence: boolean;
  } {
    const confidenceScores = predictions.map(p => p.confidence);
    const avgConfidence = confidenceScores.reduce((sum, conf) => sum + conf, 0) / confidenceScores.length;
    const minConfidence = Math.min(...confidenceScores);
    const isLowConfidence = avgConfidence < 0.7 || minConfidence < 0.5;

    return { avgConfidence, minConfidence, isLowConfidence };
  }

  /**
   * Analyze input perturbation relative to baseline
   */
  private analyzePerturbation(input: InputSample, baseline: InputSample): {
    score: number;
    isHighPerturbation: boolean;
  } {
    if (input.features.length !== baseline.features.length) {
      return { score: 1.0, isHighPerturbation: true };
    }

    // Calculate L2 norm of perturbation
    const perturbationVector = input.features.map((val, idx) => val - baseline.features[idx]);
    const l2Norm = Math.sqrt(perturbationVector.reduce((sum, val) => sum + val * val, 0));
    
    // Normalize by feature vector magnitude
    const inputMagnitude = Math.sqrt(input.features.reduce((sum, val) => sum + val * val, 0));
    const score = inputMagnitude > 0 ? l2Norm / inputMagnitude : l2Norm;
    
    const isHighPerturbation = score > 0.1;

    return { score, isHighPerturbation };
  }

  /**
   * Analyze ensemble model agreement
   */
  private analyzeEnsembleAgreement(predictions: ModelPrediction[]): {
    agreementScore: number;
    isDisagreement: boolean;
  } {
    if (predictions.length < 2) {
      return { agreementScore: 1.0, isDisagreement: false };
    }

    // Simple agreement analysis based on prediction similarity
    const predictionValues = predictions.map(p => JSON.stringify(p.prediction));
    const uniquePredictions = new Set(predictionValues);
    const agreementScore = 1.0 - (uniquePredictions.size - 1) / (predictions.length - 1);
    const isDisagreement = agreementScore < 0.7;

    return { agreementScore, isDisagreement };
  }

  /**
   * Analyze gradient information for anomalies
   */
  private analyzeGradients(predictions: ModelPrediction[]): {
    avgGradientMagnitude: number;
    maxGradientMagnitude: number;
    isAnomalous: boolean;
  } {
    const gradientMagnitudes: number[] = [];

    for (const prediction of predictions) {
      if (prediction.gradients && prediction.gradients.length > 0) {
        const magnitude = Math.sqrt(
          prediction.gradients.reduce((sum, grad) => sum + grad * grad, 0)
        );
        gradientMagnitudes.push(magnitude);
      }
    }

    if (gradientMagnitudes.length === 0) {
      return { avgGradientMagnitude: 0, maxGradientMagnitude: 0, isAnomalous: false };
    }

    const avgGradientMagnitude = gradientMagnitudes.reduce((sum, mag) => sum + mag, 0) / gradientMagnitudes.length;
    const maxGradientMagnitude = Math.max(...gradientMagnitudes);
    const isAnomalous = avgGradientMagnitude > 0.15 || maxGradientMagnitude > 0.3;

    return { avgGradientMagnitude, maxGradientMagnitude, isAnomalous };
  }

  /**
   * Analyze statistical deviation from baseline
   */
  private analyzeStatisticalDeviation(input: InputSample): {
    zScore: number;
    isOutlier: boolean;
  } {
    const inputKey = `${input.source}_baseline`;
    const baseline = this.baselineStats.get(inputKey);

    if (!baseline) {
      // Initialize baseline if not exists
      this.updateBaseline(input);
      return { zScore: 0, isOutlier: false };
    }

    // Calculate Z-score for input features
    const inputMean = input.features.reduce((sum, val) => sum + val, 0) / input.features.length;
    const zScore = baseline.stdDev > 0 ? Math.abs(inputMean - baseline.mean) / baseline.stdDev : 0;
    const isOutlier = zScore > 2.5;

    return { zScore, isOutlier };
  }

  /**
   * Analyze input for structural anomalies
   */
  private analyzeInputAnomaly(input: InputSample): {
    anomalyScore: number;
    isAnomalous: boolean;
  } {
    // Check for various input anomalies
    const checks = [
      this.checkNaNValues(input.features),
      this.checkInfiniteValues(input.features),
      this.checkValueRange(input.features),
      this.checkFeatureDistribution(input.features)
    ];

    const anomalyScore = checks.reduce((sum, check) => sum + check, 0) / checks.length;
    const isAnomalous = anomalyScore > 0.2;

    return { anomalyScore, isAnomalous };
  }

  /**
   * Check for NaN values in features
   */
  private checkNaNValues(features: number[]): number {
    const nanCount = features.filter(val => isNaN(val)).length;
    return nanCount / features.length;
  }

  /**
   * Check for infinite values in features
   */
  private checkInfiniteValues(features: number[]): number {
    const infiniteCount = features.filter(val => !isFinite(val)).length;
    return infiniteCount / features.length;
  }

  /**
   * Check if values are within expected range
   */
  private checkValueRange(features: number[]): number {
    const outOfRangeCount = features.filter(val => Math.abs(val) > 1000).length;
    return outOfRangeCount / features.length;
  }

  /**
   * Check feature distribution for anomalies
   */
  private checkFeatureDistribution(features: number[]): number {
    if (features.length < 2) return 0;

    const mean = features.reduce((sum, val) => sum + val, 0) / features.length;
    const variance = features.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / features.length;
    const stdDev = Math.sqrt(variance);

    // Check for unusual standard deviation
    return stdDev > 100 ? 1.0 : stdDev / 100;
  }

  /**
   * Update baseline statistics for input source
   */
  private updateBaseline(input: InputSample): void {
    const inputKey = `${input.source}_baseline`;
    const inputMean = input.features.reduce((sum, val) => sum + val, 0) / input.features.length;
    
    // Simple running average update
    const existing = this.baselineStats.get(inputKey);
    if (existing) {
      const newMean = (existing.mean + inputMean) / 2;
      const newStdDev = Math.sqrt(Math.pow(existing.stdDev, 2) + Math.pow(inputMean - newMean, 2)) / 2;
      this.baselineStats.set(inputKey, { mean: newMean, stdDev: newStdDev });
    } else {
      this.baselineStats.set(inputKey, { mean: inputMean, stdDev: 0 });
    }
  }

  /**
   * Combine analysis results and determine attack presence
   */
  private combineAnalysisResults({
    inputSample,
    predictions,
    confidenceAnalysis,
    perturbationAnalysis,
    ensembleAnalysis,
    gradientAnalysis,
    statisticalAnalysis,
    inputAnomalyAnalysis
  }: {
    inputSample: InputSample;
    predictions: ModelPrediction[];
    confidenceAnalysis: any;
    perturbationAnalysis: any;
    ensembleAnalysis: any;
    gradientAnalysis: any;
    statisticalAnalysis: any;
    inputAnomalyAnalysis: any;
  }): ModelEvasionDetectionResult {
    const detectionMethods: string[] = [];
    let maxSeverity: 'low' | 'medium' | 'high' | 'critical' = 'low';
    let confidence = 0;
    let attackType = 'unknown';

    // Check each signature against analysis results
    for (const signature of this.signatures) {
      let signatureMatches = 0;
      let totalChecks = 0;

      if (signature.pattern.lowConfidence) {
        totalChecks++;
        if (confidenceAnalysis.isLowConfidence) {
          signatureMatches++;
          detectionMethods.push('low_confidence');
        }
      }

      if (signature.pattern.highPerturbation) {
        totalChecks++;
        if (perturbationAnalysis.isHighPerturbation) {
          signatureMatches++;
          detectionMethods.push('high_perturbation');
        }
      }

      if (signature.pattern.ensembleDisagreement) {
        totalChecks++;
        if (ensembleAnalysis.isDisagreement) {
          signatureMatches++;
          detectionMethods.push('ensemble_disagreement');
        }
      }

      if (signature.pattern.gradientAnomaly) {
        totalChecks++;
        if (gradientAnalysis.isAnomalous) {
          signatureMatches++;
          detectionMethods.push('gradient_anomaly');
        }
      }

      if (signature.pattern.statisticalDeviation) {
        totalChecks++;
        if (statisticalAnalysis.isOutlier) {
          signatureMatches++;
          detectionMethods.push('statistical_deviation');
        }
      }

      if (signature.pattern.inputAnomaly) {
        totalChecks++;
        if (inputAnomalyAnalysis.isAnomalous) {
          signatureMatches++;
          detectionMethods.push('input_anomaly');
        }
      }

      // Calculate confidence for this signature
      const signatureConfidence = totalChecks > 0 ? signatureMatches / totalChecks : 0;
      
      if (signatureConfidence > 0.6) {
        confidence = Math.max(confidence, signatureConfidence);
        attackType = signature.name;
        
        if (this.getSeverityLevel(signature.severity) > this.getSeverityLevel(maxSeverity)) {
          maxSeverity = signature.severity;
        }
      }
    }

    const isAttack = confidence > 0.6;
    const blockedInputs = isAttack ? 1 : 0;

    return {
      isAttack,
      attackType,
      severity: maxSeverity,
      confidence,
      detectionMethods: [...new Set(detectionMethods)],
      blockedInputs,
      recommendations: this.generateRecommendations(attackType, maxSeverity),
      timestamp: new Date(),
      metadata: {
        inputId: inputSample.id,
        modelId: predictions[0]?.modelId || 'unknown',
        originalPrediction: predictions[0]?.prediction,
        confidenceScore: confidenceAnalysis.avgConfidence,
        perturbationScore: perturbationAnalysis.score,
        ensembleScore: ensembleAnalysis.agreementScore,
        gradientScore: gradientAnalysis.avgGradientMagnitude,
        statisticalScore: statisticalAnalysis.zScore,
        inputAnomalyScore: inputAnomalyAnalysis.anomalyScore
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
   * Generate security recommendations based on attack type and severity
   */
  private generateRecommendations(attackType: string, severity: string): string[] {
    const recommendations: string[] = [];

    if (attackType.includes('FGSM')) {
      recommendations.push('Deploy adversarial training with FGSM examples');
      recommendations.push('Implement input preprocessing defenses');
      recommendations.push('Use gradient masking techniques');
    }

    if (attackType.includes('PGD')) {
      recommendations.push('Implement robust adversarial training');
      recommendations.push('Deploy certified defenses');
      recommendations.push('Use input transformation defenses');
    }

    if (attackType.includes('Carlini')) {
      recommendations.push('Deploy detection-based defenses');
      recommendations.push('Implement input reconstruction defenses');
      recommendations.push('Use ensemble diversity techniques');
    }

    if (attackType.includes('DeepFool')) {
      recommendations.push('Implement feature squeezing defenses');
      recommendations.push('Deploy distillation-based defenses');
      recommendations.push('Use input validation techniques');
    }

    if (severity === 'critical' || severity === 'high') {
      recommendations.push('Block malicious input immediately');
      recommendations.push('Trigger automated incident response');
      recommendations.push('Quarantine affected model temporarily');
    }

    recommendations.push('Update adversarial training dataset');
    recommendations.push('Archive detection results for analysis');

    return recommendations;
  }

  /**
   * Block a malicious input
   */
  private async blockInput(inputId: string): Promise<void> {
    this.blockedInputs.add(inputId);
    
    logger.warn('Blocked malicious input', {
      inputId,
      component: 'ModelEvasionDetector'
    });
  }

  /**
   * Create blocked result for already blocked input
   */
  private createBlockedResult(input: InputSample, prediction: ModelPrediction): ModelEvasionDetectionResult {
    return {
      isAttack: true,
      attackType: 'Previously Blocked Input',
      severity: 'high',
      confidence: 1.0,
      detectionMethods: ['blocked_input'],
      blockedInputs: 1,
      recommendations: ['Input blocked by previous detection'],
      timestamp: new Date(),
      metadata: {
        inputId: input.id,
        modelId: prediction.modelId,
        originalPrediction: 'blocked',
        confidenceScore: 0,
        perturbationScore: 0,
        ensembleScore: 0,
        gradientScore: 0,
        statisticalScore: 0,
        inputAnomalyScore: 1.0
      }
    };
  }

  /**
   * Send security alert for detected model evasion attack
   */
  private async sendAlert(result: ModelEvasionDetectionResult): Promise<void> {
    const alertData = {
      type: 'model_evasion_attack',
      severity: result.severity,
      title: `Model Evasion Attack Detected: ${result.attackType}`,
      description: `Model evasion attack detected with ${(result.confidence * 100).toFixed(1)}% confidence`,
      details: {
        inputId: result.metadata.inputId,
        modelId: result.metadata.modelId,
        attackType: result.attackType,
        confidence: result.confidence,
        detectionMethods: result.detectionMethods,
        recommendations: result.recommendations,
        blockedInputs: result.blockedInputs
      },
      timestamp: result.timestamp
    };

    await this.notificationManager.sendAlert(alertData);
  }

  /**
   * Get detection history for a model
   */
  getDetectionHistory(modelId: string): ModelEvasionDetectionResult[] {
    return this.detectionHistory.get(modelId) || [];
  }

  /**
   * Get current detection statistics
   */
  getDetectionStats(): {
    totalDetections: number;
    attackDetections: number;
    blockedInputs: number;
    severeAttacks: number;
    avgConfidence: number;
  } {
    const allDetections = Array.from(this.detectionHistory.values()).flat();
    const attackDetections = allDetections.filter(d => d.isAttack);
    const blockedInputs = this.blockedInputs.size;
    const severeAttacks = attackDetections.filter(d => d.severity === 'high' || d.severity === 'critical');
    const avgConfidence = attackDetections.length > 0 ? 
      attackDetections.reduce((sum, d) => sum + d.confidence, 0) / attackDetections.length : 0;

    return {
      totalDetections: allDetections.length,
      attackDetections: attackDetections.length,
      blockedInputs,
      severeAttacks: severeAttacks.length,
      avgConfidence
    };
  }

  /**
   * Clear blocked inputs (for testing or manual override)
   */
  clearBlockedInputs(): void {
    this.blockedInputs.clear();
    logger.info('Cleared blocked inputs', {
      component: 'ModelEvasionDetector'
    });
  }
}