/**
 * Model Context Protocol (MCP) Security Gateway
 * Provides secure context sharing and validation for agent-based workflows
 */

import crypto from 'crypto';
import { EventEmitter } from 'events';

// MCP Protocol Types
export interface MCPContext {
  id: string;
  type: 'conversation' | 'document' | 'data' | 'model_state' | 'tool_result';
  content: any;
  metadata: MCPMetadata;
  signature?: string;
  encryption?: EncryptionInfo;
}

export interface MCPMetadata {
  version: string;
  created_at: Date;
  created_by: string; // Agent ID
  sensitivity_level: 'public' | 'internal' | 'confidential' | 'restricted';
  data_classification: string[];
  retention_policy?: RetentionPolicy;
  access_controls: AccessControl[];
}

export interface EncryptionInfo {
  algorithm: string;
  key_id: string;
  iv: string;
  auth_tag?: string;
}

export interface AccessControl {
  agent_id?: string;
  role?: string;
  permissions: Permission[];
  conditions?: AccessCondition[];
}

export interface Permission {
  action: 'read' | 'write' | 'share' | 'delete';
  granted: boolean;
}

export interface AccessCondition {
  type: 'time_based' | 'location_based' | 'context_based';
  parameters: Record<string, any>;
}

export interface RetentionPolicy {
  retain_for_days: number;
  auto_delete: boolean;
  archive_after_days?: number;
}

export interface ValidationResult {
  valid: boolean;
  issues: ValidationIssue[];
  security_score: number;
  recommendations: string[];
}

export interface ValidationIssue {
  severity: 'low' | 'medium' | 'high' | 'critical';
  type: string;
  message: string;
  field?: string;
}

export interface SensitivityAnalysis {
  detected_pii: PIIDetection[];
  classification_score: number;
  recommended_level: string;
  data_categories: string[];
}

export interface PIIDetection {
  type: 'email' | 'phone' | 'ssn' | 'credit_card' | 'name' | 'address' | 'custom';
  value: string;
  confidence: number;
  location: string;
  masked_value: string;
}

/**
 * MCP Security Gateway
 * Central service for securing Model Context Protocol communications
 */
export class MCPSecurityGateway extends EventEmitter {
  private contexts: Map<string, MCPContext> = new Map();
  private contextAccess: Map<string, ContextAccessLog[]> = new Map();
  private encryptionKeys: Map<string, CryptoKey> = new Map();
  private piiDetector: PIIDetector;
  private contextValidator: ContextValidator;

  constructor() {
    super();
    this.piiDetector = new PIIDetector();
    this.contextValidator = new ContextValidator();
  }

  /**
   * Create a secure context with validation and encryption
   */
  async createSecureContext(
    content: any,
    metadata: Partial<MCPMetadata>,
    createdBy: string
  ): Promise<MCPContext> {
    const contextId = crypto.randomUUID();

    // Analyze content sensitivity
    const sensitivityAnalysis = await this.analyzeSensitivity(content);

    // Create complete metadata
    const completeMetadata: MCPMetadata = {
      version: '1.0',
      created_at: new Date(),
      created_by: createdBy,
      sensitivity_level: metadata.sensitivity_level || sensitivityAnalysis.recommended_level as any,
      data_classification: metadata.data_classification || sensitivityAnalysis.data_categories,
      access_controls: metadata.access_controls || [],
      ...metadata
    };

    // Create context
    const context: MCPContext = {
      id: contextId,
      type: metadata.type || 'data',
      content,
      metadata: completeMetadata
    };

    // Encrypt if required
    if (completeMetadata.sensitivity_level !== 'public') {
      const encrypted = await this.encryptContext(context);
      context.content = encrypted.content;
      context.encryption = encrypted.encryption;
    }

    // Generate integrity signature
    context.signature = await this.generateContextSignature(context);

    // Store context
    this.contexts.set(contextId, context);

    // Initialize access log
    this.contextAccess.set(contextId, [{
      agent_id: createdBy,
      action: 'create',
      timestamp: new Date(),
      success: true
    }]);

    this.emit('contextCreated', {
      contextId,
      createdBy,
      sensitivityLevel: completeMetadata.sensitivity_level,
      timestamp: new Date()
    });

    return context;
  }

  /**
   * Validate context integrity and security
   */
  async validateContext(context: MCPContext): Promise<ValidationResult> {
    const issues: ValidationIssue[] = [];
    let securityScore = 100;

    // Verify signature
    const signatureValid = await this.verifyContextSignature(context);
    if (!signatureValid) {
      issues.push({
        severity: 'critical',
        type: 'integrity',
        message: 'Context signature verification failed'
      });
      securityScore -= 30;
    }

    // Validate metadata
    const metadataValidation = await this.contextValidator.validateMetadata(context.metadata);
    if (!metadataValidation.valid) {
      issues.push(...metadataValidation.issues);
      securityScore -= 20;
    }

    // Check for malicious content
    const contentSecurity = await this.contextValidator.validateContent(context.content);
    if (!contentSecurity.safe) {
      issues.push({
        severity: 'high',
        type: 'security',
        message: 'Potentially malicious content detected'
      });
      securityScore -= 25;
    }

    // Validate access controls
    if (!context.metadata.access_controls || context.metadata.access_controls.length === 0) {
      issues.push({
        severity: 'medium',
        type: 'access_control',
        message: 'No access controls specified'
      });
      securityScore -= 15;
    }

    return {
      valid: issues.filter(i => i.severity === 'critical').length === 0,
      issues,
      security_score: Math.max(0, securityScore),
      recommendations: this.generateSecurityRecommendations(issues)
    };
  }

  /**
   * Authorize agent access to context
   */
  async authorizeContextAccess(
    contextId: string,
    agentId: string,
    action: 'read' | 'write' | 'share' | 'delete'
  ): Promise<{ authorized: boolean; reason?: string }> {
    const context = this.contexts.get(contextId);
    if (!context) {
      return { authorized: false, reason: 'Context not found' };
    }

    // Check access controls
    const hasAccess = context.metadata.access_controls.some(ac => {
      if (ac.agent_id && ac.agent_id !== agentId) {
        return false;
      }

      const permission = ac.permissions.find(p => p.action === action);
      if (!permission || !permission.granted) {
        return false;
      }

      // Check conditions
      if (ac.conditions) {
        return this.evaluateAccessConditions(ac.conditions, agentId);
      }

      return true;
    });

    // Log access attempt
    const accessLog: ContextAccessLog = {
      agent_id: agentId,
      action,
      timestamp: new Date(),
      success: hasAccess
    };

    const logs = this.contextAccess.get(contextId) || [];
    logs.push(accessLog);
    this.contextAccess.set(contextId, logs);

    if (!hasAccess) {
      this.emit('unauthorizedAccess', {
        contextId,
        agentId,
        action,
        timestamp: new Date()
      });

      return { authorized: false, reason: 'Insufficient permissions' };
    }

    this.emit('contextAccessed', {
      contextId,
      agentId,
      action,
      timestamp: new Date()
    });

    return { authorized: true };
  }

  /**
   * Share context with specified agents
   */
  async shareContext(
    contextId: string,
    recipientAgents: string[],
    permissions: Permission[]
  ): Promise<{ success: boolean; shared_with: string[]; errors: string[] }> {
    const context = this.contexts.get(contextId);
    if (!context) {
      return { success: false, shared_with: [], errors: ['Context not found'] };
    }

    const sharedWith: string[] = [];
    const errors: string[] = [];

    for (const agentId of recipientAgents) {
      try {
        // Add access control for the agent
        const newAccessControl: AccessControl = {
          agent_id: agentId,
          permissions: [...permissions]
        };

        context.metadata.access_controls.push(newAccessControl);
        sharedWith.push(agentId);

        // Log sharing event
        const accessLog: ContextAccessLog = {
          agent_id: agentId,
          action: 'share',
          timestamp: new Date(),
          success: true
        };

        const logs = this.contextAccess.get(contextId) || [];
        logs.push(accessLog);
        this.contextAccess.set(contextId, logs);

      } catch (error) {
        errors.push(`Failed to share with ${agentId}: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    }

    // Update context signature after modification
    context.signature = await this.generateContextSignature(context);
    this.contexts.set(contextId, context);

    this.emit('contextShared', {
      contextId,
      sharedWith,
      permissions,
      timestamp: new Date()
    });

    return {
      success: errors.length === 0,
      shared_with: sharedWith,
      errors
    };
  }

  /**
   * Get context with access control validation
   */
  async getContext(contextId: string, requestingAgent: string): Promise<MCPContext | null> {
    const authResult = await this.authorizeContextAccess(contextId, requestingAgent, 'read');
    if (!authResult.authorized) {
      return null;
    }

    const context = this.contexts.get(contextId);
    if (!context) {
      return null;
    }

    // Decrypt if necessary
    if (context.encryption) {
      const decrypted = await this.decryptContext(context);
      return {
        ...context,
        content: decrypted
      };
    }

    return context;
  }

  /**
   * Get context access audit log
   */
  async getContextAuditLog(contextId: string): Promise<ContextAccessLog[]> {
    return this.contextAccess.get(contextId) || [];
  }

  /**
   * Analyze content sensitivity and detect PII
   */
  async analyzeSensitivity(content: any): Promise<SensitivityAnalysis> {
    return await this.piiDetector.analyze(content);
  }

  /**
   * Delete context (with retention policy compliance)
   */
  async deleteContext(contextId: string, requestingAgent: string): Promise<{ success: boolean; reason?: string }> {
    const authResult = await this.authorizeContextAccess(contextId, requestingAgent, 'delete');
    if (!authResult.authorized) {
      return { success: false, reason: authResult.reason };
    }

    const context = this.contexts.get(contextId);
    if (!context) {
      return { success: false, reason: 'Context not found' };
    }

    // Check retention policy
    if (context.metadata.retention_policy) {
      const retentionEnd = new Date(context.metadata.created_at);
      retentionEnd.setDate(retentionEnd.getDate() + context.metadata.retention_policy.retain_for_days);

      if (new Date() < retentionEnd) {
        return { success: false, reason: 'Context is within retention period' };
      }
    }

    // Delete context and access logs
    this.contexts.delete(contextId);
    this.contextAccess.delete(contextId);

    this.emit('contextDeleted', {
      contextId,
      deletedBy: requestingAgent,
      timestamp: new Date()
    });

    return { success: true };
  }

  // Private methods

  private async encryptContext(context: MCPContext): Promise<{ content: string; encryption: EncryptionInfo }> {
    const keyId = crypto.randomUUID();
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );

    this.encryptionKeys.set(keyId, key);

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const contentBuffer = Buffer.from(JSON.stringify(context.content));

    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      contentBuffer
    );

    return {
      content: Buffer.from(encrypted).toString('base64'),
      encryption: {
        algorithm: 'AES-GCM',
        key_id: keyId,
        iv: Buffer.from(iv).toString('base64')
      }
    };
  }

  private async decryptContext(context: MCPContext): Promise<any> {
    if (!context.encryption) {
      return context.content;
    }

    const key = this.encryptionKeys.get(context.encryption.key_id);
    if (!key) {
      throw new Error('Encryption key not found');
    }

    const iv = Buffer.from(context.encryption.iv, 'base64');
    const encryptedContent = Buffer.from(context.content, 'base64');

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      encryptedContent
    );

    return JSON.parse(Buffer.from(decrypted).toString());
  }

  private async generateContextSignature(context: MCPContext): Promise<string> {
    const signingData = {
      id: context.id,
      type: context.type,
      content: context.content,
      metadata: context.metadata
    };

    return crypto
      .createHash('sha256')
      .update(JSON.stringify(signingData))
      .digest('hex');
  }

  private async verifyContextSignature(context: MCPContext): Promise<boolean> {
    if (!context.signature) {
      return false;
    }

    const expectedSignature = await this.generateContextSignature({
      ...context,
      signature: undefined
    });

    return context.signature === expectedSignature;
  }

  private evaluateAccessConditions(conditions: AccessCondition[], agentId: string): boolean {
    return conditions.every(condition => {
      switch (condition.type) {
        case 'time_based':
          return this.evaluateTimeCondition(condition.parameters);
        case 'location_based':
          return this.evaluateLocationCondition(condition.parameters, agentId);
        case 'context_based':
          return this.evaluateContextCondition(condition.parameters, agentId);
        default:
          return false;
      }
    });
  }

  private evaluateTimeCondition(params: Record<string, any>): boolean {
    const now = new Date();
    if (params.start_time && new Date(params.start_time) > now) {
      return false;
    }
    if (params.end_time && new Date(params.end_time) < now) {
      return false;
    }
    return true;
  }

  private evaluateLocationCondition(params: Record<string, any>, agentId: string): boolean {
    // Implementation would check agent location against allowed locations
    return true; // Simplified for demo
  }

  private evaluateContextCondition(params: Record<string, any>, agentId: string): boolean {
    // Implementation would check contextual conditions
    return true; // Simplified for demo
  }

  private generateSecurityRecommendations(issues: ValidationIssue[]): string[] {
    const recommendations: string[] = [];

    if (issues.some(i => i.type === 'integrity')) {
      recommendations.push('Re-generate context signature');
    }

    if (issues.some(i => i.type === 'access_control')) {
      recommendations.push('Define explicit access controls');
    }

    if (issues.some(i => i.type === 'security')) {
      recommendations.push('Review and sanitize content');
    }

    return recommendations;
  }
}

// Supporting interfaces and classes

interface ContextAccessLog {
  agent_id: string;
  action: string;
  timestamp: Date;
  success: boolean;
  details?: string;
}

/**
 * PII Detector for content analysis
 */
class PIIDetector {
  private patterns = {
    email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
    phone: /\b\d{3}-\d{3}-\d{4}\b|\b\(\d{3}\)\s*\d{3}-\d{4}\b/g,
    ssn: /\b\d{3}-\d{2}-\d{4}\b/g,
    credit_card: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g
  };

  async analyze(content: any): Promise<SensitivityAnalysis> {
    const contentStr = JSON.stringify(content);
    const detectedPii: PIIDetection[] = [];

    // Check for each PII type
    for (const [type, pattern] of Object.entries(this.patterns)) {
      const matches = contentStr.match(pattern);
      if (matches) {
        for (const match of matches) {
          detectedPii.push({
            type: type as any,
            value: match,
            confidence: 0.9,
            location: 'content',
            masked_value: this.maskValue(match, type)
          });
        }
      }
    }

    // Determine classification
    let recommendedLevel = 'public';
    const dataCategories: string[] = [];

    if (detectedPii.length > 0) {
      recommendedLevel = 'confidential';
      dataCategories.push('personal_data');
    }

    if (detectedPii.some(p => p.type === 'ssn' || p.type === 'credit_card')) {
      recommendedLevel = 'restricted';
      dataCategories.push('sensitive_personal_data');
    }

    return {
      detected_pii: detectedPii,
      classification_score: detectedPii.length > 0 ? 0.8 : 0.1,
      recommended_level: recommendedLevel,
      data_categories: dataCategories
    };
  }

  private maskValue(value: string, type: string): string {
    switch (type) {
      case 'email':
        const [user, domain] = value.split('@');
        return `${user.charAt(0)}***@${domain}`;
      case 'phone':
        return value.replace(/\d/g, '*').replace(/\*{3}$/, value.slice(-3));
      case 'ssn':
        return '***-**-' + value.slice(-4);
      case 'credit_card':
        return '**** **** **** ' + value.replace(/\D/g, '').slice(-4);
      default:
        return '*'.repeat(value.length);
    }
  }
}

/**
 * Context Validator for security validation
 */
class ContextValidator {
  async validateMetadata(metadata: MCPMetadata): Promise<{ valid: boolean; issues: ValidationIssue[] }> {
    const issues: ValidationIssue[] = [];

    if (!metadata.created_by) {
      issues.push({
        severity: 'high',
        type: 'metadata',
        message: 'Creator not specified',
        field: 'created_by'
      });
    }

    if (!metadata.sensitivity_level) {
      issues.push({
        severity: 'medium',
        type: 'metadata',
        message: 'Sensitivity level not specified',
        field: 'sensitivity_level'
      });
    }

    return {
      valid: issues.filter(i => i.severity === 'critical' || i.severity === 'high').length === 0,
      issues
    };
  }

  async validateContent(content: any): Promise<{ safe: boolean; threats: string[] }> {
    const contentStr = JSON.stringify(content);
    const threats: string[] = [];

    // Check for potential script injection
    if (contentStr.includes('<script>') || contentStr.includes('javascript:')) {
      threats.push('Potential script injection detected');
    }

    // Check for SQL injection patterns
    if (/(\bUNION\b|\bSELECT\b|\bINSERT\b|\bDELETE\b|\bDROP\b)/i.test(contentStr)) {
      threats.push('Potential SQL injection detected');
    }

    // Check for command injection
    if (/(\b(rm|del|format|shutdown)\b|[;&|`$])/i.test(contentStr)) {
      threats.push('Potential command injection detected');
    }

    return {
      safe: threats.length === 0,
      threats
    };
  }
}