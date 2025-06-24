import { EventEmitter } from 'events';
import crypto from 'crypto';

export interface SecurityEvent {
  id: string;
  timestamp: Date;
  source: string;
  type: 'authentication' | 'authorization' | 'data_access' | 'system' | 'threat';
  severity: 'low' | 'medium' | 'high' | 'critical';
  category: string;
  description: string;
  actor: {
    userId?: string;
    ip: string;
    userAgent?: string;
    serviceId?: string;
  };
  target: {
    resource: string;
    resourceId?: string;
    action: string;
  };
  metadata: Record<string, any>;
  correlationId?: string;
  riskScore: number;
}

export interface ThreatIntelligence {
  iocType: 'ip' | 'domain' | 'hash' | 'url';
  iocValue: string;
  threatType: string;
  confidence: number;
  source: string;
  firstSeen: Date;
  lastSeen: Date;
  tags: string[];
}

export interface SecurityAlert {
  id: string;
  timestamp: Date;
  title: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  category: string;
  status: 'open' | 'investigating' | 'resolved' | 'false_positive';
  assignedTo?: string;
  events: SecurityEvent[];
  indicators: ThreatIntelligence[];
  automatedResponse?: string[];
  createdBy: 'system' | 'user';
  metadata: Record<string, any>;
}

export class SecurityEventCorrelationEngine extends EventEmitter {
  private events: SecurityEvent[] = [];
  private alerts: SecurityAlert[] = [];
  private threatIntelligence: ThreatIntelligence[] = [];
  private correlationRules: CorrelationRule[] = [];
  private behavioralBaselines: Map<string, BehavioralBaseline> = new Map();

  constructor() {
    super();
    this.initializeCorrelationRules();
    this.startBehavioralAnalysis();
  }

  // Ingest security event
  ingestEvent(event: Omit<SecurityEvent, 'id' | 'timestamp' | 'riskScore'>) {
    const securityEvent: SecurityEvent = {
      ...event,
      id: crypto.randomUUID(),
      timestamp: new Date(),
      riskScore: this.calculateRiskScore(event),
    };

    this.events.push(securityEvent);
    this.emit('event', securityEvent);

    // Keep only last 10000 events for performance
    if (this.events.length > 10000) {
      this.events = this.events.slice(-10000);
    }

    // Run correlation analysis
    this.correlateEvents(securityEvent);

    // Check against threat intelligence
    this.checkThreatIntelligence(securityEvent);

    // Update behavioral baselines
    this.updateBehavioralBaseline(securityEvent);

    return securityEvent;
  }

  // Add threat intelligence indicators
  addThreatIntelligence(indicators: Omit<ThreatIntelligence, 'firstSeen' | 'lastSeen'>[]) {
    const now = new Date();
    const newIndicators = indicators.map(indicator => ({
      ...indicator,
      firstSeen: now,
      lastSeen: now,
    }));

    this.threatIntelligence.push(...newIndicators);
    this.emit('threat-intelligence-updated', newIndicators);
  }

  // Get active alerts
  getActiveAlerts(): SecurityAlert[] {
    return this.alerts.filter(alert => alert.status === 'open' || alert.status === 'investigating');
  }

  // Get events by time range
  getEventsByTimeRange(startTime: Date, endTime: Date): SecurityEvent[] {
    return this.events.filter(event => 
      event.timestamp >= startTime && event.timestamp <= endTime
    );
  }

  // Create security alert
  createAlert(
    title: string,
    description: string,
    severity: SecurityAlert['severity'],
    category: string,
    relatedEvents: SecurityEvent[],
    indicators: ThreatIntelligence[] = []
  ): SecurityAlert {
    const alert: SecurityAlert = {
      id: crypto.randomUUID(),
      timestamp: new Date(),
      title,
      description,
      severity,
      category,
      status: 'open',
      events: relatedEvents,
      indicators,
      automatedResponse: this.getAutomatedResponse(severity, category),
      createdBy: 'system',
      metadata: {},
    };

    this.alerts.push(alert);
    this.emit('alert-created', alert);

    // Execute automated response
    if (alert.automatedResponse && alert.automatedResponse.length > 0) {
      this.executeAutomatedResponse(alert);
    }

    return alert;
  }

  // Correlate events to detect patterns
  private correlateEvents(newEvent: SecurityEvent) {
    const recentEvents = this.events.filter(event => 
      event.timestamp > new Date(Date.now() - 300000) // Last 5 minutes
    );

    for (const rule of this.correlationRules) {
      const matchedEvents = rule.evaluate(recentEvents, newEvent);
      if (matchedEvents.length >= rule.threshold) {
        this.createAlert(
          rule.alertTitle,
          rule.alertDescription,
          rule.severity,
          rule.category,
          matchedEvents
        );
      }
    }
  }

  // Check events against threat intelligence
  private checkThreatIntelligence(event: SecurityEvent) {
    const indicators = this.threatIntelligence.filter(indicator => {
      switch (indicator.iocType) {
        case 'ip':
          return event.actor.ip === indicator.iocValue;
        case 'domain':
          return event.metadata.domain === indicator.iocValue;
        case 'hash':
          return event.metadata.fileHash === indicator.iocValue;
        case 'url':
          return event.metadata.url === indicator.iocValue;
        default:
          return false;
      }
    });

    if (indicators.length > 0) {
      this.createAlert(
        'Threat Intelligence Match',
        `Event matched ${indicators.length} threat intelligence indicator(s)`,
        'high',
        'threat-intelligence',
        [event],
        indicators
      );
    }
  }

  // Update behavioral baselines
  private updateBehavioralBaseline(event: SecurityEvent) {
    const key = `${event.actor.userId || event.actor.ip}-${event.target.resource}`;
    const baseline = this.behavioralBaselines.get(key) || {
      userId: event.actor.userId,
      ip: event.actor.ip,
      resource: event.target.resource,
      normalAccess: [],
      riskScores: [],
      lastUpdate: new Date(),
    };

    baseline.normalAccess.push({
      timestamp: event.timestamp,
      action: event.target.action,
      userAgent: event.actor.userAgent,
    });

    baseline.riskScores.push(event.riskScore);

    // Keep only last 100 access patterns
    if (baseline.normalAccess.length > 100) {
      baseline.normalAccess = baseline.normalAccess.slice(-100);
    }

    if (baseline.riskScores.length > 100) {
      baseline.riskScores = baseline.riskScores.slice(-100);
    }

    baseline.lastUpdate = new Date();
    this.behavioralBaselines.set(key, baseline);

    // Detect anomalies
    this.detectAnomalies(event, baseline);
  }

  // Detect behavioral anomalies
  private detectAnomalies(event: SecurityEvent, baseline: BehavioralBaseline) {
    const avgRiskScore = baseline.riskScores.reduce((a, b) => a + b, 0) / baseline.riskScores.length;
    const riskThreshold = avgRiskScore + (2 * this.calculateStandardDeviation(baseline.riskScores));

    if (event.riskScore > riskThreshold) {
      this.createAlert(
        'Behavioral Anomaly Detected',
        `User behavior significantly deviates from baseline (Risk Score: ${event.riskScore}, Baseline: ${avgRiskScore.toFixed(2)})`,
        'medium',
        'behavioral-anomaly',
        [event]
      );
    }

    // Check for unusual access patterns
    const currentHour = event.timestamp.getHours();
    const normalHours = baseline.normalAccess.map(access => access.timestamp.getHours());
    const hourFrequency = normalHours.reduce((acc, hour) => {
      acc[hour] = (acc[hour] || 0) + 1;
      return acc;
    }, {} as Record<number, number>);

    if ((hourFrequency[currentHour] || 0) < 2 && baseline.normalAccess.length > 20) {
      this.createAlert(
        'Unusual Access Time',
        `Access detected at unusual time (${currentHour}:00) for user/resource pattern`,
        'low',
        'access-pattern',
        [event]
      );
    }
  }

  // Calculate risk score for an event
  private calculateRiskScore(event: Omit<SecurityEvent, 'id' | 'timestamp' | 'riskScore'>): number {
    let score = 0;

    // Base score by event type
    const typeScores = {
      authentication: 2,
      authorization: 3,
      data_access: 4,
      system: 3,
      threat: 8,
    };
    score += typeScores[event.type] || 1;

    // Severity multiplier
    const severityMultipliers = {
      low: 1,
      medium: 2,
      high: 3,
      critical: 4,
    };
    score *= severityMultipliers[event.severity];

    // Time-based factors (higher risk outside business hours)
    const hour = new Date().getHours();
    if (hour < 6 || hour > 22) {
      score *= 1.5;
    }

    // Failed authentication attempts
    if (event.type === 'authentication' && event.metadata.success === false) {
      score *= 2;
    }

    // Administrative actions
    if (event.metadata.isAdminAction) {
      score *= 1.5;
    }

    return Math.min(score, 10); // Cap at 10
  }

  // Get automated response actions
  private getAutomatedResponse(severity: SecurityAlert['severity'], category: string): string[] {
    const responses: string[] = [];

    if (severity === 'critical') {
      responses.push('immediate-notification');
      responses.push('isolate-affected-systems');
    }

    if (severity === 'high') {
      responses.push('escalate-to-security-team');
      responses.push('increase-monitoring');
    }

    if (category === 'authentication') {
      responses.push('review-access-logs');
    }

    if (category === 'threat-intelligence') {
      responses.push('block-indicators');
      responses.push('scan-for-compromise');
    }

    return responses;
  }

  // Execute automated response
  private executeAutomatedResponse(alert: SecurityAlert) {
    console.log(`Executing automated response for alert ${alert.id}:`);
    
    for (const action of alert.automatedResponse || []) {
      console.log(`- ${action}`);
      
      // In a real implementation, these would trigger actual responses
      switch (action) {
        case 'immediate-notification':
          this.sendNotification(alert, 'immediate');
          break;
        case 'escalate-to-security-team':
          this.escalateAlert(alert);
          break;
        case 'block-indicators':
          this.blockThreatIndicators(alert.indicators);
          break;
        case 'increase-monitoring':
          this.increaseMonitoring(alert);
          break;
      }
    }
  }

  // Initialize correlation rules
  private initializeCorrelationRules() {
    this.correlationRules = [
      {
        name: 'Multiple Failed Logins',
        threshold: 5,
        timeWindow: 300, // 5 minutes
        severity: 'medium',
        category: 'authentication',
        alertTitle: 'Multiple Failed Login Attempts',
        alertDescription: 'Multiple failed login attempts detected from same source',
        evaluate: (events: SecurityEvent[], newEvent: SecurityEvent) => {
          if (newEvent.type !== 'authentication' || newEvent.metadata.success !== false) {
            return [];
          }
          return events.filter(event => 
            event.type === 'authentication' &&
            event.metadata.success === false &&
            event.actor.ip === newEvent.actor.ip
          );
        },
      },
      {
        name: 'Privilege Escalation',
        threshold: 2,
        timeWindow: 600, // 10 minutes
        severity: 'high',
        category: 'authorization',
        alertTitle: 'Potential Privilege Escalation',
        alertDescription: 'User accessed resources with elevated privileges',
        evaluate: (events: SecurityEvent[], newEvent: SecurityEvent) => {
          if (newEvent.type !== 'authorization' || !newEvent.metadata.isAdminAction) {
            return [];
          }
          return events.filter(event => 
            event.type === 'authorization' &&
            event.metadata.isAdminAction &&
            event.actor.userId === newEvent.actor.userId
          );
        },
      },
      {
        name: 'Data Exfiltration',
        threshold: 3,
        timeWindow: 1800, // 30 minutes
        severity: 'critical',
        category: 'data_access',
        alertTitle: 'Potential Data Exfiltration',
        alertDescription: 'Large volume of data access detected',
        evaluate: (events: SecurityEvent[], newEvent: SecurityEvent) => {
          if (newEvent.type !== 'data_access') {
            return [];
          }
          return events.filter(event => 
            event.type === 'data_access' &&
            event.actor.userId === newEvent.actor.userId &&
            (event.metadata.dataSize || 0) > 1000000 // 1MB threshold
          );
        },
      },
    ];
  }

  // Start behavioral analysis
  private startBehavioralAnalysis() {
    setInterval(() => {
      // Clean up old behavioral data
      const cutoffTime = new Date(Date.now() - 86400000 * 7); // 7 days
      for (const [key, baseline] of this.behavioralBaselines.entries()) {
        if (baseline.lastUpdate < cutoffTime) {
          this.behavioralBaselines.delete(key);
        }
      }
    }, 3600000); // Run every hour
  }

  // Helper methods for automated responses
  private sendNotification(alert: SecurityAlert, priority: 'low' | 'medium' | 'high' | 'immediate') {
    console.log(`Sending ${priority} notification for alert: ${alert.title}`);
    // Implement notification logic (email, Slack, etc.)
  }

  private escalateAlert(alert: SecurityAlert) {
    console.log(`Escalating alert ${alert.id} to security team`);
    alert.status = 'investigating';
    // Implement escalation logic
  }

  private blockThreatIndicators(indicators: ThreatIntelligence[]) {
    console.log(`Blocking ${indicators.length} threat indicators`);
    // Implement blocking logic (firewall rules, etc.)
  }

  private increaseMonitoring(alert: SecurityAlert) {
    console.log(`Increasing monitoring for alert ${alert.id}`);
    // Implement enhanced monitoring logic
  }

  private calculateStandardDeviation(values: number[]): number {
    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    const variance = values.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / values.length;
    return Math.sqrt(variance);
  }
}

// Interfaces
interface CorrelationRule {
  name: string;
  threshold: number;
  timeWindow: number;
  severity: SecurityAlert['severity'];
  category: string;
  alertTitle: string;
  alertDescription: string;
  evaluate: (events: SecurityEvent[], newEvent: SecurityEvent) => SecurityEvent[];
}

interface BehavioralBaseline {
  userId?: string;
  ip: string;
  resource: string;
  normalAccess: Array<{
    timestamp: Date;
    action: string;
    userAgent?: string;
  }>;
  riskScores: number[];
  lastUpdate: Date;
}

// SIEM Integration
export class SIEMIntegration {
  private correlationEngine: SecurityEventCorrelationEngine;
  private integrations: Map<string, SIEMConnector> = new Map();

  constructor(correlationEngine: SecurityEventCorrelationEngine) {
    this.correlationEngine = correlationEngine;
  }

  // Add SIEM integration
  addIntegration(name: string, connector: SIEMConnector) {
    this.integrations.set(name, connector);
    
    // Forward events to SIEM
    this.correlationEngine.on('event', (event) => {
      connector.sendEvent(event);
    });

    this.correlationEngine.on('alert-created', (alert) => {
      connector.sendAlert(alert);
    });
  }

  // Get integration status
  getIntegrationStatus(): Record<string, boolean> {
    const status: Record<string, boolean> = {};
    for (const [name, connector] of this.integrations.entries()) {
      status[name] = connector.isConnected();
    }
    return status;
  }
}

// SIEM Connector interface
export interface SIEMConnector {
  sendEvent(event: SecurityEvent): Promise<void>;
  sendAlert(alert: SecurityAlert): Promise<void>;
  isConnected(): boolean;
}

// Splunk connector implementation
export class SplunkConnector implements SIEMConnector {
  private endpoint: string;
  private token: string;
  private connected: boolean = false;

  constructor(endpoint: string, token: string) {
    this.endpoint = endpoint;
    this.token = token;
    this.testConnection();
  }

  async sendEvent(event: SecurityEvent): Promise<void> {
    const splunkEvent = {
      time: event.timestamp.getTime() / 1000,
      source: 'ai-spm',
      sourcetype: 'security_event',
      event: {
        id: event.id,
        type: event.type,
        severity: event.severity,
        category: event.category,
        description: event.description,
        actor: event.actor,
        target: event.target,
        risk_score: event.riskScore,
        correlation_id: event.correlationId,
      },
    };

    await this.sendToSplunk(splunkEvent);
  }

  async sendAlert(alert: SecurityAlert): Promise<void> {
    const splunkAlert = {
      time: alert.timestamp.getTime() / 1000,
      source: 'ai-spm',
      sourcetype: 'security_alert',
      event: {
        id: alert.id,
        title: alert.title,
        description: alert.description,
        severity: alert.severity,
        category: alert.category,
        status: alert.status,
        event_count: alert.events.length,
        indicator_count: alert.indicators.length,
        automated_response: alert.automatedResponse,
      },
    };

    await this.sendToSplunk(splunkAlert);
  }

  isConnected(): boolean {
    return this.connected;
  }

  private async sendToSplunk(data: any): Promise<void> {
    try {
      const response = await fetch(`${this.endpoint}/services/collector`, {
        method: 'POST',
        headers: {
          'Authorization': `Splunk ${this.token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(data),
      });

      if (!response.ok) {
        throw new Error(`Splunk API error: ${response.statusText}`);
      }
    } catch (error) {
      console.error('Failed to send data to Splunk:', error);
      this.connected = false;
    }
  }

  private async testConnection(): Promise<void> {
    try {
      const response = await fetch(`${this.endpoint}/services/collector/health`, {
        headers: {
          'Authorization': `Splunk ${this.token}`,
        },
      });
      this.connected = response.ok;
    } catch (error) {
      this.connected = false;
    }
  }
}