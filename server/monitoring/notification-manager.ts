/**
 * Multi-Channel Notification Manager for AI-SPM Platform
 * Handles alert notifications across multiple channels with escalation policies
 */

import { EventEmitter } from 'events';
import { Alert, AlertSeverity } from './health-checker';

export interface NotificationChannel {
  name: string;
  type: 'email' | 'slack' | 'pagerduty' | 'sms' | 'webhook' | 'teams' | 'servicenow';
  enabled: boolean;
  config: NotificationConfig;
  fallback?: string; // fallback channel name
}

export interface NotificationConfig {
  // Email configuration
  smtp?: {
    host: string;
    port: number;
    secure: boolean;
    auth: { user: string; pass: string };
    from: string;
    to: string[];
  };

  // Slack configuration
  slack?: {
    webhookUrl: string;
    channel: string;
    username?: string;
    iconEmoji?: string;
  };

  // PagerDuty configuration
  pagerduty?: {
    integrationKey: string;
    severity?: string;
  };

  // SMS configuration (Twilio)
  sms?: {
    accountSid: string;
    authToken: string;
    fromNumber: string;
    toNumbers: string[];
  };

  // Webhook configuration
  webhook?: {
    url: string;
    method: 'POST' | 'PUT';
    headers: Record<string, string>;
    timeout: number;
  };

  // Microsoft Teams configuration
  teams?: {
    webhookUrl: string;
    title?: string;
  };

  // ServiceNow configuration
  servicenow?: {
    instance: string;
    username: string;
    password: string;
    table: string;
  };
}

export interface EscalationPolicy {
  name: string;
  levels: EscalationLevel[];
  enabled: boolean;
}

export interface EscalationLevel {
  level: number;
  delayMinutes: number;
  channels: string[];
  conditions?: EscalationCondition[];
}

export interface EscalationCondition {
  type: 'severity' | 'component' | 'duration' | 'acknowledgment';
  operator: 'equals' | 'contains' | 'greater_than' | 'less_than';
  value: any;
}

export interface NotificationResult {
  channel: string;
  success: boolean;
  timestamp: Date;
  error?: string;
  messageId?: string;
}

export interface NotificationTemplate {
  name: string;
  subject: string;
  body: string;
  format: 'text' | 'html' | 'markdown';
}

/**
 * Notification Manager Service
 */
export class NotificationManager extends EventEmitter {
  private channels: Map<string, NotificationChannel> = new Map();
  private escalationPolicies: Map<string, EscalationPolicy> = new Map();
  private templates: Map<string, NotificationTemplate> = new Map();
  private activeEscalations: Map<string, EscalationTracker> = new Map();

  constructor() {
    super();
    this.initializeDefaultChannels();
    this.initializeDefaultTemplates();
    this.initializeDefaultEscalationPolicies();
  }

  /**
   * Send alert notification through specified channels
   */
  async sendAlert(alert: Alert, channels: string[]): Promise<NotificationResult[]> {
    const results: NotificationResult[] = [];

    for (const channelName of channels) {
      try {
        const result = await this.sendToChannel(alert, channelName);
        results.push(result);
        
        if (result.success) {
          this.emit('notificationSent', { alert, channel: channelName, result });
        } else {
          this.emit('notificationFailed', { alert, channel: channelName, error: result.error });
          
          // Try fallback channel if available
          const channel = this.channels.get(channelName);
          if (channel?.fallback) {
            const fallbackResult = await this.sendToChannel(alert, channel.fallback);
            results.push(fallbackResult);
          }
        }
      } catch (error) {
        const errorResult: NotificationResult = {
          channel: channelName,
          success: false,
          timestamp: new Date(),
          error: error instanceof Error ? error.message : 'Unknown error'
        };
        results.push(errorResult);
        this.emit('notificationFailed', { alert, channel: channelName, error: errorResult.error });
      }
    }

    return results;
  }

  /**
   * Start escalation process for critical alerts
   */
  async startEscalation(alert: Alert, policyName: string): Promise<void> {
    const policy = this.escalationPolicies.get(policyName);
    if (!policy || !policy.enabled) {
      throw new Error(`Escalation policy '${policyName}' not found or disabled`);
    }

    const escalationId = `escalation-${alert.id}-${Date.now()}`;
    const tracker: EscalationTracker = {
      id: escalationId,
      alert,
      policy,
      currentLevel: 0,
      startTime: new Date(),
      acknowledged: false,
      completed: false,
      notifications: []
    };

    this.activeEscalations.set(escalationId, tracker);
    this.emit('escalationStarted', { escalationId, alert, policy });

    // Start first level immediately
    await this.executeEscalationLevel(tracker, 0);

    // Schedule subsequent levels
    this.scheduleNextEscalationLevel(tracker);
  }

  /**
   * Acknowledge alert and stop escalation
   */
  acknowledgeAlert(alertId: string, acknowledgedBy: string): void {
    for (const [escalationId, tracker] of this.activeEscalations) {
      if (tracker.alert.id === alertId && !tracker.acknowledged) {
        tracker.acknowledged = true;
        tracker.acknowledgedBy = acknowledgedBy;
        tracker.acknowledgedAt = new Date();
        
        this.emit('alertAcknowledged', { escalationId, alertId, acknowledgedBy });
        this.completeEscalation(escalationId);
        break;
      }
    }
  }

  /**
   * Send notification to specific channel
   */
  private async sendToChannel(alert: Alert, channelName: string): Promise<NotificationResult> {
    const channel = this.channels.get(channelName);
    if (!channel) {
      throw new Error(`Channel '${channelName}' not found`);
    }

    if (!channel.enabled) {
      throw new Error(`Channel '${channelName}' is disabled`);
    }

    const startTime = Date.now();

    try {
      let messageId: string | undefined;

      switch (channel.type) {
        case 'slack':
          messageId = await this.sendSlackNotification(alert, channel);
          break;
        case 'email':
          messageId = await this.sendEmailNotification(alert, channel);
          break;
        case 'pagerduty':
          messageId = await this.sendPagerDutyNotification(alert, channel);
          break;
        case 'sms':
          messageId = await this.sendSMSNotification(alert, channel);
          break;
        case 'webhook':
          messageId = await this.sendWebhookNotification(alert, channel);
          break;
        case 'teams':
          messageId = await this.sendTeamsNotification(alert, channel);
          break;
        case 'servicenow':
          messageId = await this.sendServiceNowNotification(alert, channel);
          break;
        default:
          throw new Error(`Unsupported channel type: ${channel.type}`);
      }

      return {
        channel: channelName,
        success: true,
        timestamp: new Date(),
        messageId
      };

    } catch (error) {
      return {
        channel: channelName,
        success: false,
        timestamp: new Date(),
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  /**
   * Send Slack notification
   */
  private async sendSlackNotification(alert: Alert, channel: NotificationChannel): Promise<string> {
    const config = channel.config.slack!;
    const template = this.getTemplate('slack', alert.severity);
    
    const message = {
      channel: config.channel,
      username: config.username || 'AI-SPM Monitor',
      icon_emoji: config.iconEmoji || this.getSeverityEmoji(alert.severity),
      attachments: [{
        color: this.getSeverityColor(alert.severity),
        title: this.formatTemplate(template.subject, alert),
        text: this.formatTemplate(template.body, alert),
        fields: [
          { title: 'Severity', value: alert.severity.toUpperCase(), short: true },
          { title: 'Component', value: alert.component, short: true },
          { title: 'Time', value: alert.timestamp.toISOString(), short: true },
          { title: 'Tags', value: alert.tags.join(', '), short: true }
        ],
        actions: [
          {
            type: 'button',
            text: 'View Dashboard',
            url: `${process.env.GRAFANA_URL}/d/ai-spm-overview`
          },
          {
            type: 'button',
            text: 'Acknowledge',
            url: `${process.env.APP_URL}/alerts/${alert.id}/acknowledge`
          }
        ],
        ts: Math.floor(alert.timestamp.getTime() / 1000)
      }]
    };

    const response = await fetch(config.webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(message)
    });

    if (!response.ok) {
      throw new Error(`Slack notification failed: ${response.status} ${response.statusText}`);
    }

    return response.headers.get('x-slack-unique-id') || `slack-${Date.now()}`;
  }

  /**
   * Send email notification
   */
  private async sendEmailNotification(alert: Alert, channel: NotificationChannel): Promise<string> {
    const config = channel.config.smtp!;
    const template = this.getTemplate('email', alert.severity);
    
    // Mock email sending - replace with actual SMTP implementation
    const messageId = `email-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    
    console.log(`Sending email notification for alert ${alert.id}:`, {
      from: config.from,
      to: config.to,
      subject: this.formatTemplate(template.subject, alert),
      body: this.formatTemplate(template.body, alert)
    });

    return messageId;
  }

  /**
   * Send PagerDuty notification
   */
  private async sendPagerDutyNotification(alert: Alert, channel: NotificationChannel): Promise<string> {
    const config = channel.config.pagerduty!;
    
    const event = {
      routing_key: config.integrationKey,
      event_action: 'trigger',
      dedup_key: `ai-spm-${alert.name}-${alert.component}`,
      payload: {
        summary: `${alert.name}: ${alert.description}`,
        severity: this.mapSeverityToPagerDuty(alert.severity),
        source: 'AI-SPM Platform',
        component: alert.component,
        group: 'ai-spm',
        class: alert.tags.includes('security') ? 'security' : 'operational',
        custom_details: {
          alert_id: alert.id,
          current_value: alert.currentValue,
          threshold: alert.threshold,
          tags: alert.tags,
          metadata: alert.metadata,
          dashboard_url: `${process.env.GRAFANA_URL}/d/ai-spm-overview`
        }
      }
    };

    const response = await fetch('https://events.pagerduty.com/v2/enqueue', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(event)
    });

    if (!response.ok) {
      throw new Error(`PagerDuty notification failed: ${response.status} ${response.statusText}`);
    }

    const result = await response.json();
    return result.dedup_key || `pagerduty-${Date.now()}`;
  }

  /**
   * Send SMS notification
   */
  private async sendSMSNotification(alert: Alert, channel: NotificationChannel): Promise<string> {
    const config = channel.config.sms!;
    const template = this.getTemplate('sms', alert.severity);
    
    const message = this.formatTemplate(template.body, alert);
    
    // Mock SMS sending - replace with actual Twilio implementation
    const messageId = `sms-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    
    console.log(`Sending SMS notification for alert ${alert.id}:`, {
      from: config.fromNumber,
      to: config.toNumbers,
      message: message.substring(0, 160) // SMS character limit
    });

    return messageId;
  }

  /**
   * Send webhook notification
   */
  private async sendWebhookNotification(alert: Alert, channel: NotificationChannel): Promise<string> {
    const config = channel.config.webhook!;
    
    const payload = {
      alert,
      timestamp: new Date().toISOString(),
      platform: 'AI-SPM',
      version: process.env.APP_VERSION || '1.0.0'
    };

    const response = await fetch(config.url, {
      method: config.method,
      headers: {
        'Content-Type': 'application/json',
        ...config.headers
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(config.timeout || 30000)
    });

    if (!response.ok) {
      throw new Error(`Webhook notification failed: ${response.status} ${response.statusText}`);
    }

    return response.headers.get('x-message-id') || `webhook-${Date.now()}`;
  }

  /**
   * Send Microsoft Teams notification
   */
  private async sendTeamsNotification(alert: Alert, channel: NotificationChannel): Promise<string> {
    const config = channel.config.teams!;
    const template = this.getTemplate('teams', alert.severity);
    
    const message = {
      "@type": "MessageCard",
      "@context": "http://schema.org/extensions",
      themeColor: this.getSeverityColorHex(alert.severity),
      summary: this.formatTemplate(template.subject, alert),
      sections: [{
        activityTitle: config.title || 'AI-SPM Alert',
        activitySubtitle: this.formatTemplate(template.subject, alert),
        activityImage: "https://via.placeholder.com/32x32/FF0000/FFFFFF?text=!",
        facts: [
          { name: "Severity", value: alert.severity.toUpperCase() },
          { name: "Component", value: alert.component },
          { name: "Time", value: alert.timestamp.toISOString() },
          { name: "Tags", value: alert.tags.join(', ') }
        ],
        markdown: true
      }],
      potentialAction: [{
        "@type": "OpenUri",
        name: "View Dashboard",
        targets: [{
          os: "default",
          uri: `${process.env.GRAFANA_URL}/d/ai-spm-overview`
        }]
      }]
    };

    const response = await fetch(config.webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(message)
    });

    if (!response.ok) {
      throw new Error(`Teams notification failed: ${response.status} ${response.statusText}`);
    }

    return `teams-${Date.now()}`;
  }

  /**
   * Send ServiceNow notification
   */
  private async sendServiceNowNotification(alert: Alert, channel: NotificationChannel): Promise<string> {
    const config = channel.config.servicenow!;
    const template = this.getTemplate('servicenow', alert.severity);
    
    const incident = {
      short_description: this.formatTemplate(template.subject, alert),
      description: this.formatTemplate(template.body, alert),
      urgency: this.mapSeverityToServiceNow(alert.severity),
      impact: this.mapSeverityToServiceNow(alert.severity),
      category: 'Software',
      subcategory: 'AI/ML Platform',
      u_component: alert.component,
      u_alert_id: alert.id,
      u_tags: alert.tags.join(',')
    };

    const auth = Buffer.from(`${config.username}:${config.password}`).toString('base64');
    
    const response = await fetch(`https://${config.instance}.service-now.com/api/now/table/${config.table}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Basic ${auth}`
      },
      body: JSON.stringify(incident)
    });

    if (!response.ok) {
      throw new Error(`ServiceNow notification failed: ${response.status} ${response.statusText}`);
    }

    const result = await response.json();
    return result.result.number || `servicenow-${Date.now()}`;
  }

  // Utility methods for formatting and mapping
  private getSeverityEmoji(severity: AlertSeverity): string {
    switch (severity) {
      case AlertSeverity.CRITICAL: return ':rotating_light:';
      case AlertSeverity.HIGH: return ':warning:';
      case AlertSeverity.MEDIUM: return ':exclamation:';
      case AlertSeverity.LOW: return ':information_source:';
      default: return ':grey_question:';
    }
  }

  private getSeverityColor(severity: AlertSeverity): string {
    switch (severity) {
      case AlertSeverity.CRITICAL: return 'danger';
      case AlertSeverity.HIGH: return 'warning';
      case AlertSeverity.MEDIUM: return 'good';
      default: return '#439FE0';
    }
  }

  private getSeverityColorHex(severity: AlertSeverity): string {
    switch (severity) {
      case AlertSeverity.CRITICAL: return '#FF0000';
      case AlertSeverity.HIGH: return '#FF8C00';
      case AlertSeverity.MEDIUM: return '#FFD700';
      default: return '#00CED1';
    }
  }

  private mapSeverityToPagerDuty(severity: AlertSeverity): string {
    switch (severity) {
      case AlertSeverity.CRITICAL: return 'critical';
      case AlertSeverity.HIGH: return 'error';
      case AlertSeverity.MEDIUM: return 'warning';
      default: return 'info';
    }
  }

  private mapSeverityToServiceNow(severity: AlertSeverity): string {
    switch (severity) {
      case AlertSeverity.CRITICAL: return '1';
      case AlertSeverity.HIGH: return '2';
      case AlertSeverity.MEDIUM: return '3';
      default: return '4';
    }
  }

  private formatTemplate(template: string, alert: Alert): string {
    return template
      .replace(/{{alert\.name}}/g, alert.name)
      .replace(/{{alert\.description}}/g, alert.description)
      .replace(/{{alert\.severity}}/g, alert.severity)
      .replace(/{{alert\.component}}/g, alert.component)
      .replace(/{{alert\.timestamp}}/g, alert.timestamp.toISOString())
      .replace(/{{alert\.tags}}/g, alert.tags.join(', '))
      .replace(/{{alert\.currentValue}}/g, alert.currentValue?.toString() || 'N/A')
      .replace(/{{alert\.threshold}}/g, alert.threshold?.toString() || 'N/A');
  }

  private getTemplate(channelType: string, severity: AlertSeverity): NotificationTemplate {
    const templateName = `${channelType}_${severity}`;
    return this.templates.get(templateName) || this.templates.get(`${channelType}_default`)!;
  }

  // Escalation handling
  private async executeEscalationLevel(tracker: EscalationTracker, level: number): Promise<void> {
    if (level >= tracker.policy.levels.length || tracker.acknowledged || tracker.completed) {
      return;
    }

    const escalationLevel = tracker.policy.levels[level];
    
    // Check conditions
    if (escalationLevel.conditions && !this.evaluateEscalationConditions(escalationLevel.conditions, tracker)) {
      return;
    }

    tracker.currentLevel = level;
    
    // Send notifications for this level
    const results = await this.sendAlert(tracker.alert, escalationLevel.channels);
    tracker.notifications.push({
      level,
      timestamp: new Date(),
      channels: escalationLevel.channels,
      results
    });

    this.emit('escalationLevelExecuted', { 
      escalationId: tracker.id, 
      level, 
      channels: escalationLevel.channels,
      results 
    });
  }

  private scheduleNextEscalationLevel(tracker: EscalationTracker): void {
    const nextLevel = tracker.currentLevel + 1;
    if (nextLevel >= tracker.policy.levels.length) {
      this.completeEscalation(tracker.id);
      return;
    }

    const escalationLevel = tracker.policy.levels[nextLevel];
    const delay = escalationLevel.delayMinutes * 60 * 1000;

    setTimeout(async () => {
      if (!tracker.acknowledged && !tracker.completed) {
        await this.executeEscalationLevel(tracker, nextLevel);
        this.scheduleNextEscalationLevel(tracker);
      }
    }, delay);
  }

  private evaluateEscalationConditions(conditions: EscalationCondition[], tracker: EscalationTracker): boolean {
    return conditions.every(condition => {
      switch (condition.type) {
        case 'severity':
          return condition.operator === 'equals' && tracker.alert.severity === condition.value;
        case 'component':
          return condition.operator === 'equals' && tracker.alert.component === condition.value;
        case 'duration':
          const duration = Date.now() - tracker.startTime.getTime();
          const minutes = duration / (1000 * 60);
          return condition.operator === 'greater_than' && minutes > condition.value;
        default:
          return true;
      }
    });
  }

  private completeEscalation(escalationId: string): void {
    const tracker = this.activeEscalations.get(escalationId);
    if (tracker) {
      tracker.completed = true;
      tracker.completedAt = new Date();
      this.emit('escalationCompleted', { escalationId, tracker });
      
      // Clean up after some time
      setTimeout(() => {
        this.activeEscalations.delete(escalationId);
      }, 3600000); // 1 hour
    }
  }

  // Initialization methods
  private initializeDefaultChannels(): void {
    // Add default channels from environment variables
    if (process.env.SLACK_WEBHOOK_URL) {
      this.channels.set('slack', {
        name: 'slack',
        type: 'slack',
        enabled: true,
        config: {
          slack: {
            webhookUrl: process.env.SLACK_WEBHOOK_URL,
            channel: process.env.SLACK_CHANNEL || '#alerts',
            username: 'AI-SPM Monitor'
          }
        }
      });
    }

    if (process.env.PAGERDUTY_INTEGRATION_KEY) {
      this.channels.set('pagerduty', {
        name: 'pagerduty',
        type: 'pagerduty',
        enabled: true,
        config: {
          pagerduty: {
            integrationKey: process.env.PAGERDUTY_INTEGRATION_KEY
          }
        }
      });
    }
  }

  private initializeDefaultTemplates(): void {
    // Slack templates
    this.templates.set('slack_critical', {
      name: 'slack_critical',
      subject: '🚨 CRITICAL: {{alert.name}}',
      body: '{{alert.description}}\n\nComponent: {{alert.component}}\nTime: {{alert.timestamp}}\nCurrent Value: {{alert.currentValue}}\nThreshold: {{alert.threshold}}',
      format: 'text'
    });

    this.templates.set('slack_default', {
      name: 'slack_default',
      subject: '⚠️ {{alert.severity.toUpperCase()}}: {{alert.name}}',
      body: '{{alert.description}}\n\nComponent: {{alert.component}}\nTime: {{alert.timestamp}}',
      format: 'text'
    });

    // Email templates
    this.templates.set('email_critical', {
      name: 'email_critical',
      subject: '[CRITICAL] AI-SPM Alert: {{alert.name}}',
      body: `CRITICAL ALERT: {{alert.name}}

Description: {{alert.description}}
Component: {{alert.component}}
Severity: {{alert.severity}}
Time: {{alert.timestamp}}
Tags: {{alert.tags}}

Current Value: {{alert.currentValue}}
Threshold: {{alert.threshold}}

Please investigate immediately.

Dashboard: ${process.env.GRAFANA_URL}/d/ai-spm-overview`,
      format: 'text'
    });

    // SMS templates
    this.templates.set('sms_critical', {
      name: 'sms_critical',
      subject: 'CRITICAL AI-SPM Alert',
      body: 'CRITICAL: {{alert.name}} - {{alert.component}}. Check dashboard immediately.',
      format: 'text'
    });
  }

  private initializeDefaultEscalationPolicies(): void {
    this.escalationPolicies.set('critical', {
      name: 'critical',
      enabled: true,
      levels: [
        {
          level: 1,
          delayMinutes: 0,
          channels: ['slack', 'pagerduty'],
          conditions: [{ type: 'severity', operator: 'equals', value: AlertSeverity.CRITICAL }]
        },
        {
          level: 2,
          delayMinutes: 5,
          channels: ['slack', 'pagerduty', 'sms'],
          conditions: [{ type: 'duration', operator: 'greater_than', value: 5 }]
        },
        {
          level: 3,
          delayMinutes: 15,
          channels: ['slack', 'pagerduty', 'sms', 'email'],
          conditions: [{ type: 'duration', operator: 'greater_than', value: 15 }]
        }
      ]
    });
  }

  // Public management methods
  public addChannel(channel: NotificationChannel): void {
    this.channels.set(channel.name, channel);
    this.emit('channelAdded', channel);
  }

  public removeChannel(name: string): void {
    this.channels.delete(name);
    this.emit('channelRemoved', name);
  }

  public getChannels(): NotificationChannel[] {
    return Array.from(this.channels.values());
  }

  public addEscalationPolicy(policy: EscalationPolicy): void {
    this.escalationPolicies.set(policy.name, policy);
    this.emit('escalationPolicyAdded', policy);
  }

  public getActiveEscalations(): EscalationTracker[] {
    return Array.from(this.activeEscalations.values());
  }
}

// Supporting interfaces
interface EscalationTracker {
  id: string;
  alert: Alert;
  policy: EscalationPolicy;
  currentLevel: number;
  startTime: Date;
  acknowledged: boolean;
  acknowledgedBy?: string;
  acknowledgedAt?: Date;
  completed: boolean;
  completedAt?: Date;
  notifications: EscalationNotification[];
}

interface EscalationNotification {
  level: number;
  timestamp: Date;
  channels: string[];
  results: NotificationResult[];
}