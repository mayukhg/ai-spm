/**
 * Multi-Channel Notification Manager
 * Handles alerts and notifications across multiple channels with escalation policies
 */

import { logger, SecurityEventType } from './logger';
import { metrics } from './metrics-collector';

export interface NotificationChannel {
  name: string;
  type: 'slack' | 'email' | 'pagerduty' | 'webhook' | 'sms' | 'teams';
  enabled: boolean;
  config: Record<string, any>;
  priority: number; // 1 = highest priority
}

export interface Alert {
  id: string;
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  message: string;
  source: string;
  timestamp: string;
  metadata?: Record<string, any>;
  escalationLevel?: number;
  acknowledgedBy?: string;
  acknowledgedAt?: string;
}

export interface EscalationPolicy {
  name: string;
  severity: string[];
  levels: {
    level: number;
    waitTimeMinutes: number;
    channels: string[];
    recipients: string[];
  }[];
}

class NotificationManager {
  private channels: Map<string, NotificationChannel> = new Map();
  private escalationPolicies: Map<string, EscalationPolicy> = new Map();
  private activeAlerts: Map<string, Alert> = new Map();
  private escalationTimers: Map<string, NodeJS.Timeout> = new Map();

  constructor() {
    this.setupDefaultChannels();
    this.setupDefaultEscalationPolicies();
  }

  private setupDefaultChannels() {
    // Slack channel
    if (process.env.SLACK_WEBHOOK_URL) {
      this.channels.set('slack', {
        name: 'slack',
        type: 'slack',
        enabled: true,
        config: {
          webhookUrl: process.env.SLACK_WEBHOOK_URL,
          channel: process.env.SLACK_CHANNEL || '#security-alerts',
          username: 'AI-SPM Platform'
        },
        priority: 1
      });
    }

    // Email channel
    if (process.env.SMTP_HOST) {
      this.channels.set('email', {
        name: 'email',
        type: 'email',
        enabled: true,
        config: {
          host: process.env.SMTP_HOST,
          port: process.env.SMTP_PORT || 587,
          secure: process.env.SMTP_SECURE === 'true',
          auth: {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASSWORD
          },
          from: process.env.SMTP_FROM || 'noreply@ai-spm.com'
        },
        priority: 2
      });
    }

    // PagerDuty channel
    if (process.env.PAGERDUTY_INTEGRATION_KEY) {
      this.channels.set('pagerduty', {
        name: 'pagerduty',
        type: 'pagerduty',
        enabled: true,
        config: {
          integrationKey: process.env.PAGERDUTY_INTEGRATION_KEY,
          apiUrl: 'https://events.pagerduty.com/v2/enqueue'
        },
        priority: 1
      });
    }

    // Microsoft Teams channel
    if (process.env.TEAMS_WEBHOOK_URL) {
      this.channels.set('teams', {
        name: 'teams',
        type: 'teams',
        enabled: true,
        config: {
          webhookUrl: process.env.TEAMS_WEBHOOK_URL
        },
        priority: 2
      });
    }

    // Generic webhook channel
    if (process.env.WEBHOOK_URL) {
      this.channels.set('webhook', {
        name: 'webhook',
        type: 'webhook',
        enabled: true,
        config: {
          url: process.env.WEBHOOK_URL,
          headers: {
            'Content-Type': 'application/json',
            'Authorization': process.env.WEBHOOK_AUTH_HEADER
          }
        },
        priority: 3
      });
    }
  }

  private setupDefaultEscalationPolicies() {
    // Critical alerts escalation
    this.escalationPolicies.set('critical', {
      name: 'critical',
      severity: ['critical'],
      levels: [
        {
          level: 1,
          waitTimeMinutes: 0,
          channels: ['slack', 'pagerduty'],
          recipients: ['security_team', 'on_call_engineer']
        },
        {
          level: 2,
          waitTimeMinutes: 5,
          channels: ['email', 'pagerduty'],
          recipients: ['security_team', 'ciso', 'engineering_manager']
        },
        {
          level: 3,
          waitTimeMinutes: 15,
          channels: ['pagerduty', 'email'],
          recipients: ['ciso', 'cto', 'incident_commander']
        }
      ]
    });

    // High severity alerts escalation
    this.escalationPolicies.set('high', {
      name: 'high',
      severity: ['high'],
      levels: [
        {
          level: 1,
          waitTimeMinutes: 0,
          channels: ['slack'],
          recipients: ['security_team']
        },
        {
          level: 2,
          waitTimeMinutes: 15,
          channels: ['email', 'slack'],
          recipients: ['security_team', 'engineering_manager']
        },
        {
          level: 3,
          waitTimeMinutes: 60,
          channels: ['email'],
          recipients: ['ciso']
        }
      ]
    });

    // Medium and low severity alerts
    this.escalationPolicies.set('standard', {
      name: 'standard',
      severity: ['medium', 'low'],
      levels: [
        {
          level: 1,
          waitTimeMinutes: 0,
          channels: ['slack'],
          recipients: ['security_team']
        },
        {
          level: 2,
          waitTimeMinutes: 120,
          channels: ['email'],
          recipients: ['security_team']
        }
      ]
    });
  }

  async sendAlert(alert: Alert): Promise<void> {
    try {
      // Store alert
      this.activeAlerts.set(alert.id, alert);

      // Determine escalation policy
      const policy = this.getEscalationPolicy(alert.severity);
      if (!policy) {
        logger.warn(`No escalation policy found for severity: ${alert.severity}`);
        return;
      }

      // Start escalation process
      await this.startEscalation(alert, policy);

      // Log alert
      logger.security(SecurityEventType.SYSTEM_SECURITY, `Alert generated: ${alert.title}`, {
        alertId: alert.id,
        severity: alert.severity,
        source: alert.source,
        type: alert.type
      });

      // Record metrics
      metrics.recordAlert(alert.type, alert.severity, 'multiple');

    } catch (error) {
      logger.error('Failed to send alert', error, { alertId: alert.id });
    }
  }

  private async startEscalation(alert: Alert, policy: EscalationPolicy): Promise<void> {
    // Send immediate notifications (level 1)
    await this.sendNotifications(alert, policy.levels[0]);

    // Schedule escalations for subsequent levels
    policy.levels.slice(1).forEach((level, index) => {
      const timeoutMs = level.waitTimeMinutes * 60 * 1000;
      const timer = setTimeout(async () => {
        // Check if alert is still active and not acknowledged
        const currentAlert = this.activeAlerts.get(alert.id);
        if (currentAlert && !currentAlert.acknowledgedBy) {
          await this.sendNotifications(alert, level);
          
          logger.info(`Alert escalated to level ${level.level}`, {
            alertId: alert.id,
            escalationLevel: level.level
          });
        }
      }, timeoutMs);

      this.escalationTimers.set(`${alert.id}-${level.level}`, timer);
    });
  }

  private async sendNotifications(alert: Alert, escalationLevel: any): Promise<void> {
    const notifications = escalationLevel.channels.map(async (channelName: string) => {
      const channel = this.channels.get(channelName);
      if (!channel || !channel.enabled) {
        logger.warn(`Channel not available: ${channelName}`);
        return;
      }

      try {
        await this.sendToChannel(alert, channel);
        logger.debug(`Alert sent to ${channelName}`, { alertId: alert.id });
      } catch (error) {
        logger.error(`Failed to send alert to ${channelName}`, error, { 
          alertId: alert.id,
          channel: channelName 
        });
      }
    });

    await Promise.allSettled(notifications);
  }

  private async sendToChannel(alert: Alert, channel: NotificationChannel): Promise<void> {
    switch (channel.type) {
      case 'slack':
        await this.sendSlackNotification(alert, channel);
        break;
      case 'email':
        await this.sendEmailNotification(alert, channel);
        break;
      case 'pagerduty':
        await this.sendPagerDutyNotification(alert, channel);
        break;
      case 'teams':
        await this.sendTeamsNotification(alert, channel);
        break;
      case 'webhook':
        await this.sendWebhookNotification(alert, channel);
        break;
      default:
        logger.warn(`Unsupported channel type: ${channel.type}`);
    }
  }

  private async sendSlackNotification(alert: Alert, channel: NotificationChannel): Promise<void> {
    const color = this.getSeverityColor(alert.severity);
    const payload = {
      channel: channel.config.channel,
      username: channel.config.username,
      attachments: [{
        color,
        title: `🚨 ${alert.title}`,
        text: alert.message,
        fields: [
          {
            title: 'Severity',
            value: alert.severity.toUpperCase(),
            short: true
          },
          {
            title: 'Source',
            value: alert.source,
            short: true
          },
          {
            title: 'Time',
            value: new Date(alert.timestamp).toLocaleString(),
            short: true
          },
          {
            title: 'Alert ID',
            value: alert.id,
            short: true
          }
        ],
        footer: 'AI-SPM Platform',
        ts: Math.floor(new Date(alert.timestamp).getTime() / 1000)
      }]
    };

    const response = await fetch(channel.config.webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      throw new Error(`Slack API error: ${response.status}`);
    }
  }

  private async sendEmailNotification(alert: Alert, channel: NotificationChannel): Promise<void> {
    // This would require a proper email client setup (nodemailer)
    // For now, log the email content
    logger.info('Email notification would be sent', {
      to: channel.config.recipients,
      subject: `[${alert.severity.toUpperCase()}] ${alert.title}`,
      body: alert.message,
      alertId: alert.id
    });
  }

  private async sendPagerDutyNotification(alert: Alert, channel: NotificationChannel): Promise<void> {
    const payload = {
      routing_key: channel.config.integrationKey,
      event_action: 'trigger',
      dedup_key: alert.id,
      payload: {
        summary: alert.title,
        source: alert.source,
        severity: alert.severity,
        timestamp: alert.timestamp,
        custom_details: {
          message: alert.message,
          alert_type: alert.type,
          metadata: alert.metadata
        }
      }
    };

    const response = await fetch(channel.config.apiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      throw new Error(`PagerDuty API error: ${response.status}`);
    }
  }

  private async sendTeamsNotification(alert: Alert, channel: NotificationChannel): Promise<void> {
    const color = this.getSeverityColor(alert.severity);
    const payload = {
      '@type': 'MessageCard',
      '@context': 'http://schema.org/extensions',
      themeColor: color,
      summary: alert.title,
      sections: [{
        activityTitle: `🚨 ${alert.title}`,
        activitySubtitle: `Severity: ${alert.severity.toUpperCase()}`,
        text: alert.message,
        facts: [
          { name: 'Source', value: alert.source },
          { name: 'Alert ID', value: alert.id },
          { name: 'Time', value: new Date(alert.timestamp).toLocaleString() }
        ]
      }]
    };

    const response = await fetch(channel.config.webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      throw new Error(`Teams webhook error: ${response.status}`);
    }
  }

  private async sendWebhookNotification(alert: Alert, channel: NotificationChannel): Promise<void> {
    const payload = {
      alert,
      timestamp: new Date().toISOString(),
      platform: 'ai-spm'
    };

    const response = await fetch(channel.config.url, {
      method: 'POST',
      headers: channel.config.headers,
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      throw new Error(`Webhook error: ${response.status}`);
    }
  }

  async acknowledgeAlert(alertId: string, acknowledgedBy: string): Promise<void> {
    const alert = this.activeAlerts.get(alertId);
    if (!alert) {
      throw new Error(`Alert not found: ${alertId}`);
    }

    alert.acknowledgedBy = acknowledgedBy;
    alert.acknowledgedAt = new Date().toISOString();

    // Cancel escalation timers
    this.cancelEscalation(alertId);

    // Log acknowledgment
    logger.audit('alert_acknowledged', `alert:${alertId}`, {
      alertId,
      acknowledgedBy,
      severity: alert.severity,
      source: alert.source
    });

    // Record metrics
    const responseTime = new Date().getTime() - new Date(alert.timestamp).getTime();
    metrics.recordAlertAcknowledgment(alert.type, alert.severity, responseTime);
  }

  async resolveAlert(alertId: string, resolvedBy: string): Promise<void> {
    const alert = this.activeAlerts.get(alertId);
    if (!alert) {
      throw new Error(`Alert not found: ${alertId}`);
    }

    // Remove from active alerts
    this.activeAlerts.delete(alertId);

    // Cancel escalation timers
    this.cancelEscalation(alertId);

    // Log resolution
    logger.audit('alert_resolved', `alert:${alertId}`, {
      alertId,
      resolvedBy,
      severity: alert.severity,
      source: alert.source
    });

    logger.info(`Alert resolved: ${alert.title}`, {
      alertId,
      resolvedBy,
      severity: alert.severity
    });
  }

  private cancelEscalation(alertId: string): void {
    // Find and clear all timers for this alert
    for (const [key, timer] of this.escalationTimers.entries()) {
      if (key.startsWith(alertId)) {
        clearTimeout(timer);
        this.escalationTimers.delete(key);
      }
    }
  }

  private getEscalationPolicy(severity: string): EscalationPolicy | undefined {
    if (severity === 'critical') {
      return this.escalationPolicies.get('critical');
    } else if (severity === 'high') {
      return this.escalationPolicies.get('high');
    } else {
      return this.escalationPolicies.get('standard');
    }
  }

  private getSeverityColor(severity: string): string {
    switch (severity) {
      case 'critical': return '#ff0000';
      case 'high': return '#ff8c00';
      case 'medium': return '#ffd700';
      case 'low': return '#90ee90';
      default: return '#808080';
    }
  }

  // Test notification channels
  async testChannel(channelName: string): Promise<boolean> {
    const channel = this.channels.get(channelName);
    if (!channel) {
      throw new Error(`Channel not found: ${channelName}`);
    }

    const testAlert: Alert = {
      id: `test-${Date.now()}`,
      type: 'test',
      severity: 'low',
      title: 'Test Notification',
      message: 'This is a test notification from AI-SPM Platform',
      source: 'notification-manager',
      timestamp: new Date().toISOString()
    };

    try {
      await this.sendToChannel(testAlert, channel);
      logger.info(`Test notification sent successfully to ${channelName}`);
      return true;
    } catch (error) {
      logger.error(`Test notification failed for ${channelName}`, error);
      return false;
    }
  }

  // Get active alerts
  getActiveAlerts(): Alert[] {
    return Array.from(this.activeAlerts.values());
  }

  // Get channels status
  getChannelsStatus(): { name: string; enabled: boolean; type: string }[] {
    return Array.from(this.channels.values()).map(channel => ({
      name: channel.name,
      enabled: channel.enabled,
      type: channel.type
    }));
  }

  // Create quick alert helpers
  async createThreatAlert(threatType: string, severity: 'critical' | 'high' | 'medium', details: any): Promise<void> {
    const alert: Alert = {
      id: `threat-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      type: 'ai_threat_detection',
      severity,
      title: `AI Threat Detected: ${threatType}`,
      message: `A ${severity} severity ${threatType} threat has been detected. Immediate attention required.`,
      source: 'ai-threat-detection',
      timestamp: new Date().toISOString(),
      metadata: details
    };

    await this.sendAlert(alert);
  }

  async createSystemAlert(component: string, issue: string, severity: 'critical' | 'high' | 'medium'): Promise<void> {
    const alert: Alert = {
      id: `system-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      type: 'system_health',
      severity,
      title: `System Issue: ${component}`,
      message: `${component} is experiencing issues: ${issue}`,
      source: 'health-monitor',
      timestamp: new Date().toISOString(),
      metadata: { component, issue }
    };

    await this.sendAlert(alert);
  }
}

// Export singleton instance
export const notificationManager = new NotificationManager();