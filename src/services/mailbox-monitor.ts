/**
 * Mailbox Monitor
 * Monitors phishing mailbox for new emails and triggers analysis
 * All functions are atomic (max 25 lines)
 */

import { Client } from '@microsoft/microsoft-graph-client';
import { ClientSecretCredential } from '@azure/identity';
import 'isomorphic-fetch';
import { securityLogger } from '../lib/logger.js';
import { PhishingAgent } from '../agents/phishing-agent.js';
import { PhishingAnalysisResult } from '../lib/types.js';
import { parseGraphEmail } from './graph-email-parser.js';

export interface MailboxMonitorConfig {
  tenantId: string;
  clientId: string;
  clientSecret: string;
  mailboxAddress: string;
  checkIntervalMs?: number;
  enabled?: boolean;
}

export class MailboxMonitor {
  private client: Client;
  private config: MailboxMonitorConfig;
  private phishingAgent: PhishingAgent;
  private checkInterval: NodeJS.Timeout | null = null;
  private lastCheckTime: Date;
  private isRunning: boolean = false;

  constructor(config: MailboxMonitorConfig, phishingAgent: PhishingAgent) {
    this.config = { checkIntervalMs: 60000, enabled: true, ...config };
    this.phishingAgent = phishingAgent;
    this.lastCheckTime = new Date(Date.now() - 5 * 60 * 1000);
    this.client = this.createGraphClient(config);
  }

  /**
   * Create Graph API client
   */
  private createGraphClient(config: MailboxMonitorConfig): Client {
    const credential = new ClientSecretCredential(
      config.tenantId,
      config.clientId,
      config.clientSecret
    );

    return Client.initWithMiddleware({
      authProvider: {
        getAccessToken: async () => {
          const token = await credential.getToken('https://graph.microsoft.com/.default');
          return token?.token || '';
        },
      },
    });
  }

  /**
   * Initialize and verify mailbox access
   */
  async initialize(): Promise<void> {
    securityLogger.info('Initializing mailbox monitor', {
      mailbox: this.config.mailboxAddress,
      checkInterval: this.config.checkIntervalMs,
    });

    try {
      await this.client.api(`/users/${this.config.mailboxAddress}/messages`).top(1).get();
      securityLogger.info('Mailbox monitor initialized successfully');
    } catch (error: any) {
      securityLogger.error('Mailbox monitor initialization failed', { error: error.message });
      throw new Error(`Mailbox monitor initialization failed: ${error.message}`);
    }
  }

  /**
   * Start monitoring
   */
  start(): void {
    if (this.isRunning || !this.config.enabled) {
      securityLogger.warn('Mailbox monitor already running or disabled');
      return;
    }

    securityLogger.info('Starting mailbox monitor', {
      mailbox: this.config.mailboxAddress,
      checkInterval: this.config.checkIntervalMs,
    });

    this.isRunning = true;
    this.checkForNewEmails().catch((error) => {
      securityLogger.error('Initial mailbox check failed', { error });
    });

    this.checkInterval = setInterval(() => {
      this.checkForNewEmails().catch((error) => {
        securityLogger.error('Periodic mailbox check failed', { error });
      });
    }, this.config.checkIntervalMs);

    securityLogger.info('Mailbox monitor started successfully');
  }

  /**
   * Stop monitoring
   */
  stop(): void {
    if (!this.isRunning) return;

    securityLogger.info('Stopping mailbox monitor');
    if (this.checkInterval) clearInterval(this.checkInterval);
    this.isRunning = false;
    securityLogger.info('Mailbox monitor stopped');
  }

  /**
   * Check for new emails
   */
  private async checkForNewEmails(): Promise<void> {
    const checkTime = new Date();
    const filterDate = this.lastCheckTime.toISOString();

    securityLogger.debug('Checking mailbox for new emails', {
      mailbox: this.config.mailboxAddress,
      since: filterDate,
    });

    try {
      const emails = await this.fetchNewEmails(filterDate);

      if (emails.length === 0) {
        securityLogger.debug('No new emails found');
        this.lastCheckTime = checkTime;
        return;
      }

      securityLogger.info('Found new emails to analyze', { count: emails.length });
      await this.processEmails(emails);
      this.lastCheckTime = checkTime;
    } catch (error: any) {
      securityLogger.error('Failed to check for new emails', { error: error.message });
      throw error;
    }
  }

  /**
   * Fetch new emails from mailbox
   */
  private async fetchNewEmails(sinceDate: string): Promise<any[]> {
    const response = await this.client
      .api(`/users/${this.config.mailboxAddress}/messages`)
      .filter(`receivedDateTime ge ${sinceDate}`)
      .orderby('receivedDateTime asc')
      .top(50)
      .select(
        'id,subject,from,toRecipients,receivedDateTime,sentDateTime,' +
        'internetMessageId,internetMessageHeaders,body,hasAttachments'
      )
      .expand('attachments($select=name,contentType,size)')
      .get();

    return response.value || [];
  }

  /**
   * Process multiple emails
   */
  private async processEmails(emails: any[]): Promise<void> {
    for (const email of emails) {
      await this.processEmail(email).catch((error) => {
        securityLogger.error('Failed to process email', {
          emailId: email.id,
          subject: email.subject,
          error: error.message,
        });
      });
    }
  }

  /**
   * Process single email
   */
  private async processEmail(graphEmail: any): Promise<void> {
    const processingId = `process-${Date.now()}-${Math.random().toString(36).substring(7)}`;

    securityLogger.info('Processing email from mailbox', {
      processingId,
      emailId: graphEmail.id,
      subject: graphEmail.subject,
      from: graphEmail.from?.emailAddress?.address,
    });

    try {
      const analysisRequest = parseGraphEmail(graphEmail);
      const analysisResult = await this.phishingAgent.analyzeEmail(analysisRequest);

      securityLogger.security('Email analyzed via mailbox monitor', {
        processingId,
        messageId: analysisResult.messageId,
        isPhishing: analysisResult.isPhishing,
        riskScore: analysisResult.riskScore,
        severity: analysisResult.severity,
      });

      await this.sendReply(graphEmail, analysisResult, processingId);
      securityLogger.info('Email processing completed successfully', { processingId });
    } catch (error: any) {
      securityLogger.error('Failed to process email', { processingId, error: error.message });
      await this.sendErrorReply(graphEmail, processingId).catch((replyError) => {
        securityLogger.error('Failed to send error reply', { processingId, error: replyError.message });
      });
    }
  }

  /**
   * Send analysis reply
   */
  private async sendReply(
    originalEmail: any,
    analysis: PhishingAnalysisResult,
    processingId: string
  ): Promise<void> {
    const senderEmail = originalEmail.from?.emailAddress?.address;
    if (!senderEmail) {
      securityLogger.warn('Cannot send reply - no sender email', { processingId });
      return;
    }

    const htmlBody = this.buildReplyHtml(analysis);
    const replyMessage = this.createReplyMessage(originalEmail, htmlBody, analysis.isPhishing);

    try {
      await this.client.api(`/users/${this.config.mailboxAddress}/sendMail`).post(replyMessage);
      securityLogger.info('Analysis reply sent', {
        processingId,
        recipient: senderEmail,
        isPhishing: analysis.isPhishing,
        riskScore: analysis.riskScore,
      });
    } catch (error: any) {
      securityLogger.error('Failed to send analysis reply', { processingId, error: error.message });
      throw error;
    }
  }

  /**
   * Build HTML reply body
   */
  private buildReplyHtml(analysis: PhishingAnalysisResult): string {
    const verdict = analysis.isPhishing ? '🚨 PHISHING DETECTED' : '✅ EMAIL APPEARS SAFE';
    const color = analysis.isPhishing ? '#D32F2F' : '#388E3C';
    const indicatorsList = this.buildIndicatorsList(analysis);
    const actionsList = this.buildActionsList(analysis);

    return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif; line-height: 1.6; color: #333; }
    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
    .header { background-color: ${color}; color: white; padding: 20px; border-radius: 8px 8px 0 0; }
    .header h1 { margin: 0; font-size: 24px; }
    .content { background-color: #f5f5f5; padding: 20px; border-radius: 0 0 8px 8px; }
    .section { margin-bottom: 20px; }
    .section h2 { color: #1976D2; font-size: 18px; margin-bottom: 10px; }
    table { width: 100%; border-collapse: collapse; }
    td { padding: 8px 0; }
    td:first-child { font-weight: 600; width: 150px; }
    pre { background-color: #fff; padding: 10px; border-left: 3px solid #1976D2; overflow-x: auto; font-size: 11px; }
    .footer { margin-top: 20px; padding-top: 20px; border-top: 1px solid #ddd; font-size: 12px; color: #666; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header"><h1>${verdict}</h1></div>
    <div class="content">
      <div class="section">
        <h2>Risk Assessment</h2>
        <table>
          <tr><td>Risk Score:</td><td>${analysis.riskScore.toFixed(1)}/10</td></tr>
          <tr><td>Severity:</td><td>${analysis.severity.toUpperCase()}</td></tr>
          <tr><td>Confidence:</td><td>${(analysis.confidence * 100).toFixed(0)}%</td></tr>
          <tr><td>Analysis ID:</td><td>${analysis.analysisId}</td></tr>
        </table>
      </div>
      ${analysis.isPhishing && analysis.indicators.length > 0 ? `<div class="section"><h2>Threat Indicators</h2><pre>${indicatorsList}</pre></div>` : ''}
      ${analysis.recommendedActions.length > 0 ? `<div class="section"><h2>Recommended Actions</h2><pre>${actionsList}</pre></div>` : ''}
      <div class="section">
        <h2>What to Do</h2>
        ${analysis.isPhishing ? '<p><strong>⚠️ Do NOT click any links or provide credentials.</strong></p>' : '<p>This email appears legitimate. However, always remain vigilant.</p>'}
      </div>
      <div class="footer">
        <p><strong>Phishing Agent</strong> | Analyzed at ${new Date(analysis.analysisTimestamp).toLocaleString()}</p>
      </div>
    </div>
  </div>
</body>
</html>`;
  }

  /**
   * Build indicators list
   */
  private buildIndicatorsList(analysis: PhishingAnalysisResult): string {
    return analysis.indicators
      .slice(0, 5)
      .map((ind) => `  • ${ind.description}`)
      .join('\n');
  }

  /**
   * Build actions list
   */
  private buildActionsList(analysis: PhishingAnalysisResult): string {
    return analysis.recommendedActions
      .slice(0, 3)
      .map((action) => {
        const icon = action.priority === 'urgent' ? '🔴' : action.priority === 'high' ? '🟡' : '🟢';
        return `  ${icon} ${action.description}`;
      })
      .join('\n');
  }

  /**
   * Create reply message
   */
  private createReplyMessage(originalEmail: any, htmlBody: string, isPhishing: boolean): any {
    const subject = originalEmail.subject || '(No Subject)';
    const senderEmail = originalEmail.from?.emailAddress?.address;

    return {
      message: {
        subject: `Re: ${subject}`,
        body: { contentType: 'HTML', content: htmlBody },
        toRecipients: [{ emailAddress: { address: senderEmail } }],
        importance: isPhishing ? 'high' : 'normal',
      },
    };
  }

  /**
   * Send error reply
   */
  private async sendErrorReply(originalEmail: any, processingId: string): Promise<void> {
    const senderEmail = originalEmail.from?.emailAddress?.address;
    if (!senderEmail) return;

    const errorHtml = `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><style>body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; } .container { max-width: 600px; margin: 0 auto; padding: 20px; } .error-box { background-color: #FFF3E0; border-left: 4px solid #FF9800; padding: 20px; }</style></head>
<body>
  <div class="container">
    <div class="error-box">
      <h2>⚠️ Analysis Error</h2>
      <p>We encountered an error while analyzing your email. The security team has been notified.</p>
      <p><strong>Processing ID:</strong> ${processingId}</p>
    </div>
  </div>
</body>
</html>`;

    const subject = originalEmail.subject || '(No Subject)';

    await this.client.api(`/users/${this.config.mailboxAddress}/sendMail`).post({
      message: {
        subject: `Re: ${subject}`,
        body: { contentType: 'HTML', content: errorHtml },
        toRecipients: [{ emailAddress: { address: senderEmail } }],
      },
    });

    securityLogger.info('Error reply sent', { processingId, recipient: senderEmail });
  }

  /**
   * Get monitoring status
   */
  getStatus(): { isRunning: boolean; mailbox: string; lastCheckTime: Date; checkInterval: number } {
    return {
      isRunning: this.isRunning,
      mailbox: this.config.mailboxAddress,
      lastCheckTime: this.lastCheckTime,
      checkInterval: this.config.checkIntervalMs!,
    };
  }

  /**
   * Health check
   */
  async healthCheck(): Promise<boolean> {
    try {
      await this.client.api(`/users/${this.config.mailboxAddress}/messages`).top(1).get();
      return true;
    } catch (error) {
      securityLogger.error('Mailbox monitor health check failed', { error });
      return false;
    }
  }
}
