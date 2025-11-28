/**
 * Mailbox Monitor
 * Monitors phishing mailbox for new emails and triggers analysis
 * Refactored to use email-processor and email-reply-builder modules
 */

import { Client } from '@microsoft/microsoft-graph-client';
import pLimit from 'p-limit';
import { securityLogger } from '../lib/logger.js';
import { PhishingAgent } from '../agents/phishing-agent.js';
import { GraphEmail, GraphEmailListResponse } from '../lib/schemas.js';
import { validateGraphEmailListResponse } from './graph-email-parser.js';
import { RateLimiter, RateLimiterConfig } from './rate-limiter.js';
import { EmailDeduplication, DeduplicationConfig } from './email-deduplication.js';
import { processEmail } from './email-processor.js';
import { createGraphClient, AzureAuthMethod } from './azure-auth.js';

export type { AzureAuthMethod };

export interface MailboxMonitorConfig {
  tenantId: string;
  clientId: string;
  clientSecret?: string; // Optional when using managed identity
  authMethod?: AzureAuthMethod; // Defaults based on environment
  mailboxAddress: string;
  checkIntervalMs?: number;
  enabled?: boolean;
  rateLimiter?: RateLimiterConfig;
  deduplication?: DeduplicationConfig;
  maxPages?: number; // Max pagination pages (default: 5)
  parallelLimit?: number; // Parallel processing limit (default: 5)
}

export class MailboxMonitor {
  private client: Client;
  private config: MailboxMonitorConfig;
  private phishingAgent: PhishingAgent;
  private checkInterval: NodeJS.Timeout | null = null;
  private lastCheckTime: Date;
  private isRunning: boolean = false;
  private rateLimiter: RateLimiter;
  private deduplication: EmailDeduplication;

  constructor(config: MailboxMonitorConfig, phishingAgent: PhishingAgent) {
    this.config = { checkIntervalMs: 60000, enabled: true, ...config };
    this.phishingAgent = phishingAgent;
    this.lastCheckTime = new Date(Date.now() - 5 * 60 * 1000);
    this.client = createGraphClient({
      tenantId: config.tenantId,
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      authMethod: config.authMethod,
    });

    this.rateLimiter = new RateLimiter(
      config.rateLimiter || {
        enabled: true,
        maxEmailsPerHour: 100,
        maxEmailsPerDay: 1000,
        circuitBreakerThreshold: 50,
        circuitBreakerWindowMs: 600000,
      }
    );

    this.deduplication = new EmailDeduplication(
      config.deduplication || {
        enabled: true,
        contentHashTtlMs: 86400000,
        senderCooldownMs: 86400000,
      }
    );
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
    } catch (error: unknown) {
      const msg = error instanceof Error ? error.message : 'Unknown error';
      securityLogger.error('Mailbox monitor initialization failed', { error: msg });
      throw new Error(`Mailbox monitor initialization failed: ${msg}`);
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

    // Use .unref() to allow process to exit cleanly during tests
    this.checkInterval = setInterval(() => {
      this.checkForNewEmails().catch((error) => {
        securityLogger.error('Periodic mailbox check failed', { error });
      });
    }, this.config.checkIntervalMs).unref();

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
    } catch (error: unknown) {
      const msg = error instanceof Error ? error.message : 'Unknown error';
      securityLogger.error('Failed to check for new emails', { error: msg });
      throw error;
    }
  }

  /**
   * Fetch new emails from mailbox with pagination support
   * Handles @odata.nextLink for large result sets
   */
  private async fetchNewEmails(sinceDate: string): Promise<GraphEmail[]> {
    const allEmails: GraphEmail[] = [];
    const maxPages = this.config.maxPages || 5;
    let pageCount = 0;
    let nextLink: string | undefined = undefined;

    do {
      const response = await this.fetchEmailPage(sinceDate, nextLink);
      const validatedEmails = validateGraphEmailListResponse(response);
      allEmails.push(...validatedEmails);
      nextLink = (response as GraphEmailListResponse)['@odata.nextLink'];
      pageCount++;
      if (nextLink) {
        securityLogger.debug('Fetching next page of emails', {
          pageCount,
          maxPages,
          emailsSoFar: allEmails.length,
        });
      }
    } while (nextLink && pageCount < maxPages);

    if (nextLink && pageCount >= maxPages) {
      securityLogger.warn('Pagination limit reached - some emails may not be fetched', {
        pageCount,
        maxPages,
        totalFetched: allEmails.length,
      });
    }
    return allEmails;
  }

  private async fetchEmailPage(
    sinceDate: string,
    nextLink?: string
  ): Promise<GraphEmailListResponse> {
    if (nextLink) {
      return this.client.api(nextLink).get();
    }
    return this.client
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
  }

  /**
   * Process multiple emails with bounded parallelism
   * Uses p-limit to prevent overwhelming downstream services
   */
  private async processEmails(emails: GraphEmail[]): Promise<void> {
    const parallelLimit = this.config.parallelLimit || 5;
    const limit = pLimit(parallelLimit);
    securityLogger.debug('Processing emails with parallel limit', {
      emailCount: emails.length,
      parallelLimit,
    });

    const tasks = emails.map((email) =>
      limit(() =>
        processEmail(email, {
          mailboxAddress: this.config.mailboxAddress,
          graphClient: this.client,
          phishingAgent: this.phishingAgent,
          rateLimiter: this.rateLimiter,
          deduplication: this.deduplication,
        }).catch((error: unknown) => {
          const msg = error instanceof Error ? error.message : 'Unknown error';
          securityLogger.error('Failed to process email', {
            emailId: email.id,
            subject: email.subject,
            error: msg,
          });
        })
      )
    );
    await Promise.all(tasks);
  }

  /**
   * Get monitoring status
   */
  getStatus(): {
    isRunning: boolean;
    mailbox: string;
    lastCheckTime: Date;
    checkInterval: number;
    rateLimitStats: ReturnType<RateLimiter['getStats']>;
    deduplicationStats: ReturnType<EmailDeduplication['getStats']>;
  } {
    return {
      isRunning: this.isRunning,
      mailbox: this.config.mailboxAddress,
      lastCheckTime: this.lastCheckTime,
      checkInterval: this.config.checkIntervalMs!,
      rateLimitStats: this.rateLimiter.getStats(),
      deduplicationStats: this.deduplication.getStats(),
    };
  }

  /**
   * Get rate limiter instance
   */
  getRateLimiter(): RateLimiter {
    return this.rateLimiter;
  }

  /**
   * Get deduplication instance
   */
  getDeduplication(): EmailDeduplication {
    return this.deduplication;
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
