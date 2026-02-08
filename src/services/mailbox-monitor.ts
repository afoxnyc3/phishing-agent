/** Mailbox Monitor - Monitors phishing mailbox for new emails and triggers analysis */

import { Client } from '@microsoft/microsoft-graph-client';
import pLimit from 'p-limit';
import { securityLogger } from '../lib/logger.js';
import { PhishingAgent } from '../agents/phishing-agent.js';
import { GraphEmail } from '../lib/schemas.js';
import { fetchNewEmails } from './email-fetcher.js';
import { createRateLimiter, IRateLimiter, RateLimiterConfig, RateLimiter, RateLimiterWrapper } from './rate-limiter.js';
import {
  createEmailDeduplication,
  IEmailDeduplication,
  DeduplicationConfig,
  EmailDeduplication,
  EmailDeduplicationWrapper,
} from './email-deduplication.js';
import { processEmail } from './email-processor.js';
import { createGraphClient, AzureAuthMethod } from './azure-auth.js';
import { CacheProvider } from '../lib/cache-provider.js';

export type { AzureAuthMethod };

export interface MailboxMonitorConfig {
  tenantId: string;
  clientId: string;
  clientSecret?: string;
  authMethod?: AzureAuthMethod;
  mailboxAddress: string;
  checkIntervalMs?: number;
  enabled?: boolean;
  rateLimiter?: RateLimiterConfig;
  deduplication?: DeduplicationConfig;
  maxPages?: number;
  parallelLimit?: number;
  cacheProvider?: CacheProvider;
}

const DEFAULT_RATE_LIMITER: RateLimiterConfig = {
  enabled: true,
  maxEmailsPerHour: 100,
  maxEmailsPerDay: 1000,
  circuitBreakerThreshold: 50,
  circuitBreakerWindowMs: 600000,
};

const DEFAULT_DEDUPLICATION: DeduplicationConfig = {
  enabled: true,
  contentHashTtlMs: 86400000,
  senderCooldownMs: 86400000,
};

export class MailboxMonitor {
  private client: Client;
  private config: MailboxMonitorConfig;
  private phishingAgent: PhishingAgent;
  private checkInterval: NodeJS.Timeout | null = null;
  private lastCheckTime: Date;
  private isRunning: boolean = false;
  private rateLimiter!: IRateLimiter;
  private deduplication!: IEmailDeduplication;

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

    // Create sync (in-memory) services - upgraded to Redis in initialize() if cacheProvider available
    const rlConfig = config.rateLimiter || DEFAULT_RATE_LIMITER;
    const dedupConfig = config.deduplication || DEFAULT_DEDUPLICATION;
    this.rateLimiter = new RateLimiterWrapper(new RateLimiter(rlConfig));
    this.deduplication = new EmailDeduplicationWrapper(new EmailDeduplication(dedupConfig));
  }

  /** Upgrades to Redis-backed services if cacheProvider is available */
  private async initializeServices(): Promise<void> {
    if (!this.config.cacheProvider?.isReady()) return;
    const rlConfig = this.config.rateLimiter || DEFAULT_RATE_LIMITER;
    const dedupConfig = this.config.deduplication || DEFAULT_DEDUPLICATION;
    this.rateLimiter = await createRateLimiter(rlConfig, this.config.cacheProvider);
    this.deduplication = await createEmailDeduplication(dedupConfig, this.config.cacheProvider);
  }

  /** Initialize and verify mailbox access */
  async initialize(): Promise<void> {
    securityLogger.info('Initializing mailbox monitor', {
      mailbox: this.config.mailboxAddress,
      checkInterval: this.config.checkIntervalMs,
      cacheMode: this.config.cacheProvider?.isReady() ? 'distributed' : 'in-memory',
    });

    // Initialize rate limiter and deduplication (uses Redis if available)
    await this.initializeServices();

    try {
      await this.client.api(`/users/${this.config.mailboxAddress}/messages`).top(1).get();
      securityLogger.info('Mailbox monitor initialized successfully');
    } catch (error: unknown) {
      const msg = error instanceof Error ? error.message : 'Unknown error';
      securityLogger.error('Mailbox monitor initialization failed', { error: msg });
      throw new Error(`Mailbox monitor initialization failed: ${msg}`);
    }
  }

  /** Start monitoring */
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

  /** Stop monitoring */
  stop(): void {
    if (!this.isRunning) return;

    securityLogger.info('Stopping mailbox monitor');
    if (this.checkInterval) clearInterval(this.checkInterval);
    this.isRunning = false;
    securityLogger.info('Mailbox monitor stopped');
  }

  /** Check for new emails */
  private async checkForNewEmails(): Promise<void> {
    const checkTime = new Date();
    const filterDate = this.lastCheckTime.toISOString();

    securityLogger.debug('Checking mailbox for new emails', {
      mailbox: this.config.mailboxAddress,
      since: filterDate,
    });

    try {
      const emails = await fetchNewEmails(
        this.client,
        {
          mailboxAddress: this.config.mailboxAddress,
          maxPages: this.config.maxPages,
        },
        filterDate
      );

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

  /** Process multiple emails with bounded parallelism */
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

  /** Get monitoring status */
  async getStatus(): Promise<{
    isRunning: boolean;
    mailbox: string;
    lastCheckTime: Date;
    checkInterval: number;
    rateLimitStats: Awaited<ReturnType<IRateLimiter['getStats']>>;
    deduplicationStats: Awaited<ReturnType<IEmailDeduplication['getStats']>>;
  }> {
    return {
      isRunning: this.isRunning,
      mailbox: this.config.mailboxAddress,
      lastCheckTime: this.lastCheckTime,
      checkInterval: this.config.checkIntervalMs!,
      rateLimitStats: await this.rateLimiter.getStats(),
      deduplicationStats: await this.deduplication.getStats(),
    };
  }

  /** Get rate limiter instance */
  getRateLimiter(): IRateLimiter {
    return this.rateLimiter;
  }

  /** Get deduplication instance */
  getDeduplication(): IEmailDeduplication {
    return this.deduplication;
  }

  /** Health check */
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
