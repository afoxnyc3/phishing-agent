/**
 * Mail Monitor Timer Fallback
 * Hourly timer-based poll as safety net for missed webhook notifications.
 * Uses existing dedup to prevent double-processing.
 */

import { Client } from '@microsoft/microsoft-graph-client';
import { securityLogger } from '../lib/logger.js';
import { GraphEmail } from '../lib/schemas.js';
import { fetchNewEmails } from './email-fetcher.js';
import { processEmail } from './email-processor.js';
import { PhishingAgent } from '../agents/phishing-agent.js';
import { IRateLimiter } from './rate-limiter.js';
import { IEmailDeduplication } from './email-deduplication.js';
import { getErrorMessage } from '../lib/errors.js';

export interface MailMonitorConfig {
  enabled: boolean;
  intervalMs: number;
  lookbackMs: number;
  mailboxAddress: string;
  maxPages?: number;
}

export interface MailMonitorDeps {
  graphClient: Client;
  phishingAgent: PhishingAgent;
  rateLimiter: IRateLimiter;
  deduplication: IEmailDeduplication;
}

export interface MailMonitorMetrics {
  pollCount: number;
  emailsFoundByTimer: number;
  emailsAlreadyProcessed: number;
  lastPollTime: Date | null;
  lastPollDurationMs: number;
  errors: number;
}

export class MailMonitor {
  private config: MailMonitorConfig;
  private deps: MailMonitorDeps;
  private timer: NodeJS.Timeout | null = null;
  private running: boolean = false;
  private pollMetrics: MailMonitorMetrics = {
    pollCount: 0,
    emailsFoundByTimer: 0,
    emailsAlreadyProcessed: 0,
    lastPollTime: null,
    lastPollDurationMs: 0,
    errors: 0,
  };

  constructor(config: MailMonitorConfig, deps: MailMonitorDeps) {
    this.config = config;
    this.deps = deps;
  }

  /** Start the timer-based polling */
  start(): void {
    if (!this.config.enabled) {
      securityLogger.info('Mail monitor timer disabled via config');
      return;
    }
    if (this.running) {
      securityLogger.warn('Mail monitor timer already running');
      return;
    }
    this.running = true;
    this.scheduleNextPoll();
    securityLogger.info('Mail monitor timer started', {
      intervalMs: this.config.intervalMs,
      lookbackMs: this.config.lookbackMs,
    });
  }

  /** Stop the timer-based polling */
  stop(): void {
    if (!this.running) return;
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    this.running = false;
    securityLogger.info('Mail monitor timer stopped');
  }

  /** Execute a single poll cycle */
  async poll(): Promise<number> {
    const startTime = Date.now();
    this.pollMetrics.pollCount++;
    try {
      const emails = await this.fetchLookbackEmails();
      const processedCount = await this.processFoundEmails(emails);
      this.recordSuccess(startTime, emails.length, processedCount);
      return processedCount;
    } catch (error: unknown) {
      this.recordError(startTime, error);
      return 0;
    }
  }

  /** Get current metrics snapshot */
  getMetrics(): MailMonitorMetrics {
    return { ...this.pollMetrics };
  }

  /** Check if the timer is currently running */
  getIsRunning(): boolean {
    return this.running;
  }

  /** Check if enabled */
  isEnabled(): boolean {
    return this.config.enabled;
  }

  /** Fetch emails within the lookback window */
  private async fetchLookbackEmails(): Promise<GraphEmail[]> {
    const lookbackDate = new Date(Date.now() - this.config.lookbackMs);
    return fetchNewEmails(
      this.deps.graphClient,
      { mailboxAddress: this.config.mailboxAddress, maxPages: this.config.maxPages },
      lookbackDate.toISOString()
    );
  }

  /** Process found emails; dedup handles already-processed ones */
  private async processFoundEmails(emails: GraphEmail[]): Promise<number> {
    if (emails.length === 0) {
      securityLogger.debug('Mail monitor poll: no emails in lookback window');
      return 0;
    }
    securityLogger.info('Mail monitor poll: found emails', { count: emails.length });
    let processedCount = 0;
    for (const email of emails) {
      if (await this.processSingleEmail(email)) processedCount++;
    }
    return processedCount;
  }

  /** Process a single email, returns true if it was new */
  private async processSingleEmail(email: GraphEmail): Promise<boolean> {
    try {
      await processEmail(email, {
        mailboxAddress: this.config.mailboxAddress,
        graphClient: this.deps.graphClient,
        phishingAgent: this.deps.phishingAgent,
        rateLimiter: this.deps.rateLimiter,
        deduplication: this.deps.deduplication,
      });
      return true;
    } catch (error: unknown) {
      securityLogger.error('Mail monitor: failed to process email', {
        emailId: email.id,
        error: getErrorMessage(error),
      });
      return false;
    }
  }

  /** Schedule the next poll using setTimeout for clean shutdown */
  private scheduleNextPoll(): void {
    this.timer = setTimeout(async () => {
      await this.poll();
      if (this.running) this.scheduleNextPoll();
    }, this.config.intervalMs);
    this.timer.unref();
  }

  /** Record successful poll metrics */
  private recordSuccess(startTime: number, found: number, processed: number): void {
    const dedupFiltered = found - processed;
    this.pollMetrics.emailsFoundByTimer += processed;
    this.pollMetrics.emailsAlreadyProcessed += dedupFiltered;
    this.pollMetrics.lastPollTime = new Date();
    this.pollMetrics.lastPollDurationMs = Date.now() - startTime;
    securityLogger.info('Mail monitor poll completed', {
      emailsFound: found,
      newEmailsProcessed: processed,
      dedupFiltered,
      totalPollCount: this.pollMetrics.pollCount,
      totalMissedEmails: this.pollMetrics.emailsFoundByTimer,
    });
  }

  /** Record poll error metrics */
  private recordError(startTime: number, error: unknown): void {
    this.pollMetrics.errors++;
    this.pollMetrics.lastPollTime = new Date();
    this.pollMetrics.lastPollDurationMs = Date.now() - startTime;
    securityLogger.error('Mail monitor poll failed', {
      error: getErrorMessage(error),
      pollCount: this.pollMetrics.pollCount,
    });
  }
}
