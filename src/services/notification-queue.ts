/**
 * Notification Queue
 * In-memory queue decoupling webhook receipt from email processing.
 * Provides retry with exponential backoff and dead letter handling.
 */

import pLimit from 'p-limit';
import { securityLogger } from '../lib/logger.js';
import { fetchEmailById } from './email-fetcher.js';
import { processEmail, EmailProcessorConfig } from './email-processor.js';
import { getErrorMessage } from '../lib/errors.js';

export interface NotificationQueueConfig {
  enabled: boolean;
  maxRetries: number;
  backoffMs: number;
  maxBackoffMs: number;
  concurrency: number;
  drainIntervalMs: number;
}

export interface QueueDeps {
  processorConfig: EmailProcessorConfig;
}

export interface QueueItem {
  messageId: string;
  enqueuedAt: number;
  attempts: number;
  lastAttemptAt?: number;
  lastError?: string;
}

export interface QueueMetrics {
  pending: number;
  deadLetterCount: number;
  totalEnqueued: number;
  totalProcessed: number;
  totalFailed: number;
}

export class NotificationQueue {
  private pending: Map<string, QueueItem> = new Map();
  private deadLetter: QueueItem[] = [];
  private timer: NodeJS.Timeout | null = null;
  private running = false;
  private draining = false;
  private totalEnqueued = 0;
  private totalProcessed = 0;
  private totalFailed = 0;

  constructor(
    private config: NotificationQueueConfig,
    private deps: QueueDeps
  ) {}

  /** Add message IDs to the queue for processing */
  enqueue(messageIds: string[]): void {
    for (const id of messageIds) {
      if (this.pending.has(id)) continue;
      this.pending.set(id, { messageId: id, enqueuedAt: Date.now(), attempts: 0 });
      this.totalEnqueued++;
    }
    if (this.running && messageIds.length > 0) {
      this.scheduleDrain(0);
    }
  }

  /** Start the consumer loop */
  start(): void {
    if (this.running) return;
    this.running = true;
    this.scheduleDrain(this.config.drainIntervalMs);
    securityLogger.info('Notification queue started', {
      concurrency: this.config.concurrency,
      maxRetries: this.config.maxRetries,
    });
  }

  /** Stop the consumer loop */
  stop(): void {
    if (!this.running) return;
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    this.running = false;
    securityLogger.info('Notification queue stopped', { pending: this.pending.size });
  }

  /** Get current queue metrics */
  getMetrics(): QueueMetrics {
    return {
      pending: this.pending.size,
      deadLetterCount: this.deadLetter.length,
      totalEnqueued: this.totalEnqueued,
      totalProcessed: this.totalProcessed,
      totalFailed: this.totalFailed,
    };
  }

  /** Get dead letter items for inspection */
  getDeadLetterItems(): QueueItem[] {
    return [...this.deadLetter];
  }

  private scheduleDrain(delayMs: number): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = setTimeout(() => this.drain(), delayMs);
    this.timer.unref();
  }

  private async drain(): Promise<void> {
    if (this.draining) return;
    this.draining = true;
    try {
      const ready = this.getReadyItems();
      if (ready.length > 0) {
        const limit = pLimit(this.config.concurrency);
        await Promise.allSettled(ready.map((item) => limit(() => this.processItem(item))));
      }
    } finally {
      this.draining = false;
      if (this.running) this.scheduleDrain(this.config.drainIntervalMs);
    }
  }

  private getReadyItems(): QueueItem[] {
    const now = Date.now();
    return [...this.pending.values()].filter((item) => {
      if (item.attempts === 0) return true;
      const backoff = this.calculateBackoff(item.attempts);
      return now - (item.lastAttemptAt || 0) >= backoff;
    });
  }

  private async processItem(item: QueueItem): Promise<void> {
    item.attempts++;
    item.lastAttemptAt = Date.now();
    try {
      const { graphClient, mailboxAddress } = this.deps.processorConfig;
      const email = await fetchEmailById(graphClient, mailboxAddress, item.messageId);
      await processEmail(email, this.deps.processorConfig);
      this.pending.delete(item.messageId);
      this.totalProcessed++;
    } catch (error: unknown) {
      item.lastError = getErrorMessage(error);
      this.handleFailure(item);
    }
  }

  private handleFailure(item: QueueItem): void {
    if (item.attempts >= this.config.maxRetries) {
      this.pending.delete(item.messageId);
      this.deadLetter.push(item);
      this.totalFailed++;
      securityLogger.error('Notification moved to dead letter queue', {
        messageId: item.messageId,
        attempts: item.attempts,
        lastError: item.lastError,
      });
    } else {
      securityLogger.warn('Notification processing failed, will retry', {
        messageId: item.messageId,
        attempts: item.attempts,
        nextRetryMs: this.calculateBackoff(item.attempts),
      });
    }
  }

  /** Exponential backoff: baseMs * 2^(attempts-1), capped at maxMs */
  calculateBackoff(attempts: number): number {
    const backoff = this.config.backoffMs * Math.pow(2, attempts - 1);
    return Math.min(backoff, this.config.maxBackoffMs);
  }
}
