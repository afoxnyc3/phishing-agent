/**
 * Email Deduplication Service
 * Prevents duplicate analysis replies for same phishing email
 * All functions are atomic (max 25 lines)
 *
 * For multi-replica deployments, configure REDIS_URL to enable distributed deduplication.
 * Use createEmailDeduplication() factory to automatically select the appropriate implementation.
 */

import crypto from 'crypto';
import { securityLogger } from '../lib/logger.js';
import { CacheProvider } from '../lib/cache-provider.js';

export interface DeduplicationConfig {
  enabled: boolean;
  contentHashTtlMs: number; // How long to remember processed emails
  senderCooldownMs: number; // Min time between replies to same sender
  cacheProvider?: CacheProvider; // Optional: for distributed deduplication
}

/** Stats returned by getStats() */
export interface DeduplicationStats {
  processedEmailsCount: number;
  uniqueSendersCount: number;
  enabled: boolean;
}

/** Common interface for deduplication services (in-memory and Redis) */
export interface IEmailDeduplication {
  shouldProcess(sender: string, subject: string, body: string): Promise<{ allowed: boolean; reason?: string }>;
  recordProcessed(sender: string, subject: string, body: string): Promise<void>;
  getStats(): Promise<DeduplicationStats>;
  reset(): Promise<void>;
}

/**
 * Factory function to create appropriate deduplication service
 * Returns RedisEmailDeduplication if cacheProvider is ready, otherwise in-memory
 */
export async function createEmailDeduplication(
  config: DeduplicationConfig,
  cacheProvider?: CacheProvider
): Promise<IEmailDeduplication> {
  if (cacheProvider?.isReady()) {
    const { RedisEmailDeduplication } = await import('./redis-email-deduplication.js');
    return new RedisEmailDeduplication(cacheProvider, config);
  }
  return new EmailDeduplicationWrapper(new EmailDeduplication(config));
}

/** Wrapper to make in-memory EmailDeduplication async-compatible */
export class EmailDeduplicationWrapper implements IEmailDeduplication {
  constructor(private dedup: EmailDeduplication) {}

  async shouldProcess(sender: string, subject: string, body: string): Promise<{ allowed: boolean; reason?: string }> {
    return this.dedup.shouldProcess(sender, subject, body);
  }
  async recordProcessed(sender: string, subject: string, body: string): Promise<void> {
    this.dedup.recordProcessed(sender, subject, body);
  }
  async getStats(): Promise<DeduplicationStats> {
    return this.dedup.getStats();
  }
  async reset(): Promise<void> {
    this.dedup.reset();
  }
}

interface CacheEntry {
  hash: string;
  timestamp: number;
  expiresAt: number;
  sender?: string;
  subject?: string;
}

export class EmailDeduplication {
  private config: DeduplicationConfig;
  private processedHashes: Map<string, CacheEntry> = new Map();
  private senderLastReply: Map<string, number> = new Map();
  private useDistributed: boolean = false;

  constructor(config: DeduplicationConfig) {
    this.config = config;
    this.useDistributed = !!(config.cacheProvider && config.cacheProvider.isReady());

    securityLogger.info('Email deduplication initialized', {
      enabled: config.enabled,
      contentHashTtl: config.contentHashTtlMs / (60 * 60 * 1000) + ' hours',
      senderCooldown: config.senderCooldownMs / (60 * 60 * 1000) + ' hours',
      mode: this.useDistributed ? 'distributed (Redis)' : 'in-memory (single instance)',
    });

    // Auto-cleanup every 5 minutes
    // Use .unref() to allow process to exit cleanly during tests
    setInterval(() => this.cleanExpired(), 5 * 60 * 1000).unref();
  }

  /**
   * Check if email should be processed
   */
  shouldProcess(sender: string, subject: string, body: string): { allowed: boolean; reason?: string } {
    if (!this.config.enabled) {
      return { allowed: true };
    }

    // Check content deduplication
    const contentHash = this.hashEmailContent(subject, body);
    if (this.isDuplicateContent(contentHash)) {
      return {
        allowed: false,
        reason: `Duplicate email already processed (hash: ${contentHash.substring(0, 8)})`,
      };
    }

    // Check sender cooldown
    if (this.isSenderInCooldown(sender)) {
      const lastReply = this.senderLastReply.get(sender.toLowerCase());
      const nextAllowed = lastReply ? new Date(lastReply + this.config.senderCooldownMs) : new Date();
      return {
        allowed: false,
        reason: `Sender in cooldown period (next allowed: ${nextAllowed.toISOString()})`,
      };
    }

    return { allowed: true };
  }

  /**
   * Record email as processed
   */
  recordProcessed(sender: string, subject: string, body: string): void {
    if (!this.config.enabled) return;

    const contentHash = this.hashEmailContent(subject, body);
    const now = Date.now();

    this.processedHashes.set(contentHash, {
      hash: contentHash,
      timestamp: now,
      expiresAt: now + this.config.contentHashTtlMs,
      sender,
      subject,
    });

    this.senderLastReply.set(sender.toLowerCase(), now);

    securityLogger.debug('Email recorded as processed', {
      hash: contentHash.substring(0, 8),
      sender,
      subject: subject.substring(0, 50),
    });
  }

  /**
   * Hash email content for deduplication
   */
  private hashEmailContent(subject: string, body: string): string {
    // Use first 1000 chars of body to avoid hashing entire email
    const content = `${subject}||${body.substring(0, 1000)}`;
    return crypto.createHash('sha256').update(content.toLowerCase().trim()).digest('hex');
  }

  /**
   * Check if content hash is duplicate
   */
  private isDuplicateContent(hash: string): boolean {
    const entry = this.processedHashes.get(hash);
    if (!entry) return false;

    if (Date.now() > entry.expiresAt) {
      this.processedHashes.delete(hash);
      return false;
    }

    return true;
  }

  /**
   * Check if sender is in cooldown period
   */
  private isSenderInCooldown(sender: string): boolean {
    const lastReply = this.senderLastReply.get(sender.toLowerCase());
    if (!lastReply) return false;

    const cooldownExpires = lastReply + this.config.senderCooldownMs;
    if (Date.now() > cooldownExpires) {
      this.senderLastReply.delete(sender.toLowerCase());
      return false;
    }

    return true;
  }

  /**
   * Clean expired entries
   */
  private cleanExpired(): void {
    const now = Date.now();
    let cleanedHashes = 0;
    let cleanedSenders = 0;

    // Clean expired content hashes
    for (const [hash, entry] of this.processedHashes.entries()) {
      if (now > entry.expiresAt) {
        this.processedHashes.delete(hash);
        cleanedHashes++;
      }
    }

    // Clean expired sender cooldowns
    for (const [sender, lastReply] of this.senderLastReply.entries()) {
      if (now > lastReply + this.config.senderCooldownMs) {
        this.senderLastReply.delete(sender);
        cleanedSenders++;
      }
    }

    if (cleanedHashes > 0 || cleanedSenders > 0) {
      securityLogger.debug('Cleaned expired deduplication entries', {
        cleanedHashes,
        cleanedSenders,
        remainingHashes: this.processedHashes.size,
        remainingSenders: this.senderLastReply.size,
      });
    }
  }

  /**
   * Get deduplication statistics
   */
  getStats(): {
    processedEmailsCount: number;
    uniqueSendersCount: number;
    enabled: boolean;
  } {
    return {
      processedEmailsCount: this.processedHashes.size,
      uniqueSendersCount: this.senderLastReply.size,
      enabled: this.config.enabled,
    };
  }

  /**
   * Reset all data (for testing/admin)
   */
  reset(): void {
    this.processedHashes.clear();
    this.senderLastReply.clear();
    securityLogger.warn('Email deduplication reset');
  }
}
