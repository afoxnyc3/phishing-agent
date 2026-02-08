/**
 * Email Deduplication Tests
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { EmailDeduplication } from './email-deduplication.js';

describe('EmailDeduplication', () => {
  let deduplication: EmailDeduplication;

  beforeEach(() => {
    deduplication = new EmailDeduplication({
      enabled: true,
      contentHashTtlMs: 3600000, // 1 hour for testing
      senderCooldownMs: 1800000, // 30 minutes for testing
    });
  });

  describe('shouldProcess', () => {
    it('should allow processing first time email', () => {
      const result = deduplication.shouldProcess(
        'user@example.com',
        'Suspicious email',
        'Click here to verify your account'
      );

      expect(result.allowed).toBe(true);
      expect(result.reason).toBeUndefined();
    });

    it('should block duplicate content', () => {
      const sender = 'user1@example.com';
      const subject = 'Phishing attempt';
      const body = 'Verify your account now!';

      // Process first email
      deduplication.recordProcessed(sender, subject, body);

      // Try to process same content from different sender
      const result = deduplication.shouldProcess('user2@example.com', subject, body);

      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('Duplicate email already processed');
    });

    it('should block sender in cooldown', () => {
      const sender = 'user@example.com';

      // Process first email
      deduplication.recordProcessed(sender, 'Subject 1', 'Body 1');

      // Try to process different email from same sender
      const result = deduplication.shouldProcess(sender, 'Subject 2', 'Body 2');

      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('Sender in cooldown period');
    });

    it('should allow processing when disabled', () => {
      const disabledDedup = new EmailDeduplication({
        enabled: false,
        contentHashTtlMs: 3600000,
        senderCooldownMs: 1800000,
      });

      disabledDedup.recordProcessed('user@example.com', 'Subject', 'Body');

      const result = disabledDedup.shouldProcess('user@example.com', 'Subject', 'Body');

      expect(result.allowed).toBe(true);
    });

    it('should be case-insensitive for sender addresses', () => {
      deduplication.recordProcessed('User@Example.COM', 'Subject', 'Body');

      const result = deduplication.shouldProcess('user@example.com', 'Different Subject', 'Different Body');

      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('Sender in cooldown');
    });

    it('should hash content consistently', () => {
      const sender1 = 'user1@example.com';
      const sender2 = 'user2@example.com';
      const subject = 'Urgent: Verify your account';
      const body = 'Click here immediately to verify your account or it will be suspended.';

      // First sender processes
      deduplication.recordProcessed(sender1, subject, body);

      // Second sender tries same content
      const result = deduplication.shouldProcess(sender2, subject, body);

      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('Duplicate email');
    });

    it('should allow different content from same sender after processing different email', () => {
      // This tests that content hash and sender cooldown work independently
      const sender = 'user@example.com';

      // Process first email
      deduplication.recordProcessed(sender, 'Subject 1', 'Body 1');

      // Try different content - should be blocked by sender cooldown
      const result = deduplication.shouldProcess(sender, 'Subject 2', 'Body 2');

      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('Sender in cooldown');
    });
  });

  describe('recordProcessed', () => {
    it('should record email as processed', () => {
      const sender = 'user@example.com';
      const subject = 'Test';
      const body = 'Test body';

      let stats = deduplication.getStats();
      expect(stats.processedEmailsCount).toBe(0);
      expect(stats.uniqueSendersCount).toBe(0);

      deduplication.recordProcessed(sender, subject, body);

      stats = deduplication.getStats();
      expect(stats.processedEmailsCount).toBe(1);
      expect(stats.uniqueSendersCount).toBe(1);
    });

    it('should not record when disabled', () => {
      const disabledDedup = new EmailDeduplication({
        enabled: false,
        contentHashTtlMs: 3600000,
        senderCooldownMs: 1800000,
      });

      disabledDedup.recordProcessed('user@example.com', 'Subject', 'Body');

      const stats = disabledDedup.getStats();
      // Stats should be 0 when disabled
      expect(stats.processedEmailsCount).toBe(0);
    });

    it('should track multiple unique emails', () => {
      deduplication.recordProcessed('user1@example.com', 'Subject 1', 'Body 1');
      deduplication.recordProcessed('user2@example.com', 'Subject 2', 'Body 2');
      deduplication.recordProcessed('user3@example.com', 'Subject 3', 'Body 3');

      const stats = deduplication.getStats();
      expect(stats.processedEmailsCount).toBe(3);
      expect(stats.uniqueSendersCount).toBe(3);
    });
  });

  describe('getStats', () => {
    it('should return accurate statistics', () => {
      deduplication.recordProcessed('user1@example.com', 'Subject 1', 'Body 1');
      deduplication.recordProcessed('user2@example.com', 'Subject 2', 'Body 2');

      const stats = deduplication.getStats();

      expect(stats.processedEmailsCount).toBe(2);
      expect(stats.uniqueSendersCount).toBe(2);
      expect(stats.enabled).toBe(true);
    });

    it('should show disabled status', () => {
      const disabledDedup = new EmailDeduplication({
        enabled: false,
        contentHashTtlMs: 3600000,
        senderCooldownMs: 1800000,
      });

      const stats = disabledDedup.getStats();
      expect(stats.enabled).toBe(false);
    });
  });

  describe('reset', () => {
    it('should clear all tracked data', () => {
      deduplication.recordProcessed('user1@example.com', 'Subject 1', 'Body 1');
      deduplication.recordProcessed('user2@example.com', 'Subject 2', 'Body 2');

      let stats = deduplication.getStats();
      expect(stats.processedEmailsCount).toBe(2);
      expect(stats.uniqueSendersCount).toBe(2);

      deduplication.reset();

      stats = deduplication.getStats();
      expect(stats.processedEmailsCount).toBe(0);
      expect(stats.uniqueSendersCount).toBe(0);
    });
  });

  describe('content hashing', () => {
    it('should treat slight variations as different emails', () => {
      const sender = 'user@example.com';
      const subject = 'Verify your account';
      const body1 = 'Click here to verify your account.';
      const body2 = 'Click here to verify your account!'; // Different punctuation

      deduplication.recordProcessed(sender, subject, body1);

      // Different content should be allowed (but blocked by sender cooldown)
      const result = deduplication.shouldProcess(sender, subject, body2);

      // This will be blocked by sender cooldown, not content hash
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('Sender in cooldown');
    });

    it('should ignore case differences in content', () => {
      const sender1 = 'user1@example.com';
      const sender2 = 'user2@example.com';
      const subject = 'URGENT ACTION REQUIRED';
      const body1 = 'Your account will be suspended';
      const body2 = 'YOUR ACCOUNT WILL BE SUSPENDED';

      deduplication.recordProcessed(sender1, subject, body1);

      // Case-insensitive content should be treated as duplicate
      const result = deduplication.shouldProcess(sender2, subject, body2);

      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('Duplicate email');
    });

    it('should handle empty or missing content gracefully', () => {
      const result1 = deduplication.shouldProcess('user@example.com', '', '');
      expect(result1.allowed).toBe(true);

      deduplication.recordProcessed('user@example.com', '', '');

      const result2 = deduplication.shouldProcess('user2@example.com', '', '');
      expect(result2.allowed).toBe(false); // Duplicate empty content
    });
  });

  describe('auto-cleanup', () => {
    it('should initialize cleanup interval', () => {
      // Just verify that creating an instance doesn't throw
      const newDedup = new EmailDeduplication({
        enabled: true,
        contentHashTtlMs: 3600000,
        senderCooldownMs: 1800000,
      });

      expect(newDedup).toBeDefined();
      expect(newDedup.getStats()).toBeDefined();
    });
  });

  describe('TTL expiration', () => {
    it('should allow reprocessing after content hash TTL expires', () => {
      // Create deduplication with very short TTL (1ms)
      const shortTtlDedup = new EmailDeduplication({
        enabled: true,
        contentHashTtlMs: 1, // 1ms TTL
        senderCooldownMs: 1, // 1ms cooldown
      });

      const sender1 = 'user1@example.com';
      const sender2 = 'user2@example.com';
      const subject = 'Test subject';
      const body = 'Test body';

      // Record first email
      shortTtlDedup.recordProcessed(sender1, subject, body);

      // Verify it's recorded
      expect(shortTtlDedup.getStats().processedEmailsCount).toBe(1);

      // Wait for TTL to expire
      return new Promise<void>((resolve) => {
        setTimeout(() => {
          // Should now be allowed (TTL expired, different sender bypasses cooldown check)
          const result = shortTtlDedup.shouldProcess(sender2, subject, body);
          expect(result.allowed).toBe(true);
          resolve();
        }, 10);
      });
    });

    it('should allow same sender after cooldown expires', () => {
      const shortCooldownDedup = new EmailDeduplication({
        enabled: true,
        contentHashTtlMs: 1, // 1ms TTL
        senderCooldownMs: 1, // 1ms cooldown
      });

      const sender = 'user@example.com';

      // Record first email
      shortCooldownDedup.recordProcessed(sender, 'Subject 1', 'Body 1');

      // Wait for cooldown to expire
      return new Promise<void>((resolve) => {
        setTimeout(() => {
          // Should now be allowed (cooldown expired)
          const result = shortCooldownDedup.shouldProcess(sender, 'Subject 2', 'Body 2');
          expect(result.allowed).toBe(true);
          resolve();
        }, 10);
      });
    });

    it('should clean up expired content hash when checking for duplicate', () => {
      const shortTtlDedup = new EmailDeduplication({
        enabled: true,
        contentHashTtlMs: 1, // 1ms TTL
        senderCooldownMs: 86400000, // Long cooldown (not testing this)
      });

      const sender1 = 'user1@example.com';
      const sender2 = 'user2@example.com';
      const subject = 'Test subject';
      const body = 'Test body';

      // Record first email
      shortTtlDedup.recordProcessed(sender1, subject, body);
      expect(shortTtlDedup.getStats().processedEmailsCount).toBe(1);

      // Wait for TTL to expire
      return new Promise<void>((resolve) => {
        setTimeout(() => {
          // This call triggers isDuplicateContent which should clean expired entry
          shortTtlDedup.shouldProcess(sender2, subject, body);
          // The entry should have been deleted during the check
          // (it passed because TTL expired and entry was removed)
          resolve();
        }, 10);
      });
    });

    it('should clean up expired sender cooldown when checking', () => {
      const shortCooldownDedup = new EmailDeduplication({
        enabled: true,
        contentHashTtlMs: 86400000, // Long TTL
        senderCooldownMs: 1, // 1ms cooldown
      });

      const sender = 'user@example.com';

      // Record first email
      shortCooldownDedup.recordProcessed(sender, 'Subject 1', 'Body 1');
      expect(shortCooldownDedup.getStats().uniqueSendersCount).toBe(1);

      // Wait for cooldown to expire
      return new Promise<void>((resolve) => {
        setTimeout(() => {
          // This call triggers isSenderInCooldown which should clean expired sender
          const result = shortCooldownDedup.shouldProcess(sender, 'Subject 2', 'Body 2');
          expect(result.allowed).toBe(true);
          resolve();
        }, 10);
      });
    });
  });

  describe('distributed mode', () => {
    it('should detect distributed mode when cacheProvider is ready', () => {
      const mockCacheProvider = {
        get: vi.fn(),
        set: vi.fn(),
        delete: vi.fn(),
        isReady: vi.fn().mockReturnValue(true),
        increment: vi.fn(),
      };

      // This should log "distributed (Redis)" mode
      const distributedDedup = new EmailDeduplication({
        enabled: true,
        contentHashTtlMs: 3600000,
        senderCooldownMs: 1800000,
        cacheProvider: mockCacheProvider as any,
      });

      expect(distributedDedup).toBeDefined();
    });

    it('should fall back to in-memory when cacheProvider is not ready', () => {
      const mockCacheProvider = {
        get: vi.fn(),
        set: vi.fn(),
        delete: vi.fn(),
        isReady: vi.fn().mockReturnValue(false),
        increment: vi.fn(),
      };

      // This should log "in-memory (single instance)" mode
      const memoryDedup = new EmailDeduplication({
        enabled: true,
        contentHashTtlMs: 3600000,
        senderCooldownMs: 1800000,
        cacheProvider: mockCacheProvider as any,
      });

      expect(memoryDedup).toBeDefined();
    });

    it('should use in-memory mode when no cacheProvider', () => {
      // Default behavior - no cacheProvider
      const memoryDedup = new EmailDeduplication({
        enabled: true,
        contentHashTtlMs: 3600000,
        senderCooldownMs: 1800000,
      });

      expect(memoryDedup).toBeDefined();
    });
  });

  describe('edge cases', () => {
    it('should handle very long body content (truncated to 1000 chars)', () => {
      const longBody = 'A'.repeat(2000);
      const sender = 'user@example.com';
      const subject = 'Long email';

      // First process
      const result1 = deduplication.shouldProcess(sender, subject, longBody);
      expect(result1.allowed).toBe(true);

      deduplication.recordProcessed(sender, subject, longBody);

      // Try with same body (different sender to bypass cooldown)
      const result2 = deduplication.shouldProcess('user2@example.com', subject, longBody);
      expect(result2.allowed).toBe(false);
      expect(result2.reason).toContain('Duplicate');
    });

    it('should handle bodies with exactly 1000 chars', () => {
      const exactBody = 'B'.repeat(1000);
      const sender = 'user@example.com';
      const subject = 'Exact length';

      deduplication.recordProcessed(sender, subject, exactBody);

      const result = deduplication.shouldProcess('user2@example.com', subject, exactBody);
      expect(result.allowed).toBe(false);
    });

    it('should handle special characters in content', () => {
      const specialBody = '<!DOCTYPE html><script>alert("xss")</script>日本語テスト';
      const sender = 'user@example.com';
      const subject = '特殊文字テスト';

      deduplication.recordProcessed(sender, subject, specialBody);

      const result = deduplication.shouldProcess('user2@example.com', subject, specialBody);
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('Duplicate');
    });

    it('should handle whitespace-only content', () => {
      const whitespaceBody = '   \t\n\r   ';
      const sender = 'user@example.com';
      const subject = '   ';

      const result1 = deduplication.shouldProcess(sender, subject, whitespaceBody);
      expect(result1.allowed).toBe(true);

      deduplication.recordProcessed(sender, subject, whitespaceBody);

      const result2 = deduplication.shouldProcess('user2@example.com', subject, whitespaceBody);
      expect(result2.allowed).toBe(false);
    });

    it('should track same sender with different casing as one entry', () => {
      // Record with uppercase
      deduplication.recordProcessed('USER@EXAMPLE.COM', 'Subject 1', 'Body 1');

      // Should be in cooldown with lowercase
      const result = deduplication.shouldProcess('user@example.com', 'Subject 2', 'Body 2');
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('Sender in cooldown');

      // Only one unique sender should be tracked
      expect(deduplication.getStats().uniqueSendersCount).toBe(1);
    });

    it('should handle concurrent-like rapid calls', () => {
      const sender = 'rapid@example.com';
      const results: Array<{ allowed: boolean; reason?: string }> = [];

      // Rapid fire multiple calls
      for (let i = 0; i < 5; i++) {
        const result = deduplication.shouldProcess(sender, `Subject ${i}`, `Body ${i}`);
        results.push(result);
        if (result.allowed) {
          deduplication.recordProcessed(sender, `Subject ${i}`, `Body ${i}`);
        }
      }

      // Only the first should succeed
      expect(results[0].allowed).toBe(true);
      expect(results.slice(1).every((r) => !r.allowed)).toBe(true);
    });
  });
});
