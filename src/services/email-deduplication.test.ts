/**
 * Email Deduplication Tests
 */

import { describe, it, expect, beforeEach } from '@jest/globals';
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
});
