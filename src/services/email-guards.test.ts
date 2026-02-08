/**
 * Email Guards Tests
 * Tests for guardrail functions preventing loops, auto-responder replies, and unauthorized senders
 */

import { describe, it, expect, beforeEach, jest } from '@jest/globals';

// Mock logger
jest.unstable_mockModule('../lib/logger.js', () => ({
  securityLogger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}));

const { evaluateEmailGuards, __testResetMessageIdCache } = await import('./email-guards.js');

describe('Email Guards', () => {
  const MAILBOX_ADDRESS = 'phishing@company.com';

  beforeEach(() => {
    __testResetMessageIdCache();
    // Reset environment variables
    delete process.env.ALLOWED_SENDER_EMAILS;
    delete process.env.ALLOWED_SENDER_DOMAINS;
    delete process.env.NODE_ENV;
  });

  const createGraphEmail = (
    overrides: Partial<{
      from: { emailAddress: { address: string } };
      internetMessageId: string;
      id: string;
      internetMessageHeaders: Array<{ name: string; value: string }>;
    }> = {}
  ) => ({
    from: { emailAddress: { address: 'user@external.com' } },
    internetMessageId: '<test-message-id@example.com>',
    id: 'graph-id-123',
    internetMessageHeaders: [],
    ...overrides,
  });

  describe('evaluateEmailGuards - Main Entry Point', () => {
    it('should return allowed:true when all guards pass (dev mode, no allowlist)', () => {
      process.env.NODE_ENV = 'development';
      const email = createGraphEmail();

      const result = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);

      expect(result.allowed).toBe(true);
      expect(result.reason).toBeUndefined();
    });

    it('should return allowed:false with reason missing-sender when sender is empty', () => {
      const email = createGraphEmail({
        from: { emailAddress: { address: '' } },
      });

      const result = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('missing-sender');
    });

    it('should return allowed:false with reason missing-sender when from is undefined', () => {
      const email = {
        from: undefined,
        internetMessageId: '<test@example.com>',
        id: 'id-123',
      };

      const result = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('missing-sender');
    });

    it('should return allowed:false with reason missing-message-id when no message ID', () => {
      const email = createGraphEmail({
        internetMessageId: '',
        id: '',
      });

      const result = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('missing-message-id');
    });

    it('should return allowed:false with reason duplicate-message-id on duplicate', () => {
      process.env.NODE_ENV = 'development';
      const email = createGraphEmail();

      // First call should pass
      const result1 = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);
      expect(result1.allowed).toBe(true);

      // Second call with same message ID should fail
      const result2 = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);
      expect(result2.allowed).toBe(false);
      expect(result2.reason).toBe('duplicate-message-id');
    });

    it('should return allowed:false with reason self-sender-detected for self-emails', () => {
      const email = createGraphEmail({
        from: { emailAddress: { address: MAILBOX_ADDRESS } },
      });

      const result = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('self-sender-detected');
    });

    it('should return allowed:false with reason sender-not-allowlisted in production without allowlist', () => {
      process.env.NODE_ENV = 'production';
      const email = createGraphEmail();

      const result = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('sender-not-allowlisted');
    });

    it('should return allowed:false with reason auto-responder-detected for auto-replies', () => {
      process.env.NODE_ENV = 'development';
      const email = createGraphEmail({
        internetMessageHeaders: [{ name: 'Auto-Submitted', value: 'auto-replied' }],
      });

      const result = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('auto-responder-detected');
    });
  });

  describe('buildHeaderMap - Header Parsing', () => {
    it('should handle undefined headers', () => {
      process.env.NODE_ENV = 'development';
      const email = createGraphEmail({
        internetMessageHeaders: undefined as any,
      });

      const result = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);

      // Should pass (no auto-responder headers to detect)
      expect(result.allowed).toBe(true);
    });

    it('should handle empty array headers', () => {
      process.env.NODE_ENV = 'development';
      const email = createGraphEmail({
        internetMessageHeaders: [],
      });

      const result = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);

      expect(result.allowed).toBe(true);
    });

    it('should normalize header names to lowercase', () => {
      process.env.NODE_ENV = 'development';
      const email = createGraphEmail({
        internetMessageHeaders: [{ name: 'AUTO-SUBMITTED', value: 'auto-replied' }],
      });

      const result = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('auto-responder-detected');
    });

    it('should skip headers with missing name or value', () => {
      process.env.NODE_ENV = 'development';
      const email = createGraphEmail({
        internetMessageHeaders: [
          { name: '', value: 'auto-replied' },
          { name: 'Auto-Submitted', value: '' },
          { name: undefined as any, value: 'test' },
        ],
      });

      const result = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);

      // Should pass (malformed headers ignored)
      expect(result.allowed).toBe(true);
    });
  });

  describe('isMessageIdDuplicate - Duplicate Detection', () => {
    it('should return false for first occurrence', () => {
      process.env.NODE_ENV = 'development';
      const email = createGraphEmail({
        internetMessageId: '<unique-id-1@example.com>',
      });

      const result = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);

      expect(result.allowed).toBe(true);
    });

    it('should return true for immediate duplicate', () => {
      process.env.NODE_ENV = 'development';
      const email = createGraphEmail({
        internetMessageId: '<duplicate-test@example.com>',
      });

      evaluateEmailGuards(email as any, MAILBOX_ADDRESS);
      const result = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('duplicate-message-id');
    });

    it('should use graph ID as fallback when internetMessageId is empty', () => {
      process.env.NODE_ENV = 'development';
      const email = createGraphEmail({
        internetMessageId: '',
        id: 'fallback-graph-id',
      });

      const result = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);

      // Should fail because the fallback ID is also empty after trim
      // Actually looking at the code, id: 'fallback-graph-id' should work
      expect(result.allowed).toBe(true);

      // Second call should detect duplicate
      const result2 = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);
      expect(result2.allowed).toBe(false);
      expect(result2.reason).toBe('duplicate-message-id');
    });

    it('should handle different message IDs independently', () => {
      process.env.NODE_ENV = 'development';
      const email1 = createGraphEmail({ internetMessageId: '<id-1@example.com>' });
      const email2 = createGraphEmail({ internetMessageId: '<id-2@example.com>' });

      const result1 = evaluateEmailGuards(email1 as any, MAILBOX_ADDRESS);
      const result2 = evaluateEmailGuards(email2 as any, MAILBOX_ADDRESS);

      expect(result1.allowed).toBe(true);
      expect(result2.allowed).toBe(true);
    });

    it('should reset cache with __testResetMessageIdCache', () => {
      process.env.NODE_ENV = 'development';
      const email = createGraphEmail();

      evaluateEmailGuards(email as any, MAILBOX_ADDRESS);
      __testResetMessageIdCache();
      const result = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);

      expect(result.allowed).toBe(true);
    });
  });

  describe('isSelfOrSiblingSender - Loop Prevention', () => {
    it('should detect exact self-match', () => {
      const email = createGraphEmail({
        from: { emailAddress: { address: 'phishing@company.com' } },
      });

      const result = evaluateEmailGuards(email as any, 'phishing@company.com');

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('self-sender-detected');
    });

    it('should detect case-insensitive self-match', () => {
      const email = createGraphEmail({
        from: { emailAddress: { address: 'PHISHING@COMPANY.COM' } },
      });

      const result = evaluateEmailGuards(email as any, 'phishing@company.com');

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('self-sender-detected');
    });

    it('should detect sibling sender (phishing-noreply@company.com)', () => {
      const email = createGraphEmail({
        from: { emailAddress: { address: 'phishing-noreply@company.com' } },
      });

      const result = evaluateEmailGuards(email as any, 'phishing@company.com');

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('self-sender-detected');
    });

    it('should detect sibling sender (phishing.alerts@company.com)', () => {
      const email = createGraphEmail({
        from: { emailAddress: { address: 'phishing.alerts@company.com' } },
      });

      const result = evaluateEmailGuards(email as any, 'phishing@company.com');

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('self-sender-detected');
    });

    it('should allow different domains', () => {
      process.env.NODE_ENV = 'development';
      const email = createGraphEmail({
        from: { emailAddress: { address: 'user@external.com' } },
      });

      const result = evaluateEmailGuards(email as any, 'phishing@company.com');

      expect(result.allowed).toBe(true);
    });

    it('should allow different local parts on same domain', () => {
      process.env.NODE_ENV = 'development';
      process.env.ALLOWED_SENDER_DOMAINS = 'company.com';
      const email = createGraphEmail({
        from: { emailAddress: { address: 'user@company.com' } },
      });

      const result = evaluateEmailGuards(email as any, 'phishing@company.com');

      expect(result.allowed).toBe(true);
    });

    it('should not detect sibling when local part does not start with mailbox local', () => {
      process.env.NODE_ENV = 'development';
      process.env.ALLOWED_SENDER_DOMAINS = 'company.com';
      const email = createGraphEmail({
        from: { emailAddress: { address: 'security@company.com' } },
      });

      const result = evaluateEmailGuards(email as any, 'phishing@company.com');

      expect(result.allowed).toBe(true);
    });
  });

  describe('isAllowlistedSender - Allowlist Logic', () => {
    it('should block all senders in production when no allowlist configured', () => {
      process.env.NODE_ENV = 'production';
      const email = createGraphEmail();

      const result = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('sender-not-allowlisted');
    });

    it('should allow all senders in development when no allowlist configured', () => {
      process.env.NODE_ENV = 'development';
      const email = createGraphEmail();

      const result = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);

      expect(result.allowed).toBe(true);
    });

    it('should allow all senders when NODE_ENV is undefined (development default)', () => {
      delete process.env.NODE_ENV;
      const email = createGraphEmail();

      const result = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);

      expect(result.allowed).toBe(true);
    });

    it('should match exact email in ALLOWED_SENDER_EMAILS', () => {
      process.env.NODE_ENV = 'production';
      process.env.ALLOWED_SENDER_EMAILS = 'user@external.com';
      const email = createGraphEmail({
        from: { emailAddress: { address: 'user@external.com' } },
      });

      const result = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);

      expect(result.allowed).toBe(true);
    });

    it('should match domain in ALLOWED_SENDER_DOMAINS', () => {
      process.env.NODE_ENV = 'production';
      process.env.ALLOWED_SENDER_DOMAINS = 'external.com';
      const email = createGraphEmail({
        from: { emailAddress: { address: 'anyone@external.com' } },
      });

      const result = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);

      expect(result.allowed).toBe(true);
    });

    it('should perform case-insensitive email matching', () => {
      process.env.NODE_ENV = 'production';
      process.env.ALLOWED_SENDER_EMAILS = 'User@External.Com';
      const email = createGraphEmail({
        from: { emailAddress: { address: 'USER@EXTERNAL.COM' } },
      });

      const result = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);

      expect(result.allowed).toBe(true);
    });

    it('should perform case-insensitive domain matching', () => {
      process.env.NODE_ENV = 'production';
      process.env.ALLOWED_SENDER_DOMAINS = 'External.Com';
      const email = createGraphEmail({
        from: { emailAddress: { address: 'user@EXTERNAL.COM' } },
      });

      const result = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);

      expect(result.allowed).toBe(true);
    });

    it('should handle comma-separated email list', () => {
      process.env.NODE_ENV = 'production';
      process.env.ALLOWED_SENDER_EMAILS = 'first@example.com,second@example.com,third@example.com';
      const email = createGraphEmail({
        from: { emailAddress: { address: 'second@example.com' } },
      });

      const result = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);

      expect(result.allowed).toBe(true);
    });

    it('should handle comma-separated domain list', () => {
      process.env.NODE_ENV = 'production';
      process.env.ALLOWED_SENDER_DOMAINS = 'domain1.com,domain2.com,domain3.com';
      const email = createGraphEmail({
        from: { emailAddress: { address: 'user@domain2.com' } },
      });

      const result = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);

      expect(result.allowed).toBe(true);
    });

    it('should handle whitespace in comma-separated lists', () => {
      process.env.NODE_ENV = 'production';
      process.env.ALLOWED_SENDER_EMAILS = ' user@example.com , admin@example.com ';
      const email = createGraphEmail({
        from: { emailAddress: { address: 'admin@example.com' } },
      });

      const result = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);

      expect(result.allowed).toBe(true);
    });

    it('should reject sender not in allowlist', () => {
      process.env.NODE_ENV = 'production';
      process.env.ALLOWED_SENDER_EMAILS = 'allowed@example.com';
      process.env.ALLOWED_SENDER_DOMAINS = 'trusted.com';
      const email = createGraphEmail({
        from: { emailAddress: { address: 'attacker@malicious.com' } },
      });

      const result = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('sender-not-allowlisted');
    });

    it('should prioritize email allowlist over domain allowlist', () => {
      process.env.NODE_ENV = 'production';
      process.env.ALLOWED_SENDER_EMAILS = 'specific@blocked-domain.com';
      // Note: domain not in allowlist
      const email = createGraphEmail({
        from: { emailAddress: { address: 'specific@blocked-domain.com' } },
      });

      const result = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);

      expect(result.allowed).toBe(true);
    });
  });

  describe('isAutoResponder - Auto-Reply Detection', () => {
    it('should detect mailer-daemon in sender', () => {
      process.env.NODE_ENV = 'development';
      const email = createGraphEmail({
        from: { emailAddress: { address: 'mailer-daemon@example.com' } },
      });

      const result = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('auto-responder-detected');
    });

    it('should detect MAILER-DAEMON case-insensitive', () => {
      process.env.NODE_ENV = 'development';
      const email = createGraphEmail({
        from: { emailAddress: { address: 'MAILER-DAEMON@example.com' } },
      });

      const result = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('auto-responder-detected');
    });

    it('should detect postmaster in sender', () => {
      process.env.NODE_ENV = 'development';
      const email = createGraphEmail({
        from: { emailAddress: { address: 'postmaster@example.com' } },
      });

      const result = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('auto-responder-detected');
    });

    it('should detect auto-submitted: auto-replied header', () => {
      process.env.NODE_ENV = 'development';
      const email = createGraphEmail({
        internetMessageHeaders: [{ name: 'Auto-Submitted', value: 'auto-replied' }],
      });

      const result = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('auto-responder-detected');
    });

    it('should detect auto-submitted: auto-generated header', () => {
      process.env.NODE_ENV = 'development';
      const email = createGraphEmail({
        internetMessageHeaders: [{ name: 'Auto-Submitted', value: 'auto-generated' }],
      });

      const result = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('auto-responder-detected');
    });

    it('should detect auto-submitted: auto-notified header', () => {
      process.env.NODE_ENV = 'development';
      const email = createGraphEmail({
        internetMessageHeaders: [{ name: 'Auto-Submitted', value: 'auto-notified' }],
      });

      const result = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('auto-responder-detected');
    });

    it('should detect precedence: bulk header', () => {
      process.env.NODE_ENV = 'development';
      const email = createGraphEmail({
        internetMessageHeaders: [{ name: 'Precedence', value: 'bulk' }],
      });

      const result = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('auto-responder-detected');
    });

    it('should detect precedence: junk header', () => {
      process.env.NODE_ENV = 'development';
      const email = createGraphEmail({
        internetMessageHeaders: [{ name: 'Precedence', value: 'junk' }],
      });

      const result = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('auto-responder-detected');
    });

    it('should detect precedence: auto_reply header', () => {
      process.env.NODE_ENV = 'development';
      const email = createGraphEmail({
        internetMessageHeaders: [{ name: 'Precedence', value: 'auto_reply' }],
      });

      const result = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('auto-responder-detected');
    });

    it('should detect x-auto-response-suppress: all header', () => {
      process.env.NODE_ENV = 'development';
      const email = createGraphEmail({
        internetMessageHeaders: [{ name: 'X-Auto-Response-Suppress', value: 'All' }],
      });

      const result = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('auto-responder-detected');
    });

    it('should detect x-auto-response-suppress: DR header', () => {
      process.env.NODE_ENV = 'development';
      const email = createGraphEmail({
        internetMessageHeaders: [{ name: 'X-Auto-Response-Suppress', value: 'DR' }],
      });

      const result = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('auto-responder-detected');
    });

    it('should detect x-auto-response-suppress: AutoReply header', () => {
      process.env.NODE_ENV = 'development';
      const email = createGraphEmail({
        internetMessageHeaders: [{ name: 'X-Auto-Response-Suppress', value: 'AutoReply' }],
      });

      const result = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('auto-responder-detected');
    });

    it('should detect mailer-daemon in headers (not just sender)', () => {
      process.env.NODE_ENV = 'development';
      const email = createGraphEmail({
        internetMessageHeaders: [{ name: 'X-Original-Sender', value: 'mailer-daemon@example.com' }],
      });

      const result = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('auto-responder-detected');
    });

    it('should allow normal emails without auto-responder indicators', () => {
      process.env.NODE_ENV = 'development';
      const email = createGraphEmail({
        from: { emailAddress: { address: 'human@example.com' } },
        internetMessageHeaders: [
          { name: 'Subject', value: 'Normal email' },
          { name: 'Content-Type', value: 'text/plain' },
        ],
      });

      const result = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);

      expect(result.allowed).toBe(true);
    });
  });

  describe('Guard Order and Precedence', () => {
    it('should check sender before message ID', () => {
      const email = createGraphEmail({
        from: { emailAddress: { address: '' } },
        internetMessageId: '',
      });

      const result = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);

      // Should fail on sender first
      expect(result.reason).toBe('missing-sender');
    });

    it('should check message ID before duplicate check', () => {
      const email = createGraphEmail({
        internetMessageId: '',
        id: '',
      });

      const result = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);

      expect(result.reason).toBe('missing-message-id');
    });

    it('should check self-sender before allowlist', () => {
      process.env.NODE_ENV = 'production';
      process.env.ALLOWED_SENDER_EMAILS = 'phishing@company.com';
      const email = createGraphEmail({
        from: { emailAddress: { address: 'phishing@company.com' } },
      });

      const result = evaluateEmailGuards(email as any, 'phishing@company.com');

      // Should fail on self-sender even though email is allowlisted
      expect(result.reason).toBe('self-sender-detected');
    });

    it('should check allowlist before auto-responder', () => {
      process.env.NODE_ENV = 'production';
      // No allowlist configured
      const email = createGraphEmail({
        internetMessageHeaders: [{ name: 'Auto-Submitted', value: 'auto-replied' }],
      });

      const result = evaluateEmailGuards(email as any, MAILBOX_ADDRESS);

      // Should fail on allowlist before checking auto-responder
      expect(result.reason).toBe('sender-not-allowlisted');
    });
  });
});
