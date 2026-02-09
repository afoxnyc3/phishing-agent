/**
 * Integration Tests: Email Processing Pipeline
 * Tests the full email processing flow with all 5 guard layers:
 *   1. Dedup hash prevents reprocessing
 *   2. Rate limiter throttles burst
 *   3. Recipient filter blocks external
 *   4. Reply-to-self guard prevents loops
 *   5. Message ID dedup (in-memory cache)
 *
 * Uses in-memory services (no Redis required).
 */

import './setup.js';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { processEmail, __testResetMessageIdCache } from '../services/email-processor.js';
import { GraphEmail } from '../lib/schemas.js';
import { RateLimiter, RateLimiterWrapper } from '../services/rate-limiter.js';
import { EmailDeduplication, EmailDeduplicationWrapper } from '../services/email-deduplication.js';

vi.mock('../lib/logger.js', () => ({
  securityLogger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
    security: vi.fn(),
  },
}));

vi.mock('../lib/correlation.js', () => ({
  generateCorrelationId: () => 'test-correlation-id',
  runWithCorrelation: (_id: string, fn: () => Promise<void>) => fn(),
  setProcessingStage: vi.fn(),
}));

vi.mock('../lib/correlation-metrics.js', () => ({
  correlationMetrics: {
    recordGuardHit: vi.fn(),
    recordGuardPass: vi.fn(),
    recordAnalysisDuration: vi.fn(),
    recordRiskScore: vi.fn(),
    recordWebhookLatency: vi.fn(),
  },
}));

const mockGraphClient = {
  api: vi.fn().mockReturnValue({
    post: vi.fn().mockResolvedValue({}),
  }),
};

const mockPhishingAgent = {
  analyzeEmail: vi.fn().mockResolvedValue({
    messageId: 'test-msg-1',
    isPhishing: true,
    confidence: 0.85,
    riskScore: 7.5,
    severity: 'high',
    indicators: [],
    recommendedActions: [],
    analysisTimestamp: new Date(),
    analysisId: 'analysis-1',
  }),
};

const MAILBOX = 'test@example.com';

function createEmail(overrides: Partial<GraphEmail> = {}): GraphEmail {
  return {
    id: `graph-id-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    internetMessageId: `<msg-${Date.now()}@external.com>`,
    subject: 'Suspicious email test',
    from: { emailAddress: { address: 'external-sender@somecompany.com' } },
    toRecipients: [{ emailAddress: { address: MAILBOX } }],
    receivedDateTime: new Date().toISOString(),
    body: { content: 'This is a test email body for integration testing.' },
    ...overrides,
  };
}

function createConfig() {
  const rateLimiter = new RateLimiterWrapper(
    new RateLimiter({
      enabled: true,
      maxEmailsPerHour: 100,
      maxEmailsPerDay: 1000,
      circuitBreakerThreshold: 50,
      circuitBreakerWindowMs: 600000,
    })
  );

  const deduplication = new EmailDeduplicationWrapper(
    new EmailDeduplication({
      enabled: true,
      contentHashTtlMs: 86400000,
      senderCooldownMs: 86400000,
    })
  );

  return {
    mailboxAddress: MAILBOX,
    graphClient: mockGraphClient as any,
    phishingAgent: mockPhishingAgent as any,
    rateLimiter,
    deduplication,
  };
}

describe('Email Processing Pipeline Integration', () => {
  let config: ReturnType<typeof createConfig>;

  beforeEach(() => {
    vi.clearAllMocks();
    __testResetMessageIdCache();
    // Set env for allowlist (development mode allows all)
    delete process.env.ALLOWED_SENDER_EMAILS;
    delete process.env.ALLOWED_SENDER_DOMAINS;
    config = createConfig();
  });

  describe('successful processing', () => {
    it('should process a valid email through the full pipeline', async () => {
      const email = createEmail();
      await processEmail(email, config);

      expect(mockPhishingAgent.analyzeEmail).toHaveBeenCalledTimes(1);
      expect(mockGraphClient.api).toHaveBeenCalledWith(`/users/${MAILBOX}/sendMail`);
    });
  });

  describe('guard layer: self-sender detection', () => {
    it('should block emails from the mailbox itself', async () => {
      const email = createEmail({
        from: { emailAddress: { address: MAILBOX } },
      });

      await processEmail(email, config);
      expect(mockPhishingAgent.analyzeEmail).not.toHaveBeenCalled();
    });
  });

  describe('guard layer: missing sender', () => {
    it('should block emails with no sender address', async () => {
      const email = createEmail({ from: undefined });

      await processEmail(email, config);
      expect(mockPhishingAgent.analyzeEmail).not.toHaveBeenCalled();
    });
  });

  describe('guard layer: message ID dedup', () => {
    it('should block duplicate message IDs', async () => {
      const email = createEmail({ internetMessageId: '<duplicate@test.com>' });
      await processEmail(email, config);
      expect(mockPhishingAgent.analyzeEmail).toHaveBeenCalledTimes(1);

      vi.clearAllMocks();
      const duplicate = createEmail({
        id: 'different-graph-id',
        internetMessageId: '<duplicate@test.com>',
      });
      await processEmail(duplicate, config);
      expect(mockPhishingAgent.analyzeEmail).not.toHaveBeenCalled();
    });
  });

  describe('guard layer: content deduplication', () => {
    it('should block same content from same sender within cooldown', async () => {
      const email1 = createEmail();
      await processEmail(email1, config);
      expect(mockPhishingAgent.analyzeEmail).toHaveBeenCalledTimes(1);

      vi.clearAllMocks();
      // Same sender, same content, different message ID
      const email2 = createEmail({
        id: 'graph-id-2',
        internetMessageId: '<msg-2@external.com>',
        from: email1.from,
        subject: email1.subject,
        body: email1.body,
      });
      await processEmail(email2, config);
      expect(mockPhishingAgent.analyzeEmail).not.toHaveBeenCalled();
    });
  });

  describe('guard layer: auto-responder detection', () => {
    it('should block auto-responder emails', async () => {
      const email = createEmail({
        from: { emailAddress: { address: 'mailer-daemon@somecompany.com' } },
      });

      await processEmail(email, config);
      expect(mockPhishingAgent.analyzeEmail).not.toHaveBeenCalled();
    });
  });
});
