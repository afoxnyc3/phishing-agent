/**
 * Email Processor Tests
 * Tests for email processing pipeline with rate limiting and deduplication
 */

import { describe, it, expect, beforeEach, jest } from '@jest/globals';

// Mock dependencies
jest.unstable_mockModule('../lib/logger.js', () => ({
  securityLogger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
    security: jest.fn(),
  },
}));

jest.unstable_mockModule('./metrics.js', () => ({
  metrics: {
    recordEmailProcessed: jest.fn(),
    recordAnalysisLatency: jest.fn(),
    recordReplyLatency: jest.fn(),
    recordReplySent: jest.fn(),
    recordReplyFailed: jest.fn(),
    recordDeduplicationHit: jest.fn(),
    recordRateLimitHit: jest.fn(),
    recordAnalysisError: jest.fn(),
  },
}));

const mockEvaluateEmailGuards = jest.fn();
jest.unstable_mockModule('./email-guards.js', () => ({
  evaluateEmailGuards: mockEvaluateEmailGuards,
  __testResetMessageIdCache: jest.fn(),
}));

jest.unstable_mockModule('./graph-email-parser.js', () => ({
  parseGraphEmail: jest.fn().mockReturnValue({
    messageId: 'test-msg-id',
    subject: 'Test Subject',
    from: 'sender@example.com',
    body: 'Test body content',
    headers: {},
    receivedDate: new Date(),
  }),
}));

jest.unstable_mockModule('./email-reply-builder.js', () => ({
  buildReplyHtml: jest.fn().mockReturnValue('<html>Reply</html>'),
  buildErrorReplyHtml: jest.fn().mockReturnValue('<html>Error</html>'),
  createReplyMessage: jest.fn().mockReturnValue({ message: {} }),
}));

const { processEmail } = await import('./email-processor.js');
const { metrics } = await import('./metrics.js');

describe('Email Processor', () => {
  // Mock objects with proper typing - declare outside, reset in beforeEach
  let mockPost: jest.Mock<() => Promise<object>>;
  let mockGraphClient: { api: jest.Mock; post: jest.Mock };
  let mockAnalyzeEmail: jest.Mock<() => Promise<object>>;
  let mockPhishingAgent: { analyzeEmail: jest.Mock };
  let mockRateLimiter: {
    canSendEmail: jest.Mock;
    recordEmailSent: jest.Mock;
    getStats: jest.Mock;
  };
  let mockDeduplication: {
    shouldProcess: jest.Mock;
    recordProcessed: jest.Mock;
  };

  beforeEach(() => {
    mockPost = jest.fn<() => Promise<object>>().mockResolvedValue({});
    mockGraphClient = {
      api: jest.fn().mockReturnThis(),
      post: mockPost,
    };

    mockAnalyzeEmail = jest.fn<() => Promise<object>>().mockResolvedValue({
      messageId: 'test-msg-id',
      isPhishing: true,
      confidence: 0.9,
      riskScore: 8.5,
      severity: 'high',
      indicators: [],
      recommendedActions: [],
      analysisTimestamp: new Date(),
      analysisId: 'analysis-123',
    });

    mockPhishingAgent = {
      analyzeEmail: mockAnalyzeEmail,
    };

    mockRateLimiter = {
      canSendEmail: jest.fn().mockReturnValue({ allowed: true }),
      recordEmailSent: jest.fn(),
      getStats: jest.fn().mockReturnValue({ lastHour: 1 }),
    };

    mockDeduplication = {
      shouldProcess: jest.fn().mockReturnValue({ allowed: true }),
      recordProcessed: jest.fn(),
    };

    mockEvaluateEmailGuards.mockReturnValue({ allowed: true });
  });

  const createMockConfig = () => ({
    mailboxAddress: 'phishing@example.com',
    graphClient: mockGraphClient as any,
    phishingAgent: mockPhishingAgent as any,
    rateLimiter: mockRateLimiter as any,
    deduplication: mockDeduplication as any,
  });

  const createMockEmail = (overrides = {}) => ({
    id: 'email-123',
    subject: 'Test Subject',
    from: { emailAddress: { address: 'sender@example.com' } },
    body: { content: 'Test body content', contentType: 'text' },
    bodyPreview: 'Test preview',
    receivedDateTime: new Date().toISOString(),
    ...overrides,
  });

  describe('processEmail', () => {
    it('should process email through full pipeline', async () => {
      const config = createMockConfig();
      const email = createMockEmail();

      await processEmail(email as any, config);

      expect(mockPhishingAgent.analyzeEmail).toHaveBeenCalled();
      expect(mockGraphClient.api).toHaveBeenCalled();
      expect(mockDeduplication.recordProcessed).toHaveBeenCalled();
    });

    it('should skip processing when guards block email', async () => {
      mockEvaluateEmailGuards.mockReturnValue({
        allowed: false,
        reason: 'Self-sent email detected',
      });

      const config = createMockConfig();
      const email = createMockEmail();

      await processEmail(email as any, config);

      expect(mockPhishingAgent.analyzeEmail).not.toHaveBeenCalled();
      expect(metrics.recordDeduplicationHit).toHaveBeenCalled();
    });

    it('should skip processing when deduplication blocks', async () => {
      mockDeduplication.shouldProcess.mockReturnValue({
        allowed: false,
        reason: 'Duplicate content',
      });

      const config = createMockConfig();
      const email = createMockEmail();

      await processEmail(email as any, config);

      expect(mockPhishingAgent.analyzeEmail).not.toHaveBeenCalled();
      expect(metrics.recordDeduplicationHit).toHaveBeenCalled();
    });

    it('should handle missing sender email', async () => {
      const config = createMockConfig();
      const email = createMockEmail({
        from: { emailAddress: { address: undefined } },
      });

      await processEmail(email as any, config);

      // Should still analyze but not send reply
      expect(mockPhishingAgent.analyzeEmail).toHaveBeenCalled();
    });
  });

  describe('rate limiting', () => {
    it('should block reply when rate limit exceeded', async () => {
      mockRateLimiter.canSendEmail.mockReturnValue({
        allowed: false,
        reason: 'Hourly limit reached',
      });

      const config = createMockConfig();
      const email = createMockEmail();

      await processEmail(email as any, config);

      expect(mockPhishingAgent.analyzeEmail).toHaveBeenCalled();
      expect(mockGraphClient.post).not.toHaveBeenCalled();
      expect(metrics.recordRateLimitHit).toHaveBeenCalled();
    });

    it('should record email sent after successful reply', async () => {
      const config = createMockConfig();
      const email = createMockEmail();

      await processEmail(email as any, config);

      expect(mockRateLimiter.recordEmailSent).toHaveBeenCalled();
    });
  });

  describe('error handling', () => {
    it('should handle analysis errors gracefully', async () => {
      mockAnalyzeEmail.mockRejectedValueOnce(new Error('Analysis failed'));

      const config = createMockConfig();
      const email = createMockEmail();

      await expect(processEmail(email as any, config)).resolves.not.toThrow();
      expect(metrics.recordAnalysisError).toHaveBeenCalled();
    });

    it('should send error reply on processing failure', async () => {
      mockAnalyzeEmail.mockRejectedValueOnce(new Error('Analysis failed'));

      const config = createMockConfig();
      const email = createMockEmail();

      await processEmail(email as any, config);

      // Should attempt to send error reply
      expect(mockGraphClient.api).toHaveBeenCalled();
    });

    it('should handle reply sending errors', async () => {
      mockPost.mockRejectedValueOnce(new Error('Send failed'));

      const config = createMockConfig();
      const email = createMockEmail();

      await expect(processEmail(email as any, config)).resolves.not.toThrow();
      expect(metrics.recordReplyFailed).toHaveBeenCalled();
    });
  });

  describe('metrics recording', () => {
    it('should record email processed metric', async () => {
      const config = createMockConfig();
      const email = createMockEmail();

      await processEmail(email as any, config);

      expect(metrics.recordEmailProcessed).toHaveBeenCalledWith(true); // isPhishing = true
    });

    it('should record analysis latency', async () => {
      const config = createMockConfig();
      const email = createMockEmail();

      await processEmail(email as any, config);

      expect(metrics.recordAnalysisLatency).toHaveBeenCalled();
    });

    it('should record reply latency on successful send', async () => {
      const config = createMockConfig();
      const email = createMockEmail();

      await processEmail(email as any, config);

      expect(metrics.recordReplyLatency).toHaveBeenCalled();
      expect(metrics.recordReplySent).toHaveBeenCalled();
    });
  });

  describe('context extraction', () => {
    it('should handle email with no subject', async () => {
      const config = createMockConfig();
      const email = createMockEmail({ subject: undefined });

      await expect(processEmail(email as any, config)).resolves.not.toThrow();
    });

    it('should handle email with no body', async () => {
      const config = createMockConfig();
      const email = createMockEmail({ body: undefined, bodyPreview: 'Preview only' });

      await expect(processEmail(email as any, config)).resolves.not.toThrow();
    });

    it('should use bodyPreview when body.content is empty', async () => {
      const config = createMockConfig();
      const email = createMockEmail({
        body: { content: '', contentType: 'text' },
        bodyPreview: 'This is the preview',
      });

      await expect(processEmail(email as any, config)).resolves.not.toThrow();
    });
  });
});
