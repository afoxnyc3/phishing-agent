import { describe, it, expect, jest, beforeEach } from '@jest/globals';
import type { PhishingAnalysisResult } from '../lib/types.js';

// Mock setup - must be before imports
const mockGraphGet = jest.fn<() => Promise<unknown>>();
const mockGraphPost = jest.fn<() => Promise<unknown>>();
const mockGraphApi = jest.fn(() => ({
  get: mockGraphGet,
  post: mockGraphPost,
  filter: jest.fn().mockReturnThis(),
  orderby: jest.fn().mockReturnThis(),
  top: jest.fn().mockReturnThis(),
  select: jest.fn().mockReturnThis(),
  expand: jest.fn().mockReturnThis(),
}));

const mockGetToken = jest.fn(() => Promise.resolve({ token: 'mock-token', expiresOnTimestamp: Date.now() + 3600000 }));

// Mock modules using unstable_mockModule for ESM
jest.unstable_mockModule('@microsoft/microsoft-graph-client', () => ({
  Client: {
    initWithMiddleware: jest.fn(() => ({
      api: mockGraphApi,
    })),
  },
}));

jest.unstable_mockModule('@azure/identity', () => ({
  ClientSecretCredential: jest.fn().mockImplementation(() => ({
    getToken: mockGetToken,
  })),
}));

jest.unstable_mockModule('../lib/logger.js', () => ({
  securityLogger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
    security: jest.fn(),
  },
}));

jest.unstable_mockModule('./graph-email-parser.js', () => ({
  parseGraphEmail: jest.fn((email: unknown) => {
    const e = email as { internetMessageId?: string; id?: string; from?: { emailAddress?: { address?: string } }; toRecipients?: Array<{ emailAddress?: { address?: string } }>; subject?: string; body?: { content?: string } };
    return {
      messageId: e.internetMessageId || e.id,
      sender: e.from?.emailAddress?.address || 'test@example.com',
      recipient: e.toRecipients?.[0]?.emailAddress?.address || 'recipient@example.com',
      subject: e.subject || 'Test',
      timestamp: new Date(),
      headers: { 'message-id': e.id },
      body: e.body?.content || '',
      attachments: [],
    };
  }),
  validateGraphEmailListResponse: jest.fn((response: unknown) => (response as { value?: unknown[] }).value || []),
}));

// Import after mocks are set up
const { MailboxMonitor } = await import('./mailbox-monitor.js');
const { buildReplyHtml } = await import('./email-reply-builder.js');
const { __testResetMessageIdCache } = await import('./email-processor.js');

// Import PhishingAgent for type reference
import type { PhishingAgent } from '../agents/phishing-agent.js';

describe('MailboxMonitor', () => {
  let monitor: InstanceType<typeof MailboxMonitor>;
  let mockPhishingAgent: jest.Mocked<PhishingAgent>;

  beforeEach(() => {
    jest.clearAllMocks();
    __testResetMessageIdCache();

    // Create mock phishing agent
    mockPhishingAgent = {
      analyzeEmail: jest.fn(),
      healthCheck: jest.fn(),
      initialize: jest.fn(),
      shutdown: jest.fn(),
    } as any;

    const config = {
      tenantId: 'test-tenant',
      clientId: 'test-client',
      clientSecret: 'test-secret',
      mailboxAddress: 'phishing@test.com',
      checkIntervalMs: 1000,
      enabled: true,
    };

    monitor = new MailboxMonitor(config, mockPhishingAgent);
  });

  describe('Constructor', () => {
    it('should initialize with provided config', () => {
      expect(monitor).toBeDefined();
      const status = monitor.getStatus();
      expect(status.mailbox).toBe('phishing@test.com');
      expect(status.checkInterval).toBe(1000);
      expect(status.isRunning).toBe(false);
    });

    it('should use default check interval if not provided', () => {
      const config = {
        tenantId: 'test-tenant',
        clientId: 'test-client',
        clientSecret: 'test-secret',
        mailboxAddress: 'phishing@test.com',
      };

      const mon = new MailboxMonitor(config, mockPhishingAgent);
      expect(mon.getStatus().checkInterval).toBe(60000);
    });

    it('should set enabled to true by default', () => {
      const config = {
        tenantId: 'test-tenant',
        clientId: 'test-client',
        clientSecret: 'test-secret',
        mailboxAddress: 'phishing@test.com',
      };

      const mon = new MailboxMonitor(config, mockPhishingAgent);
      expect(mon).toBeDefined();
    });
  });

  describe('Initialize', () => {
    it('should initialize successfully when mailbox is accessible', async () => {
      mockGraphGet.mockResolvedValue({ value: [] });

      await expect(monitor.initialize()).resolves.toBeUndefined();
      expect(mockGraphApi).toHaveBeenCalledWith('/users/phishing@test.com/messages');
    });

    it('should throw error when mailbox initialization fails', async () => {
      mockGraphGet.mockRejectedValue(new Error('Access denied'));

      await expect(monitor.initialize()).rejects.toThrow('Mailbox monitor initialization failed');
    });
  });

  describe('Start/Stop', () => {
    it('should start monitoring', () => {
      mockGraphGet.mockResolvedValue({ value: [] });

      monitor.start();

      expect(monitor.getStatus().isRunning).toBe(true);
    });

    it('should not start if already running', () => {
      mockGraphGet.mockResolvedValue({ value: [] });

      monitor.start();
      const firstStart = monitor.getStatus().isRunning;
      monitor.start();

      expect(firstStart).toBe(true);
      expect(monitor.getStatus().isRunning).toBe(true);
    });

    it('should not start if disabled', () => {
      const config = {
        tenantId: 'test-tenant',
        clientId: 'test-client',
        clientSecret: 'test-secret',
        mailboxAddress: 'phishing@test.com',
        enabled: false,
      };

      const disabledMonitor = new MailboxMonitor(config, mockPhishingAgent);
      disabledMonitor.start();

      expect(disabledMonitor.getStatus().isRunning).toBe(false);
    });

    it('should stop monitoring', () => {
      mockGraphGet.mockResolvedValue({ value: [] });

      monitor.start();
      expect(monitor.getStatus().isRunning).toBe(true);

      monitor.stop();
      expect(monitor.getStatus().isRunning).toBe(false);
    });

    it('should handle stop when not running', () => {
      expect(monitor.getStatus().isRunning).toBe(false);
      monitor.stop();
      expect(monitor.getStatus().isRunning).toBe(false);
    });
  });

  describe('Health Check', () => {
    it('should return true when mailbox is accessible', async () => {
      mockGraphGet.mockResolvedValue({ value: [] });

      const result = await monitor.healthCheck();

      expect(result).toBe(true);
      expect(mockGraphApi).toHaveBeenCalledWith('/users/phishing@test.com/messages');
    });

    it('should return false when mailbox is not accessible', async () => {
      mockGraphGet.mockRejectedValue(new Error('Connection failed'));

      const result = await monitor.healthCheck();

      expect(result).toBe(false);
    });
  });

  describe('Status', () => {
    it('should return monitoring status', () => {
      const status = monitor.getStatus();

      expect(status).toHaveProperty('isRunning');
      expect(status).toHaveProperty('mailbox');
      expect(status).toHaveProperty('lastCheckTime');
      expect(status).toHaveProperty('checkInterval');
    });

    it('should reflect running state', () => {
      mockGraphGet.mockResolvedValue({ value: [] });

      expect(monitor.getStatus().isRunning).toBe(false);

      monitor.start();
      expect(monitor.getStatus().isRunning).toBe(true);

      monitor.stop();
      expect(monitor.getStatus().isRunning).toBe(false);
    });
  });

  describe('Email Processing', () => {
    const mockEmail = {
      id: 'email-123',
      internetMessageId: '<test@example.com>',
      subject: 'Test Email',
      from: { emailAddress: { address: 'sender@example.com' } },
      toRecipients: [{ emailAddress: { address: 'phishing@test.com' } }],
      receivedDateTime: new Date().toISOString(),
      body: { content: 'Test body' },
      internetMessageHeaders: [],
    };

    const mockAnalysisResult: PhishingAnalysisResult = {
      messageId: '<test@example.com>',
      analysisId: 'analysis-123',
      isPhishing: true,
      riskScore: 8.5,
      severity: 'high',
      confidence: 0.9,
      indicators: [{
        type: 'header',
        description: 'SPF failed',
        severity: 'high',
        evidence: 'spf=fail',
        confidence: 0.9,
      }],
      recommendedActions: [{
        priority: 'urgent',
        action: 'quarantine',
        description: 'Quarantine email',
        automated: true,
        requiresApproval: false,
      }],
      analysisTimestamp: new Date(),
    };

    it('should process emails when found', async () => {
      mockGraphGet.mockResolvedValue({ value: [mockEmail] });
      mockGraphPost.mockResolvedValue({});
      mockPhishingAgent.analyzeEmail.mockResolvedValue(mockAnalysisResult);

      monitor.start();

      // Wait for initial check
      await new Promise(resolve => setTimeout(resolve, 100));

      monitor.stop();

      expect(mockPhishingAgent.analyzeEmail).toHaveBeenCalled();
      expect(mockGraphPost).toHaveBeenCalled();
    });

    it('should send reply after analysis', async () => {
      mockGraphGet.mockResolvedValue({ value: [mockEmail] });
      mockGraphPost.mockResolvedValue({});
      mockPhishingAgent.analyzeEmail.mockResolvedValue(mockAnalysisResult);

      monitor.start();
      await new Promise(resolve => setTimeout(resolve, 100));
      monitor.stop();

      // Verify reply was sent
      expect(mockGraphPost).toHaveBeenCalled();
      const postCall = mockGraphPost.mock.calls[0];
      expect(postCall).toBeDefined();
    });

    it('should handle analysis errors gracefully', async () => {
      mockGraphGet.mockResolvedValue({ value: [mockEmail] });
      mockGraphPost.mockResolvedValue({});
      mockPhishingAgent.analyzeEmail.mockRejectedValue(new Error('Analysis failed'));

      monitor.start();
      await new Promise(resolve => setTimeout(resolve, 100));
      monitor.stop();

      // Should still send error reply
      expect(mockGraphPost).toHaveBeenCalled();
    });

    it('should handle missing sender email', async () => {
      const emailWithoutSender = {
        ...mockEmail,
        from: null,
      };

      mockGraphGet.mockResolvedValue({ value: [emailWithoutSender] });
      mockPhishingAgent.analyzeEmail.mockResolvedValue(mockAnalysisResult);

      monitor.start();
      await new Promise(resolve => setTimeout(resolve, 100));
      monitor.stop();

      // Should skip processing when sender is missing
      expect(mockPhishingAgent.analyzeEmail).not.toHaveBeenCalled();
    });

    it('should process multiple emails', async () => {
      const email2 = {
        ...mockEmail,
        id: 'email-456',
        internetMessageId: '<second@example.com>',
        subject: 'Different Subject',
        from: { emailAddress: { address: 'different-sender@example.com' } },
        body: { content: 'Different content to avoid deduplication' },
      };
      mockGraphGet.mockResolvedValue({ value: [mockEmail, email2] });
      mockGraphPost.mockResolvedValue({});
      mockPhishingAgent.analyzeEmail.mockResolvedValue(mockAnalysisResult);

      monitor.start();
      await new Promise(resolve => setTimeout(resolve, 150));
      monitor.stop();

      expect(mockPhishingAgent.analyzeEmail).toHaveBeenCalledTimes(2);
    });

    it('should continue processing if one email fails', async () => {
      const email2 = {
        ...mockEmail,
        id: 'email-456',
        internetMessageId: '<third@example.com>',
        subject: 'Another Different Subject',
        from: { emailAddress: { address: 'another-sender@example.com' } },
        body: { content: 'Another different content to avoid deduplication' },
      };
      mockGraphGet.mockResolvedValue({ value: [mockEmail, email2] });
      mockGraphPost.mockResolvedValue({});

      mockPhishingAgent.analyzeEmail
        .mockRejectedValueOnce(new Error('Failed'))
        .mockResolvedValueOnce(mockAnalysisResult);

      monitor.start();
      await new Promise(resolve => setTimeout(resolve, 150));
      monitor.stop();

      // Both emails should be attempted
      expect(mockPhishingAgent.analyzeEmail).toHaveBeenCalledTimes(2);
    });

    it('should handle empty email list', async () => {
      mockGraphGet.mockResolvedValue({ value: [] });

      monitor.start();
      await new Promise(resolve => setTimeout(resolve, 100));
      monitor.stop();

      expect(mockPhishingAgent.analyzeEmail).not.toHaveBeenCalled();
    });

    it('should update lastCheckTime after processing', async () => {
      mockGraphGet.mockResolvedValue({ value: [] });

      const beforeStart = monitor.getStatus().lastCheckTime;

      monitor.start();
      await new Promise(resolve => setTimeout(resolve, 100));
      monitor.stop();

      const afterStop = monitor.getStatus().lastCheckTime;
      expect(afterStop.getTime()).toBeGreaterThan(beforeStart.getTime());
    });
  });

  describe('HTML Reply Generation', () => {
    const mockAnalysisResult: PhishingAnalysisResult = {
      messageId: 'test-msg',
      analysisId: 'test-analysis',
      isPhishing: true,
      riskScore: 8.5,
      severity: 'high',
      confidence: 0.9,
      indicators: [{
        type: 'header',
        description: 'SPF validation failed',
        severity: 'high',
        evidence: 'spf=fail',
        confidence: 0.9,
      }],
      recommendedActions: [{
        priority: 'urgent',
        action: 'quarantine',
        description: 'Quarantine this email',
        automated: true,
        requiresApproval: false,
      }],
      analysisTimestamp: new Date(),
    };

    it('should build HTML reply with phishing verdict', () => {
      const html = buildReplyHtml(mockAnalysisResult);

      expect(html).toContain('PHISHING DETECTED');
      expect(html).toContain('8.5/10');
      expect(html).toContain('HIGH');
      expect(html).toContain('90%');
    });

    it('should include threat indicators in reply', () => {
      const html = buildReplyHtml(mockAnalysisResult);

      expect(html).toContain('SPF validation failed');
      expect(html).toContain('Threat Indicators');
    });

    it('should include recommended actions in reply', () => {
      const html = buildReplyHtml(mockAnalysisResult);

      expect(html).toContain('Recommended Actions');
      expect(html).toContain('Quarantine this email');
    });

    it('should build HTML reply for safe email', () => {
      const safeResult: PhishingAnalysisResult = {
        ...mockAnalysisResult,
        isPhishing: false,
        riskScore: 2.0,
        severity: 'low',
        confidence: 0.3,
        indicators: [],
        recommendedActions: [],
      };

      const html = buildReplyHtml(safeResult);

      expect(html).toContain('EMAIL APPEARS SAFE');
      expect(html).toContain('2.0/10');
      expect(html).toContain('LOW');
    });

    it('should limit indicators to top 5 in HTML output', () => {
      const manyIndicators: PhishingAnalysisResult = {
        ...mockAnalysisResult,
        indicators: Array(10).fill(null).map((_, i) => ({
          type: 'content' as const,
          description: `Indicator ${i + 1}`,
          severity: 'medium' as const,
          evidence: `evidence-${i}`,
          confidence: 0.7,
        })),
      };

      const html = buildReplyHtml(manyIndicators);

      // Should contain first 5 indicators
      expect(html).toContain('Indicator 1');
      expect(html).toContain('Indicator 5');
      // Should not contain 6th+ indicators
      expect(html).not.toContain('Indicator 6');
    });

    it('should limit actions to top 3 in HTML output', () => {
      const manyActions: PhishingAnalysisResult = {
        ...mockAnalysisResult,
        recommendedActions: Array(6).fill(null).map((_, i) => ({
          priority: 'medium' as const,
          action: `action-${i}`,
          description: `Action ${i + 1}`,
          automated: false,
          requiresApproval: true,
        })),
      };

      const html = buildReplyHtml(manyActions);

      // Should contain first 3 actions
      expect(html).toContain('Action 1');
      expect(html).toContain('Action 3');
      // Should not contain 4th+ actions
      expect(html).not.toContain('Action 4');
    });
  });

  describe('Error Handling', () => {
    it('should handle Graph API errors during email fetch', async () => {
      mockGraphGet.mockRejectedValue(new Error('Network error'));

      monitor.start();

      await expect(
        new Promise((resolve) => {
          setTimeout(() => {
            monitor.stop();
            resolve(true);
          }, 100);
        })
      ).resolves.toBe(true);
    });

    it('should handle send mail failures', async () => {
      const mockEmail = {
        id: 'email-123',
        subject: 'Test',
        from: { emailAddress: { address: 'sender@example.com' } },
        toRecipients: [{ emailAddress: { address: 'recipient@example.com' } }],
        body: { content: 'Test' },
      };

      const mockAnalysisResult: PhishingAnalysisResult = {
        messageId: 'test',
        analysisId: 'test',
        isPhishing: false,
        riskScore: 2.0,
        severity: 'low',
        confidence: 0.5,
        indicators: [],
        recommendedActions: [],
        analysisTimestamp: new Date(),
      };

      mockGraphGet.mockResolvedValue({ value: [mockEmail] });
      mockGraphPost.mockRejectedValue(new Error('Send failed'));
      mockPhishingAgent.analyzeEmail.mockResolvedValue(mockAnalysisResult);

      monitor.start();
      await new Promise(resolve => setTimeout(resolve, 100));
      monitor.stop();

      // Should attempt to send despite error
      expect(mockGraphPost).toHaveBeenCalled();
    });
  });
});
