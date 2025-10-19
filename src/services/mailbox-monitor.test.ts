import { describe, it, expect, jest, beforeEach } from '@jest/globals';
import { MailboxMonitor, MailboxMonitorConfig } from './mailbox-monitor.js';
import { PhishingAgent } from '../agents/phishing-agent.js';
import { PhishingAnalysisResult } from '../lib/types.js';

// Mock dependencies
jest.mock('../lib/logger.js', () => ({
  securityLogger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
    security: jest.fn(),
  },
}));

jest.mock('@azure/identity', () => {
  const mockGetToken: any = jest.fn();
  return {
    ClientSecretCredential: jest.fn().mockImplementation(() => ({
      getToken: mockGetToken.mockResolvedValue({ token: 'mock-token' }),
    })),
  };
});

jest.mock('@microsoft/microsoft-graph-client', () => ({
  Client: {
    initWithMiddleware: jest.fn().mockReturnValue({
      api: jest.fn(),
    }),
  },
}));

describe('MailboxMonitor', () => {
  let mockConfig: MailboxMonitorConfig;
  let mockPhishingAgent: PhishingAgent;
  let mockClient: any;
  let monitor: MailboxMonitor;

  beforeEach(() => {
    jest.clearAllMocks();

    mockConfig = {
      tenantId: 'test-tenant',
      clientId: 'test-client',
      clientSecret: 'test-secret',
      mailboxAddress: 'phishing@test.com',
      checkIntervalMs: 5000,
      enabled: true,
    };

    mockPhishingAgent = {
      analyzeEmail: jest.fn() as unknown as (req: any) => Promise<PhishingAnalysisResult>,
      initialize: jest.fn() as unknown as () => Promise<void>,
    } as PhishingAgent;

    mockClient = {
      api: jest.fn().mockReturnThis(),
      get: jest.fn(),
      post: jest.fn(),
      filter: jest.fn().mockReturnThis(),
      orderby: jest.fn().mockReturnThis(),
      top: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      expand: jest.fn().mockReturnThis(),
    };

    const { Client } = require('@microsoft/microsoft-graph-client');
    Client.initWithMiddleware.mockReturnValue(mockClient);

    monitor = new MailboxMonitor(mockConfig, mockPhishingAgent);
  });

  describe('Constructor', () => {
    it('should initialize with provided config', () => {
      expect(monitor).toBeDefined();
      const status = monitor.getStatus();
      expect(status.mailbox).toBe('phishing@test.com');
      expect(status.checkInterval).toBe(5000);
    });

    it('should use default check interval if not provided', () => {
      const configWithoutInterval = { ...mockConfig };
      delete configWithoutInterval.checkIntervalMs;
      const mon = new MailboxMonitor(configWithoutInterval, mockPhishingAgent);
      expect(mon.getStatus().checkInterval).toBe(60000);
    });

    it('should set lastCheckTime to 5 minutes ago', () => {
      const status = monitor.getStatus();
      const fiveMinutesAgo = Date.now() - 5 * 60 * 1000;
      expect(status.lastCheckTime.getTime()).toBeGreaterThanOrEqual(fiveMinutesAgo - 1000);
      expect(status.lastCheckTime.getTime()).toBeLessThanOrEqual(fiveMinutesAgo + 1000);
    });
  });

  describe('Initialization', () => {
    it('should initialize successfully when mailbox is accessible', async () => {
      mockClient.get.mockResolvedValue({ value: [] });

      await expect(monitor.initialize()).resolves.toBeUndefined();
      expect(mockClient.api).toHaveBeenCalledWith('/users/phishing@test.com/messages');
    });

    it('should throw error when mailbox initialization fails', async () => {
      mockClient.get.mockRejectedValue(new Error('Access denied'));

      await expect(monitor.initialize()).rejects.toThrow(
        'Mailbox monitor initialization failed: Access denied'
      );
    });
  });

  describe('Start/Stop Monitoring', () => {
    it('should start monitoring when not running', () => {
      monitor.start();
      expect(monitor.getStatus().isRunning).toBe(true);
    });

    it('should not start if already running', () => {
      monitor.start();
      const firstStatus = monitor.getStatus().isRunning;
      monitor.start(); // Try to start again
      expect(firstStatus).toBe(true);
      expect(monitor.getStatus().isRunning).toBe(true);
    });

    it('should not start if disabled', () => {
      const disabledConfig = { ...mockConfig, enabled: false };
      const disabledMonitor = new MailboxMonitor(disabledConfig, mockPhishingAgent);
      disabledMonitor.start();
      expect(disabledMonitor.getStatus().isRunning).toBe(false);
    });

    it('should stop monitoring when running', () => {
      monitor.start();
      expect(monitor.getStatus().isRunning).toBe(true);
      monitor.stop();
      expect(monitor.getStatus().isRunning).toBe(false);
    });

    it('should handle stop when not running', () => {
      expect(monitor.getStatus().isRunning).toBe(false);
      monitor.stop(); // Should not throw
      expect(monitor.getStatus().isRunning).toBe(false);
    });
  });

  describe('Health Check', () => {
    it('should return true when mailbox is accessible', async () => {
      mockClient.get.mockResolvedValue({ value: [] });

      const result = await monitor.healthCheck();
      expect(result).toBe(true);
    });

    it('should return false when mailbox is not accessible', async () => {
      mockClient.get.mockRejectedValue(new Error('Connection failed'));

      const result = await monitor.healthCheck();
      expect(result).toBe(false);
    });
  });

  describe('Status', () => {
    it('should return current monitoring status', () => {
      const status = monitor.getStatus();

      expect(status).toHaveProperty('isRunning');
      expect(status).toHaveProperty('mailbox');
      expect(status).toHaveProperty('lastCheckTime');
      expect(status).toHaveProperty('checkInterval');
      expect(status.mailbox).toBe('phishing@test.com');
    });

    it('should reflect running state correctly', () => {
      expect(monitor.getStatus().isRunning).toBe(false);
      monitor.start();
      expect(monitor.getStatus().isRunning).toBe(true);
      monitor.stop();
      expect(monitor.getStatus().isRunning).toBe(false);
    });
  });

  describe('Email Fetching', () => {
    it('should fetch new emails with correct filter', async () => {
      mockClient.get.mockResolvedValue({ value: [] });
      monitor.start();

      // Wait a bit for initial check
      await new Promise(resolve => setTimeout(resolve, 100));
      monitor.stop();

      expect(mockClient.filter).toHaveBeenCalled();
      expect(mockClient.orderby).toHaveBeenCalledWith('receivedDateTime asc');
      expect(mockClient.top).toHaveBeenCalledWith(50);
    });
  });

  describe('Email Processing', () => {
    const mockEmail = {
      id: 'test-email-1',
      subject: 'Test Email',
      from: { emailAddress: { address: 'sender@example.com' } },
      receivedDateTime: new Date().toISOString(),
      body: { content: 'Test body', contentType: 'text' },
      internetMessageHeaders: [],
      internetMessageId: '<test@example.com>',
      hasAttachments: false,
    };

    const mockAnalysisResult: PhishingAnalysisResult = {
      messageId: 'test-msg-id',
      analysisId: 'test-analysis-id',
      isPhishing: true,
      riskScore: 8.5,
      severity: 'high',
      confidence: 0.9,
      indicators: [
        {
          type: 'header',
          description: 'SPF failed',
          severity: 'high',
          evidence: 'spf=fail',
          confidence: 0.9,
        },
      ],
      recommendedActions: [
        {
          priority: 'urgent',
          action: 'quarantine_email',
          description: 'Quarantine this email immediately',
          automated: true,
          requiresApproval: false,
        },
      ],
      analysisTimestamp: new Date(),
    };

    it('should process email and send reply successfully', async () => {
      mockClient.get.mockResolvedValue({ value: [mockEmail] });
      mockClient.post.mockResolvedValue({});
      (mockPhishingAgent.analyzeEmail as any).mockResolvedValue(mockAnalysisResult);

      monitor.start();
      await new Promise(resolve => setTimeout(resolve, 100));
      monitor.stop();

      expect(mockPhishingAgent.analyzeEmail).toHaveBeenCalled();
      expect(mockClient.post).toHaveBeenCalled();
    });

    it('should send error reply when analysis fails', async () => {
      mockClient.get.mockResolvedValue({ value: [mockEmail] });
      mockClient.post.mockResolvedValue({});
      (mockPhishingAgent.analyzeEmail as any).mockRejectedValue(new Error('Analysis failed'));

      monitor.start();
      await new Promise(resolve => setTimeout(resolve, 100));
      monitor.stop();

      // Error reply should still be sent
      expect(mockClient.post).toHaveBeenCalled();
    });

    it('should handle missing sender email gracefully', async () => {
      const emailWithoutSender = { ...mockEmail, from: null };
      mockClient.get.mockResolvedValue({ value: [emailWithoutSender] });
      (mockPhishingAgent.analyzeEmail as any).mockResolvedValue(mockAnalysisResult);

      monitor.start();
      await new Promise(resolve => setTimeout(resolve, 100));
      monitor.stop();

      // Should not crash, but also not send reply
      expect(mockPhishingAgent.analyzeEmail).toHaveBeenCalled();
    });
  });

  describe('HTML Reply Building', () => {
    it('should build HTML with phishing verdict', () => {
      const analysis: PhishingAnalysisResult = {
        messageId: 'test',
        analysisId: 'test-analysis',
        isPhishing: true,
        riskScore: 8.5,
        severity: 'high',
        confidence: 0.9,
        indicators: [
          { type: 'header', description: 'SPF failed', severity: 'high', evidence: 'spf=fail', confidence: 0.9 },
        ],
        recommendedActions: [
          { priority: 'urgent', action: 'quarantine', description: 'Quarantine email', automated: true, requiresApproval: false },
        ],
        analysisTimestamp: new Date(),
      };

      const html = (monitor as any).buildReplyHtml(analysis);

      expect(html).toContain('PHISHING DETECTED');
      expect(html).toContain('8.5/10');
      expect(html).toContain('HIGH');
      expect(html).toContain('90%');
      expect(html).toContain('SPF failed');
    });

    it('should build HTML with safe verdict', () => {
      const analysis: PhishingAnalysisResult = {
        messageId: 'test',
        analysisId: 'test-analysis',
        isPhishing: false,
        riskScore: 2.0,
        severity: 'low',
        confidence: 0.3,
        indicators: [],
        recommendedActions: [],
        analysisTimestamp: new Date(),
      };

      const html = (monitor as any).buildReplyHtml(analysis);

      expect(html).toContain('EMAIL APPEARS SAFE');
      expect(html).toContain('2.0/10');
      expect(html).toContain('LOW');
    });
  });

  describe('Error Handling', () => {
    it('should continue processing other emails if one fails', async () => {
      const email1 = {
        id: 'email-1',
        subject: 'Email 1',
        from: { emailAddress: { address: 'sender1@example.com' } },
        body: { content: 'Body 1' },
        internetMessageHeaders: [],
      };

      const email2 = {
        id: 'email-2',
        subject: 'Email 2',
        from: { emailAddress: { address: 'sender2@example.com' } },
        body: { content: 'Body 2' },
        internetMessageHeaders: [],
      };

      mockClient.get.mockResolvedValue({ value: [email1, email2] });
      mockClient.post.mockResolvedValue({});

      const mockAnalyze: any = mockPhishingAgent.analyzeEmail;
      mockAnalyze
        .mockRejectedValueOnce(new Error('Analysis failed'))
        .mockResolvedValueOnce({
          messageId: 'test',
          analysisId: 'test',
          isPhishing: false,
          riskScore: 2.0,
          severity: 'low',
          confidence: 0.5,
          indicators: [],
          recommendedActions: [],
          analysisTimestamp: new Date(),
        });

      monitor.start();
      await new Promise(resolve => setTimeout(resolve, 150));
      monitor.stop();

      // Both emails should be processed despite first one failing
      expect(mockPhishingAgent.analyzeEmail).toHaveBeenCalledTimes(2);
    });
  });
});
