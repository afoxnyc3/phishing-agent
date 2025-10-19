// @ts-nocheck - Test file with complex Jest mocks
import { describe, it, expect, jest, beforeEach } from '@jest/globals';
import { PhishingAgent } from './phishing-agent.js';
import { EmailAnalysisRequest } from '../lib/types.js';

// Mock all dependencies
jest.mock('../lib/logger.js', () => ({
  securityLogger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}));

jest.mock('../services/threat-intel.js', () => ({
  ThreatIntelService: jest.fn().mockImplementation(() => ({
    healthCheck: jest.fn().mockResolvedValue(true),
    enrichEmail: jest.fn().mockResolvedValue({
      indicators: [],
      riskContribution: 0,
    }),
  })),
}));

describe('PhishingAgent', () => {
  let agent: PhishingAgent;

  beforeEach(async () => {
    jest.clearAllMocks();
    agent = new PhishingAgent();
    await agent.initialize();
  });

  describe('Initialization', () => {
    it('should initialize successfully', async () => {
      const newAgent = new PhishingAgent();
      await expect(newAgent.initialize()).resolves.not.toThrow();
    });

    it('should check threat intel health during initialization', async () => {
      const newAgent = new PhishingAgent();
      await newAgent.initialize();

      expect((newAgent as any).initialized).toBe(true);
    });
  });

  describe('Email Analysis', () => {
    it('should throw error if not initialized', async () => {
      const uninitializedAgent = new PhishingAgent();

      const request: EmailAnalysisRequest = {
        messageId: 'test-1',
        subject: 'Test',
        sender: 'test@example.com',
        recipient: 'user@test.com',
        timestamp: new Date(),
        headers: {
          'message-id': 'test-1',
          from: 'test@example.com',
          to: 'user@test.com',
          subject: 'Test',
          date: new Date().toISOString(),
        },
      };

      await expect(uninitializedAgent.analyzeEmail(request)).rejects.toThrow('not initialized');
    });

    it('should analyze legitimate email correctly', async () => {
      const request: EmailAnalysisRequest = {
        messageId: 'test-1',
        subject: 'Test',
        sender: 'john@example.com',
        recipient: 'user@test.com',
        timestamp: new Date(),
        headers: {
          'message-id': 'test-1',
          from: 'john@example.com',
          to: 'user@test.com',
          subject: 'Test',
          date: new Date().toISOString(),
          'received-spf': 'pass',
          'authentication-results': 'spf=pass; dkim=pass; dmarc=pass',
        },
        body: 'Hello, this is a normal email.',
      };

      const result = await agent.analyzeEmail(request);

      expect(result.messageId).toBe('test-1');
      expect(result.analysisId).toBeTruthy();
      expect(result.analysisTimestamp).toBeInstanceOf(Date);
      expect(result.isPhishing).toBe(false);
      expect(result.riskScore).toBeLessThan(5.0);
      expect(result.severity).toBe('low');
    });

    it('should detect phishing email with failed headers', async () => {
      const request: EmailAnalysisRequest = {
        messageId: 'test-2',
        subject: 'URGENT: Verify Account',
        sender: 'fake@evil.com',
        recipient: 'victim@test.com',
        timestamp: new Date(),
        headers: {
          'message-id': 'test-2',
          from: 'fake@evil.com',
          to: 'victim@test.com',
          subject: 'URGENT: Verify Account',
          date: new Date().toISOString(),
          'received-spf': 'fail',
          'authentication-results': 'spf=fail; dkim=fail; dmarc=fail',
        },
        body: 'Your account will be suspended! Click here immediately!',
      };

      const result = await agent.analyzeEmail(request);

      expect(result.isPhishing).toBe(true);
      expect(result.riskScore).toBeGreaterThanOrEqual(5.0);
      expect(result.indicators.length).toBeGreaterThan(0);
      expect(result.severity).toMatch(/high|critical/);
    });

    it('should detect phishing with suspicious content patterns', async () => {
      const request: EmailAnalysisRequest = {
        messageId: 'test-3',
        subject: 'Prize Winner!',
        sender: 'notifications@company.com',
        recipient: 'user@test.com',
        timestamp: new Date(),
        headers: {
          'message-id': 'test-3',
          from: 'notifications@company.com',
          to: 'user@test.com',
          subject: 'Prize Winner!',
          date: new Date().toISOString(),
          'received-spf': 'fail',
          'authentication-results': 'spf=fail; dkim=pass; dmarc=pass',
        },
        body: `
          Urgent! You've won the lottery!
          Enter your password and credit card to claim your prize.
          Click here: https://192.168.1.1/claim
        `,
      };

      const result = await agent.analyzeEmail(request);

      expect(result.indicators.some(i => i.description.includes('Urgency'))).toBe(true);
      expect(result.indicators.some(i => i.description.includes('Credential'))).toBe(true);
      expect(result.riskScore).toBeGreaterThanOrEqual(5.0);
    });

    it('should detect brand impersonation', async () => {
      const request: EmailAnalysisRequest = {
        messageId: 'test-4',
        subject: 'PayPal Account Alert',
        sender: 'security@paypa1-secure.com',
        recipient: 'user@test.com',
        timestamp: new Date(),
        headers: {
          'message-id': 'test-4',
          from: 'security@paypa1-secure.com',
          to: 'user@test.com',
          subject: 'PayPal Account Alert',
          date: new Date().toISOString(),
        },
        body: 'Your PayPal account needs verification. Click here immediately.',
      };

      const result = await agent.analyzeEmail(request);

      const brandIndicator = result.indicators.find(i => i.description.includes('PayPal'));
      expect(brandIndicator).toBeDefined();
      expect(brandIndicator?.severity).toBe('critical');
    });
  });

  describe('Threat Intel Integration', () => {
    it('should enrich analysis with threat intel data', async () => {
      const mockThreatIntel = {
        healthCheck: jest.fn().mockResolvedValue(true),
        enrichEmail: jest.fn().mockResolvedValue({
          indicators: [
            {
              type: 'url',
              description: 'Malicious URL detected by VirusTotal',
              severity: 'critical',
              evidence: 'Detected by 10/15 scanners',
              confidence: 0.9,
            },
          ],
          riskContribution: 2.5,
        }),
      };

      (agent as any).threatIntel = mockThreatIntel;

      const request: EmailAnalysisRequest = {
        messageId: 'test-5',
        subject: 'Test',
        sender: 'test@example.com',
        recipient: 'user@test.com',
        timestamp: new Date(),
        headers: {
          'message-id': 'test-5',
          from: 'test@example.com',
          to: 'user@test.com',
          subject: 'Test',
          date: new Date().toISOString(),
        },
        body: 'Click here: https://evil.com',
      };

      const result = await agent.analyzeEmail(request);

      expect(mockThreatIntel.enrichEmail).toHaveBeenCalled();
      expect(result.indicators.some(i => i.description.includes('VirusTotal'))).toBe(true);
      expect(result.riskScore).toBeGreaterThan(0);
    });

    it('should continue analysis if threat intel fails', async () => {
      const mockThreatIntel = {
        healthCheck: jest.fn().mockResolvedValue(true),
        enrichEmail: jest.fn().mockRejectedValue(new Error('API Error')),
      };

      (agent as any).threatIntel = mockThreatIntel;

      const request: EmailAnalysisRequest = {
        messageId: 'test-6',
        subject: 'Test',
        sender: 'test@example.com',
        recipient: 'user@test.com',
        timestamp: new Date(),
        headers: {
          'message-id': 'test-6',
          from: 'test@example.com',
          to: 'user@test.com',
          subject: 'Test',
          date: new Date().toISOString(),
        },
      };

      const result = await agent.analyzeEmail(request);

      expect(result).toBeDefined();
      expect(result.messageId).toBe('test-6');
    });
  });

  describe('Severity Determination', () => {
    it('should boost severity with high threat intel contribution', async () => {
      const mockThreatIntel = {
        healthCheck: jest.fn().mockResolvedValue(true),
        enrichEmail: jest.fn().mockResolvedValue({
          indicators: [
            {
              type: 'url',
              description: 'Malicious URL',
              severity: 'critical',
              evidence: 'test',
              confidence: 0.95,
            },
          ],
          riskContribution: 3.0,
        }),
      };

      (agent as any).threatIntel = mockThreatIntel;

      const request: EmailAnalysisRequest = {
        messageId: 'test-7',
        subject: 'URGENT',
        sender: 'phisher@evil.com',
        recipient: 'victim@test.com',
        timestamp: new Date(),
        headers: {
          'message-id': 'test-7',
          from: 'phisher@evil.com',
          to: 'victim@test.com',
          subject: 'URGENT',
          date: new Date().toISOString(),
          'received-spf': 'fail',
          'authentication-results': 'spf=fail; dkim=fail; dmarc=fail',
        },
        body: 'Enter your password now!',
      };

      const result = await agent.analyzeEmail(request);

      expect(result.severity).toBe('critical');
      expect(result.riskScore).toBeGreaterThan(8.0);
    });
  });

  describe('IP Extraction', () => {
    it('should extract IP from Received header', async () => {
      const request: EmailAnalysisRequest = {
        messageId: 'test-8',
        subject: 'Test',
        sender: 'test@example.com',
        recipient: 'user@test.com',
        timestamp: new Date(),
        headers: {
          'message-id': 'test-8',
          from: 'test@example.com',
          to: 'user@test.com',
          subject: 'Test',
          date: new Date().toISOString(),
          received: 'from mail.example.com [192.168.1.100]',
        },
      };

      const ip = (agent as any).extractSenderIP(request.headers);
      expect(ip).toBe('192.168.1.100');
    });

    it('should extract IP from X-Originating-IP header', async () => {
      const request: EmailAnalysisRequest = {
        messageId: 'test-9',
        subject: 'Test',
        sender: 'test@example.com',
        recipient: 'user@test.com',
        timestamp: new Date(),
        headers: {
          'message-id': 'test-9',
          from: 'test@example.com',
          to: 'user@test.com',
          subject: 'Test',
          date: new Date().toISOString(),
          'x-originating-ip': '10.0.0.1',
        },
      };

      const ip = (agent as any).extractSenderIP(request.headers);
      expect(ip).toBe('10.0.0.1');
    });

    it('should return null if no IP found', async () => {
      const request: EmailAnalysisRequest = {
        messageId: 'test-10',
        subject: 'Test',
        sender: 'test@example.com',
        recipient: 'user@test.com',
        timestamp: new Date(),
        headers: {
          'message-id': 'test-10',
          from: 'test@example.com',
          to: 'user@test.com',
          subject: 'Test',
          date: new Date().toISOString(),
        },
      };

      const ip = (agent as any).extractSenderIP(request.headers);
      expect(ip).toBeNull();
    });
  });

  describe('Error Handling', () => {
    it('should handle analysis errors gracefully', async () => {
      // Force an error by passing invalid data
      const request: any = {
        messageId: 'test-error',
        headers: null, // This will cause an error
      };

      const result = await agent.analyzeEmail(request);

      expect(result.messageId).toBe('test-error');
      expect(result.severity).toBe('medium');
      expect(result.indicators.length).toBeGreaterThan(0);
      expect(result.indicators[0].description).toContain('Analysis error');
      expect(result.recommendedActions[0].action).toBe('flag_for_review');
    });

    it('should include error details in result', async () => {
      const request: any = {
        messageId: 'test-error-2',
        headers: null,
      };

      const result = await agent.analyzeEmail(request);

      expect(result.indicators[0].type).toBe('behavioral');
      expect(result.indicators[0].confidence).toBe(1.0);
    });
  });

  describe('Health Check', () => {
    it('should pass health check when components healthy', async () => {
      const health = await agent.healthCheck();
      expect(health).toBe(true);
    });

    it('should handle health check errors', async () => {
      const mockThreatIntel = {
        healthCheck: jest.fn().mockRejectedValue(new Error('Health check failed')),
      };

      (agent as any).threatIntel = mockThreatIntel;

      const health = await agent.healthCheck();
      expect(health).toBe(false);
    });
  });

  describe('Shutdown', () => {
    it('should shutdown gracefully', async () => {
      await agent.shutdown();
      expect((agent as any).initialized).toBe(false);
    });

    it('should prevent analysis after shutdown', async () => {
      await agent.shutdown();

      const request: EmailAnalysisRequest = {
        messageId: 'test-shutdown',
        subject: 'Test',
        sender: 'test@example.com',
        recipient: 'user@test.com',
        timestamp: new Date(),
        headers: {
          'message-id': 'test-shutdown',
          from: 'test@example.com',
          to: 'user@test.com',
          subject: 'Test',
          date: new Date().toISOString(),
        },
      };

      await expect(agent.analyzeEmail(request)).rejects.toThrow('not initialized');
    });
  });

  describe('Analysis ID Generation', () => {
    it('should generate unique analysis IDs', async () => {
      const request: EmailAnalysisRequest = {
        messageId: 'test-id',
        subject: 'Test',
        sender: 'test@example.com',
        recipient: 'user@test.com',
        timestamp: new Date(),
        headers: {
          'message-id': 'test-id',
          from: 'test@example.com',
          to: 'user@test.com',
          subject: 'Test',
          date: new Date().toISOString(),
        },
      };

      const result1 = await agent.analyzeEmail(request);
      const result2 = await agent.analyzeEmail(request);

      expect(result1.analysisId).not.toBe(result2.analysisId);
      expect(result1.analysisId).toMatch(/^analysis-/);
      expect(result2.analysisId).toMatch(/^analysis-/);
    });
  });
});
