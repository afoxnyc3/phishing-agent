import { describe, it, expect, jest, beforeEach } from '@jest/globals';
import { HttpServer } from './server.js';
import { PhishingAgent } from './agents/phishing-agent.js';
import { MailboxMonitor } from './services/mailbox-monitor.js';

// Mock dependencies
jest.mock('./lib/logger.js', () => ({
  securityLogger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
    security: jest.fn(),
  },
}));

jest.mock('./lib/config.js', () => ({
  config: {
    server: {
      port: 3000,
    },
  },
}));

describe('HttpServer', () => {
  let server: HttpServer;
  let mockPhishingAgent: any;
  let mockMailboxMonitor: any;

  beforeEach(() => {
    jest.clearAllMocks();

    server = new HttpServer();

    mockPhishingAgent = {
      healthCheck: jest.fn(),
    };

    mockMailboxMonitor = {
      healthCheck: jest.fn(),
      getRateLimiter: jest.fn().mockReturnValue({ getStats: jest.fn() }),
      getDeduplication: jest.fn().mockReturnValue({ getStats: jest.fn() }),
    };
  });

  describe('Constructor', () => {
    it('should initialize HTTP server', () => {
      expect(server).toBeDefined();
    });
  });

  describe('Health Check Endpoint', () => {
    it('should return healthy status', async () => {
      const mockReq: any = {};
      const mockRes: any = {
        json: jest.fn(),
      };

      await (server as any).handleHealth(mockReq, mockRes);

      expect(mockRes.json).toHaveBeenCalled();
      const response = mockRes.json.mock.calls[0][0];
      expect(response.status).toBe('healthy');
      expect(response.timestamp).toBeDefined();
      expect(response.uptime).toBeGreaterThanOrEqual(0);
    });

    it('should include uptime in health check', async () => {
      const mockReq: any = {};
      const mockRes: any = {
        json: jest.fn(),
      };

      await (server as any).handleHealth(mockReq, mockRes);

      const response = mockRes.json.mock.calls[0][0];
      expect(typeof response.uptime).toBe('number');
    });
  });

  describe('Readiness Check Endpoint', () => {
    it('should return ready when both components are healthy', async () => {
      mockPhishingAgent.healthCheck.mockResolvedValue(true);
      mockMailboxMonitor.healthCheck.mockResolvedValue(true);

      server.setPhishingAgent(mockPhishingAgent as PhishingAgent);
      server.setMailboxMonitor(mockMailboxMonitor as MailboxMonitor);

      const mockReq: any = {};
      const mockRes: any = {
        json: jest.fn(),
        status: jest.fn().mockReturnThis(),
      };

      await (server as any).handleReady(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.json).toHaveBeenCalled();
      const response = mockRes.json.mock.calls[0][0];
      expect(response.status).toBe('ready');
      expect(response.phishingAgent).toBe(true);
      expect(response.mailboxMonitor).toBe(true);
    });

    it('should return not ready when phishing agent is unhealthy', async () => {
      mockPhishingAgent.healthCheck.mockResolvedValue(false);
      mockMailboxMonitor.healthCheck.mockResolvedValue(true);

      server.setPhishingAgent(mockPhishingAgent as PhishingAgent);
      server.setMailboxMonitor(mockMailboxMonitor as MailboxMonitor);

      const mockReq: any = {};
      const mockRes: any = {
        json: jest.fn(),
        status: jest.fn().mockReturnThis(),
      };

      await (server as any).handleReady(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(503);
      expect(mockRes.json).toHaveBeenCalled();
      const response = mockRes.json.mock.calls[0][0];
      expect(response.status).toBe('not ready');
      expect(response.phishingAgent).toBe(false);
    });

    it('should return not ready when mailbox monitor is unhealthy', async () => {
      mockPhishingAgent.healthCheck.mockResolvedValue(true);
      mockMailboxMonitor.healthCheck.mockResolvedValue(false);

      server.setPhishingAgent(mockPhishingAgent as PhishingAgent);
      server.setMailboxMonitor(mockMailboxMonitor as MailboxMonitor);

      const mockReq: any = {};
      const mockRes: any = {
        json: jest.fn(),
        status: jest.fn().mockReturnThis(),
      };

      await (server as any).handleReady(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(503);
      const response = mockRes.json.mock.calls[0][0];
      expect(response.mailboxMonitor).toBe(false);
    });

    it('should return not ready when components are not set', async () => {
      const mockReq: any = {};
      const mockRes: any = {
        json: jest.fn(),
        status: jest.fn().mockReturnThis(),
      };

      await (server as any).handleReady(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(503);
      const response = mockRes.json.mock.calls[0][0];
      expect(response.status).toBe('not ready');
      expect(response.phishingAgent).toBe(false);
      expect(response.mailboxMonitor).toBe(false);
    });
  });

  describe('Metrics Endpoint', () => {
    it('should return JSON metrics when Accept header is application/json', () => {
      const mockReq: any = {
        headers: {
          accept: 'application/json',
        },
      };
      const mockRes: any = {
        json: jest.fn(),
        type: jest.fn().mockReturnThis(),
        send: jest.fn(),
      };

      (server as any).handleMetrics(mockReq, mockRes);

      expect(mockRes.json).toHaveBeenCalled();
      const response = mockRes.json.mock.calls[0][0];
      expect(response).toHaveProperty('uptime');
      expect(response).toHaveProperty('business');
      expect(response).toHaveProperty('latency');
    });

    it('should return Prometheus format when Accept header is not application/json', () => {
      const mockReq: any = {
        headers: {
          accept: 'text/plain',
        },
      };
      const mockRes: any = {
        json: jest.fn(),
        type: jest.fn().mockReturnThis(),
        send: jest.fn(),
      };

      (server as any).handleMetrics(mockReq, mockRes);

      expect(mockRes.type).toHaveBeenCalledWith('text/plain');
      expect(mockRes.send).toHaveBeenCalled();
      const response = mockRes.send.mock.calls[0][0];
      expect(response).toContain('phishing_agent_uptime_ms');
      expect(response).toContain('# TYPE');
      expect(response).toContain('# HELP');
    });
  });

  describe('Root Endpoint', () => {
    it('should return service information', () => {
      const mockReq: any = {};
      const mockRes: any = {
        json: jest.fn(),
      };

      (server as any).handleRoot(mockReq, mockRes);

      expect(mockRes.json).toHaveBeenCalled();
      const response = mockRes.json.mock.calls[0][0];
      expect(response.name).toBe('Phishing Agent');
      expect(response.version).toBeDefined();
      expect(response.status).toBe('running');
    });
  });

  describe('Component Setters', () => {
    it('should set phishing agent', () => {
      server.setPhishingAgent(mockPhishingAgent as PhishingAgent);
      expect((server as any).phishingAgent).toBe(mockPhishingAgent);
    });

    it('should set mailbox monitor', () => {
      server.setMailboxMonitor(mockMailboxMonitor as MailboxMonitor);
      expect((server as any).mailboxMonitor).toBe(mockMailboxMonitor);
    });

    it('should wire rate limiter and deduplication when setting mailbox monitor', () => {
      const mockRateLimiter = { getStats: jest.fn() };
      const mockDeduplication = { getStats: jest.fn() };

      mockMailboxMonitor.getRateLimiter = jest.fn().mockReturnValue(mockRateLimiter);
      mockMailboxMonitor.getDeduplication = jest.fn().mockReturnValue(mockDeduplication);

      server.setMailboxMonitor(mockMailboxMonitor as any);

      expect(mockMailboxMonitor.getRateLimiter).toHaveBeenCalled();
      expect(mockMailboxMonitor.getDeduplication).toHaveBeenCalled();
    });
  });

  describe('Server Startup', () => {
    it('should start server on configured port', async () => {
      const mockListen = jest.fn((port: number, callback: any) => {
        callback();
        return { close: jest.fn() };
      });

      (server as any).app.listen = mockListen;

      await server.start();

      expect(mockListen).toHaveBeenCalledWith(3000, expect.any(Function));
    });
  });
});
