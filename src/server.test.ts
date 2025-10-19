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
