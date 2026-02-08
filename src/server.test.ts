import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { PhishingAgent } from './agents/phishing-agent.js';
import type { MailboxMonitor } from './services/mailbox-monitor.js';

// Mock dependencies using unstable_mockModule for ESM compatibility
vi.mock('./lib/logger.js', () => ({
  securityLogger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
    security: vi.fn(),
  },
}));

vi.mock('./lib/config.js', () => ({
  config: {
    server: { port: 3000, environment: 'test' },
    http: { helmetEnabled: false, bodyLimit: '4mb', healthCacheTtlMs: 30000 },
    llm: {
      apiKey: undefined,
      demoMode: false,
      timeoutMs: 10000,
      retryAttempts: 3,
      circuitBreakerThreshold: 5,
      circuitBreakerResetMs: 60000,
    },
    threatIntel: { enabled: false, timeoutMs: 5000, cacheTtlMs: 300000 },
  },
  isProduction: vi.fn().mockReturnValue(false),
}));

vi.mock('./services/llm-analyzer.js', () => ({
  shouldRunLlmAnalysis: vi.fn<any>().mockReturnValue(false),
  generateThreatExplanation: vi.fn<any>().mockResolvedValue(null),
  getLlmServiceStatus: vi.fn<any>().mockReturnValue({
    enabled: false,
    circuitBreakerState: 'not-initialized',
    consecutiveFailures: 0,
  }),
  healthCheck: vi.fn<any>().mockResolvedValue(true),
}));

// Import after mocks are set up
const { HttpServer } = await import('./server.js');

describe('HttpServer', () => {
  let server: InstanceType<typeof HttpServer>;
  let mockPhishingAgent: any;
  let mockMailboxMonitor: any;

  beforeEach(() => {
    vi.clearAllMocks();

    server = new HttpServer();

    mockPhishingAgent = {
      healthCheck: vi.fn(),
    };

    mockMailboxMonitor = {
      healthCheck: vi.fn(),
      getRateLimiter: vi.fn().mockReturnValue({ getStats: vi.fn() }),
      getDeduplication: vi.fn().mockReturnValue({ getStats: vi.fn() }),
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
        json: vi.fn(),
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
        json: vi.fn(),
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
        json: vi.fn(),
        status: vi.fn().mockReturnThis(),
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
        json: vi.fn(),
        status: vi.fn().mockReturnThis(),
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
        json: vi.fn(),
        status: vi.fn().mockReturnThis(),
      };

      await (server as any).handleReady(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(503);
      const response = mockRes.json.mock.calls[0][0];
      expect(response.mailboxMonitor).toBe(false);
    });

    it('should return not ready when components are not set', async () => {
      const mockReq: any = {};
      const mockRes: any = {
        json: vi.fn(),
        status: vi.fn().mockReturnThis(),
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
        json: vi.fn(),
        type: vi.fn().mockReturnThis(),
        send: vi.fn(),
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
        json: vi.fn(),
        type: vi.fn().mockReturnThis(),
        send: vi.fn(),
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
        json: vi.fn(),
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
      const mockRateLimiter = { getStats: vi.fn() };
      const mockDeduplication = { getStats: vi.fn() };

      mockMailboxMonitor.getRateLimiter = vi.fn().mockReturnValue(mockRateLimiter);
      mockMailboxMonitor.getDeduplication = vi.fn().mockReturnValue(mockDeduplication);

      server.setMailboxMonitor(mockMailboxMonitor as any);

      expect(mockMailboxMonitor.getRateLimiter).toHaveBeenCalled();
      expect(mockMailboxMonitor.getDeduplication).toHaveBeenCalled();
    });
  });

  describe('Server Startup', () => {
    it('should start server on configured port', async () => {
      const mockListen = vi.fn((port: number, callback: any) => {
        callback();
        return { close: vi.fn() };
      });

      (server as any).app.listen = mockListen;

      await server.start();

      expect(mockListen).toHaveBeenCalledWith(3000, expect.any(Function));
    });
  });
});
