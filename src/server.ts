/**
 * HTTP Server
 * Minimal Express server for health checks
 * All functions are atomic (max 25 lines)
 */

import express, { Request, Response } from 'express';
import { securityLogger } from './lib/logger.js';
import { config } from './lib/config.js';
import { PhishingAgent } from './agents/phishing-agent.js';
import { MailboxMonitor } from './services/mailbox-monitor.js';
import { metrics } from './services/metrics.js';
import { healthChecker } from './services/health-checker.js';
import { NextFunction } from 'express';

export class HttpServer {
  private app: express.Application;
  private phishingAgent?: PhishingAgent;
  private mailboxMonitor?: MailboxMonitor;

  constructor() {
    this.app = express();
    this.setupMiddleware();
    this.setupRoutes();
  }

  /**
   * Setup middleware
   */
  private setupMiddleware(): void {
    this.app.use(express.json());
    this.app.use((req, res, next) => {
      securityLogger.debug('HTTP request', {
        method: req.method,
        path: req.path,
        ip: req.ip,
      });
      next();
    });
  }

  /**
   * Setup routes
   */
  private setupRoutes(): void {
    const securedRouter = express.Router();
    securedRouter.use(this.authenticateRequest.bind(this));
    securedRouter.use(this.rateLimit.bind(this));

    securedRouter.get('/health', this.handleHealth.bind(this));
    securedRouter.get('/health/deep', this.handleDeepHealth.bind(this));
    securedRouter.get('/ready', this.handleReady.bind(this));
    securedRouter.get('/metrics', this.handleMetrics.bind(this));

    this.app.use(securedRouter);
    this.app.get('/', this.handleRoot.bind(this));
  }

  /**
   * Handle health check
   */
  private async handleHealth(req: Request, res: Response): Promise<void> {
    const health = {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
    };

    res.json(health);
  }

  /**
   * Handle deep health check
   */
  private async handleDeepHealth(req: Request, res: Response): Promise<void> {
    const health = await healthChecker.checkHealth();

    res.status(health.healthy ? 200 : 503).json(health);
  }

  /**
   * Handle readiness check
   */
  private async handleReady(req: Request, res: Response): Promise<void> {
    const agentHealthy = this.phishingAgent ? await this.phishingAgent.healthCheck() : false;
    const mailboxHealthy = this.mailboxMonitor ? await this.mailboxMonitor.healthCheck() : false;

    const ready = {
      status: agentHealthy && mailboxHealthy ? 'ready' : 'not ready',
      timestamp: new Date().toISOString(),
      phishingAgent: agentHealthy,
      mailboxMonitor: mailboxHealthy,
    };

    res.status(agentHealthy && mailboxHealthy ? 200 : 503).json(ready);
  }

  /**
   * Handle metrics endpoint
   */
  private handleMetrics(req: Request, res: Response): void {
    const accept = req.headers.accept || '';

    if (accept.includes('application/json')) {
      // Return JSON metrics
      res.json(metrics.getMetrics());
    } else {
      // Return Prometheus-formatted metrics
      res.type('text/plain').send(metrics.getPrometheusMetrics());
    }
  }

  /**
   * Handle root
   */
  private handleRoot(req: Request, res: Response): void {
    res.json({
      name: 'Phishing Agent',
      version: '1.0.0',
      status: 'running',
    });
  }

  /**
   * Set phishing agent
   */
  setPhishingAgent(agent: PhishingAgent): void {
    this.phishingAgent = agent;
    healthChecker.setPhishingAgent(agent);
  }

  /**
   * Set mailbox monitor
   */
  setMailboxMonitor(monitor: MailboxMonitor): void {
    this.mailboxMonitor = monitor;
    healthChecker.setMailboxMonitor(monitor);
    healthChecker.setRateLimiter(monitor.getRateLimiter());
    healthChecker.setDeduplication(monitor.getDeduplication());
  }

  /**
   * Start server
   */
  async start(): Promise<void> {
    const port = config.server.port;

    return new Promise((resolve) => {
      this.app.listen(port, () => {
        securityLogger.info('HTTP server started', { port });
        resolve();
      });
    });
  }

  /**
   * Authentication middleware for operational endpoints
   */
  private authenticateRequest(req: Request, res: Response, next: NextFunction): void {
    const apiKey = process.env.API_KEY || process.env.HEALTH_API_KEY || process.env.METRICS_API_KEY;
    const authHeader = req.headers.authorization || '';
    const headerToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : undefined;
    const providedKey = headerToken || (req.headers['x-api-key'] as string | undefined);

    // Fail secure in production if no key configured
    if (!apiKey && config.server.environment === 'production') {
      securityLogger.error('Operational endpoint blocked - missing API key configuration');
      res.status(503).json({ status: 'unavailable', message: 'API key not configured' });
      return;
    }

    if (apiKey && providedKey !== apiKey) {
      res.status(401).json({ status: 'unauthorized' });
      return;
    }

    next();
  }

  /**
   * Lightweight rate limiting for operational endpoints
   */
  private rateLimit(req: Request, res: Response, next: NextFunction): void {
    const windowMs = 60 * 1000;
    const maxRequests = 60;
    const now = Date.now();
    const key = req.ip || 'unknown';

    const bucket = rateLimitBuckets.get(key) || { count: 0, resetAt: now + windowMs };

    if (now > bucket.resetAt) {
      bucket.count = 0;
      bucket.resetAt = now + windowMs;
    }

    bucket.count += 1;
    rateLimitBuckets.set(key, bucket);

    if (bucket.count > maxRequests) {
      res.status(429).json({ status: 'rate_limited', retryAfterMs: bucket.resetAt - now });
      return;
    }

    next();
  }
}

const rateLimitBuckets: Map<string, { count: number; resetAt: number }> = new Map();
