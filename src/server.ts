/**
 * HTTP Server
 * Minimal Express server for health checks
 * All functions are atomic (max 25 lines)
 */

import express, { Request, Response } from 'express';
import helmet from 'helmet';
import { securityLogger } from './lib/logger.js';
import { config, isProduction } from './lib/config.js';
import { PhishingAgent } from './agents/phishing-agent.js';
import { MailboxMonitor } from './services/mailbox-monitor.js';
import { metrics } from './services/metrics.js';
import { correlationMetrics } from './lib/correlation-metrics.js';
import { healthChecker, SystemHealth } from './services/health-checker.js';
import { NextFunction } from 'express';
import { ResilientCacheProvider } from './lib/resilient-cache-provider.js';
import { createWebhookRouter } from './services/webhook-route.js';
import type { NotificationQueue } from './services/notification-queue.js';

// Health check cache for /health/deep to avoid Graph API rate limiting
let deepHealthCache: { result: SystemHealth; timestamp: number } | null = null;

export class HttpServer {
  private app: express.Application;
  private phishingAgent?: PhishingAgent;
  private mailboxMonitor?: MailboxMonitor;
  private notificationQueue?: NotificationQueue;

  constructor() {
    this.app = express();
    this.setupMiddleware();
    this.setupRoutes();
  }

  /**
   * Setup middleware with security hardening
   */
  private setupMiddleware(): void {
    // Add Helmet security headers
    if (config.http.helmetEnabled) {
      if (isProduction()) {
        // Production: strict security headers
        this.app.use(
          helmet({
            contentSecurityPolicy: {
              directives: {
                defaultSrc: ["'self'"],
                scriptSrc: ["'self'"],
                styleSrc: ["'self'"],
                imgSrc: ["'self'"],
                connectSrc: ["'self'"],
                fontSrc: ["'self'"],
                objectSrc: ["'none'"],
                frameSrc: ["'none'"],
              },
            },
            hsts: {
              maxAge: 31536000,
              includeSubDomains: true,
              preload: true,
            },
          })
        );
        // Trust proxy for proper IP logging behind Azure load balancer
        this.app.set('trust proxy', 1);
      } else {
        // Development: basic helmet config
        this.app.use(helmet());
      }
    }

    // Body parsing with size limits
    this.app.use(express.json({ limit: config.http.bodyLimit }));

    // Request logging
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
    this.setupWebhookRoute();

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

  /** Register webhook route (public, no auth — Graph API must reach it) */
  private setupWebhookRoute(): void {
    const clientState = process.env.WEBHOOK_CLIENT_STATE || '';
    if (clientState) {
      const onNotification = (ids: string[]): void => {
        this.notificationQueue?.enqueue(ids);
      };
      this.app.use(createWebhookRouter(clientState, onNotification));
      securityLogger.info('Webhook route registered at POST /webhooks/mail');
    }
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
   * Handle deep health check with caching to avoid Graph API rate limiting
   */
  private async handleDeepHealth(req: Request, res: Response): Promise<void> {
    const now = Date.now();
    const cacheTtlMs = config.http.healthCacheTtlMs;

    // Return cached result if still fresh
    if (deepHealthCache && now - deepHealthCache.timestamp < cacheTtlMs) {
      const cached = deepHealthCache.result;
      res.status(cached.healthy ? 200 : 503).json({ ...cached, cached: true });
      return;
    }

    // Perform fresh health check
    const health = await healthChecker.checkHealth();

    // Cache the result
    deepHealthCache = { result: health, timestamp: now };

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
      res.json({
        ...metrics.getMetrics(),
        correlation: correlationMetrics.getSnapshot(),
      });
    } else {
      const base = metrics.getPrometheusMetrics();
      const corr = correlationMetrics.getPrometheusMetrics();
      res.type('text/plain').send(`${base}\n\n${corr}`);
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
   * Set notification queue for async webhook processing
   */
  setNotificationQueue(queue: NotificationQueue): void {
    this.notificationQueue = queue;
  }

  /**
   * Set cache provider for health checks
   */
  setCacheProvider(cache: ResilientCacheProvider): void {
    healthChecker.setCacheProvider(cache);
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
