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
    this.app.get('/health', this.handleHealth.bind(this));
    this.app.get('/ready', this.handleReady.bind(this));
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
  }

  /**
   * Set mailbox monitor
   */
  setMailboxMonitor(monitor: MailboxMonitor): void {
    this.mailboxMonitor = monitor;
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
}
