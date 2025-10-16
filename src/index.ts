/**
 * Phishing Agent - Main Entry Point
 * Automated phishing email detection service
 */

import { securityLogger } from './lib/logger.js';
import { config } from './lib/config.js';
import { PhishingAgent } from './agents/phishing-agent.js';
import { MailboxMonitor } from './services/mailbox-monitor.js';
import { HttpServer } from './server.js';

/**
 * Main application
 */
class Application {
  private phishingAgent!: PhishingAgent;
  private mailboxMonitor!: MailboxMonitor;
  private httpServer!: HttpServer;

  /**
   * Initialize application
   */
  async initialize(): Promise<void> {
    securityLogger.info('Initializing Phishing Agent...');

    // Initialize phishing agent
    this.phishingAgent = new PhishingAgent();
    await this.phishingAgent.initialize();

    // Initialize mailbox monitor
    this.mailboxMonitor = new MailboxMonitor(
      {
        tenantId: config.azure.tenantId,
        clientId: config.azure.clientId,
        clientSecret: config.azure.clientSecret || '',
        mailboxAddress: config.mailbox.address,
        checkIntervalMs: config.mailbox.checkIntervalMs,
        enabled: config.mailbox.enabled,
      },
      this.phishingAgent
    );

    await this.mailboxMonitor.initialize();

    // Initialize HTTP server
    this.httpServer = new HttpServer();
    this.httpServer.setPhishingAgent(this.phishingAgent);
    this.httpServer.setMailboxMonitor(this.mailboxMonitor);

    securityLogger.info('Phishing Agent initialized successfully');
  }

  /**
   * Start application
   */
  async start(): Promise<void> {
    securityLogger.info('Starting Phishing Agent...');

    // Start HTTP server
    await this.httpServer.start();

    // Start mailbox monitoring
    this.mailboxMonitor.start();

    securityLogger.info('Phishing Agent started successfully', {
      port: config.server.port,
      mailbox: config.mailbox.address,
      environment: config.server.environment,
    });
  }

  /**
   * Stop application
   */
  async stop(): Promise<void> {
    securityLogger.info('Stopping Phishing Agent...');

    this.mailboxMonitor.stop();
    await this.phishingAgent.shutdown();

    securityLogger.info('Phishing Agent stopped');
  }

  /**
   * Setup signal handlers
   */
  setupSignalHandlers(): void {
    const shutdown = async (signal: string) => {
      securityLogger.info(`Received ${signal}, shutting down gracefully...`);
      await this.stop();
      process.exit(0);
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
  }

  /**
   * Handle errors
   */
  setupErrorHandlers(): void {
    process.on('uncaughtException', (error) => {
      securityLogger.error('Uncaught exception', { error: error.message, stack: error.stack });
      process.exit(1);
    });

    process.on('unhandledRejection', (reason) => {
      securityLogger.error('Unhandled rejection', { reason });
      process.exit(1);
    });
  }
}

/**
 * Main function
 */
async function main() {
  const app = new Application();

  try {
    app.setupSignalHandlers();
    app.setupErrorHandlers();

    await app.initialize();
    await app.start();

    securityLogger.info('Phishing Agent is running');
  } catch (error: any) {
    securityLogger.error('Failed to start Phishing Agent', {
      error: error.message,
      stack: error.stack,
    });
    process.exit(1);
  }
}

// Run application
main();
