/**
 * Phishing Agent - Main Entry Point
 * Automated phishing email detection service
 */

import { config as dotenvConfig } from 'dotenv';
import { loadSecretsFromKeyVault } from './lib/keyvault.js';

// Load .env first (for local dev and AZURE_KEY_VAULT_NAME)
dotenvConfig();

// Bootstrap function to load secrets before other modules
async function bootstrap(): Promise<{
  securityLogger: typeof import('./lib/logger.js').securityLogger;
  config: typeof import('./lib/config.js').config;
  PhishingAgent: typeof import('./agents/phishing-agent.js').PhishingAgent;
  MailboxMonitor: typeof import('./services/mailbox-monitor.js').MailboxMonitor;
  HttpServer: typeof import('./server.js').HttpServer;
}> {
  // Load secrets from Key Vault if configured
  await loadSecretsFromKeyVault();

  // Now dynamically import modules that depend on config
  const { securityLogger } = await import('./lib/logger.js');
  const { config } = await import('./lib/config.js');
  const { PhishingAgent } = await import('./agents/phishing-agent.js');
  const { MailboxMonitor } = await import('./services/mailbox-monitor.js');
  const { HttpServer } = await import('./server.js');

  return { securityLogger, config, PhishingAgent, MailboxMonitor, HttpServer };
}

// Type definitions for bootstrapped modules
type BootstrappedModules = Awaited<ReturnType<typeof bootstrap>>;

/**
 * Main application
 */
class Application {
  private modules!: BootstrappedModules;
  private phishingAgent!: InstanceType<BootstrappedModules['PhishingAgent']>;
  private mailboxMonitor!: InstanceType<BootstrappedModules['MailboxMonitor']>;
  private httpServer!: InstanceType<BootstrappedModules['HttpServer']>;

  constructor(modules: BootstrappedModules) {
    this.modules = modules;
  }

  /**
   * Initialize application
   */
  async initialize(): Promise<void> {
    const { securityLogger, config, PhishingAgent, MailboxMonitor, HttpServer } = this.modules;

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
        rateLimiter: config.rateLimit,
        deduplication: config.deduplication,
      },
      this.phishingAgent
    );

    // Only initialize if mailbox monitoring is enabled
    if (config.mailbox.enabled) {
      await this.mailboxMonitor.initialize();
    } else {
      securityLogger.info('Mailbox monitoring is disabled, skipping initialization');
    }

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
    const { securityLogger, config } = this.modules;

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
    const { securityLogger } = this.modules;

    securityLogger.info('Stopping Phishing Agent...');

    this.mailboxMonitor.stop();
    await this.phishingAgent.shutdown();

    securityLogger.info('Phishing Agent stopped');
  }

  /**
   * Setup signal handlers
   */
  setupSignalHandlers(): void {
    const { securityLogger } = this.modules;

    const shutdown = async (signal: string): Promise<void> => {
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
    const { securityLogger } = this.modules;

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
async function main(): Promise<void> {
  try {
    // Bootstrap: load Key Vault secrets and import modules
    const modules = await bootstrap();
    const { securityLogger } = modules;

    const app = new Application(modules);

    app.setupSignalHandlers();
    app.setupErrorHandlers();

    await app.initialize();
    await app.start();

    securityLogger.info('Phishing Agent is running');
  } catch (error: unknown) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    const errorStack = error instanceof Error ? error.stack : undefined;
    console.error('Failed to start Phishing Agent:', errorMessage, errorStack);
    process.exit(1);
  }
}

// Run application
main();
