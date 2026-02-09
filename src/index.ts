/**
 * Phishing Agent - Main Entry Point
 * Automated phishing email detection service
 */

import { config as dotenvConfig } from 'dotenv';
import { loadSecretsFromKeyVault } from './lib/keyvault.js';
import { getErrorMessage } from './lib/errors.js';

// Load .env first (for local dev and AZURE_KEY_VAULT_NAME)
dotenvConfig();

// Bootstrap function to load secrets before other modules
async function bootstrap(): Promise<{
  securityLogger: typeof import('./lib/logger.js').securityLogger;
  config: typeof import('./lib/config.js').config;
  PhishingAgent: typeof import('./agents/phishing-agent.js').PhishingAgent;
  MailboxMonitor: typeof import('./services/mailbox-monitor.js').MailboxMonitor;
  MailMonitor: typeof import('./services/mail-monitor.js').MailMonitor;
  HttpServer: typeof import('./server.js').HttpServer;
  createResilientCacheProvider: typeof import('./lib/cache-provider.js').createResilientCacheProvider;
  createSubscriptionManager: typeof import('./services/subscription-factory.js').createSubscriptionManager;
  createNotificationQueue: typeof import('./services/notification-queue-factory.js').createNotificationQueue;
}> {
  await loadSecretsFromKeyVault();
  const { securityLogger } = await import('./lib/logger.js');
  const { config } = await import('./lib/config.js');
  const { PhishingAgent } = await import('./agents/phishing-agent.js');
  const { MailboxMonitor } = await import('./services/mailbox-monitor.js');
  const { MailMonitor } = await import('./services/mail-monitor.js');
  const { HttpServer } = await import('./server.js');
  const { createResilientCacheProvider } = await import('./lib/cache-provider.js');
  const { createSubscriptionManager } = await import('./services/subscription-factory.js');
  const { createNotificationQueue } = await import('./services/notification-queue-factory.js');

  return {
    securityLogger,
    config,
    PhishingAgent,
    MailboxMonitor,
    MailMonitor,
    HttpServer,
    createResilientCacheProvider,
    createSubscriptionManager,
    createNotificationQueue,
  };
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
  private mailMonitor!: InstanceType<BootstrappedModules['MailMonitor']>;
  private httpServer!: InstanceType<BootstrappedModules['HttpServer']>;
  private cacheProvider?: Awaited<ReturnType<BootstrappedModules['createResilientCacheProvider']>>;
  private subscriptionManager?: Awaited<ReturnType<BootstrappedModules['createSubscriptionManager']>>;
  private notificationQueue?: NonNullable<ReturnType<BootstrappedModules['createNotificationQueue']>>;

  constructor(modules: BootstrappedModules) {
    this.modules = modules;
  }

  /**
   * Initialize application
   */
  async initialize(): Promise<void> {
    const { securityLogger, config, PhishingAgent, createResilientCacheProvider } = this.modules;

    securityLogger.info('Initializing Phishing Agent...');

    // Initialize cache provider if Redis URL is configured
    if (config.redis.url) {
      this.cacheProvider = await createResilientCacheProvider(config.redis.url, config.redis.keyPrefix);
    }

    this.phishingAgent = new PhishingAgent();
    await this.phishingAgent.initialize();

    await this.initializeMailboxMonitor();
    this.initializeMailMonitor();
    this.notificationQueue =
      this.modules.createNotificationQueue(
        config.notificationQueue,
        config.mailbox.address,
        this.mailboxMonitor,
        this.phishingAgent
      ) ?? undefined;
    await this.initializeSubscriptionManager();
    await this.initializeHttpServer();
    securityLogger.info('Phishing Agent initialized successfully');
  }

  private async initializeMailboxMonitor(): Promise<void> {
    const { securityLogger, config, MailboxMonitor } = this.modules;
    this.mailboxMonitor = new MailboxMonitor(
      {
        tenantId: config.azure.tenantId,
        clientId: config.azure.clientId,
        clientSecret: config.azure.clientSecret || '',
        mailboxAddress: config.mailbox.address,
        checkIntervalMs: config.mailbox.checkIntervalMs,
        enabled: config.mailbox.enabled,
        pollingEnabled: config.mailbox.pollingEnabled,
        rateLimiter: config.rateLimit,
        deduplication: config.deduplication,
        cacheProvider: this.cacheProvider,
      },
      this.phishingAgent
    );

    if (config.mailbox.enabled) {
      await this.mailboxMonitor.initialize();
    } else {
      securityLogger.info('Mailbox monitoring is disabled, skipping initialization');
    }
  }

  private initializeMailMonitor(): void {
    const { config, MailMonitor } = this.modules;
    this.mailMonitor = new MailMonitor(
      {
        enabled: config.mailMonitor.enabled,
        intervalMs: config.mailMonitor.intervalMs,
        lookbackMs: config.mailMonitor.lookbackMs,
        mailboxAddress: config.mailbox.address,
        maxPages: config.mailbox.maxPages,
      },
      {
        graphClient: this.mailboxMonitor.getGraphClient(),
        phishingAgent: this.phishingAgent,
        rateLimiter: this.mailboxMonitor.getRateLimiter(),
        deduplication: this.mailboxMonitor.getDeduplication(),
      }
    );
  }

  private async initializeSubscriptionManager(): Promise<void> {
    const { securityLogger, config, createSubscriptionManager } = this.modules;
    try {
      this.subscriptionManager = await createSubscriptionManager(
        this.mailboxMonitor.getGraphClient(),
        config.webhookSubscription,
        config.mailbox.address,
        () => this.mailMonitor.poll().then(() => {})
      );
    } catch (error: unknown) {
      securityLogger.error('Subscription manager initialization failed, continuing without push notifications', {
        error: getErrorMessage(error),
      });
    }
  }

  private async initializeHttpServer(): Promise<void> {
    const { HttpServer } = this.modules;
    this.httpServer = new HttpServer();
    this.httpServer.setPhishingAgent(this.phishingAgent);
    this.httpServer.setMailboxMonitor(this.mailboxMonitor);
    if (this.notificationQueue) this.httpServer.setNotificationQueue(this.notificationQueue);
    if (this.cacheProvider) {
      const { ResilientCacheProvider } = await import('./lib/resilient-cache-provider.js');
      if (this.cacheProvider instanceof ResilientCacheProvider) {
        this.httpServer.setCacheProvider(this.cacheProvider);
      }
    }
  }

  /**
   * Start application
   */
  async start(): Promise<void> {
    const { securityLogger, config } = this.modules;
    securityLogger.info('Starting Phishing Agent...');
    await this.httpServer.start();
    this.mailboxMonitor.start();
    this.mailMonitor.start();
    this.notificationQueue?.start();
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
    this.notificationQueue?.stop();
    this.subscriptionManager?.stop();
    this.mailMonitor.stop();
    this.mailboxMonitor.stop();
    await this.phishingAgent.shutdown();
    if (this.cacheProvider) await this.cacheProvider.shutdown();
    securityLogger.info('Phishing Agent stopped');
  }

  /**
   * Setup signal handlers
   */
  setupSignalHandlers(): void {
    const shutdown = async (signal: string): Promise<void> => {
      this.modules.securityLogger.info(`Received ${signal}, shutting down gracefully...`);
      await this.stop();
      process.exit(0);
    };
    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
  }

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

async function main(): Promise<void> {
  try {
    const modules = await bootstrap();
    const app = new Application(modules);
    app.setupSignalHandlers();
    app.setupErrorHandlers();
    await app.initialize();
    await app.start();
    modules.securityLogger.info('Phishing Agent is running');
  } catch (error: unknown) {
    // eslint-disable-next-line no-console -- Top-level error before logger may be available
    console.error('Failed to start Phishing Agent:', getErrorMessage(error));
    process.exit(1);
  }
}

main();
