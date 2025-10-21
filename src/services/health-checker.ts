/**
 * Health Checker Service
 * Provides deep health checks for all system components
 */

import { securityLogger } from '../lib/logger.js';
import { PhishingAgent } from '../agents/phishing-agent.js';
import { MailboxMonitor } from '../services/mailbox-monitor.js';
import { RateLimiter } from '../services/rate-limiter.js';
import { EmailDeduplication } from '../services/email-deduplication.js';

export interface HealthStatus {
  healthy: boolean;
  component: string;
  message?: string;
  details?: Record<string, unknown>;
}

export interface SystemHealth {
  healthy: boolean;
  timestamp: string;
  components: {
    phishingAgent: HealthStatus;
    mailboxMonitor: HealthStatus;
    rateLimiter: HealthStatus;
    deduplication: HealthStatus;
    memory: HealthStatus;
  };
}

export class HealthChecker {
  private phishingAgent?: PhishingAgent;
  private mailboxMonitor?: MailboxMonitor;
  private rateLimiter?: RateLimiter;
  private deduplication?: EmailDeduplication;

  setPhishingAgent(agent: PhishingAgent): void {
    this.phishingAgent = agent;
  }

  setMailboxMonitor(monitor: MailboxMonitor): void {
    this.mailboxMonitor = monitor;
  }

  setRateLimiter(limiter: RateLimiter): void {
    this.rateLimiter = limiter;
  }

  setDeduplication(dedupe: EmailDeduplication): void {
    this.deduplication = dedupe;
  }

  /**
   * Perform comprehensive system health check
   */
  async checkHealth(): Promise<SystemHealth> {
    const components = {
      phishingAgent: await this.checkPhishingAgent(),
      mailboxMonitor: await this.checkMailboxMonitor(),
      rateLimiter: this.checkRateLimiter(),
      deduplication: this.checkDeduplication(),
      memory: this.checkMemory(),
    };

    const healthy = Object.values(components).every((c) => c.healthy);

    return {
      healthy,
      timestamp: new Date().toISOString(),
      components,
    };
  }

  /**
   * Check phishing agent health
   */
  private async checkPhishingAgent(): Promise<HealthStatus> {
    if (!this.phishingAgent) {
      return {
        healthy: false,
        component: 'phishingAgent',
        message: 'Component not initialized',
      };
    }

    try {
      const healthy = await this.phishingAgent.healthCheck();
      return {
        healthy,
        component: 'phishingAgent',
        message: healthy ? 'Agent operational' : 'Agent unhealthy',
      };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      return {
        healthy: false,
        component: 'phishingAgent',
        message: `Health check failed: ${message}`,
      };
    }
  }

  /**
   * Check mailbox monitor health
   */
  private async checkMailboxMonitor(): Promise<HealthStatus> {
    if (!this.mailboxMonitor) {
      return {
        healthy: false,
        component: 'mailboxMonitor',
        message: 'Component not initialized',
      };
    }

    try {
      const status = this.mailboxMonitor.getStatus();
      const healthy = await this.mailboxMonitor.healthCheck();

      return {
        healthy,
        component: 'mailboxMonitor',
        message: healthy ? 'Monitor operational' : 'Monitor unhealthy',
        details: {
          isRunning: status.isRunning,
          lastCheckTime: status.lastCheckTime.toISOString(),
        },
      };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      return {
        healthy: false,
        component: 'mailboxMonitor',
        message: `Health check failed: ${message}`,
      };
    }
  }

  /**
   * Check rate limiter health
   */
  private checkRateLimiter(): HealthStatus {
    if (!this.rateLimiter) {
      return {
        healthy: true,
        component: 'rateLimiter',
        message: 'Component not configured (optional)',
      };
    }

    const stats = this.rateLimiter.getStats();

    // Consider unhealthy if circuit breaker is tripped
    const healthy = !stats.circuitBreakerTripped;

    return {
      healthy,
      component: 'rateLimiter',
      message: healthy ? 'Rate limiter operational' : 'Circuit breaker tripped',
      details: {
        emailsSentLastHour: stats.lastHour,
        emailsSentLastDay: stats.lastDay,
        emailsSentLast10Min: stats.last10Min,
        circuitBreakerTripped: stats.circuitBreakerTripped,
      },
    };
  }

  /**
   * Check deduplication health
   */
  private checkDeduplication(): HealthStatus {
    if (!this.deduplication) {
      return {
        healthy: true,
        component: 'deduplication',
        message: 'Component not configured (optional)',
      };
    }

    const stats = this.deduplication.getStats();

    return {
      healthy: true,
      component: 'deduplication',
      message: 'Deduplication operational',
      details: {
        processedEmailsCount: stats.processedEmailsCount,
        uniqueSendersCount: stats.uniqueSendersCount,
        enabled: stats.enabled,
      },
    };
  }

  /**
   * Check memory health
   */
  private checkMemory(): HealthStatus {
    const usage = process.memoryUsage();
    const heapUsedMB = Math.round(usage.heapUsed / 1024 / 1024);
    const heapTotalMB = Math.round(usage.heapTotal / 1024 / 1024);
    const percentUsed = Math.round((usage.heapUsed / usage.heapTotal) * 100);

    // Consider unhealthy if using >90% of heap
    const healthy = percentUsed < 90;

    return {
      healthy,
      component: 'memory',
      message: healthy ? 'Memory usage normal' : 'Memory usage high',
      details: {
        heapUsedMB,
        heapTotalMB,
        percentUsed,
        rss: Math.round(usage.rss / 1024 / 1024),
      },
    };
  }
}

// Global health checker instance
export const healthChecker = new HealthChecker();
