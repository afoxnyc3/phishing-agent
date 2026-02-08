/**
 * Notification Queue Factory
 * Creates NotificationQueue from application-level dependencies.
 * Keeps index.ts under the max-lines limit.
 */

import { NotificationQueue, NotificationQueueConfig } from './notification-queue.js';
import type { PhishingAgent } from '../agents/phishing-agent.js';
import type { Client } from '@microsoft/microsoft-graph-client';
import type { IRateLimiter } from './rate-limiter.js';
import type { IEmailDeduplication } from './email-deduplication.js';

interface MonitorLike {
  getGraphClient(): Client;
  getRateLimiter(): IRateLimiter;
  getDeduplication(): IEmailDeduplication;
}

export function createNotificationQueue(
  config: NotificationQueueConfig,
  mailboxAddress: string,
  monitor: MonitorLike,
  phishingAgent: PhishingAgent
): NotificationQueue | undefined {
  if (!config.enabled) return undefined;
  return new NotificationQueue(config, {
    processorConfig: {
      mailboxAddress,
      graphClient: monitor.getGraphClient(),
      phishingAgent,
      rateLimiter: monitor.getRateLimiter(),
      deduplication: monitor.getDeduplication(),
    },
  });
}
