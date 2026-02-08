/**
 * Subscription Manager Factory
 * Creates and configures a SubscriptionManager from app config.
 * All functions are atomic (max 25 lines).
 */

import { Client } from '@microsoft/microsoft-graph-client';
import { securityLogger } from '../lib/logger.js';
import { SubscriptionManager, SubscriptionConfig } from './subscription-manager.js';
import { setCatchUpPollCallback } from './subscription-lifecycle.js';

export interface WebhookSubscriptionConfig {
  enabled: boolean;
  notificationUrl?: string;
  clientState?: string;
  resource?: string;
  renewalMarginMs: number;
}

/** Check if webhook subscription is properly configured */
export function isSubscriptionConfigured(ws: WebhookSubscriptionConfig): boolean {
  return ws.enabled && !!ws.notificationUrl && !!ws.clientState;
}

/** Build subscription config from app settings */
export function buildSubscriptionConfig(ws: WebhookSubscriptionConfig, mailboxAddress: string): SubscriptionConfig {
  return {
    notificationUrl: ws.notificationUrl!,
    clientState: ws.clientState!,
    resource: ws.resource || `users/${mailboxAddress}/messages`,
    renewalMarginMs: ws.renewalMarginMs,
  };
}

/** Create and initialize a SubscriptionManager */
export async function createSubscriptionManager(
  graphClient: Client,
  ws: WebhookSubscriptionConfig,
  mailboxAddress: string,
  catchUpPoll: () => Promise<void>
): Promise<SubscriptionManager | undefined> {
  if (!isSubscriptionConfigured(ws)) {
    securityLogger.info('Webhook subscription disabled or not configured');
    return undefined;
  }
  const config = buildSubscriptionConfig(ws, mailboxAddress);
  const manager = new SubscriptionManager(graphClient, config);
  setCatchUpPollCallback(catchUpPoll);
  await manager.initialize();
  return manager;
}
