/**
 * Graph API Subscription Manager
 * Creates and auto-renews change notification subscriptions for mail.
 * All functions are atomic (max 25 lines).
 */

import { Client } from '@microsoft/microsoft-graph-client';
import { securityLogger } from '../lib/logger.js';
import { getErrorMessage } from '../lib/errors.js';
import { handleLifecycleEvent, LifecycleEventType } from './subscription-lifecycle.js';

export interface SubscriptionConfig {
  notificationUrl: string;
  clientState: string;
  resource: string;
  renewalMarginMs?: number;
}

export interface SubscriptionState {
  subscriptionId: string | null;
  expirationDateTime: Date | null;
  isActive: boolean;
}

/** Maximum subscription lifetime for mail resources (4230 minutes = ~2.94 days) */
const MAX_SUBSCRIPTION_MINUTES = 4230;

/** Default renewal margin: renew 2 hours before expiry */
const DEFAULT_RENEWAL_MARGIN_MS = 2 * 60 * 60 * 1000;

export class SubscriptionManager {
  private graphClient: Client;
  private config: SubscriptionConfig;
  private state: SubscriptionState;
  private renewalTimer: ReturnType<typeof setTimeout> | null = null;
  private renewalMarginMs: number;

  constructor(graphClient: Client, config: SubscriptionConfig) {
    this.graphClient = graphClient;
    this.config = config;
    this.renewalMarginMs = config.renewalMarginMs ?? DEFAULT_RENEWAL_MARGIN_MS;
    this.state = { subscriptionId: null, expirationDateTime: null, isActive: false };
  }

  /** Initialize subscription: check for existing or create new */
  async initialize(): Promise<void> {
    securityLogger.info('Initializing subscription manager', {
      resource: this.config.resource,
      notificationUrl: this.config.notificationUrl,
    });
    try {
      const existing = await this.findExistingSubscription();
      if (existing) {
        this.applySubscriptionState(existing.id, existing.expirationDateTime);
        securityLogger.info('Found existing subscription', { id: existing.id });
        return;
      }
      await this.createSubscription();
    } catch (error: unknown) {
      securityLogger.error('Subscription initialization failed', { error: getErrorMessage(error) });
    }
  }

  /** Create a new Graph API subscription */
  async createSubscription(): Promise<void> {
    const expiration = this.calculateExpiration();
    try {
      const subscription = await this.graphClient.api('/subscriptions').post({
        changeType: 'created',
        notificationUrl: this.config.notificationUrl,
        resource: this.config.resource,
        expirationDateTime: expiration.toISOString(),
        clientState: this.config.clientState,
      });
      this.applySubscriptionState(subscription.id, subscription.expirationDateTime);
      securityLogger.info('Subscription created', {
        id: subscription.id,
        expirationDateTime: subscription.expirationDateTime,
      });
    } catch (error: unknown) {
      securityLogger.error('Failed to create subscription', { error: getErrorMessage(error) });
    }
  }

  /** Renew the current subscription */
  async renewSubscription(): Promise<void> {
    if (!this.state.subscriptionId) {
      securityLogger.warn('No subscription to renew, creating new one');
      await this.createSubscription();
      return;
    }
    const expiration = this.calculateExpiration();
    try {
      const updated = await this.graphClient
        .api(`/subscriptions/${this.state.subscriptionId}`)
        .patch({ expirationDateTime: expiration.toISOString() });
      this.applySubscriptionState(updated.id, updated.expirationDateTime);
      securityLogger.info('Subscription renewed', {
        id: updated.id,
        expirationDateTime: updated.expirationDateTime,
      });
    } catch (error: unknown) {
      securityLogger.error('Failed to renew subscription', { error: getErrorMessage(error) });
      await this.handleRenewalFailure();
    }
  }

  /** Handle a lifecycle notification from Graph API */
  async handleLifecycleNotification(eventType: LifecycleEventType): Promise<void> {
    await handleLifecycleEvent(eventType, this);
  }

  /** Stop the subscription manager and clear timers */
  stop(): void {
    this.clearRenewalTimer();
    this.state.isActive = false;
    securityLogger.info('Subscription manager stopped');
  }

  /** Get current subscription state */
  getState(): SubscriptionState {
    return { ...this.state };
  }

  /** Apply subscription state and schedule renewal */
  private applySubscriptionState(id: string, expirationDateTime: string): void {
    this.state.subscriptionId = id;
    this.state.expirationDateTime = new Date(expirationDateTime);
    this.state.isActive = true;
    this.scheduleRenewal();
  }

  /** Schedule auto-renewal before expiry */
  private scheduleRenewal(): void {
    this.clearRenewalTimer();
    if (!this.state.expirationDateTime) return;
    const msUntilExpiry = this.state.expirationDateTime.getTime() - Date.now();
    const renewInMs = Math.max(msUntilExpiry - this.renewalMarginMs, 0);
    securityLogger.debug('Scheduling subscription renewal', { renewInMs });
    this.renewalTimer = setTimeout(() => {
      this.renewSubscription().catch((err: unknown) => {
        securityLogger.error('Auto-renewal failed', { error: getErrorMessage(err) });
      });
    }, renewInMs);
    this.renewalTimer.unref();
  }

  /** Clear the renewal timer */
  private clearRenewalTimer(): void {
    if (this.renewalTimer) {
      clearTimeout(this.renewalTimer);
      this.renewalTimer = null;
    }
  }

  /** Calculate expiration date for new/renewed subscription */
  private calculateExpiration(): Date {
    return new Date(Date.now() + MAX_SUBSCRIPTION_MINUTES * 60 * 1000);
  }

  /** Find an existing subscription matching our resource and notification URL */
  private async findExistingSubscription(): Promise<{ id: string; expirationDateTime: string } | null> {
    const response = await this.graphClient.api('/subscriptions').get();
    const subscriptions = response?.value as Array<{
      id: string;
      resource: string;
      notificationUrl: string;
      expirationDateTime: string;
    }>;
    if (!Array.isArray(subscriptions)) return null;
    return (
      subscriptions.find(
        (s) => s.resource === this.config.resource && s.notificationUrl === this.config.notificationUrl
      ) ?? null
    );
  }

  /** Handle renewal failure by attempting to recreate */
  private async handleRenewalFailure(): Promise<void> {
    securityLogger.warn('Renewal failed, attempting to recreate subscription');
    this.state.subscriptionId = null;
    this.state.isActive = false;
    await this.createSubscription();
  }
}
