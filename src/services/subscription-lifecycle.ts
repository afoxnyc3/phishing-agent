/**
 * Subscription Lifecycle Event Handler
 * Handles Graph API lifecycle notifications: subscriptionRemoved, missed, reauthorizationRequired.
 * All functions are atomic (max 25 lines).
 */

import { securityLogger } from '../lib/logger.js';
import { getErrorMessage } from '../lib/errors.js';

export type LifecycleEventType = 'subscriptionRemoved' | 'missed' | 'reauthorizationRequired';

/** Interface for the subscription manager methods needed by lifecycle handlers */
export interface SubscriptionManagerRef {
  createSubscription(): Promise<boolean>;
  renewSubscription(): Promise<void>;
}

/** Callback for catch-up polling on missed notifications */
export type CatchUpPollCallback = () => Promise<void>;

/** Optional catch-up poll handler, set by the application */
let catchUpPollCallback: CatchUpPollCallback | null = null;

/** Register a callback for catch-up polling when missed notifications occur */
export function setCatchUpPollCallback(callback: CatchUpPollCallback | null): void {
  catchUpPollCallback = callback;
}

/** Get the current catch-up poll callback (for testing) */
export function getCatchUpPollCallback(): CatchUpPollCallback | null {
  return catchUpPollCallback;
}

/** Handle a lifecycle event from Graph API */
export async function handleLifecycleEvent(
  eventType: LifecycleEventType,
  manager: SubscriptionManagerRef
): Promise<void> {
  securityLogger.warn('Subscription lifecycle event received', { eventType });
  switch (eventType) {
    case 'subscriptionRemoved':
      await handleSubscriptionRemoved(manager);
      break;
    case 'missed':
      await handleMissedNotifications();
      break;
    case 'reauthorizationRequired':
      await handleReauthorizationRequired(manager);
      break;
    default:
      securityLogger.warn('Unknown lifecycle event type', { eventType });
  }
}

/** Handle subscriptionRemoved: recreate subscription */
async function handleSubscriptionRemoved(manager: SubscriptionManagerRef): Promise<void> {
  securityLogger.warn('Subscription removed by Graph API, recreating');
  try {
    await manager.createSubscription();
    securityLogger.info('Subscription recreated after removal');
  } catch (error: unknown) {
    securityLogger.error('Failed to recreate subscription after removal', {
      error: getErrorMessage(error),
    });
  }
}

/** Handle missed notifications: trigger catch-up poll */
async function handleMissedNotifications(): Promise<void> {
  securityLogger.warn('Missed notifications detected, triggering catch-up poll');
  if (!catchUpPollCallback) {
    securityLogger.warn('No catch-up poll callback registered');
    return;
  }
  try {
    await catchUpPollCallback();
    securityLogger.info('Catch-up poll completed after missed notifications');
  } catch (error: unknown) {
    securityLogger.error('Catch-up poll failed', { error: getErrorMessage(error) });
  }
}

/** Handle reauthorizationRequired: renew the subscription */
async function handleReauthorizationRequired(manager: SubscriptionManagerRef): Promise<void> {
  securityLogger.warn('Reauthorization required, renewing subscription');
  try {
    await manager.renewSubscription();
    securityLogger.info('Subscription renewed after reauthorization request');
  } catch (error: unknown) {
    securityLogger.error('Failed to renew subscription after reauthorization request', {
      error: getErrorMessage(error),
    });
  }
}
