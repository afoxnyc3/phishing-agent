/**
 * Graph API Webhook Handler
 * Handles Microsoft Graph change notifications for new mail.
 * All functions are atomic (max 25 lines).
 */

import type { Request, Response } from 'express';
import { securityLogger } from '../lib/logger.js';

/** Graph API change notification payload */
export interface GraphNotification {
  subscriptionId: string;
  clientState: string;
  changeType: string;
  resource: string;
  resourceData: {
    '@odata.id': string;
    id: string;
  };
}

export interface NotificationPayload {
  value: GraphNotification[];
}

/** Extract message IDs from notification payload */
export function extractMessageIds(payload: NotificationPayload): string[] {
  return payload.value
    .filter((n) => n.changeType === 'created')
    .map((n) => n.resourceData.id)
    .filter(Boolean);
}

/** Validate clientState matches expected secret */
export function validateClientState(notifications: GraphNotification[], expectedState: string): boolean {
  return notifications.every((n) => n.clientState === expectedState);
}

/** Validate token contains only safe characters (alphanumeric, base64, URL-safe) */
function isSafeToken(token: string): boolean {
  return /^[\w\-.~+/=%]+$/.test(token) && token.length <= 4096;
}

/** Handle validation handshake from Graph API */
export function handleValidationHandshake(req: Request, res: Response): boolean {
  const rawToken = req.query.validationToken;
  const validationToken = typeof rawToken === 'string' ? rawToken : undefined;
  if (validationToken) {
    if (!isSafeToken(validationToken)) {
      securityLogger.warn('Rejected validation token with unsafe characters');
      res.status(400).type('text/plain').send('Invalid validation token');
      return true;
    }
    securityLogger.info('Webhook validation handshake received');
    res.status(200).type('text/plain').send(validationToken);
    return true;
  }
  return false;
}

/** Validate notification payload structure */
export function isValidPayload(body: unknown): body is NotificationPayload {
  if (!body || typeof body !== 'object') return false;
  const payload = body as Record<string, unknown>;
  return Array.isArray(payload.value) && payload.value.length > 0;
}
