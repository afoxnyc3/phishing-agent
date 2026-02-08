/**
 * Webhook Express Route
 * POST /webhooks/mail - receives Graph API change notifications
 */

import { Router, Request, Response } from 'express';
import { securityLogger } from '../lib/logger.js';
import {
  handleValidationHandshake,
  isValidPayload,
  validateClientState,
  extractMessageIds,
} from './webhook-handler.js';
import { webhookArrivalTimes } from './webhook-arrival-times.js';

/** Callback invoked with extracted message IDs after validation */
export type NotificationCallback = (messageIds: string[]) => void;

/** Create webhook router with clientState validation and optional processing callback */
export function createWebhookRouter(clientState: string, onNotification?: NotificationCallback): Router {
  const router = Router();
  router.post('/webhooks/mail', (req: Request, res: Response) => {
    handleWebhookNotification(req, res, clientState, onNotification);
  });
  return router;
}

/** Handle incoming webhook notification */
function handleWebhookNotification(
  req: Request,
  res: Response,
  clientState: string,
  onNotification?: NotificationCallback
): void {
  if (handleValidationHandshake(req, res)) return;

  if (!isValidPayload(req.body)) {
    securityLogger.warn('Invalid webhook payload received');
    res.status(400).json({ error: 'Invalid payload' });
    return;
  }

  if (!validateClientState(req.body.value, clientState)) {
    securityLogger.warn('Webhook clientState mismatch — possible spoofing');
    res.status(403).json({ error: 'Forbidden' });
    return;
  }

  acceptNotification(req, res, onNotification);
}

/** Accept valid notification, record arrival times, and enqueue for processing */
function acceptNotification(req: Request, res: Response, onNotification?: NotificationCallback): void {
  const arrivalTime = Date.now();
  const messageIds = extractMessageIds(req.body);
  messageIds.forEach((id) => webhookArrivalTimes.record(id, arrivalTime));

  if (onNotification && messageIds.length > 0) {
    onNotification(messageIds);
  }

  securityLogger.info('Webhook notification accepted', {
    messageCount: messageIds.length,
    subscriptionId: req.body.value[0]?.subscriptionId,
    queued: !!onNotification,
  });

  res.status(202).json({ status: 'accepted' });
}
