/**
 * Email Guards
 * Guardrail functions to prevent loops, auto-responder replies, and unauthorized senders
 */

import { securityLogger } from '../lib/logger.js';
import { GraphEmail } from '../lib/schemas.js';

const MESSAGE_ID_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const MAX_MESSAGE_CACHE = 5000;
const processedMessageIds: Map<string, number> = new Map();

/**
 * Evaluate guardrails to prevent loops, auto-responder replies, and unauthorized senders.
 */
export function evaluateEmailGuards(
  graphEmail: GraphEmail,
  mailboxAddress: string
): { allowed: boolean; reason?: string } {
  const normalizedMailbox = mailboxAddress.toLowerCase();
  const senderEmail = (graphEmail.from?.emailAddress?.address || '').toLowerCase().trim();
  const messageId = (graphEmail.internetMessageId || graphEmail.id || '').trim();
  const headers = buildHeaderMap(graphEmail.internetMessageHeaders);

  if (!senderEmail) return { allowed: false, reason: 'missing-sender' };
  if (!messageId) return { allowed: false, reason: 'missing-message-id' };
  if (isMessageIdDuplicate(messageId)) return { allowed: false, reason: 'duplicate-message-id' };
  if (isSelfOrSiblingSender(senderEmail, normalizedMailbox)) {
    return { allowed: false, reason: 'self-sender-detected' };
  }
  if (!isAllowlistedSender(senderEmail)) return { allowed: false, reason: 'sender-not-allowlisted' };
  if (isAutoResponder(headers, senderEmail)) return { allowed: false, reason: 'auto-responder-detected' };
  return { allowed: true };
}

function buildHeaderMap(
  headers: Array<{ name?: string; value?: string }> | undefined
): Record<string, string> {
  if (!Array.isArray(headers)) return {};
  return headers.reduce<Record<string, string>>((acc, header) => {
    if (header.name && header.value) {
      acc[header.name.toLowerCase()] = header.value;
    }
    return acc;
  }, {});
}

function isMessageIdDuplicate(messageId: string): boolean {
  const now = Date.now();
  const existing = processedMessageIds.get(messageId);
  if (processedMessageIds.size > MAX_MESSAGE_CACHE) {
    cleanupMessageIdCache(now);
  }
  if (existing && now - existing < MESSAGE_ID_TTL_MS) return true;
  processedMessageIds.set(messageId, now);
  return false;
}

function cleanupMessageIdCache(now: number): void {
  for (const [id, ts] of processedMessageIds.entries()) {
    if (now - ts >= MESSAGE_ID_TTL_MS) processedMessageIds.delete(id);
  }
}

function isSelfOrSiblingSender(senderEmail: string, mailboxAddress: string): boolean {
  const senderDomain = extractDomain(senderEmail);
  const mailboxDomain = extractDomain(mailboxAddress);
  const senderLocal = senderEmail.split('@')[0];
  const mailboxLocal = mailboxAddress.split('@')[0];
  if (senderEmail === mailboxAddress) return true;
  return senderDomain === mailboxDomain && senderLocal.startsWith(mailboxLocal);
}

function extractDomain(email: string): string {
  const [, domain] = email.split('@');
  return (domain || '').toLowerCase();
}

function isAllowlistedSender(senderEmail: string): boolean {
  const allowlistEmails = (process.env.ALLOWED_SENDER_EMAILS || '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  const allowlistDomains = (process.env.ALLOWED_SENDER_DOMAINS || '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);

  if (allowlistEmails.length === 0 && allowlistDomains.length === 0) {
    const isProduction = process.env.NODE_ENV === 'production';
    if (isProduction) {
      securityLogger.error('SECURITY: No sender allowlist configured in production - blocking all senders', {
        sender: senderEmail,
        env: 'production',
      });
      return false;
    }
    securityLogger.warn('No sender allowlist configured - allowing all senders (development mode only)', {
      sender: senderEmail,
      env: process.env.NODE_ENV || 'development',
    });
    return true;
  }

  const senderDomain = extractDomain(senderEmail);
  return allowlistEmails.includes(senderEmail) || allowlistDomains.includes(senderDomain);
}

function isAutoResponder(headers: Record<string, string>, senderEmail: string): boolean {
  const headerBlob = JSON.stringify(headers).toLowerCase();
  if (headerBlob.includes('mailer-daemon') || senderEmail.includes('mailer-daemon')) return true;
  if (headerBlob.includes('postmaster') || senderEmail.includes('postmaster')) return true;

  const autoSubmitted = headers['auto-submitted'];
  if (autoSubmitted && /auto-replied|auto-generated|auto-notified/i.test(autoSubmitted)) return true;

  const precedence = headers['precedence'];
  if (precedence && /bulk|junk|auto_reply/i.test(precedence)) return true;

  const xAutoResponse = headers['x-auto-response-suppress'];
  if (xAutoResponse && /all|dr|autoreply/i.test(xAutoResponse)) return true;

  return false;
}

/** Test hook to reset cache state */
export function __testResetMessageIdCache(): void {
  processedMessageIds.clear();
}
