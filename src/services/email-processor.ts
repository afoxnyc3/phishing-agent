/**
 * Email Processor
 * Handles email processing with rate limiting and deduplication
 * All functions follow production-ready size limits (max 50 lines/function)
 */

import { Client } from '@microsoft/microsoft-graph-client';
import { securityLogger } from '../lib/logger.js';
import { PhishingAgent } from '../agents/phishing-agent.js';
import { PhishingAnalysisResult } from '../lib/types.js';
import { parseGraphEmail } from './graph-email-parser.js';
import { RateLimiter } from './rate-limiter.js';
import { EmailDeduplication } from './email-deduplication.js';
import { buildReplyHtml, buildErrorReplyHtml, createReplyMessage } from './email-reply-builder.js';
import { metrics } from './metrics.js';

export interface EmailProcessorConfig {
  mailboxAddress: string;
  graphClient: Client;
  phishingAgent: PhishingAgent;
  rateLimiter: RateLimiter;
  deduplication: EmailDeduplication;
}

/**
 * Process single email with full analysis pipeline
 */
export async function processEmail(
  graphEmail: any,
  config: EmailProcessorConfig
): Promise<void> {
  const processingId = generateProcessingId();
  const senderEmail = graphEmail.from?.emailAddress?.address || 'unknown';
  const subject = graphEmail.subject || '(No Subject)';
  const body = graphEmail.body?.content || graphEmail.bodyPreview || '';

  securityLogger.info('Processing email from mailbox', {
    processingId,
    emailId: graphEmail.id,
    subject,
    from: senderEmail,
  });

  // Security guards before any processing to avoid loops/backscatter
  const guardResult = evaluateEmailGuards(graphEmail, config.mailboxAddress);
  if (!guardResult.allowed) {
    metrics.recordDeduplicationHit();
    securityLogger.warn('Email blocked by guardrail', {
      processingId,
      emailId: graphEmail.id,
      subject,
      from: senderEmail,
      reason: guardResult.reason,
    });
    return;
  }

  // Check deduplication before processing
  const dedupeCheck = config.deduplication.shouldProcess(senderEmail, subject, body);
  if (!dedupeCheck.allowed) {
    metrics.recordDeduplicationHit();
    securityLogger.info('Email skipped due to deduplication', {
      processingId,
      sender: senderEmail,
      subject,
      reason: dedupeCheck.reason,
    });
    return;
  }

  try {
    const analysisStart = Date.now();
    const analysisRequest = parseGraphEmail(graphEmail);
    const analysisResult = await config.phishingAgent.analyzeEmail(analysisRequest);
    const analysisLatency = Date.now() - analysisStart;

    // Record metrics
    metrics.recordAnalysisLatency(analysisLatency);
    metrics.recordEmailProcessed(analysisResult.isPhishing);

    securityLogger.security('Email analyzed via mailbox monitor', {
      processingId,
      messageId: analysisResult.messageId,
      isPhishing: analysisResult.isPhishing,
      riskScore: analysisResult.riskScore,
      severity: analysisResult.severity,
    });

    await sendAnalysisReply(graphEmail, analysisResult, processingId, config);

    // Record as processed after successful reply
    config.deduplication.recordProcessed(senderEmail, subject, body);

    securityLogger.info('Email processing completed successfully', { processingId });
  } catch (error: any) {
    metrics.recordAnalysisError();
    securityLogger.error('Failed to process email', { processingId, error: error.message });
    await sendErrorReply(graphEmail, processingId, config).catch((replyError) => {
      securityLogger.error('Failed to send error reply', {
        processingId,
        error: replyError.message,
      });
    });
  }
}

/**
 * Send analysis reply with rate limiting
 */
async function sendAnalysisReply(
  originalEmail: any,
  analysis: PhishingAnalysisResult,
  processingId: string,
  config: EmailProcessorConfig
): Promise<void> {
  const senderEmail = originalEmail.from?.emailAddress?.address;
  if (!senderEmail) {
    securityLogger.warn('Cannot send reply - no sender email', { processingId });
    return;
  }

  // Check rate limits before sending
  const rateLimitCheck = config.rateLimiter.canSendEmail();
  if (!rateLimitCheck.allowed) {
    metrics.recordRateLimitHit();
    securityLogger.warn('Email reply blocked by rate limiter', {
      processingId,
      recipient: senderEmail,
      reason: rateLimitCheck.reason,
      stats: config.rateLimiter.getStats(),
    });
    return;
  }

  const htmlBody = buildReplyHtml(analysis);
  const replyMessage = createReplyMessage(originalEmail, htmlBody, analysis.isPhishing);

  try {
    const replyStart = Date.now();
    await config.graphClient
      .api(`/users/${config.mailboxAddress}/sendMail`)
      .post(replyMessage);
    const replyLatency = Date.now() - replyStart;

    // Record metrics
    metrics.recordReplyLatency(replyLatency);
    metrics.recordReplySent();

    // Record email sent after successful send
    config.rateLimiter.recordEmailSent();

    securityLogger.info('Analysis reply sent', {
      processingId,
      recipient: senderEmail,
      isPhishing: analysis.isPhishing,
      riskScore: analysis.riskScore,
      rateLimitStats: config.rateLimiter.getStats(),
    });
  } catch (error: any) {
    metrics.recordReplyFailed();
    securityLogger.error('Failed to send analysis reply', { processingId, error: error.message });
    throw error;
  }
}

/**
 * Send error reply to user
 */
async function sendErrorReply(
  originalEmail: any,
  processingId: string,
  config: EmailProcessorConfig
): Promise<void> {
  const senderEmail = originalEmail.from?.emailAddress?.address;
  if (!senderEmail) return;

  const errorHtml = buildErrorReplyHtml(processingId);
  const subject = originalEmail.subject || '(No Subject)';

  await config.graphClient.api(`/users/${config.mailboxAddress}/sendMail`).post({
    message: {
      subject: `Re: ${subject}`,
      body: { contentType: 'HTML', content: errorHtml },
      toRecipients: [{ emailAddress: { address: senderEmail } }],
    },
  });

  securityLogger.info('Error reply sent', { processingId, recipient: senderEmail });
}

/**
 * Generate unique processing ID
 */
function generateProcessingId(): string {
  return `process-${Date.now()}-${Math.random().toString(36).substring(7)}`;
}

const MESSAGE_ID_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const MAX_MESSAGE_CACHE = 5000;
const processedMessageIds: Map<string, number> = new Map();

/**
 * Evaluate guardrails to prevent loops, auto-responder replies, and unauthorized senders.
 */
export function evaluateEmailGuards(
  graphEmail: any,
  mailboxAddress: string
): { allowed: boolean; reason?: string } {
  const normalizedMailbox = mailboxAddress.toLowerCase();
  const senderEmail = (graphEmail.from?.emailAddress?.address || '').toLowerCase().trim();
  const messageId = (graphEmail.internetMessageId || graphEmail.id || '').trim();
  const headers = buildHeaderMap(graphEmail.internetMessageHeaders);

  if (!senderEmail) {
    return { allowed: false, reason: 'missing-sender' };
  }

  if (!messageId) {
    return { allowed: false, reason: 'missing-message-id' };
  }

  if (isMessageIdDuplicate(messageId)) {
    return { allowed: false, reason: 'duplicate-message-id' };
  }

  if (isSelfOrSiblingSender(senderEmail, normalizedMailbox)) {
    return { allowed: false, reason: 'self-sender-detected' };
  }

  if (!isAllowlistedSender(senderEmail)) {
    return { allowed: false, reason: 'sender-not-allowlisted' };
  }

  if (isAutoResponder(headers, senderEmail)) {
    return { allowed: false, reason: 'auto-responder-detected' };
  }

  return { allowed: true };
}

function buildHeaderMap(headers: any[] | undefined): Record<string, string> {
  if (!Array.isArray(headers)) return {};
  return headers.reduce<Record<string, string>>((acc, header) => {
    const name = header?.name;
    const value = header?.value;
    if (typeof name === 'string' && typeof value === 'string') {
      acc[name.toLowerCase()] = value;
    }
    return acc;
  }, {});
}

function isMessageIdDuplicate(messageId: string): boolean {
  const now = Date.now();
  const existing = processedMessageIds.get(messageId);

  // Clean stale entries opportunistically
  if (processedMessageIds.size > MAX_MESSAGE_CACHE) {
    cleanupMessageIdCache(now);
  }

  if (existing && now - existing < MESSAGE_ID_TTL_MS) {
    return true;
  }

  processedMessageIds.set(messageId, now);
  return false;
}

function cleanupMessageIdCache(now: number): void {
  for (const [id, ts] of processedMessageIds.entries()) {
    if (now - ts >= MESSAGE_ID_TTL_MS) {
      processedMessageIds.delete(id);
    }
  }
}

function isSelfOrSiblingSender(senderEmail: string, mailboxAddress: string): boolean {
  const senderDomain = extractDomain(senderEmail);
  const mailboxDomain = extractDomain(mailboxAddress);
  const senderLocal = senderEmail.split('@')[0];
  const mailboxLocal = mailboxAddress.split('@')[0];

  if (senderEmail === mailboxAddress) return true;
  const sameDomainAgent = senderDomain === mailboxDomain && senderLocal.startsWith(mailboxLocal);
  return sameDomainAgent;
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
    return true; // Backward compatible default
  }

  const senderDomain = extractDomain(senderEmail);
  if (allowlistEmails.includes(senderEmail)) return true;
  if (allowlistDomains.includes(senderDomain)) return true;

  return false;
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

// Test hook to reset cache state
export function __testResetMessageIdCache(): void {
  processedMessageIds.clear();
}
