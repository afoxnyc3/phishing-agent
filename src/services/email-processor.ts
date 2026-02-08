/**
 * Email Processor
 * Handles email processing with rate limiting and deduplication
 * All functions follow production-ready size limits (max 50 lines/function)
 */

import { Client } from '@microsoft/microsoft-graph-client';
import { securityLogger } from '../lib/logger.js';
import { PhishingAgent } from '../agents/phishing-agent.js';
import { PhishingAnalysisResult } from '../lib/types.js';
import { GraphEmail } from '../lib/schemas.js';
import { parseGraphEmail } from './graph-email-parser.js';
import { IRateLimiter } from './rate-limiter.js';
import { IEmailDeduplication } from './email-deduplication.js';
import { buildReplyHtml, buildErrorReplyHtml, createReplyMessage } from './email-reply-builder.js';
import { metrics } from './metrics.js';
import { evaluateEmailGuards, __testResetMessageIdCache } from './email-guards.js';
import { getErrorMessage } from '../lib/errors.js';

// Re-export guards for backwards compatibility
export { evaluateEmailGuards, __testResetMessageIdCache };

export interface EmailProcessorConfig {
  mailboxAddress: string;
  graphClient: Client;
  phishingAgent: PhishingAgent;
  rateLimiter: IRateLimiter;
  deduplication: IEmailDeduplication;
}

interface EmailContext {
  processingId: string;
  senderEmail: string;
  subject: string;
  body: string;
}

function extractEmailContext(graphEmail: GraphEmail): EmailContext {
  return {
    processingId: generateProcessingId(),
    senderEmail: graphEmail.from?.emailAddress?.address || 'unknown',
    subject: graphEmail.subject || '(No Subject)',
    body: graphEmail.body?.content || graphEmail.bodyPreview || '',
  };
}

async function checkPreConditions(
  graphEmail: GraphEmail,
  ctx: EmailContext,
  config: EmailProcessorConfig
): Promise<boolean> {
  const guardResult = evaluateEmailGuards(graphEmail, config.mailboxAddress);
  if (!guardResult.allowed) {
    metrics.recordDeduplicationHit();
    securityLogger.warn('Email blocked by guardrail', {
      processingId: ctx.processingId,
      emailId: graphEmail.id,
      reason: guardResult.reason,
    });
    return false;
  }
  const dedupeCheck = await config.deduplication.shouldProcess(ctx.senderEmail, ctx.subject, ctx.body);
  if (!dedupeCheck.allowed) {
    metrics.recordDeduplicationHit();
    securityLogger.info('Email skipped due to deduplication', {
      processingId: ctx.processingId,
      reason: dedupeCheck.reason,
    });
    return false;
  }
  return true;
}

/**
 * Process single email with full analysis pipeline
 */
export async function processEmail(graphEmail: GraphEmail, config: EmailProcessorConfig): Promise<void> {
  const ctx = extractEmailContext(graphEmail);
  securityLogger.info('Processing email from mailbox', {
    processingId: ctx.processingId,
    emailId: graphEmail.id,
    subject: ctx.subject,
    from: ctx.senderEmail,
  });

  if (!(await checkPreConditions(graphEmail, ctx, config))) return;

  try {
    const analysisResult = await executeAnalysis(graphEmail, ctx.processingId, config);
    await sendAnalysisReply(graphEmail, analysisResult, ctx.processingId, config);
    await config.deduplication.recordProcessed(ctx.senderEmail, ctx.subject, ctx.body);
    securityLogger.info('Email processing completed successfully', {
      processingId: ctx.processingId,
    });
  } catch (error: unknown) {
    await handleProcessingError(error, graphEmail, ctx.processingId, config);
  }
}

async function executeAnalysis(
  graphEmail: GraphEmail,
  processingId: string,
  config: EmailProcessorConfig
): Promise<PhishingAnalysisResult> {
  const analysisStart = Date.now();
  const analysisRequest = parseGraphEmail(graphEmail);
  const analysisResult = await config.phishingAgent.analyzeEmail(analysisRequest);
  metrics.recordAnalysisLatency(Date.now() - analysisStart);
  metrics.recordEmailProcessed(analysisResult.isPhishing);
  securityLogger.security('Email analyzed via mailbox monitor', {
    processingId,
    messageId: analysisResult.messageId,
    isPhishing: analysisResult.isPhishing,
    riskScore: analysisResult.riskScore,
    severity: analysisResult.severity,
  });
  return analysisResult;
}

async function handleProcessingError(
  error: unknown,
  graphEmail: GraphEmail,
  processingId: string,
  config: EmailProcessorConfig
): Promise<void> {
  metrics.recordAnalysisError();
  const errorMessage = getErrorMessage(error);
  securityLogger.error('Failed to process email', { processingId, error: errorMessage });
  await sendErrorReply(graphEmail, processingId, config).catch((replyError: unknown) => {
    securityLogger.error('Failed to send error reply', { processingId, error: getErrorMessage(replyError) });
  });
}

/**
 * Send analysis reply with rate limiting
 */
async function sendAnalysisReply(
  originalEmail: GraphEmail,
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
  const rateLimitCheck = await config.rateLimiter.canSendEmail();
  if (!rateLimitCheck.allowed) {
    metrics.recordRateLimitHit();
    securityLogger.warn('Email reply blocked by rate limiter', {
      processingId,
      recipient: senderEmail,
      reason: rateLimitCheck.reason,
      stats: await config.rateLimiter.getStats(),
    });
    return;
  }

  const htmlBody = buildReplyHtml(analysis);
  const replyMessage = createReplyMessage(originalEmail, htmlBody, analysis.isPhishing);

  try {
    const replyStart = Date.now();
    await config.graphClient.api(`/users/${config.mailboxAddress}/sendMail`).post(replyMessage);
    const replyLatency = Date.now() - replyStart;

    // Record metrics
    metrics.recordReplyLatency(replyLatency);
    metrics.recordReplySent();

    // Record email sent after successful send
    await config.rateLimiter.recordEmailSent();

    securityLogger.info('Analysis reply sent', {
      processingId,
      recipient: senderEmail,
      isPhishing: analysis.isPhishing,
      riskScore: analysis.riskScore,
      rateLimitStats: await config.rateLimiter.getStats(),
    });
  } catch (error: unknown) {
    metrics.recordReplyFailed();
    securityLogger.error('Failed to send analysis reply', { processingId, error: getErrorMessage(error) });
    throw error;
  }
}

/**
 * Send error reply to user
 */
async function sendErrorReply(
  originalEmail: GraphEmail,
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
