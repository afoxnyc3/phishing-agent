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

  // Check deduplication before processing
  const dedupeCheck = config.deduplication.shouldProcess(senderEmail, subject, body);
  if (!dedupeCheck.allowed) {
    securityLogger.info('Email skipped due to deduplication', {
      processingId,
      sender: senderEmail,
      subject,
      reason: dedupeCheck.reason,
    });
    return;
  }

  try {
    const analysisRequest = parseGraphEmail(graphEmail);
    const analysisResult = await config.phishingAgent.analyzeEmail(analysisRequest);

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
    await config.graphClient
      .api(`/users/${config.mailboxAddress}/sendMail`)
      .post(replyMessage);

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
